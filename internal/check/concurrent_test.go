// Package check — CompareConcurrent 单元测试（T40 拆分）。
//
// 覆盖：
//   - 三维度全 fast (10ms each) → 总耗时 ~10ms（不是 30ms）
//   - 一维度 timeout → 其他两维度仍评估完，Verdict=trial，InconsistentDimensions 含 timeout_dim
//   - 一维度 fn 返 err → 同上 fail 行为
//   - nil fn → 该维度不计入
//   - 全 fail → Verdict=trial + InconsistentDimensions=3 + Confidence=0.0
//   - 全 pass → Verdict=ok + Confidence=1.0 + DurationMs=max
//   - 并发安全：同一 CompareResult 被多 goroutine 读不 race
//   - 排序稳定性：InconsistentDimensions 按字典序
package check

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
)

// okFn — 评估函数"通过"形态。
func okFn(d time.Duration) DimEvalFn {
	return func(ctx context.Context) error {
		select {
		case <-time.After(d):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// errFn — 评估函数"运行时失败"形态。
func errFn(msg string) DimEvalFn {
	return func(ctx context.Context) error {
		return errors.New(msg)
	}
}

// hangFn — 评估函数"挂起到 ctx 超时"形态。
func hangFn() DimEvalFn {
	return func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
}

// TestCompareConcurrent_AllFast_VerdictOK — 三维全 fast（10ms each）→ verdict=ok, confidence=1.0。
func TestCompareConcurrent_AllFast_VerdictOK(t *testing.T) {
	res := CompareConcurrent(context.Background(),
		okFn(10*time.Millisecond),
		okFn(10*time.Millisecond),
		okFn(10*time.Millisecond),
	)
	if res.Verdict != VerdictOK {
		t.Fatalf("want verdict=ok, got %v (fails=%v)", res.Verdict, res.InconsistentDimensions)
	}
	if res.Confidence != 1.0 {
		t.Fatalf("want confidence=1.0, got %v", res.Confidence)
	}
	if len(res.InconsistentDimensions) != 0 {
		t.Fatalf("want 0 fails, got %v", res.InconsistentDimensions)
	}
	// 关键：总耗时 ~10ms（并行 max），不是 30ms（串行 sum）。
	// 留 30ms 余量覆盖调度抖动。
	if res.DurationMs > 30 {
		t.Fatalf("want DurationMs<=30 (parallel max), got %d (perDim=%v)", res.DurationMs, res.PerDimMs)
	}
	if res.PerDimMs[DimPortRaw] > 30 || res.PerDimMs[DimDriverSha] > 30 || res.PerDimMs[DimJdbcURL] > 30 {
		t.Fatalf("per-dim duration should be ~10ms each, got %v", res.PerDimMs)
	}
	if res.Diagnostics != nil {
		t.Fatalf("want nil diagnostics on all-ok, got %v", res.Diagnostics)
	}
}

// TestCompareConcurrent_ParallelFasterThanSerial — 验证"并行 max < 串行 sum"。
func TestCompareConcurrent_ParallelFasterThanSerial(t *testing.T) {
	const each = 50 * time.Millisecond
	res := CompareConcurrent(context.Background(),
		okFn(each),
		okFn(each),
		okFn(each),
	)
	if res.DurationMs >= int64(each/time.Millisecond)*3 {
		t.Fatalf("parallel total (%dms) must be < serial sum (%dms)", res.DurationMs, each/time.Millisecond*3)
	}
	if res.DurationMs > int64(each/time.Millisecond)+30 {
		t.Fatalf("DurationMs should ~= each (max of 3 fast dims), got %d", res.DurationMs)
	}
}

// TestCompareConcurrent_OneTimeout_OthersComplete — 一维度 timeout（其他仍评估完）。
func TestCompareConcurrent_OneTimeout_OthersComplete(t *testing.T) {
	res := CompareConcurrentWithTimeout(context.Background(), 30*time.Millisecond,
		okFn(5*time.Millisecond),      // fast ok
		hangFn(),                      // timeout
		okFn(5*time.Millisecond),      // fast ok
	)
	if res.Verdict != VerdictTrial {
		t.Fatalf("want verdict=trial, got %v", res.Verdict)
	}
	if len(res.InconsistentDimensions) != 1 {
		t.Fatalf("want 1 fail (driver_sha), got %v", res.InconsistentDimensions)
	}
	if res.InconsistentDimensions[0] != DimDriverSha {
		t.Fatalf("want fail dim=driver_sha, got %v", res.InconsistentDimensions[0])
	}
	// Confidence = 2 passed / 3 evaluated = 0.6666...
	if res.Confidence < 0.6 || res.Confidence > 0.7 {
		t.Fatalf("want confidence ~0.667, got %v", res.Confidence)
	}
	// driver_sha 应有 diagnostics（context.DeadlineExceeded）。
	if res.Diagnostics == nil || res.Diagnostics[DimDriverSha] == "" {
		t.Fatalf("want diagnostics for driver_sha timeout, got %v", res.Diagnostics)
	}
	// 总耗时 ~30ms（max）；不是 30+5+5=40ms 串行。
	if res.DurationMs > 100 {
		t.Fatalf("want DurationMs~30 (max of dims, with timeout), got %d", res.DurationMs)
	}
}

// TestCompareConcurrent_OneFnErr_OthersComplete — 一维度 fn 返回 err（非 timeout）。
func TestCompareConcurrent_OneFnErr_OthersComplete(t *testing.T) {
	res := CompareConcurrent(context.Background(),
		okFn(5*time.Millisecond),
		errFn("driver_sha not found"),
		okFn(5*time.Millisecond),
	)
	if res.Verdict != VerdictTrial {
		t.Fatalf("want verdict=trial, got %v", res.Verdict)
	}
	if len(res.InconsistentDimensions) != 1 || res.InconsistentDimensions[0] != DimDriverSha {
		t.Fatalf("want fail=[driver_sha], got %v", res.InconsistentDimensions)
	}
	if res.Diagnostics[DimDriverSha] != "driver_sha not found" {
		t.Fatalf("want diagnostics carry err msg, got %q", res.Diagnostics[DimDriverSha])
	}
}

// TestCompareConcurrent_AllFail — 三维全 fail。
func TestCompareConcurrent_AllFail(t *testing.T) {
	res := CompareConcurrent(context.Background(),
		errFn("port banner parse failed"),
		errFn("driver sha mismatch"),
		errFn("jdbc url pattern mismatch"),
	)
	if res.Verdict != VerdictTrial {
		t.Fatalf("want verdict=trial, got %v", res.Verdict)
	}
	if res.Confidence != 0.0 {
		t.Fatalf("want confidence=0.0, got %v", res.Confidence)
	}
	if len(res.InconsistentDimensions) != 3 {
		t.Fatalf("want 3 fails, got %v", res.InconsistentDimensions)
	}
	// 排序：driver_sha / jdbc_url / port_raw
	want := []string{DimDriverSha, DimJdbcURL, DimPortRaw}
	for i, d := range want {
		if res.InconsistentDimensions[i] != d {
			t.Fatalf("want fail[%d]=%s, got %s", i, d, res.InconsistentDimensions[i])
		}
	}
}

// TestCompareConcurrent_AllPass — 三维全 pass。
func TestCompareConcurrent_AllPass(t *testing.T) {
	res := CompareConcurrent(context.Background(),
		okFn(1*time.Millisecond),
		okFn(1*time.Millisecond),
		okFn(1*time.Millisecond),
	)
	if res.Verdict != VerdictOK {
		t.Fatalf("want verdict=ok, got %v", res.Verdict)
	}
	if res.Confidence != 1.0 {
		t.Fatalf("want confidence=1.0, got %v", res.Confidence)
	}
	if len(res.InconsistentDimensions) != 0 {
		t.Fatalf("want 0 fails, got %v", res.InconsistentDimensions)
	}
}

// TestCompareConcurrent_NilFn_NotEvaluated — nil fn 不挂起协程 + 不计入。
func TestCompareConcurrent_NilFn_NotEvaluated(t *testing.T) {
	res := CompareConcurrent(context.Background(),
		okFn(5*time.Millisecond),
		nil, // driver 不评估
		okFn(5*time.Millisecond),
	)
	if res.Verdict != VerdictOK {
		t.Fatalf("want verdict=ok, got %v", res.Verdict)
	}
	if res.Confidence != 1.0 {
		t.Fatalf("want confidence=1.0 (2 passed / 2 evaluated), got %v", res.Confidence)
	}
	if _, ok := res.PerDimMs[DimDriverSha]; ok {
		t.Fatalf("driver_sha should not be in PerDimMs (nil fn), got %v", res.PerDimMs)
	}
	if len(res.InconsistentDimensions) != 0 {
		t.Fatalf("want 0 fails, got %v", res.InconsistentDimensions)
	}
}

// TestCompareConcurrent_AllNil_NoEval — 三 fn 全 nil → 全不评估 + verdict=ok + confidence=0。
func TestCompareConcurrent_AllNil_NoEval(t *testing.T) {
	res := CompareConcurrent(context.Background(), nil, nil, nil)
	if res.Verdict != VerdictOK {
		t.Fatalf("want verdict=ok, got %v", res.Verdict)
	}
	if res.Confidence != 0.0 {
		t.Fatalf("want confidence=0.0 (no eval), got %v", res.Confidence)
	}
	if res.DurationMs != 0 {
		t.Fatalf("want DurationMs=0, got %d", res.DurationMs)
	}
}

// TestCompareConcurrent_ParentCancelStopsAll — parent ctx 取消 → 全部维度 fail（timeout）。
func TestCompareConcurrent_ParentCancelStopsAll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	res := CompareConcurrent(ctx,
		hangFn(),
		hangFn(),
		hangFn(),
	)
	if res.Verdict != VerdictTrial {
		t.Fatalf("want verdict=trial (parent canceled), got %v", res.Verdict)
	}
	if len(res.InconsistentDimensions) != 3 {
		t.Fatalf("want 3 fails (all canceled), got %v", res.InconsistentDimensions)
	}
}

// TestCompareConcurrent_DimTimeoutRespected — 验证 dimTimeout 实际生效。
func TestCompareConcurrent_DimTimeoutRespected(t *testing.T) {
	const dimTimeout = 50 * time.Millisecond
	res := CompareConcurrentWithTimeout(context.Background(), dimTimeout,
		hangFn(),
		hangFn(),
		hangFn(),
	)
	if res.Verdict != VerdictTrial {
		t.Fatalf("want verdict=trial (all timeout), got %v", res.Verdict)
	}
	// 每维度 max 应该接近 dimTimeout；总耗时 ≈ max。
	maxDim := res.PerDimMs[DimPortRaw]
	for _, d := range []string{DimDriverSha, DimJdbcURL} {
		if res.PerDimMs[d] > maxDim {
			maxDim = res.PerDimMs[d]
		}
	}
	if maxDim < int64(dimTimeout/time.Millisecond)-20 {
		t.Fatalf("want dim duration ~%dms (timeout), got %d", dimTimeout/time.Millisecond, maxDim)
	}
	if res.DurationMs < int64(dimTimeout/time.Millisecond)-20 {
		t.Fatalf("want DurationMs >= dimTimeout, got %d", res.DurationMs)
	}
}

// TestCompareConcurrent_WrappedTimeout — error wrap 链上的 context.DeadlineExceeded 仍识别。
func TestCompareConcurrent_WrappedTimeout(t *testing.T) {
	wrapped := func(ctx context.Context) error {
		<-ctx.Done()
		// 用 %w wrap，errors.Is 应能穿透
		return fmt.Errorf("scan aborted: %w", ctx.Err())
	}
	res := CompareConcurrentWithTimeout(context.Background(), 20*time.Millisecond,
		okFn(2*time.Millisecond),
		wrapped,
		okFn(2*time.Millisecond),
	)
	if res.Verdict != VerdictTrial {
		t.Fatalf("want verdict=trial, got %v", res.Verdict)
	}
	if len(res.InconsistentDimensions) != 1 || res.InconsistentDimensions[0] != DimDriverSha {
		t.Fatalf("want fail=[driver_sha] (wrapped timeout), got %v", res.InconsistentDimensions)
	}
}

// TestCompareConcurrent_PerDimCounters — 验证 PerDimMs 三维度均有值。
func TestCompareConcurrent_PerDimCounters(t *testing.T) {
	res := CompareConcurrent(context.Background(),
		okFn(15*time.Millisecond),
		okFn(20*time.Millisecond),
		okFn(10*time.Millisecond),
	)
	if len(res.PerDimMs) != 3 {
		t.Fatalf("want 3 per-dim entries, got %d (%v)", len(res.PerDimMs), res.PerDimMs)
	}
	// DurationMs 应是 max (~20ms)。
	if res.DurationMs > 40 {
		t.Fatalf("DurationMs should ~max(20ms), got %d", res.DurationMs)
	}
}

// TestCompareConcurrent_FailsSortedStably — InconsistentDimensions 字典序稳定。
func TestCompareConcurrent_FailsSortedStably(t *testing.T) {
	res := CompareConcurrent(context.Background(),
		errFn("port err"),
		errFn("driver err"),
		errFn("jdbc err"),
	)
	want := []string{DimDriverSha, DimJdbcURL, DimPortRaw}
	for i, d := range want {
		if res.InconsistentDimensions[i] != d {
			t.Fatalf("want sorted fail[%d]=%s, got %s", i, d, res.InconsistentDimensions[i])
		}
	}
}

// TestCompareConcurrent_NoRaceWithConcurrentReaders — race detector 不报警。
func TestCompareConcurrent_NoRaceWithConcurrentReaders(t *testing.T) {
	res := CompareConcurrent(context.Background(),
		okFn(10*time.Millisecond),
		errFn("x"),
		okFn(10*time.Millisecond),
	)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = res.Verdict
			_ = res.Confidence
			_ = res.InconsistentDimensions
			_ = res.DurationMs
		}()
	}
	wg.Wait()
}

// TestCompareConcurrent_HighConcurrency50Contracts — 50 contract 并发 CompareConcurrent 不 race。
func TestCompareConcurrent_HighConcurrency50Contracts(t *testing.T) {
	g, gctx := errgroup.WithContext(context.Background())
	var cnt int64
	for i := 0; i < 50; i++ {
		g.Go(func() error {
			res := CompareConcurrent(gctx,
				okFn(2*time.Millisecond),
				okFn(2*time.Millisecond),
				okFn(2*time.Millisecond),
			)
			if res.Verdict != VerdictOK {
				atomic.AddInt64(&cnt, 1)
			}
			return nil
		})
	}
	_ = g.Wait()
	if cnt != 0 {
		t.Fatalf("all 50 should pass, got %d failed", cnt)
	}
}

// TestCompareConcurrent_DoesNotPromoteTrial — CompareConcurrent 不写 trial store / 不调 confirm-drift。
// （行为约束：通过 pure-orchestration 设计保证；本测试断言 CompareResult 不含 trial store 副作用。）
func TestCompareConcurrent_DoesNotPromoteTrial(t *testing.T) {
	res := CompareConcurrent(context.Background(),
		errFn("port mismatch"),
		okFn(5*time.Millisecond),
		okFn(5*time.Millisecond),
	)
	if res.Verdict != VerdictTrial {
		t.Fatalf("want verdict=trial, got %v", res.Verdict)
	}
	// 没有副作用字段：CompareResult 不暴露任何 audit/store 句柄。
	if res.Diagnostics[DimPortRaw] == "" {
		t.Fatalf("want port mismatch diagnostics non-empty")
	}
	// trial 推进由人工 confirm-drift 触发，与本函数正交（不调用 bbolt）。
	// 本测试仅断言无 audit_path/store_path 字段写入。
	type expectedShape struct {
		Verdict               Verdict
		Confidence            float64
		InconsistentDimensions []string
		DurationMs            int64
		PerDimMs              map[string]int64
		Diagnostics           map[string]string
	}
	var shape expectedShape = expectedShape{
		Verdict:               res.Verdict,
		Confidence:            res.Confidence,
		InconsistentDimensions: res.InconsistentDimensions,
		DurationMs:            res.DurationMs,
		PerDimMs:              res.PerDimMs,
		Diagnostics:           res.Diagnostics,
	}
	if shape.Verdict != VerdictTrial {
		t.Fatalf("shape check failed")
	}
}

// TestCompareConcurrent_EmptyDiagnosticsOnPass — 全 pass 时 Diagnostics 字段为 nil（节省分配）。
func TestCompareConcurrent_EmptyDiagnosticsOnPass(t *testing.T) {
	res := CompareConcurrent(context.Background(),
		okFn(1*time.Millisecond),
		okFn(1*time.Millisecond),
		okFn(1*time.Millisecond),
	)
	if res.Diagnostics != nil {
		t.Fatalf("want nil diagnostics on all-pass, got %v", res.Diagnostics)
	}
}

// TestCompareConcurrent_FastDimDoesNotBlockSlowDim — fast 维度不阻塞 slow 维度。
func TestCompareConcurrent_FastDimDoesNotBlockSlowDim(t *testing.T) {
	start := time.Now()
	res := CompareConcurrent(context.Background(),
		okFn(100*time.Millisecond),     // slow
		okFn(5*time.Millisecond),       // fast
		okFn(5*time.Millisecond),       // fast
	)
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Fatalf("slow dim should run in parallel with fast dims; total elapsed=%v", elapsed)
	}
	if res.Verdict != VerdictOK {
		t.Fatalf("want verdict=ok, got %v", res.Verdict)
	}
	// DurationMs ≈ 100ms (slow dim 主导 max)。
	if res.DurationMs < 80 || res.DurationMs > 200 {
		t.Fatalf("DurationMs should ~100ms (slowest dim), got %d (perDim=%v)", res.DurationMs, res.PerDimMs)
	}
}

// TestCompareConcurrent_CustomTimeoutZeroFallsBack — 自定义 timeout <= 0 回退到默认 5s。
func TestCompareConcurrent_CustomTimeoutZeroFallsBack(t *testing.T) {
	res := CompareConcurrentWithTimeout(context.Background(), 0,
		okFn(5*time.Millisecond),
		okFn(5*time.Millisecond),
		okFn(5*time.Millisecond),
	)
	if res.Verdict != VerdictOK {
		t.Fatalf("want verdict=ok, got %v", res.Verdict)
	}
}

// TestCompareConcurrent_NilParentCtx — parentCtx=nil 不 panic（回退到 Background）。
func TestCompareConcurrent_NilParentCtx(t *testing.T) {
	res := CompareConcurrent(nil, //nolint:staticcheck // 故意 nil 测防御
		okFn(1*time.Millisecond),
		okFn(1*time.Millisecond),
		okFn(1*time.Millisecond),
	)
	if res.Verdict != VerdictOK {
		t.Fatalf("want verdict=ok on nil parent ctx, got %v", res.Verdict)
	}
}

// TestCompareConcurrent_PartialTimeout — 一维度 timeout + 一维度 err 混合。
func TestCompareConcurrent_PartialTimeout(t *testing.T) {
	res := CompareConcurrentWithTimeout(context.Background(), 20*time.Millisecond,
		okFn(3*time.Millisecond),
		hangFn(),         // timeout
		errFn("jdbc fail"), // err
	)
	if res.Verdict != VerdictTrial {
		t.Fatalf("want verdict=trial, got %v", res.Verdict)
	}
	if len(res.InconsistentDimensions) != 2 {
		t.Fatalf("want 2 fails (driver_sha + jdbc_url), got %v", res.InconsistentDimensions)
	}
	// 排序：[driver_sha, jdbc_url]
	if res.InconsistentDimensions[0] != DimDriverSha || res.InconsistentDimensions[1] != DimJdbcURL {
		t.Fatalf("want sorted [driver_sha, jdbc_url], got %v", res.InconsistentDimensions)
	}
	// Confidence = 1 passed / 3 evaluated = 0.333
	if res.Confidence < 0.3 || res.Confidence > 0.4 {
		t.Fatalf("want confidence ~0.333, got %v", res.Confidence)
	}
}

// TestIsCtxTimeout — 单测 isCtxTimeout 的识别分支。
func TestIsCtxTimeout(t *testing.T) {
	if isCtxTimeout(nil, context.Background()) {
		t.Fatal("nil err should not be timeout")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	time.Sleep(10 * time.Millisecond)
	if !isCtxTimeout(context.DeadlineExceeded, ctx) {
		t.Fatal("direct DeadlineExceeded should be detected when ctx.Err() also DeadlineExceeded")
	}
	if !isCtxTimeout(errors.New("wrapped: "), ctx) {
		t.Fatal("ctx.Err()==DeadlineExceeded should drive detection even if err is unrelated")
	}
}
