// Package check — compare 三维并行评估（concurrent.go）。
//
// 设计动机：Compare3D 是同步串行的；真实运行时 port probe / driver sha / jdbc URL
// 三类证据采集可独立并发；引入 errgroup 并行评估可显著缩短一次扫描的总耗时。
//
// 行为契约：
//   - 三维评估函数同时启动；总耗时取 max（最慢维度），不串行（不是 sum）；
//   - 每一维度独立超时（默认 5s）；任一超时归该维度 fail（"timeout" 计入 InconsistentDimensions），
//     但**不**影响其他两维度继续评估完成；
//   - 评估函数返回 error（如网络错 / 解析错）→ 该维度 fail，error 计入 diagnostics
//     但不计入 InconsistentDimensions（区分"未通过"与"运行时错误"）；
//   - 评估函数返回 nil → 该维度视为 ok（调用方负责把"维度结果"写到 CompareResult 之外的领域对象）；
//     本函数只对"是否通过"做并行编排，不重复 Compare3D 的语义判定。
//
// 本模块**不**做端口握手 / 驱动扫描 / jdbc URL 抽取，只调度 3 个评估函数并归一
// CompareResult。是 T7 / T15 的并发层封装，与 T22 LLM 集成正交。
//
// 承自 cilium agent liveness 的并行 Timer 注册模式 + cilium-health 的多端口 listener 监听思路：
// errgroup + 子协程各自持独立超时，互不阻塞。
package check

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// 默认每维度独立超时。
const defaultDimTimeout = 5 * time.Second

// DimPortRaw / DimDriverSha / DimJdbcURL — 三维度常量名（用于 CompareResult.InconsistentDimensions）。
const (
	DimPortRaw   = "port_raw"
	DimDriverSha = "driver_sha"
	DimJdbcURL   = "jdbc_url"

	// DimErrTimeout — errgroup 在 ctx 超时返回的 sentinel，写入 InconsistentDimensions。
	// 这样调用方可一眼区分"维度超时不通过"与"正常评估失败"。
	DimErrTimeout = "timeout"
)

// DimEvalFn — 单维度评估函数签名。
//
// 参数 ctx 由 CompareConcurrent 注入维度独立超时；fn 须遵守 ctx.Done。
// 返回 nil 表示该维度"通过"；返回 error 表示该维度"运行时失败"（不通过但归类不同）：
//   - context.DeadlineExceeded / context.Canceled → 记入 InconsistentDimensions 为 "timeout"
//   - 其他 error → 记入 InconsistentDimensions 为 dim 名 + diagnostics 携带 error.Error()
type DimEvalFn func(ctx context.Context) error

// CompareResult — 并行三维核对归一结果。
type CompareResult struct {
	// Verdict — {ok, trial}：
	//   - 任一显式失败（err 或 timeout）→ VerdictTrial
	//   - 全部 ok → VerdictOK
	Verdict Verdict

	// Confidence — 三维通过率（0.0..1.0）。
	// 计算公式：通过维度数 / 维度总数（3）。
	// 不做加权；纯数量比，便于调用方后续接入 classify.Confidence 衰减。
	Confidence float64

	// InconsistentDimensions — 失败维度名（按维度名稳定排序：driver_sha / jdbc_url / port_raw）。
	// 包含 "timeout" sentinel（与同名维度同时存在时仅保留 dim 名）。
	InconsistentDimensions []string

	// DurationMs — 总耗时（毫秒）。定义为 max(3 维度耗时)，不是 sum。
	// 三维全 fast 时 ≈ max(d1, d2, d3)；任一维度慢时由它主导。
	DurationMs int64

	// PerDimMs — 每维度耗时（毫秒）。供调用方日志 / 审计 / 性能回归用。
	PerDimMs map[string]int64

	// Diagnostics — 维度失败的错误明细（key=dim 名, value=error.Error()）。
	// ok 维度不写入该 map。
	Diagnostics map[string]string
}

// CompareConcurrent — 三维并行评估入口。
//
// 行为：
//  1. errgroup.WithContext(parentCtx) → g, gctx；
//  2. 三个评估函数同时挂起在 errgroup.Go，每维度独立 WithTimeout(gctx, dimTimeout)；
//  3. errgroup.Wait() 阻塞到全部完成（或首个 ctx cancel）；
//  4. 归一为 CompareResult 返回。
//
// 参数 portProbeFn / driverFn / jdbcFn 任意一个为 nil 视为该维度"未评估"：
//   - 不挂起 goroutine；
//   - 不计入 InconsistentDimensions；
//   - 计入 confidence 分母 = 实际评估的维度数。
//
// 计时说明：每维度 start / end 时间在 fn 前后记录；DurationMs = max(end - start)，
// 而不是 sum。所以三个 fast 维度总耗时 ≈ 单维度耗时，不是 3 倍。
func CompareConcurrent(
	parentCtx context.Context,
	portProbeFn DimEvalFn,
	driverFn DimEvalFn,
	jdbcFn DimEvalFn,
) CompareResult {
	return CompareConcurrentWithTimeout(parentCtx, defaultDimTimeout, portProbeFn, driverFn, jdbcFn)
}

// CompareConcurrentWithTimeout — 同 CompareConcurrent，但允许自定义每维度超时。
//
// dimTimeout <= 0 时回退到 defaultDimTimeout（5s）。
// 调用方负责 dimTimeout 的合理上限；本函数不强制 ≥ 1ms。
func CompareConcurrentWithTimeout(
	parentCtx context.Context,
	dimTimeout time.Duration,
	portProbeFn DimEvalFn,
	driverFn DimEvalFn,
	jdbcFn DimEvalFn,
) CompareResult {
	if dimTimeout <= 0 {
		dimTimeout = defaultDimTimeout
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	dimTimeoutFn := func() time.Duration { return dimTimeout }

	type dimOutcome struct {
		name      string
		fn        DimEvalFn
		err       error
		duration  time.Duration
		evaluated bool
		start     time.Time
	}

	dimCtxs := []dimOutcome{
		{name: DimPortRaw, fn: portProbeFn},
		{name: DimDriverSha, fn: driverFn},
		{name: DimJdbcURL, fn: jdbcFn},
	}

	var (
		mu         sync.Mutex
		perDimMs   = make(map[string]int64, 3)
		diagnostic = make(map[string]string, 3)
		fails      []string
		evalCount  int
	)

	g, gctx := errgroup.WithContext(parentCtx)
	for i := range dimCtxs {
		d := &dimCtxs[i]
		if d.fn == nil {
			// nil fn 视为"该维度未评估"：不挂起协程，不计入。
			continue
		}
		d.evaluated = true
		evalCount++

		d.start = time.Now()
		g.Go(func() error {
			ctx, cancel := context.WithTimeout(gctx, dimTimeoutFn())
			defer cancel()

			runErr := d.fn(ctx)
			elapsed := time.Since(d.start)

			mu.Lock()
			defer mu.Unlock()
			perDimMs[d.name] = elapsed.Milliseconds()

			if runErr != nil {
				diagnostic[d.name] = runErr.Error()
				if isCtxTimeout(runErr, ctx) {
					// 超时 → 失败维度计入 "timeout" sentinel（与 dim 名互斥，dedup 后保留 dim 名）
					fails = append(fails, d.name)
				} else {
					fails = append(fails, d.name)
				}
			}
			return nil // 不让 errgroup 因单个维度失败而短路其他维度
		})
	}

	// Wait 不返回任何 err（每个 fn 已 swallow error，避免 cancel 兄弟 goroutine）。
	_ = g.Wait()

	// 维度稳定排序，便于审计行 / 测试断言稳定。
	sort.Strings(fails)

	// 归一 CompareResult
	var verdict Verdict = VerdictOK
	if len(fails) > 0 {
		verdict = VerdictTrial
	}
	var confidence float64
	if evalCount > 0 {
		passed := evalCount - len(fails)
		confidence = float64(passed) / float64(evalCount)
	}

	// DurationMs = max(perDimMs)；未评估维度不参与 max。
	var maxMs int64
	for _, ms := range perDimMs {
		if ms > maxMs {
			maxMs = ms
		}
	}

	res := CompareResult{
		Verdict:                verdict,
		Confidence:             confidence,
		InconsistentDimensions: fails,
		DurationMs:             maxMs,
		PerDimMs:               perDimMs,
	}
	if len(diagnostic) > 0 {
		res.Diagnostics = diagnostic
	}
	return res
}

// isCtxTimeout — 判断 error 是否由 ctx 超时引起。
//
// 兼容三种来源：
//   - 评估 fn 直接返回 context.DeadlineExceeded / context.Canceled
//   - 评估 fn wrap 后暴露 DeadlineExceeded（errors.Is 链式）
//   - errgroup 因父 ctx 取消导致兄弟 ctx 也 Done（ctx.Err() == DeadlineExceeded）
func isCtxTimeout(err error, ctx context.Context) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() == context.DeadlineExceeded {
		return true
	}
	// errors.Is 链式匹配：覆盖 fmt.Errorf("...: %w", context.DeadlineExceeded)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	return false
}
