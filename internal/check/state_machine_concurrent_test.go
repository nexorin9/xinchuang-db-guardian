// Package check_test — 状态机并发安全验证（T17 / T20 并发安全层拆分）。
//
// 设计原则：
//   - 状态机推进 trial 由 TrialStore.mu (sync.Mutex) 严格串行化；
//   - 10 goroutine 并发 confirm-drift 同一 event_id（target=remedied）→ 仅 1 个成功；
//   - 其余 9 个调用 PromoteTrial 时，旧 State 已被第一个写入 remedied，
//     CanTransition(remedied, remedied) 因同状态拒绝返回 ErrInvalidTransition；
//   - audit.jsonl 至少 +1 行 drift_remedied（仅成功路径 AppendJSONL）；
//   - prev_evidence_sha256 链不被并发写乱（每次 PromoteTrial 在 mutex 内算 HashBody+SelfHash）；
//   - 50 个不同 event_id 并发 → 全部成功（独立互不影响）；
//   - race detector 必须无报警（go test -race）。
//
// 承自 cilium healthz 的 mutex 保护思路（pkg/datapath/agentliveness），把
// "全局不变量由 mutex 守护"模式移植到状态机推进路径。
package check_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xinchuang-db-guardian/internal/check"
	"xinchuang-db-guardian/internal/output"
)

// sampleConcurrentEvidence — 构造一个 trial 状态下的标准 DriftEvidence。
//
// 用于 state_machine_concurrent_test.go 内部；不复用 store_test.go 的 helper
// 是因为该文件位于 check 包测试（package check_test）而非 output 包测试。
func sampleConcurrentEvidence(eventID, contractID string, ts time.Time) check.DriftEvidence {
	return check.DriftEvidence{
		EventID:            eventID,
		ContractID:         contractID,
		SystemID:           "his-core",
		Vendor:             "kingbase",
		Declared:           "KingbaseES V008R006",
		Actual:             "PostgreSQL 14.10 (Debian)",
		PortRaw:            "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1)",
		DriverSha:          "abc123",
		JDBCURL:            "jdbc:kingbase8://10.0.0.1:54321/TEST",
		Verdict:            check.VerdictTrial,
		Confidence:         0.95,
		EvidenceSHA256:     "evidence-" + eventID,
		Status:             check.StateTrial,
		PrevEvidenceSHA256: "",
		SelfHash:           "",
		TsUTC:              ts.UTC().Format(time.RFC3339Nano),
	}
}

// tempDbPathForConcurrent — 给并发测试生成一个独立的 bbolt 文件路径。
//
// t.TempDir() 自带清理；并发打开同一文件需用 bolt.Options{Timeout: 5s}。
func tempDbPathForConcurrent(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "trial_concurrent.db")
}

// seedTrialStore — 在测试开始前写入一条 trial 状态的事件；返回 store 与其 Close 清理函数。
func seedTrialStore(t *testing.T, eventID, contractID string) (*output.TrialStore, func()) {
	t.Helper()
	path := tempDbPathForConcurrent(t)
	store, err := output.OpenTrialStore(path)
	if err != nil {
		t.Fatalf("open trial store: %v", err)
	}
	ev := sampleConcurrentEvidence(eventID, contractID, time.Now().UTC())
	ev = output.MakeDriftEvidence(ev, "")
	if err := store.SaveTrial(ev); err != nil {
		_ = store.Close()
		t.Fatalf("save trial: %v", err)
	}
	return store, func() { _ = store.Close() }
}

// TestPromoteTrial_ConcurrentSameEventOnlyOneSuccess — 核心并发安全验证。
//
// 场景：10 goroutine 同时对同一 event_id 调 PromoteTrial(target=remedied)。
// 期望：
//   - success counter == 1（仅首个拿到 Status=trial 的 goroutine 成功）；
//   - 9 个失败的 error 含 ErrInvalidTransition 语义（trial 已被首个人推进 remedied，
//     后续 9 个看到 remedied→remedied 同状态拒绝）；
//   - 最终 DriftEvidence.State == remedied（不被乱序覆盖）；
//   - race detector 无报警。
func TestPromoteTrial_ConcurrentSameEventOnlyOneSuccess(t *testing.T) {
	const goroutines = 10
	eventID := "test-001"
	contractID := "c-concurrent"
	store, cleanup := seedTrialStore(t, eventID, contractID)
	t.Cleanup(cleanup)

	var (
		successCount int64
		invalidCount int64
		otherCount   int64
		wg           sync.WaitGroup
		start        = make(chan struct{})
	)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // 同步起步，最大化并发争抢
			_, err := store.PromoteTrial(eventID, check.StateRemedied, fmt.Sprintf("operator-%d", idx))
			switch {
			case err == nil:
				atomic.AddInt64(&successCount, 1)
			case errors.Is(err, output.ErrInvalidTransition),
				check.IsInvalidTransition(err):
				atomic.AddInt64(&invalidCount, 1)
			default:
				atomic.AddInt64(&otherCount, 1)
				t.Errorf("goroutine %d 收到非预期错误: %v", idx, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	// 断言 1：仅 1 个成功。
	if got := atomic.LoadInt64(&successCount); got != 1 {
		t.Errorf("success count = %d, want 1", got)
	}
	// 断言 2：其余 9 个都返回 ErrInvalidTransition 语义（同状态拒绝）。
	if got := atomic.LoadInt64(&invalidCount); got != int64(goroutines-1) {
		t.Errorf("invalid_transition count = %d, want %d", got, goroutines-1)
	}
	// 断言 3：无其他类型错误。
	if got := atomic.LoadInt64(&otherCount); got != 0 {
		t.Errorf("unexpected error count = %d, want 0", got)
	}

	// 断言 4：最终 State == remedied（不被乱序覆盖）。
	final, err := store.LoadTrial(eventID)
	if err != nil {
		t.Fatalf("load final: %v", err)
	}
	if final.Status != check.StateRemedied {
		t.Errorf("final status = %q, want %q", final.Status, check.StateRemedied)
	}
	if final.SelfHash == "" {
		t.Error("final self_hash must be set after promotion")
	}
	if final.PrevEvidenceSHA256 == "" {
		t.Error("final prev_evidence_sha256 must be set after promotion")
	}
}

// TestPromoteTrial_ConcurrentSameEventExactlyOneDriftRow — 验证审计行仅 1 条 drift_remedied。
//
// 镜像 cmd_confirm 的真实审计落盘逻辑：
//   - 外层先 LoadTrial + CanTransition → 失败时 AppendJSONL kind=invalid_transition；
//   - 外层检查通过后调 PromoteTrial → 成功时 AppendJSONL kind=drift_remedied；
//   - 外层检查通过但 PromoteTrial 失败（TOCTOU race）→ 不落审计行（与 cmd_confirm 一致）。
//
// 关键不变量：
//   - drift_remedied 行恰好 1 条（PromoteTrial 内部 mutex 串行化保证）；
//   - VerifyChain 通过（prev_evidence_sha256 链不被并发写乱）。
func TestPromoteTrial_ConcurrentSameEventExactlyOneDriftRow(t *testing.T) {
	const goroutines = 10
	eventID := "test-audit"
	contractID := "c-concurrent-audit"
	store, cleanup := seedTrialStore(t, eventID, contractID)
	t.Cleanup(cleanup)

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var (
		driftRows   int64 // kind=drift_remedied 计数
		invalidRows int64 // kind=invalid_transition 计数
		raceLosers  int64 // 跑过外层 check 但 PromoteTrial 失败（不落审计行）
		wg          sync.WaitGroup
		start       = make(chan struct{})
		auditMu     sync.Mutex
	)
	appendAudit := func(row output.AuditRow) {
		auditMu.Lock()
		defer auditMu.Unlock()
		if _, err := output.AppendJSONL(auditPath, row); err != nil {
			t.Errorf("append audit: %v", err)
		}
	}

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			target := check.StateRemedied

			// 外层预检（与 cmd_confirm 一致）。
			current, err := store.LoadTrial(eventID)
			if err != nil {
				t.Errorf("goroutine %d load: %v", idx, err)
				return
			}
			if err := check.CanTransition(current.Status, target); err != nil {
				atomic.AddInt64(&invalidRows, 1)
				appendAudit(output.AuditRow{
					TsUTC:          time.Now().UTC().Format(time.RFC3339Nano),
					EventID:        eventID,
					ContractID:     current.ContractID,
					SystemID:       current.SystemID,
					Vendor:         current.Vendor,
					Declared:       current.Declared,
					Actual:         current.Actual,
					PortRaw:        current.PortRaw,
					DriverSha:      current.DriverSha,
					JDBCURL:        current.JDBCURL,
					Verdict:        string(current.Verdict),
					Confidence:     current.Confidence,
					EvidenceSHA256: current.EvidenceSHA256,
					Action:         "remedied",
					Operator:       fmt.Sprintf("operator-%d", idx),
					Kind:           "invalid_transition",
				})
				return
			}

			// PromoteTrial 调用：可能因 TOCTOU race 失败（外层锁外层，PromoteTrial 内部锁内层；
			// 外层过 check 后等 mutex 期间，状态可能已被前一个 Goroutine 推进）。
			updated, perr := store.PromoteTrial(eventID, target, fmt.Sprintf("operator-%d", idx))
			if perr != nil {
				// 与 cmd_confirm 一致：仅 stderr 报错，不落审计行。
				if !errors.Is(perr, output.ErrInvalidTransition) && !check.IsInvalidTransition(perr) {
					t.Errorf("goroutine %d 收到非预期 promote 错误: %v", idx, perr)
					return
				}
				atomic.AddInt64(&raceLosers, 1)
				return
			}

			atomic.AddInt64(&driftRows, 1)
			appendAudit(output.AuditRow{
				TsUTC:              updated.TsUTC,
				EventID:            updated.EventID,
				ContractID:         updated.ContractID,
				SystemID:           updated.SystemID,
				Vendor:             updated.Vendor,
				Declared:           updated.Declared,
				Actual:             updated.Actual,
				PortRaw:            updated.PortRaw,
				DriverSha:          updated.DriverSha,
				JDBCURL:            updated.JDBCURL,
				Verdict:            string(updated.Verdict),
				Confidence:         updated.Confidence,
				EvidenceSHA256:     updated.EvidenceSHA256,
				PrevEvidenceSHA256: updated.PrevEvidenceSHA256,
				Action:             "remedied",
				Operator:           fmt.Sprintf("operator-%d", idx),
				Kind:               "drift_remedied",
			})
		}(i)
	}
	close(start)
	wg.Wait()

	// 断言 1：仅 1 条 drift_remedied 行。
	if got := atomic.LoadInt64(&driftRows); got != 1 {
		t.Errorf("drift_remedied rows = %d, want 1", got)
	}
	// 断言 2：invalid_transition + race_losers + drift_remedied = 10（无丢失）。
	total := atomic.LoadInt64(&driftRows) + atomic.LoadInt64(&invalidRows) + atomic.LoadInt64(&raceLosers)
	if total != int64(goroutines) {
		t.Errorf("drift(%d) + invalid_transition(%d) + race_loser(%d) = %d, want %d",
			atomic.LoadInt64(&driftRows), atomic.LoadInt64(&invalidRows),
			atomic.LoadInt64(&raceLosers), total, goroutines)
	}
	// 断言 3：audit.jsonl 链 VerifyChain 通过（prev_hash 不被并发写乱）。
	if err := output.VerifyChain(auditPath); err != nil {
		t.Errorf("audit verify-chain failed under concurrency: %v", err)
	}
}

// TestPromoteTrial_ConcurrentDifferentEventsAllSucceed — fuzz / 独立事件并发。
//
// 50 个不同 event_id 同时跑 PromoteTrial；每个 event_id 独立一条 trial，
// PromoteTrial 在 mutex 内串行化但事件之间无依赖 → 全部成功。
//
// 验证：
//   - 50 个全部 success（无 ErrInvalidTransition 事件间互不干扰）；
//   - 50 个 audit 行均 kind=drift_remedied；
//   - VerifyChain 通过（50 节链 prev 链接正确）；
//   - race detector 无报警。
func TestPromoteTrial_ConcurrentDifferentEventsAllSucceed(t *testing.T) {
	const events = 50
	path := tempDbPathForConcurrent(t)
	store, err := output.OpenTrialStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// 先把 50 条 trial 状态写入 store。
	now := time.Now().UTC()
	for i := 0; i < events; i++ {
		eventID := fmt.Sprintf("fuzz-%03d", i)
		ev := sampleConcurrentEvidence(eventID, "c-fuzz", now)
		ev = output.MakeDriftEvidence(ev, "")
		if err := store.SaveTrial(ev); err != nil {
			t.Fatalf("seed %s: %v", eventID, err)
		}
	}

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var (
		successCount int64
		wg           sync.WaitGroup
		start        = make(chan struct{})
		auditMu      sync.Mutex
	)

	for i := 0; i < events; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			eventID := fmt.Sprintf("fuzz-%03d", idx)
			updated, err := store.PromoteTrial(eventID, check.StateRemedied, "auto-fuzz")
			if err != nil {
				t.Errorf("promote %s: %v", eventID, err)
				return
			}
			if updated.Status != check.StateRemedied {
				t.Errorf("%s status = %q, want remedied", eventID, updated.Status)
			}
			atomic.AddInt64(&successCount, 1)
			auditMu.Lock()
			if _, err := output.AppendJSONL(auditPath, output.AuditRow{
				TsUTC:              updated.TsUTC,
				EventID:            updated.EventID,
				ContractID:         updated.ContractID,
				SystemID:           updated.SystemID,
				Vendor:             updated.Vendor,
				Declared:           updated.Declared,
				Actual:             updated.Actual,
				PortRaw:            updated.PortRaw,
				DriverSha:          updated.DriverSha,
				JDBCURL:            updated.JDBCURL,
				Verdict:            string(updated.Verdict),
				Confidence:         updated.Confidence,
				EvidenceSHA256:     updated.EvidenceSHA256,
				PrevEvidenceSHA256: updated.PrevEvidenceSHA256,
				Action:             "remedied",
				Operator:           "auto-fuzz",
				Kind:               "drift_remedied",
			}); err != nil {
				t.Errorf("append audit %s: %v", eventID, err)
			}
			auditMu.Unlock()
		}(i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&successCount); got != int64(events) {
		t.Errorf("success count = %d, want %d", got, events)
	}

	if err := output.VerifyChain(auditPath); err != nil {
		t.Errorf("audit verify-chain failed across %d events: %v", events, err)
	}
}

// TestPromoteTrial_ConcurrentCanTransitionNotMutated — 并发调 CanTransition 不会
// 改 transfer table 的内存视图。
//
// 50 goroutine 持续跑 CanTransition(各种 from/to 组合)，同时 1 goroutine 跑
// PromoteTrial；CanTransition 是纯函数，无共享可变状态，race detector 必须无报警。
//
// 这是 T17 状态机"非法 back-edge 拒绝"的不变量在并发下的保活验证。
func TestPromoteTrial_ConcurrentCanTransitionNotMutated(t *testing.T) {
	eventID := "test-immut"
	contractID := "c-immut"
	store, cleanup := seedTrialStore(t, eventID, contractID)
	t.Cleanup(cleanup)

	const pairs = 1000
	var wg sync.WaitGroup
	start := make(chan struct{})

	// 1 个 goroutine 跑 PromoteTrial；其它 50 个跑 CanTransition 压测。
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if _, err := store.PromoteTrial(eventID, check.StateRemedied, "immut-op"); err != nil {
			t.Errorf("promote: %v", err)
		}
	}()

	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			states := []check.State{
				check.StateTrial, check.StateConfirmed, check.StateRemedied,
				check.StateReVerified, check.StateDisputed,
			}
			for i := 0; i < pairs; i++ {
				from := states[i%len(states)]
				to := states[(i+1)%len(states)]
				_ = check.CanTransition(from, to)
				_ = check.AllowedTransitions(from)
				_ = check.ValidState(string(from))
			}
		}()
	}
	close(start)
	wg.Wait()

	// 最终状态必须确定是 remedied（不被中间态搅乱）。
	final, err := store.LoadTrial(eventID)
	if err != nil {
		t.Fatalf("load final: %v", err)
	}
	if final.Status != check.StateRemedied {
		t.Errorf("final status = %q, want remedied", final.Status)
	}
}