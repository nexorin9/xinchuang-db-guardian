// Package output_test — drift 去重窗口与 MakeDriftEvidence 的单元测试。
//
// 覆盖：
//   - 同 (system_id, vendor) 5 分钟内第 2 次返回 Deduped=true；
//   - 6 分钟后再命中返回 AlertSent=true；
//   - 同 evidence_sha256 命中返回 Idempotent=true，不增长计数；
//   - 跨 (system_id, vendor) 不互相干扰；
//   - MakeDriftEvidence 的 SelfHash 链头/续链确定性；
//   - 并发 10 goroutine 写时 entries 索引内部一致。
package output_test

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xinchuang-db-guardian/internal/check"
	"xinchuang-db-guardian/internal/output"
)

func sampleEvidence(systemID, vendor, evidenceSHA string) check.DriftEvidence {
	return check.DriftEvidence{
		EventID:        "ev-" + systemID + "-" + vendor,
		ContractID:     "c-" + systemID,
		SystemID:       systemID,
		Vendor:         vendor,
		Declared:       "v8.1",
		Actual:         "DM Database Server V8.1.0",
		PortRaw:        "DM Database Server V8.1.0",
		DriverSha:      "deadbeef",
		JDBCURL:        "jdbc:dm://10.0.0.1:5236/DB",
		Verdict:        check.VerdictTrial,
		Confidence:     0.95,
		EvidenceSHA256: evidenceSHA,
		Status:         check.StateTrial,
		TsUTC:          time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func TestDedupWindow_FirstHitAlertSent(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	r := w.RecordAndCheck(sampleEvidence("his-core", "dm8", "sha-1"), now)
	if !r.AlertSent {
		t.Fatalf("expected AlertSent=true on first hit, got %+v", r)
	}
	if r.Deduped || r.Idempotent {
		t.Fatalf("first hit must not be Deduped/Idempotent, got %+v", r)
	}
	if w.Size() != 1 {
		t.Fatalf("expected 1 entry, got %d", w.Size())
	}
}

func TestDedupWindow_SameVendorWithin5MinDeduped(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	w.RecordAndCheck(sampleEvidence("his-core", "dm8", "sha-1"), now)
	now2 := now.Add(2 * time.Minute)
	r := w.RecordAndCheck(sampleEvidence("his-core", "dm8", "sha-2"), now2)
	if r.AlertSent {
		t.Fatalf("second hit within window must not alert, got %+v", r)
	}
	if !r.Deduped {
		t.Fatalf("second hit within window must be Deduped, got %+v", r)
	}
	if r.WindowReason != "dedup_window" {
		t.Fatalf("window reason should be dedup_window, got %q", r.WindowReason)
	}
}

func TestDedupWindow_AfterWindowAlert(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	w.RecordAndCheck(sampleEvidence("his-core", "dm8", "sha-1"), now)
	now2 := now.Add(6 * time.Minute)
	r := w.RecordAndCheck(sampleEvidence("his-core", "dm8", "sha-2"), now2)
	if !r.AlertSent {
		t.Fatalf("after 6min new entry should alert, got %+v", r)
	}
}

func TestDedupWindow_SameEvidenceSHAIdempotent(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	w.RecordAndCheck(sampleEvidence("his-core", "dm8", "same-sha"), now)
	now2 := now.Add(30 * time.Second)
	r := w.RecordAndCheck(sampleEvidence("his-core", "dm8", "same-sha"), now2)
	if !r.Idempotent {
		t.Fatalf("same evidence_sha must be Idempotent, got %+v", r)
	}
	if r.AlertSent || r.Deduped {
		t.Fatalf("Idempotent must not alert/dedupe, got %+v", r)
	}
	if r.WindowReason != "evidence_sha_match" {
		t.Fatalf("window reason should be evidence_sha_match, got %q", r.WindowReason)
	}
}

func TestDedupWindow_DifferentSystemIndependent(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	w.RecordAndCheck(sampleEvidence("his-core", "dm8", "sha-a"), now)
	r := w.RecordAndCheck(sampleEvidence("emr", "dm8", "sha-b"), now)
	if !r.AlertSent {
		t.Fatalf("different system_id must alert independently, got %+v", r)
	}
	if w.Size() != 2 {
		t.Fatalf("expected 2 entries for 2 system_ids, got %d", w.Size())
	}
}

func TestDedupWindow_GCRemovesOld(t *testing.T) {
	w := output.NewDedupWindow(1 * time.Minute)
	now := time.Now().UTC()
	w.RecordAndCheck(sampleEvidence("his-core", "dm8", "sha-1"), now)
	// 3 分钟远超 window*2 = 2 分钟，GC 应当清掉。
	removed := w.GC(now.Add(3 * time.Minute))
	if removed != 1 {
		t.Fatalf("GC should remove 1 entry, removed=%d", removed)
	}
	if w.Size() != 0 {
		t.Fatalf("expected empty after GC, got %d", w.Size())
	}
}

func TestDedupWindow_DefaultWindow(t *testing.T) {
	w := output.NewDedupWindow(0)
	if w.Window() != output.DefaultDedupWindow {
		t.Fatalf("expected default window %s, got %s", output.DefaultDedupWindow, w.Window())
	}
}

func TestMakeDriftEvidence_SelfHashDeterministic(t *testing.T) {
	ev := sampleEvidence("his-core", "dm8", "sha-x")
	// 相同 prev + 相同 body → 相同 self_hash。
	a := output.MakeDriftEvidence(ev, "prev-1")
	b := output.MakeDriftEvidence(ev, "prev-1")
	if a.SelfHash == "" {
		t.Fatalf("self_hash must not be empty")
	}
	if a.SelfHash != b.SelfHash {
		t.Fatalf("self_hash must be deterministic for same inputs, %s != %s", a.SelfHash, b.SelfHash)
	}
	if a.PrevEvidenceSHA256 != "prev-1" {
		t.Fatalf("prev_evidence_sha256 should be propagated, got %q", a.PrevEvidenceSHA256)
	}
	if !strings.HasPrefix(a.SelfHash, "") || len(a.SelfHash) != 64 {
		t.Fatalf("self_hash should be 64 hex chars, got %q", a.SelfHash)
	}
}

func TestMakeDriftEvidence_DifferentPrevDifferentSelfHash(t *testing.T) {
	ev := sampleEvidence("his-core", "dm8", "sha-y")
	a := output.MakeDriftEvidence(ev, "")
	b := output.MakeDriftEvidence(ev, "non-empty-prev")
	if a.SelfHash == b.SelfHash {
		t.Fatalf("different prev must produce different self_hash")
	}
}

func TestComputeEvidenceChainID_Deterministic(t *testing.T) {
	ev := sampleEvidence("his-core", "dm8", "sha-z")
	ev.SelfHash = "abcd"
	id1 := output.ComputeEvidenceChainID(ev)
	id2 := output.ComputeEvidenceChainID(ev)
	if id1 != id2 || len(id1) != 64 {
		t.Fatalf("chain id should be deterministic 64 hex chars, got id1=%s id2=%s", id1, id2)
	}
}

func TestDedupWindow_Concurrent10Goroutines(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 同一 system_id / vendor，但不同 evidence_sha。
			sha := "sha-" + string(rune('a'+i))
			r := w.RecordAndCheck(sampleEvidence("his-core", "dm8", sha), now)
			_ = r
		}(i)
	}
	wg.Wait()
	if w.Size() != 1 {
		t.Fatalf("concurrent same (system,vendor) should share one entry, got %d", w.Size())
	}
}

// 以下为 task 26 详细实现拆分层新增的单元测试：覆盖 env 配置化、并发安全
// 计数、DedupedCount 累加、多 vendor 隔离、跨窗口后重新 AlertSent 等。

func TestDedupWindowFromEnv_DefaultWhenUnset(t *testing.T) {
	t.Setenv("DEDUP_WINDOW_SECS", "")
	w, err := output.NewDedupWindowFromEnv()
	if err != nil {
		t.Fatalf("empty env should not error, got %v", err)
	}
	if w.Window() != output.DefaultDedupWindow {
		t.Fatalf("unset env should default to %s, got %s", output.DefaultDedupWindow, w.Window())
	}
}

func TestDedupWindowFromEnv_CustomValue(t *testing.T) {
	t.Setenv("DEDUP_WINDOW_SECS", "60")
	w, err := output.NewDedupWindowFromEnv()
	if err != nil {
		t.Fatalf("custom value should not error, got %v", err)
	}
	if w.Window() != 60*time.Second {
		t.Fatalf("custom env should produce 60s window, got %s", w.Window())
	}
}

func TestDedupWindowFromEnv_HourValue(t *testing.T) {
	t.Setenv("DEDUP_WINDOW_SECS", "3600")
	w, err := output.NewDedupWindowFromEnv()
	if err != nil {
		t.Fatalf("3600s should be accepted, got %v", err)
	}
	if w.Window() != time.Hour {
		t.Fatalf("3600s env should produce 1h window, got %s", w.Window())
	}
}

func TestDedupWindowFromEnv_InvalidValueJunk(t *testing.T) {
	t.Setenv("DEDUP_WINDOW_SECS", "abc-not-number")
	w, err := output.NewDedupWindowFromEnv()
	if err == nil {
		t.Fatalf("junk value must return error, got nil")
	}
	if w != nil {
		t.Fatalf("junk value must return nil window, got %+v", w)
	}
}

func TestDedupWindowFromEnv_InvalidValueZero(t *testing.T) {
	t.Setenv("DEDUP_WINDOW_SECS", "0")
	_, err := output.NewDedupWindowFromEnv()
	if err == nil {
		t.Fatalf("zero value must return error, got nil")
	}
}

func TestDedupWindowFromEnv_InvalidValueNegative(t *testing.T) {
	t.Setenv("DEDUP_WINDOW_SECS", "-30")
	_, err := output.NewDedupWindowFromEnv()
	if err == nil {
		t.Fatalf("negative value must return error, got nil")
	}
}

func TestDedupWindowFromEnv_InvalidValueTooLarge(t *testing.T) {
	t.Setenv("DEDUP_WINDOW_SECS", "86401") // > 24h
	_, err := output.NewDedupWindowFromEnv()
	if err == nil {
		t.Fatalf("value > 86400 must return error, got nil")
	}
}

func TestDedupWindowFromEnv_AcceptMaxBoundary(t *testing.T) {
	t.Setenv("DEDUP_WINDOW_SECS", "86400") // exactly 24h
	w, err := output.NewDedupWindowFromEnv()
	if err != nil {
		t.Fatalf("86400 should be accepted, got %v", err)
	}
	if w.Window() != 24*time.Hour {
		t.Fatalf("86400 env should produce 24h window, got %s", w.Window())
	}
}

func TestDedupWindow_DedupCountIncrements(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	w.RecordAndCheck(sampleEvidence("lis", "opengauss", "sha-1"), now)
	for i := 0; i < 5; i++ {
		r := w.RecordAndCheck(sampleEvidence("lis", "opengauss", "sha-different-"+string(rune('a'+i))), now.Add(time.Duration(i+1)*time.Second))
		if !r.Deduped {
			t.Fatalf("hit #%d should be Deduped, got %+v", i, r)
		}
	}
	// Size 仍然 1（不增长）。
	if w.Size() != 1 {
		t.Fatalf("expected 1 entry after multiple dedups, got %d", w.Size())
	}
}

func TestDedupWindow_MultipleDistinctVendorsIndependent(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	vendors := []string{"dm8", "kingbase", "opengauss", "ivorysql", "pg-compat"}
	for _, v := range vendors {
		r := w.RecordAndCheck(sampleEvidence("his-core", v, "sha-"+v), now)
		if !r.AlertSent {
			t.Fatalf("vendor=%s first hit must alert, got %+v", v, r)
		}
	}
	if w.Size() != len(vendors) {
		t.Fatalf("expected %d entries, got %d", len(vendors), w.Size())
	}
	// 同 system_id 不同 vendor → 各自独立。
	for _, v := range vendors {
		r := w.RecordAndCheck(sampleEvidence("his-core", v, "sha-"+v+"-2"), now.Add(10*time.Second))
		if !r.Deduped {
			t.Fatalf("second hit on vendor=%s must Dedup (independent), got %+v", v, r)
		}
	}
}

func TestDedupWindow_EvidenceSHAAlwaysIdempotentRegardlessOfWindow(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	w.RecordAndCheck(sampleEvidence("emr", "kingbase", "same-sha"), now)
	// 同一 sha 跨越「窗口外」也应永远 Idempotent。
	r := w.RecordAndCheck(sampleEvidence("emr", "kingbase", "same-sha"), now.Add(10*time.Minute))
	if !r.Idempotent {
		t.Fatalf("same evidence_sha must be Idempotent even after window expires, got %+v", r)
	}
	if r.WindowReason != "evidence_sha_match" {
		t.Fatalf("window reason should be evidence_sha_match, got %q", r.WindowReason)
	}
}

func TestDedupWindow_ReAlertAfterWindowElapsedWithDifferentSHA(t *testing.T) {
	w := output.NewDedupWindow(1 * time.Minute)
	now := time.Now().UTC()
	w.RecordAndCheck(sampleEvidence("yb-proxy", "dm8", "sha-old"), now)
	now2 := now.Add(2 * time.Minute) // 跨窗口
	r := w.RecordAndCheck(sampleEvidence("yb-proxy", "dm8", "sha-new"), now2)
	if !r.AlertSent {
		t.Fatalf("after window expires with new sha must alert again, got %+v", r)
	}
	// entries 仍 1 条（被替换）。
	if w.Size() != 1 {
		t.Fatalf("expected 1 entry after re-alert, got %d", w.Size())
	}
}

func TestDedupWindow_DedupedSHA256Populated(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	w.RecordAndCheck(sampleEvidence("pacs", "dm8", "sha-A"), now)
	r := w.RecordAndCheck(sampleEvidence("pacs", "dm8", "sha-B"), now.Add(30*time.Second))
	if r.DedupedSHA256 != "sha-A" {
		t.Fatalf("DedupedSHA256 should be the original 'sha-A', got %q", r.DedupedSHA256)
	}
}

func TestDedupWindow_ConcurrentSafety10GoroutinesAlertedCount(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	var (
		wg          sync.WaitGroup
		alertSent   atomic.Int64
		deduped     atomic.Int64
		idempotent  atomic.Int64
		totalCalls  = 50
	)
	for i := 0; i < totalCalls; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 同一 system/vendor + 不同 sha。
			sha := "sha-c-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			r := w.RecordAndCheck(sampleEvidence("oa", "dm8", sha), now)
			if r.AlertSent {
				alertSent.Add(1)
			}
			if r.Deduped {
				deduped.Add(1)
			}
			if r.Idempotent {
				idempotent.Add(1)
			}
		}(i)
	}
	wg.Wait()
	// 50 个 goroutine 同时运行：只有 1 个进入 firstSeen，其余都进入 Deduped 分支。
	if got := alertSent.Load(); got != 1 {
		t.Fatalf("expected exactly 1 AlertSent, got %d", got)
	}
	if got := deduped.Load() + idempotent.Load(); got != int64(totalCalls-1) {
		t.Fatalf("expected %d to be Deduped/Idempotent, got %d", totalCalls-1, got)
	}
	if w.Size() != 1 {
		t.Fatalf("expected 1 entry after concurrent writes, got %d", w.Size())
	}
}

func TestDedupWindow_ConcurrentSafety100GoroutinesIndependentSystems(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	var wg sync.WaitGroup
	systems := []string{"his-core", "emr", "lis", "pacs", "yb-proxy", "pharmacy", "lab-lis", "pacs-archive", "his-bak", "mobile-nurse"}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sys := systems[i%len(systems)]
			r := w.RecordAndCheck(sampleEvidence(sys, "dm8", "sha-"+string(rune('a'+i%26))), now)
			_ = r
		}(i)
	}
	wg.Wait()
	// 10 个 system_id × 1 个 vendor = 10 entries（每个 system 一个 vendor entry）。
	if w.Size() != len(systems) {
		t.Fatalf("expected %d entries for %d systems, got %d", len(systems), len(systems), w.Size())
	}
}

func TestMakeDriftEvidence_DoesNotMutatePrevAfterFirstCall(t *testing.T) {
	ev := sampleEvidence("his-core", "dm8", "sha-fix")
	a := output.MakeDriftEvidence(ev, "prev-A")
	b := output.MakeDriftEvidence(ev, "prev-A")
	// 两次相同输入产生相同 self_hash。
	if a.SelfHash != b.SelfHash {
		t.Fatalf("deterministic self_hash violated: %s != %s", a.SelfHash, b.SelfHash)
	}
	if a.PrevEvidenceSHA256 != "prev-A" || b.PrevEvidenceSHA256 != "prev-A" {
		t.Fatalf("prev must propagate, got a=%q b=%q", a.PrevEvidenceSHA256, b.PrevEvidenceSHA256)
	}
}

func TestMakeDriftEvidence_ChainHeadEmptyPrev(t *testing.T) {
	ev := sampleEvidence("his-core", "dm8", "sha-chain-head")
	r := output.MakeDriftEvidence(ev, "")
	if r.PrevEvidenceSHA256 != "" {
		t.Fatalf("chain head prev must be empty, got %q", r.PrevEvidenceSHA256)
	}
	if r.SelfHash == "" {
		t.Fatalf("self_hash must be set even for chain head")
	}
}

func TestMakeDriftEvidence_SelfHashChangesWithBody(t *testing.T) {
	base := sampleEvidence("his-core", "dm8", "sha-base")
	r1 := output.MakeDriftEvidence(base, "prev-x")

	// 改 Confidence → 应当产生不同 self_hash。
	mut := base
	mut.Confidence = 0.42
	r2 := output.MakeDriftEvidence(mut, "prev-x")
	if r1.SelfHash == r2.SelfHash {
		t.Fatalf("changing Confidence should change self_hash")
	}

	// 改 Status → 应当产生不同 self_hash。
	mut2 := base
	mut2.Status = check.StateConfirmed
	r3 := output.MakeDriftEvidence(mut2, "prev-x")
	if r1.SelfHash == r3.SelfHash {
		t.Fatalf("changing Status should change self_hash")
	}
}

func TestComputeEvidenceChainID_StableAcrossEvStatus(t *testing.T) {
	ev := sampleEvidence("his-core", "dm8", "sha-chain")
	ev.SelfHash = "fixed-self-hash"
	ev.TsUTC = "2026-10-10T05:00:00Z"
	id1 := output.ComputeEvidenceChainID(ev)
	ev.Status = check.StateConfirmed
	id2 := output.ComputeEvidenceChainID(ev)
	// Status 改变 → chain id 也改变（写入证据装订 zip 时能区分。
	if id1 == id2 {
		t.Fatalf("ComputeEvidenceChainID should be sensitive to Status, both %s", id1)
	}
}

func TestComputeEvidenceChainID_DifferentEventIDsDistinct(t *testing.T) {
	evA := sampleEvidence("his-core", "dm8", "sha-a")
	evA.SelfHash = "self-a"
	evA.TsUTC = "2026-10-10T05:00:00Z"
	evB := sampleEvidence("his-core", "dm8", "sha-a")
	evB.EventID = "different-event-id"
	evB.SelfHash = "self-a"
	evB.TsUTC = "2026-10-10T05:00:00Z"
	if output.ComputeEvidenceChainID(evA) == output.ComputeEvidenceChainID(evB) {
		t.Fatalf("different event_id should yield different chain id")
	}
}

func TestDedupWindow_GCLeavesRecentEntries(t *testing.T) {
	w := output.NewDedupWindow(1 * time.Minute)
	now := time.Now().UTC()
	w.RecordAndCheck(sampleEvidence("his-core", "dm8", "sha-fresh"), now)
	w.RecordAndCheck(sampleEvidence("emr", "dm8", "sha-fresh"), now.Add(30*time.Second))
	// 1 分 30 秒后：超过 window*2 = 2min 的不应有（窗口内=1min）。
	// 但 1分30秒 没超 2 分钟 → 仍保留。
	removed := w.GC(now.Add(90 * time.Second))
	if removed != 0 {
		t.Fatalf("entries within window*2 should not be removed, got removed=%d", removed)
	}
	if w.Size() != 2 {
		t.Fatalf("expected 2 entries preserved, got %d", w.Size())
	}
}

func TestDedupWindow_AlertResultAlertSent_DedupedSHA256Empty(t *testing.T) {
	w := output.NewDedupWindow(5 * time.Minute)
	now := time.Now().UTC()
	r := w.RecordAndCheck(sampleEvidence("his-core", "dm8", "sha-first"), now)
	if !r.AlertSent {
		t.Fatalf("first hit must alert, got %+v", r)
	}
	// AlertSent=true 时 DedupedSHA256 必为 ""（没有"上一条"）。
	if r.DedupedSHA256 != "" {
		t.Fatalf("first hit DedupedSHA256 should be empty, got %q", r.DedupedSHA256)
	}
	if r.WindowReason != "" {
		t.Fatalf("first hit WindowReason should be empty, got %q", r.WindowReason)
	}
}
