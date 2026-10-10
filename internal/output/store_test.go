// Package output_test — bbolt trial store 单元测试。
//
// 覆盖：
//   - OpenTrialStore 建表 + Close 幂等；
//   - SaveTrial / LoadTrial 往返；
//   - SaveTrial 自动维护 contract_index；
//   - ListByContractID 返回按 event_id 字典序；
//   - PromoteTrial 推进 trial → confirmed → remedied → re_verified 合法路径；
//   - PromoteTrial 拒绝非法转移（trial → re_verified 直接拒绝）；
//   - SaveTrial 拒绝空 EventID / ContractID；
//   - SelfHash 链头为空首条 prev=""，后续 prev=上一条 SelfHash。
package output_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"xinchuang-db-guardian/internal/check"
	"xinchuang-db-guardian/internal/output"
)

func tempDbPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "trial.db")
}

func sampleEvidenceForStore(eventID, contractID string, ts time.Time) check.DriftEvidence {
	return check.DriftEvidence{
		EventID:            eventID,
		ContractID:         contractID,
		SystemID:           "his-core",
		Vendor:             "dm8",
		Declared:           "v8.1",
		Actual:             "DM Database Server V8.1.0",
		PortRaw:            "DM Database Server V8.1.0",
		DriverSha:          "deadbeef",
		JDBCURL:            "jdbc:dm://10.0.0.1:5236/DB",
		Verdict:            check.VerdictTrial,
		Confidence:         0.95,
		EvidenceSHA256:     "evidence-" + eventID,
		Status:             check.StateTrial,
		PrevEvidenceSHA256: "",
		SelfHash:           "",
		TsUTC:              ts.UTC().Format(time.RFC3339Nano),
	}
}

func TestOpenTrialStore_EmptyPath(t *testing.T) {
	_, err := output.OpenTrialStore("")
	if err == nil {
		t.Fatal("empty path must error")
	}
}

func TestOpenTrialStore_CreatesAndClosesIdempotent(t *testing.T) {
	p := tempDbPath(t)
	store, err := output.OpenTrialStore(p)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if store.Path() != p {
		t.Fatalf("path mismatch: %q vs %q", store.Path(), p)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}
	// 二次 close 幂等。
	if err := store.Close(); err != nil {
		t.Fatalf("close 2 must be idempotent: %v", err)
	}
}

func TestSaveAndLoad_Roundtrip(t *testing.T) {
	p := tempDbPath(t)
	store, err := output.OpenTrialStore(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ev := sampleEvidenceForStore("ev-001", "c-his-core", time.Now().UTC())
	ev = output.MakeDriftEvidence(ev, "")
	if err := store.SaveTrial(ev); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := store.LoadTrial("ev-001")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.EventID != "ev-001" {
		t.Fatalf("event_id mismatch: got %q", got.EventID)
	}
	if got.ContractID != "c-his-core" {
		t.Fatalf("contract_id mismatch: got %q", got.ContractID)
	}
	if got.EvidenceSHA256 != ev.EvidenceSHA256 {
		t.Fatalf("evidence_sha mismatch: got %q want %q", got.EvidenceSHA256, ev.EvidenceSHA256)
	}
	if got.SelfHash == "" {
		t.Fatal("self_hash must be set after MakeDriftEvidence + SaveTrial")
	}
}

func TestSave_RejectsEmptyEventID(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	ev := sampleEvidenceForStore("", "c-x", time.Now().UTC())
	err := store.SaveTrial(ev)
	if !errors.Is(err, output.ErrEmptyEventID) {
		t.Fatalf("expected ErrEmptyEventID, got %v", err)
	}
}

func TestSave_RejectsEmptyContractID(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	ev := sampleEvidenceForStore("ev-2", "", time.Now().UTC())
	err := store.SaveTrial(ev)
	if !errors.Is(err, output.ErrEmptyContractID) {
		t.Fatalf("expected ErrEmptyContractID, got %v", err)
	}
}

func TestListByContractID_ReturnsSorted(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	ts := time.Now().UTC()
	ids := []string{"ev-c", "ev-a", "ev-b"}
	for _, id := range ids {
		ev := sampleEvidenceForStore(id, "c-his-core", ts)
		ev = output.MakeDriftEvidence(ev, "")
		if err := store.SaveTrial(ev); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	out, err := store.ListByContractID("c-his-core")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 trials, got %d", len(out))
	}
	// 索引按 event_id 字典序。
	wantOrder := []string{"ev-a", "ev-b", "ev-c"}
	for i, e := range out {
		if e.EventID != wantOrder[i] {
			t.Fatalf("[%d] event_id=%q want %q", i, e.EventID, wantOrder[i])
		}
	}
}

func TestLoadTrial_NotFound(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	_, err := store.LoadTrial("nonexistent")
	if !errors.Is(err, output.ErrTrialNotFound) {
		t.Fatalf("expected ErrTrialNotFound, got %v", err)
	}
}

func TestPromoteTrial_LegalConfirmedThenRemedied(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	ev := sampleEvidenceForStore("ev-promote", "c-his-core", time.Now().UTC())
	ev = output.MakeDriftEvidence(ev, "")
	if err := store.SaveTrial(ev); err != nil {
		t.Fatalf("save: %v", err)
	}

	// trial → confirmed。
	after1, err := store.PromoteTrial("ev-promote", check.StateConfirmed, "张三")
	if err != nil {
		t.Fatalf("promote to confirmed: %v", err)
	}
	if after1.Status != check.StateConfirmed {
		t.Fatalf("status should be confirmed, got %q", after1.Status)
	}
	if after1.PrevEvidenceSHA256 == "" {
		t.Fatal("prev_evidence_sha256 must be set after first promotion")
	}
	if after1.SelfHash == "" || after1.SelfHash == ev.SelfHash {
		t.Fatal("self_hash must change after promotion")
	}

	// confirmed → remedied。
	after2, err := store.PromoteTrial("ev-promote", check.StateRemedied, "张三")
	if err != nil {
		t.Fatalf("promote to remedied: %v", err)
	}
	if after2.Status != check.StateRemedied {
		t.Fatalf("status should be remedied, got %q", after2.Status)
	}
	if after2.PrevEvidenceSHA256 != after1.SelfHash {
		t.Fatalf("prev_evidence_sha256 chain broken: got %q want %q", after2.PrevEvidenceSHA256, after1.SelfHash)
	}
}

func TestPromoteTrial_RemediedToReVerified(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	ev := sampleEvidenceForStore("ev-rv", "c-his-core", time.Now().UTC())
	ev = output.MakeDriftEvidence(ev, "")
	_ = store.SaveTrial(ev)

	// 不走 confirmed 直接 trial → remedied 是否合法（spec 允许 trial→remedied）。
	if _, err := store.PromoteTrial("ev-rv", check.StateRemedied, "op"); err != nil {
		t.Fatalf("trial→remedied legal: %v", err)
	}
	if _, err := store.PromoteTrial("ev-rv", check.StateReVerified, "auto"); err != nil {
		t.Fatalf("remedied→re_verified legal: %v", err)
	}
}

func TestPromoteTrial_RejectsTrialToReVerified(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	ev := sampleEvidenceForStore("ev-illegal", "c-his-core", time.Now().UTC())
	ev = output.MakeDriftEvidence(ev, "")
	_ = store.SaveTrial(ev)

	// trial → re_verified 是非法转移，应返回 wrap ErrInvalidTransition。
	_, err := store.PromoteTrial("ev-illegal", check.StateReVerified, "op")
	if err == nil {
		t.Fatal("trial→re_verified must error")
	}
	if !errors.Is(err, output.ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}
}

func TestPromoteTrial_RejectsBackToTrial(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	ev := sampleEvidenceForStore("ev-backedge", "c-his-core", time.Now().UTC())
	ev = output.MakeDriftEvidence(ev, "")
	_ = store.SaveTrial(ev)

	if _, err := store.PromoteTrial("ev-backedge", check.StateConfirmed, "op"); err != nil {
		t.Fatalf("trial→confirmed: %v", err)
	}
	// confirmed → trial back-edge 拒绝。
	_, err := store.PromoteTrial("ev-backedge", check.StateTrial, "op")
	if err == nil {
		t.Fatal("confirmed→trial back-edge must error")
	}
	if !errors.Is(err, output.ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}
}

func TestPromoteTrial_NotFound(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	_, err := store.PromoteTrial("nope", check.StateConfirmed, "op")
	if !errors.Is(err, output.ErrTrialNotFound) {
		t.Fatalf("expected ErrTrialNotFound, got %v", err)
	}
}

func TestGlobalChainHead_Advances(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	head0, _ := store.GlobalChainHead()
	if head0 != "" {
		t.Fatalf("initial head should be empty, got %q", head0)
	}
	ev := sampleEvidenceForStore("ev-head", "c-his-core", time.Now().UTC())
	ev = output.MakeDriftEvidence(ev, "")
	if err := store.SaveTrial(ev); err != nil {
		t.Fatalf("save: %v", err)
	}
	head1, _ := store.GlobalChainHead()
	if head1 != ev.SelfHash {
		t.Fatalf("head should advance to %q, got %q", ev.SelfHash, head1)
	}
}

func TestSaveTrial_IdempotentOnSameEventID(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	ev := sampleEvidenceForStore("ev-idemp", "c-his-core", time.Now().UTC())
	ev = output.MakeDriftEvidence(ev, "")
	_ = store.SaveTrial(ev)
	// 二次 save 同一 event_id 不应 panic，索引也不应重复。
	_ = store.SaveTrial(ev)

	out, _ := store.ListByContractID("c-his-core")
	ids := 0
	for _, e := range out {
		if e.EventID == "ev-idemp" {
			ids++
		}
	}
	if ids != 1 {
		t.Fatalf("index must not duplicate event_id, found %d entries", ids)
	}
}

func TestDeleteTrial(t *testing.T) {
	p := tempDbPath(t)
	store, _ := output.OpenTrialStore(p)
	t.Cleanup(func() { _ = store.Close() })

	ev := sampleEvidenceForStore("ev-del", "c-x", time.Now().UTC())
	ev = output.MakeDriftEvidence(ev, "")
	_ = store.SaveTrial(ev)

	if err := store.DeleteTrial("ev-del"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.LoadTrial("ev-del"); !errors.Is(err, output.ErrTrialNotFound) {
		t.Fatalf("expected ErrTrialNotFound after delete, got %v", err)
	}
}
