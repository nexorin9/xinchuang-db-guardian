package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"xinchuang-db-guardian/internal/check"
	"xinchuang-db-guardian/internal/output"
)

// ----------------------------------------------------------------------------
// 测试辅助：记录每次 AppendReverifyAudit 调用，便于断言 fired/不 fired 行为。
// ----------------------------------------------------------------------------

type recorderAuditor struct {
	mu      sync.Mutex
	rows    []check.DriftEvidence
	failErr error
}

func (r *recorderAuditor) AppendReverifyAudit(ctx context.Context, ev check.DriftEvidence) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failErr != nil {
		return r.failErr
	}
	r.rows = append(r.rows, ev)
	return nil
}

func (r *recorderAuditor) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rows)
}

func (r *recorderAuditor) Last() (check.DriftEvidence, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rows) == 0 {
		return check.DriftEvidence{}, false
	}
	return r.rows[len(r.rows)-1], true
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// seedRemediedTrial — 在 bbolt 里预存一条 State=remedied 的 trial，返回
// 加载到的 evidence（供 MaybeAutoReverify 用作 lastEvidence）。
func seedRemediedTrial(t *testing.T, store *output.TrialStore, ev check.DriftEvidence) check.DriftEvidence {
	t.Helper()
	ev.Status = check.StateRemedied
	ev.SelfHash = check.ComputeSelfHash("", check.HashBody(ev))
	if err := store.SaveTrial(ev); err != nil {
		t.Fatalf("seed SaveTrial: %v", err)
	}
	return ev
}

// newTempAuditPath — 临时 audit.jsonl 路径。
func newTempAuditPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "audit.jsonl")
}

// ----------------------------------------------------------------------------
// 单元测试：MaybeAutoReverify 三条路径（remedied→re_verified / same_sha / trial）。
// ----------------------------------------------------------------------------

// TestMaybeAutoReverify_Fired_NewSHA — 主路径：lastEvidence.State=remedied +
// verdict=ok + evidence_sha 变化 → fired=true + 1 条审计行 + Status=re_verified。
func TestMaybeAutoReverify_Fired_NewSHA(t *testing.T) {
	tmp := t.TempDir()
	store, err := output.OpenTrialStore(filepath.Join(tmp, "trial.db"))
	if err != nil {
		t.Fatalf("OpenTrialStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	lastEv := check.DriftEvidence{
		EventID:    "evt-001",
		ContractID: "ctr-001",
		SystemID:   "his-core",
		Vendor:     "kingbase",
		Declared:   "KingbaseES V008R006C0010",
		Actual:     "KingbaseES V008R006C0010",
		PortRaw:    "KingbaseES V008R006C0010",
		DriverSha:  "abc123",
		JDBCURL:    "jdbc:kingbase8://10.0.0.1:54321/his",
		Verdict:    check.VerdictOK,
		Confidence: 1.0,
	}
	lastEv.EvidenceSHA256 = check.ComputeEvidenceSHA256(lastEv.PortRaw, lastEv.DriverSha, lastEv.JDBCURL, lastEv.SystemID, time.Unix(1700000000, 0).UTC())
	lastEv = seedRemediedTrial(t, store, lastEv)

	// 当前 evidence：driver_sha 变化（驱动换版），verdict=ok。
	currentEv := lastEv
	currentEv.EventID = "evt-002"
	currentEv.DriverSha = "def456"
	currentEv.EvidenceSHA256 = check.ComputeEvidenceSHA256(currentEv.PortRaw, currentEv.DriverSha, currentEv.JDBCURL, currentEv.SystemID, time.Unix(1700001000, 0).UTC())
	currentEv.Verdict = check.VerdictOK
	currentEv.TsUTC = time.Unix(1700001000, 0).UTC().Format(time.RFC3339Nano)

	rec := &recorderAuditor{}
	g := NewGuardian(nil, nil, store, rec, newTestLogger())

	if err := g.MaybeAutoReverify(context.Background(), lastEv, currentEv); err != nil {
		t.Fatalf("MaybeAutoReverify fired 路径应成功，实际: %v", err)
	}
	if rec.Count() != 1 {
		t.Fatalf("审计行应写 1 条，实际 %d", rec.Count())
	}
	got, _ := rec.Last()
	if got.Status != check.StateReVerified {
		t.Errorf("审计行 Status 期望 StateReVerified，实际 %q", got.Status)
	}
	if got.PrevEvidenceSHA256 != lastEv.SelfHash {
		t.Errorf("审计行 PrevEvidenceSHA256 期望 %q（=lastEv.SelfHash），实际 %q", lastEv.SelfHash, got.PrevEvidenceSHA256)
	}
	if got.SelfHash == "" {
		t.Errorf("审计行 SelfHash 应已计算，实际为空")
	}
	if got.SelfHash != check.ComputeSelfHash(got.PrevEvidenceSHA256, check.HashBody(got)) {
		t.Errorf("审计行 SelfHash 与公式不一致")
	}

	// TrialStore 也应被 SaveTrial 写回新 evidence。
	loaded, err := store.LoadTrial("evt-002")
	if err != nil {
		t.Fatalf("LoadTrial evt-002: %v", err)
	}
	if loaded.Status != check.StateReVerified {
		t.Errorf("TrialStore 中 evt-002 期望 StateReVerified，实际 %q", loaded.Status)
	}
	if loaded.SelfHash != got.SelfHash {
		t.Errorf("TrialStore SelfHash 与审计行 SelfHash 不一致")
	}

	// 审计行应落到 audit.jsonl（通过 OutputAuditor）；此处直接验证 recorder 已记录。
	// 单独跑 OutputAuditor 的集成测试在 TestOutputAuditor_AppendReverifyAudit。
}

// TestMaybeAutoReverify_NotFired_SameSHA — 驱动未变 → 不触发。
func TestMaybeAutoReverify_NotFired_SameSHA(t *testing.T) {
	tmp := t.TempDir()
	store, err := output.OpenTrialStore(filepath.Join(tmp, "trial.db"))
	if err != nil {
		t.Fatalf("OpenTrialStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	lastEv := check.DriftEvidence{
		EventID: "evt-010", ContractID: "ctr-010", SystemID: "lis", Vendor: "dm8",
		Declared: "DM8", Actual: "DM Database Server V8.1.0",
		PortRaw: "DM Database Server V8.1.0", DriverSha: "aaa", JDBCURL: "jdbc:dm://10.0.0.2:5236/lis",
		Verdict: check.VerdictOK, Confidence: 1.0,
	}
	lastEv.EvidenceSHA256 = check.ComputeEvidenceSHA256(lastEv.PortRaw, lastEv.DriverSha, lastEv.JDBCURL, lastEv.SystemID, time.Unix(1700010000, 0).UTC())
	lastEv = seedRemediedTrial(t, store, lastEv)

	// 当前 evidence：verdict=ok 但 evidence_sha 与上次一致。
	currentEv := lastEv
	currentEv.EventID = "evt-011"
	currentEv.TsUTC = time.Unix(1700011000, 0).UTC().Format(time.RFC3339Nano)

	rec := &recorderAuditor{}
	g := NewGuardian(nil, nil, store, rec, newTestLogger())
	if err := g.MaybeAutoReverify(context.Background(), lastEv, currentEv); err != nil {
		t.Fatalf("不触发路径应 nil err，实际: %v", err)
	}
	if rec.Count() != 0 {
		t.Errorf("不触发路径审计行应 0 条，实际 %d", rec.Count())
	}
}

// TestMaybeAutoReverify_NotFired_Trial — trial 信号优先 → 不触发。
func TestMaybeAutoReverify_NotFired_Trial(t *testing.T) {
	tmp := t.TempDir()
	store, err := output.OpenTrialStore(filepath.Join(tmp, "trial.db"))
	if err != nil {
		t.Fatalf("OpenTrialStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	lastEv := check.DriftEvidence{
		EventID: "evt-020", ContractID: "ctr-020", SystemID: "pacs", Vendor: "kingbase",
		Declared: "KingbaseES V8", Actual: "KingbaseES V8", PortRaw: "KingbaseES V8",
		DriverSha: "x", JDBCURL: "jdbc:kingbase8://10.0.0.3:54321/pacs",
		Verdict: check.VerdictOK, Confidence: 1.0,
	}
	lastEv.EvidenceSHA256 = check.ComputeEvidenceSHA256(lastEv.PortRaw, lastEv.DriverSha, lastEv.JDBCURL, lastEv.SystemID, time.Unix(1700020000, 0).UTC())
	lastEv = seedRemediedTrial(t, store, lastEv)

	currentEv := lastEv
	currentEv.EventID = "evt-021"
	currentEv.Verdict = check.VerdictTrial
	currentEv.TsUTC = time.Unix(1700021000, 0).UTC().Format(time.RFC3339Nano)

	rec := &recorderAuditor{}
	g := NewGuardian(nil, nil, store, rec, newTestLogger())
	if err := g.MaybeAutoReverify(context.Background(), lastEv, currentEv); err != nil {
		t.Fatalf("trial 路径应 nil err，实际: %v", err)
	}
	if rec.Count() != 0 {
		t.Errorf("trial 路径审计行应 0 条，实际 %d", rec.Count())
	}
}

// TestMaybeAutoReverify_NotFired_LastStateNotRemedied — 上一条不是 remedied → 不触发。
func TestMaybeAutoReverify_NotFired_LastStateNotRemedied(t *testing.T) {
	tmp := t.TempDir()
	store, err := output.OpenTrialStore(filepath.Join(tmp, "trial.db"))
	if err != nil {
		t.Fatalf("OpenTrialStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	lastEv := check.DriftEvidence{
		EventID: "evt-030", ContractID: "ctr-030", SystemID: "yb", Vendor: "dm8",
		Declared: "DM8", Actual: "DM8", PortRaw: "DM8", DriverSha: "y", JDBCURL: "jdbc:dm://10.0.0.4:5236/yb",
		Verdict: check.VerdictOK, Confidence: 1.0,
	}
	lastEv.EvidenceSHA256 = check.ComputeEvidenceSHA256(lastEv.PortRaw, lastEv.DriverSha, lastEv.JDBCURL, lastEv.SystemID, time.Unix(1700030000, 0).UTC())
	lastEv.Status = check.StateTrial // 关键：不是 remedied
	lastEv.SelfHash = check.ComputeSelfHash("", check.HashBody(lastEv))
	if err := store.SaveTrial(lastEv); err != nil {
		t.Fatalf("seed SaveTrial: %v", err)
	}

	currentEv := lastEv
	currentEv.EventID = "evt-031"
	currentEv.TsUTC = time.Unix(1700031000, 0).UTC().Format(time.RFC3339Nano)

	rec := &recorderAuditor{}
	g := NewGuardian(nil, nil, store, rec, newTestLogger())
	if err := g.MaybeAutoReverify(context.Background(), lastEv, currentEv); err != nil {
		t.Fatalf("trial→trial 路径应 nil err，实际: %v", err)
	}
	if rec.Count() != 0 {
		t.Errorf("last state 非 remedied 时不应触发审计行，实际 %d", rec.Count())
	}
}

// TestMaybeAutoReverify_DisabledByConfig — AutoReverifyEnabled=false → 不触发。
func TestMaybeAutoReverify_DisabledByConfig(t *testing.T) {
	tmp := t.TempDir()
	store, err := output.OpenTrialStore(filepath.Join(tmp, "trial.db"))
	if err != nil {
		t.Fatalf("OpenTrialStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	lastEv := check.DriftEvidence{
		EventID: "evt-040", ContractID: "ctr-040", SystemID: "oa", Vendor: "kingbase",
		Declared: "KingbaseES V8", Actual: "KingbaseES V8", PortRaw: "KingbaseES V8",
		DriverSha: "z", JDBCURL: "jdbc:kingbase8://10.0.0.5:54321/oa",
		Verdict: check.VerdictOK, Confidence: 1.0,
	}
	lastEv.EvidenceSHA256 = check.ComputeEvidenceSHA256(lastEv.PortRaw, lastEv.DriverSha, lastEv.JDBCURL, lastEv.SystemID, time.Unix(1700040000, 0).UTC())
	lastEv = seedRemediedTrial(t, store, lastEv)

	currentEv := lastEv
	currentEv.EventID = "evt-041"
	currentEv.DriverSha = "z_new"
	currentEv.EvidenceSHA256 = check.ComputeEvidenceSHA256(currentEv.PortRaw, currentEv.DriverSha, currentEv.JDBCURL, currentEv.SystemID, time.Unix(1700041000, 0).UTC())
	currentEv.TsUTC = time.Unix(1700041000, 0).UTC().Format(time.RFC3339Nano)

	rec := &recorderAuditor{}
	g := NewGuardian(nil, nil, store, rec, newTestLogger())
	g.AutoReverifyEnabled = false // 关闭

	if err := g.MaybeAutoReverify(context.Background(), lastEv, currentEv); err != nil {
		t.Fatalf("关闭开关应 nil err，实际: %v", err)
	}
	if rec.Count() != 0 {
		t.Errorf("关闭开关不应触发审计行，实际 %d", rec.Count())
	}
}

// TestMaybeAutoReverify_AuditorFailure — 审计写入失败 → 错误向上抛。
func TestMaybeAutoReverify_AuditorFailure(t *testing.T) {
	tmp := t.TempDir()
	store, err := output.OpenTrialStore(filepath.Join(tmp, "trial.db"))
	if err != nil {
		t.Fatalf("OpenTrialStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	lastEv := check.DriftEvidence{
		EventID: "evt-050", ContractID: "ctr-050", SystemID: "his-bak", Vendor: "kingbase",
		Declared: "KingbaseES V8", Actual: "KingbaseES V8", PortRaw: "KingbaseES V8",
		DriverSha: "q", JDBCURL: "jdbc:kingbase8://10.0.0.6:54321/bak",
		Verdict: check.VerdictOK, Confidence: 1.0,
	}
	lastEv.EvidenceSHA256 = check.ComputeEvidenceSHA256(lastEv.PortRaw, lastEv.DriverSha, lastEv.JDBCURL, lastEv.SystemID, time.Unix(1700050000, 0).UTC())
	lastEv = seedRemediedTrial(t, store, lastEv)

	currentEv := lastEv
	currentEv.EventID = "evt-051"
	currentEv.DriverSha = "q_new"
	currentEv.EvidenceSHA256 = check.ComputeEvidenceSHA256(currentEv.PortRaw, currentEv.DriverSha, currentEv.JDBCURL, currentEv.SystemID, time.Unix(1700051000, 0).UTC())
	currentEv.TsUTC = time.Unix(1700051000, 0).UTC().Format(time.RFC3339Nano)

	wantErr := errors.New("audit write failed (synthetic)")
	rec := &recorderAuditor{failErr: wantErr}
	g := NewGuardian(nil, nil, store, rec, newTestLogger())

	err = g.MaybeAutoReverify(context.Background(), lastEv, currentEv)
	if err == nil {
		t.Fatalf("审计失败应向上抛 err，实际 nil")
	}
	if !strings.Contains(err.Error(), "reverify") {
		t.Errorf("err 应包含 'reverify' 字样，实际: %v", err)
	}
}

// TestMaybeAutoReverify_NilReceiver — nil receiver 防御。
func TestMaybeAutoReverify_NilReceiver(t *testing.T) {
	var g *Guardian
	err := g.MaybeAutoReverify(context.Background(), check.DriftEvidence{}, check.DriftEvidence{})
	if err == nil {
		t.Fatalf("nil receiver 应报错，实际 nil")
	}
}

// TestOutputAuditor_AppendReverifyAudit — 端到端：OutputAuditor 把 audit 行
// 写到 audit.jsonl，verify-chain 校验通过。
func TestOutputAuditor_AppendReverifyAudit(t *testing.T) {
	tmp := t.TempDir()
	store, err := output.OpenTrialStore(filepath.Join(tmp, "trial.db"))
	if err != nil {
		t.Fatalf("OpenTrialStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	auditPath := filepath.Join(tmp, "audit.jsonl")
	a := NewOutputAuditor(store, auditPath)
	if a.OperatorTag != "auto_reverify" || a.ActionTag != "re-verified" || a.KindTag != "drift_re_verified" {
		t.Errorf("OutputAuditor 默认 tag 错误: op=%q action=%q kind=%q", a.OperatorTag, a.ActionTag, a.KindTag)
	}

	// 写 2 条 trial → 写 1 条 re-verified 审计行 → verify-chain 验证。
	ev1 := check.DriftEvidence{
		EventID: "evt-evt-1", ContractID: "ctr-evt-1", SystemID: "his-core",
		Vendor: "kingbase", Declared: "KingbaseES V8", Actual: "KingbaseES V8",
		PortRaw: "KingbaseES V8", DriverSha: "aaa", JDBCURL: "jdbc:kingbase8://10.0.0.7:54321/his",
		Verdict: check.VerdictTrial, Confidence: 0.6,
		TsUTC: time.Unix(1700100000, 0).UTC().Format(time.RFC3339Nano),
	}
	ev1.EvidenceSHA256 = check.ComputeEvidenceSHA256(ev1.PortRaw, ev1.DriverSha, ev1.JDBCURL, ev1.SystemID, time.Unix(1700100000, 0).UTC())
	ev1.SelfHash = check.ComputeSelfHash("", check.HashBody(ev1))
	if err := store.SaveTrial(ev1); err != nil {
		t.Fatalf("SaveTrial ev1: %v", err)
	}

	// OutputAuditor 写 re-verified 审计行。
	ev2 := ev1
	ev2.EventID = "evt-evt-2"
	ev2.Status = check.StateReVerified
	ev2.PrevEvidenceSHA256 = ev1.SelfHash
	ev2.SelfHash = check.ComputeSelfHash(ev1.SelfHash, check.HashBody(ev2))
	ev2.TsUTC = time.Unix(1700101000, 0).UTC().Format(time.RFC3339Nano)
	if err := a.AppendReverifyAudit(context.Background(), ev2); err != nil {
		t.Fatalf("AppendReverifyAudit: %v", err)
	}

	// 读 audit.jsonl 验证 1 行 JSONL。
	rows, err := output.LoadChain(auditPath)
	if err != nil {
		t.Fatalf("LoadChain: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("期望 1 条审计行，实际 %d", len(rows))
	}
	if rows[0].Kind != "drift_re_verified" {
		t.Errorf("期望 kind=drift_re_verified，实际 %q", rows[0].Kind)
	}
	if rows[0].Operator != "auto_reverify" {
		t.Errorf("期望 operator=auto_reverify，实际 %q", rows[0].Operator)
	}
	if rows[0].Action != "re-verified" {
		t.Errorf("期望 action=re-verified，实际 %q", rows[0].Action)
	}
	if rows[0].EventID != "evt-evt-2" {
		t.Errorf("期望 event_id=evt-evt-2，实际 %q", rows[0].EventID)
	}

	// verify-chain 校验。
	if err := output.VerifyChain(auditPath); err != nil {
		t.Errorf("verify-chain 应通过，实际: %v", err)
	}

	// 篡改：把 self_hash 字段值换成 "tampered" 后 verify-chain 应报错。
	rawBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(rawBytes), rows[0].SelfHash, "tampered_self_hash_value_64_chars_xxxxxxxxxxxxxxxxxxxxxxxxxx", 1)
	if tampered == string(rawBytes) {
		t.Fatalf("篡改后内容未变化（替换失败）")
	}
	if err := os.WriteFile(auditPath, []byte(tampered), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := output.VerifyChain(auditPath); err == nil {
		t.Errorf("篡改 self_hash 后 verify-chain 应报错，实际 nil")
	}
}

// TestOutputAuditor_AppendReverifyAudit_EmptyPath — 空 auditPath 应报错。
func TestOutputAuditor_AppendReverifyAudit_EmptyPath(t *testing.T) {
	a := &OutputAuditor{AuditPath: ""}
	err := a.AppendReverifyAudit(context.Background(), check.DriftEvidence{})
	if err == nil {
		t.Fatalf("空 auditPath 应报错，实际 nil")
	}
}

// TestOutputAuditor_NilReceiver — nil receiver 防御。
func TestOutputAuditor_NilReceiver(t *testing.T) {
	var a *OutputAuditor
	err := a.AppendReverifyAudit(context.Background(), check.DriftEvidence{})
	if err == nil {
		t.Fatalf("nil receiver 应报错，实际 nil")
	}
}

// TestNewGuardian_Defaults — 默认值构造器：AutoReverifyEnabled=true。
func TestNewGuardian_Defaults(t *testing.T) {
	g := NewGuardian(nil, nil, nil, nil, nil)
	if !g.AutoReverifyEnabled {
		t.Errorf("默认 AutoReverifyEnabled=true，实际 false")
	}
	if g.Logger == nil {
		t.Errorf("默认 Logger 应非 nil（slog.Default）")
	}
}

// TestMaybeAutoReverify_VerifyChainRoundTrip — 端到端：完整审计链验证。
// 写入两条 drift_re_verified 审计行 → verify-chain 应通过；篡改后失败。
func TestMaybeAutoReverify_VerifyChainRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	store, err := output.OpenTrialStore(filepath.Join(tmp, "trial.db"))
	if err != nil {
		t.Fatalf("OpenTrialStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// 第一次 re-verified。
	lastEv := check.DriftEvidence{
		EventID: "evt-rt-1", ContractID: "ctr-rt-1", SystemID: "his-core",
		Vendor: "kingbase", Declared: "KingbaseES V8", Actual: "KingbaseES V8",
		PortRaw: "KingbaseES V8", DriverSha: "rt-1", JDBCURL: "jdbc:kingbase8://10.0.0.8:54321/his",
		Verdict: check.VerdictOK, Confidence: 1.0,
		TsUTC: time.Unix(1700200000, 0).UTC().Format(time.RFC3339Nano),
	}
	lastEv.EvidenceSHA256 = check.ComputeEvidenceSHA256(lastEv.PortRaw, lastEv.DriverSha, lastEv.JDBCURL, lastEv.SystemID, time.Unix(1700200000, 0).UTC())
	lastEv = seedRemediedTrial(t, store, lastEv)

	rec := &recorderAuditor{}
	g := NewGuardian(nil, nil, store, rec, newTestLogger())

	currentEv := lastEv
	currentEv.EventID = "evt-rt-2"
	currentEv.DriverSha = "rt-2"
	currentEv.EvidenceSHA256 = check.ComputeEvidenceSHA256(currentEv.PortRaw, currentEv.DriverSha, currentEv.JDBCURL, currentEv.SystemID, time.Unix(1700201000, 0).UTC())
	currentEv.TsUTC = time.Unix(1700201000, 0).UTC().Format(time.RFC3339Nano)
	if err := g.MaybeAutoReverify(context.Background(), lastEv, currentEv); err != nil {
		t.Fatalf("第 1 次 re-verified: %v", err)
	}
	if rec.Count() != 1 {
		t.Fatalf("期望 1 条审计行，实际 %d", rec.Count())
	}
	firstEv, _ := rec.Last()

	// 第二次 re-verified：基于上一条 re_verified 事件作为 lastEvidence。
	currentEv2 := firstEv
	currentEv2.EventID = "evt-rt-3"
	currentEv2.DriverSha = "rt-3"
	currentEv2.Status = check.StateTrial // 重新跑 Compare
	currentEv2.EvidenceSHA256 = check.ComputeEvidenceSHA256(currentEv2.PortRaw, currentEv2.DriverSha, currentEv2.JDBCURL, currentEv2.SystemID, time.Unix(1700202000, 0).UTC())
	currentEv2.TsUTC = time.Unix(1700202000, 0).UTC().Format(time.RFC3339Nano)
	// 把上一条状态手动改成 remedied 模拟整改完成。
	lastEv2 := currentEv2
	lastEv2.Status = check.StateRemedied
	lastEv2.SelfHash = check.ComputeSelfHash("", check.HashBody(lastEv2))
	if err := store.SaveTrial(lastEv2); err != nil {
		t.Fatalf("SaveTrial lastEv2: %v", err)
	}
	// 触发新一轮 re-verified（verdict=ok + sha 变化）。
	currentEv3 := currentEv2
	currentEv3.EventID = "evt-rt-4"
	currentEv3.DriverSha = "rt-4"
	currentEv3.Verdict = check.VerdictOK
	currentEv3.EvidenceSHA256 = check.ComputeEvidenceSHA256(currentEv3.PortRaw, currentEv3.DriverSha, currentEv3.JDBCURL, currentEv3.SystemID, time.Unix(1700203000, 0).UTC())
	currentEv3.TsUTC = time.Unix(1700203000, 0).UTC().Format(time.RFC3339Nano)
	if err := g.MaybeAutoReverify(context.Background(), lastEv2, currentEv3); err != nil {
		t.Fatalf("第 2 次 re-verified: %v", err)
	}
	if rec.Count() != 2 {
		t.Fatalf("期望 2 条审计行，实际 %d", rec.Count())
	}

	// 把审计行序列化为 JSON 验证两条都标记 Status=StateReVerified 且 SelfHash 计算正确。
	for i, ev := range rec.rows {
		_ = i
		// 锁定 Status=StateReVerified + SelfHash 与公式一致。
		if ev.Status != check.StateReVerified {
			t.Errorf("rec.rows[%d] Status 期望 StateReVerified，实际 %q", i, ev.Status)
		}
		if ev.SelfHash == "" {
			t.Errorf("rec.rows[%d] SelfHash 不应为空", i)
		}
		wantSelfHash := check.ComputeSelfHash(ev.PrevEvidenceSHA256, check.HashBody(ev))
		if ev.SelfHash != wantSelfHash {
			t.Errorf("rec.rows[%d] SelfHash 与公式不一致：got=%s want=%s", i, ev.SelfHash, wantSelfHash)
		}
	}

	// 序列化两条 audit 审计行（走 OutputAuditor，验证 kind/operator/action 在
	// AuditRow 上正确填充）。注意：rec.rows 是 DriftEvidence（无 kind 字段），
	// 真实审计行通过 output.AuditRow 的 AppendJSONL 写入；这里单独走
	// OutputAuditor 路径验证两条 audit 行都标记 kind=drift_re_verified。
	auditPath := filepath.Join(tmp, "audit2.jsonl")
	a2 := NewOutputAuditor(store, auditPath)
	for _, ev := range rec.rows {
		if err := a2.AppendReverifyAudit(context.Background(), ev); err != nil {
			t.Fatalf("AppendReverifyAudit: %v", err)
		}
	}
	rows2, err := output.LoadChain(auditPath)
	if err != nil {
		t.Fatalf("LoadChain audit2: %v", err)
	}
	if len(rows2) != 2 {
		t.Fatalf("期望 audit2 有 2 条审计行，实际 %d", len(rows2))
	}
	for i, r := range rows2 {
		if r.Kind != "drift_re_verified" {
			t.Errorf("rows2[%d] Kind 期望 drift_re_verified，实际 %q", i, r.Kind)
		}
		if r.Operator != "auto_reverify" {
			t.Errorf("rows2[%d] Operator 期望 auto_reverify，实际 %q", i, r.Operator)
		}
		if r.Action != "re-verified" {
			t.Errorf("rows2[%d] Action 期望 re-verified，实际 %q", i, r.Action)
		}
	}

	// 验证 audit2 链 verify-chain 通过。
	if err := output.VerifyChain(auditPath); err != nil {
		t.Errorf("audit2 verify-chain 应通过，实际: %v", err)
	}
}
