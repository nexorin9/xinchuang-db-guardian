// internal/output/llm_conflict_audit_test.go — T42 AppendLLMConflictAudit 测试
//
// 覆盖：
//   - 落盘 1 行 + verify-chain OK；
//   - 多次落盘链式验通（链头推进 + prev_evidence_sha256 接续）；
//   - 与 drift 行混写同一条链 verify-chain 仍 OK；
//   - trial 状态不被推进（TrialStore.GlobalChainHead 不被污染）；
//   - 10 goroutine 并发落盘不被穿插；
//   - 空 auditPath / 空 EventID 报错；
//   - LLMCallAudit 元数据完整落审计行；
//   - 审计行不含患者可识别字段。
package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"xinchuang-db-guardian/internal/check"
	"xinchuang-db-guardian/internal/llm"
)

const (
	testEventID     = "evt-conflict-001"
	testContractID  = "C-LIS-001"
	testSystemID    = "lis-pacs-1"
	testVendor      = "kingbase"
	testDeclared    = "KingbaseES V008R006C10"
	testActual      = "PostgreSQL 14.10 (Debian)"
	testEvidenceSHA = "21c9d66e586e4bc6faeeda70b2fa401d9537399e97afaf59c9c1e75ba381d1b2"
)

func testTsUTC() time.Time {
	return time.Date(2026, 10, 10, 5, 0, 0, 0, time.UTC)
}

func newLLMCallAuditOK() llm.LLMCallAudit {
	return llm.LLMCallAudit{
		TsUTC:        "2026-10-10T05:00:00Z",
		LLMInSHA256:  strings.Repeat("a", 64),
		LLMOutSHA256: strings.Repeat("b", 64),
		LLMModel:     "gpt-4o-mini",
		LatencyMs:    1200,
		HTTPStatus:   200,
	}
}

func newLLMCallAuditConflict() llm.LLMCallAudit {
	return llm.LLMCallAudit{
		TsUTC:        "2026-10-10T05:00:00Z",
		LLMInSHA256:  strings.Repeat("c", 64),
		LLMOutSHA256: strings.Repeat("d", 64),
		LLMModel:     "gpt-4o-mini",
		LatencyMs:    1500,
		HTTPStatus:   200,
	}
}

func newDecisionHigh() check.LLMConflictDecision {
	return check.ResolveConflict(check.VerdictOK, 0.95, nil)
}

func newDecisionConflict() check.LLMConflictDecision {
	return check.ResolveConflict(check.VerdictOK, 0.5, &check.LLMVerdict{
		Verdict:    llm.VerdictConfirmed,
		Confidence: 0.55,
		ReasonZH:   "LLM 判定有漂移",
		Audit:      newLLMCallAuditConflict(),
	})
}

func newDecisionLowSignal() check.LLMConflictDecision {
	return check.ResolveConflict(check.VerdictOK, 0.1, nil)
}

func newDecisionFallback() check.LLMConflictDecision {
	return check.ResolveConflict(check.VerdictOK, 0.5, nil)
}

// ----------------------------------------------------------------------------
// 落盘 + verify-chain
// ----------------------------------------------------------------------------

func TestAppendLLMConflictAudit_WritesAuditRow_VerifyChainOK(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	decision := newDecisionConflict()
	meta := newLLMCallAuditConflict()
	ctx := check.ConflictAuditContext{
		EventID:        testEventID,
		ContractID:     testContractID,
		SystemID:       testSystemID,
		Vendor:         testVendor,
		Declared:       testDeclared,
		Actual:         testActual,
		TsUTC:          testTsUTC(),
		EvidenceSHA256: testEvidenceSHA,
	}

	row, err := AppendLLMConflictAudit(auditPath, ctx, decision, 0.5, &meta)
	if err != nil {
		t.Fatalf("AppendLLMConflictAudit failed: %v", err)
	}
	if row.Kind != check.ConflictKind {
		t.Errorf("row.Kind expected %s, got %s", check.ConflictKind, row.Kind)
	}
	if row.Action != check.ConflictActionRuleAndLLMConflict {
		t.Errorf("row.Action expected %s, got %s", check.ConflictActionRuleAndLLMConflict, row.Action)
	}
	if row.Operator != check.ConflictOperator {
		t.Errorf("row.Operator expected %s, got %s", check.ConflictOperator, row.Operator)
	}
	if row.Verdict != string(check.VerdictTrial) {
		t.Errorf("row.Verdict expected %s, got %s", check.VerdictTrial, row.Verdict)
	}
	if row.EventID != testEventID {
		t.Errorf("row.EventID expected %s, got %s", testEventID, row.EventID)
	}

	// verify-chain OK
	if err := VerifyChain(auditPath); err != nil {
		t.Errorf("VerifyChain failed: %v", err)
	}

	// 文件存在 + 1 行
	data, _ := os.ReadFile(auditPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	// JSON round-trip
	var roundTrip AuditRow
	if err := json.Unmarshal([]byte(lines[0]), &roundTrip); err != nil {
		t.Fatalf("unmarshal audit row: %v", err)
	}
	if roundTrip.Kind != check.ConflictKind {
		t.Errorf("roundTrip.Kind expected %s, got %s", check.ConflictKind, roundTrip.Kind)
	}
}

// ----------------------------------------------------------------------------
// LLMCallAudit 元数据完整落审计行
// ----------------------------------------------------------------------------

func TestAppendLLMConflictAudit_PreservesLLMCallAudit(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	decision := newDecisionConflict()
	meta := newLLMCallAuditConflict()
	ctx := check.ConflictAuditContext{
		EventID:        testEventID,
		ContractID:     testContractID,
		SystemID:       testSystemID,
		Vendor:         testVendor,
		Declared:       testDeclared,
		Actual:         testActual,
		TsUTC:          testTsUTC(),
		EvidenceSHA256: testEvidenceSHA,
	}

	row, err := AppendLLMConflictAudit(auditPath, ctx, decision, 0.5, &meta)
	if err != nil {
		t.Fatalf("AppendLLMConflictAudit failed: %v", err)
	}

	if row.LLMInSHA256 != meta.LLMInSHA256 {
		t.Errorf("LLMInSHA256 expected %s, got %s", meta.LLMInSHA256, row.LLMInSHA256)
	}
	if row.LLMOutSHA256 != meta.LLMOutSHA256 {
		t.Errorf("LLMOutSHA256 expected %s, got %s", meta.LLMOutSHA256, row.LLMOutSHA256)
	}
	if row.LLMModel != meta.LLMModel {
		t.Errorf("LLMModel expected %s, got %s", meta.LLMModel, row.LLMModel)
	}
	if row.LatencyMs != meta.LatencyMs {
		t.Errorf("LatencyMs expected %d, got %d", meta.LatencyMs, row.LatencyMs)
	}
}

// ----------------------------------------------------------------------------
// llmMeta=nil 时 LLM 字段全空（fallback 路径）
// ----------------------------------------------------------------------------

func TestAppendLLMConflictAudit_LLMFieldsEmpty_WhenMetaNil(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	decision := newDecisionFallback()
	ctx := check.ConflictAuditContext{
		EventID:        testEventID,
		ContractID:     testContractID,
		SystemID:       testSystemID,
		Vendor:         testVendor,
		Declared:       testDeclared,
		Actual:         testActual,
		TsUTC:          testTsUTC(),
		EvidenceSHA256: testEvidenceSHA,
	}

	row, err := AppendLLMConflictAudit(auditPath, ctx, decision, 0.5, nil)
	if err != nil {
		t.Fatalf("AppendLLMConflictAudit failed: %v", err)
	}
	if row.LLMInSHA256 != "" {
		t.Errorf("LLMInSHA256 expected empty when meta=nil, got %s", row.LLMInSHA256)
	}
	if row.LLMOutSHA256 != "" {
		t.Errorf("LLMOutSHA256 expected empty when meta=nil, got %s", row.LLMOutSHA256)
	}
	if row.LLMModel != "" {
		t.Errorf("LLMModel expected empty when meta=nil, got %s", row.LLMModel)
	}
	if row.LatencyMs != 0 {
		t.Errorf("LatencyMs expected 0 when meta=nil, got %d", row.LatencyMs)
	}
	if row.Action != check.ConflictActionLLMUnavailableFallback {
		t.Errorf("Action expected %s, got %s", check.ConflictActionLLMUnavailableFallback, row.Action)
	}
}

// ----------------------------------------------------------------------------
// 多次落盘链式验通
// ----------------------------------------------------------------------------

func TestAppendLLMConflictAudit_MultipleRows_ChainHeadAdvances(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	// 第一次：high confidence → rule_verdict_accepted
	d1 := newDecisionHigh()
	ctx1 := check.ConflictAuditContext{
		EventID: "evt-001", ContractID: testContractID, SystemID: testSystemID,
		Vendor: testVendor, Declared: testDeclared, Actual: testActual,
		TsUTC: testTsUTC(), EvidenceSHA256: strings.Repeat("a", 64),
	}
	if _, err := AppendLLMConflictAudit(auditPath, ctx1, d1, 0.95, nil); err != nil {
		t.Fatalf("first append: %v", err)
	}

	// 第二次：conflict → trial
	d2 := newDecisionConflict()
	meta := newLLMCallAuditConflict()
	ctx2 := check.ConflictAuditContext{
		EventID: "evt-002", ContractID: testContractID, SystemID: testSystemID,
		Vendor: testVendor, Declared: testDeclared, Actual: testActual,
		TsUTC: testTsUTC().Add(time.Second), EvidenceSHA256: strings.Repeat("b", 64),
	}
	if _, err := AppendLLMConflictAudit(auditPath, ctx2, d2, 0.5, &meta); err != nil {
		t.Fatalf("second append: %v", err)
	}

	// 验证 2 行 + verify-chain OK + 链头推进
	if err := VerifyChain(auditPath); err != nil {
		t.Errorf("VerifyChain failed: %v", err)
	}
	data, _ := os.ReadFile(auditPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var row1, row2 AuditRow
	if err := json.Unmarshal([]byte(lines[0]), &row1); err != nil {
		t.Fatalf("unmarshal row1: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &row2); err != nil {
		t.Fatalf("unmarshal row2: %v", err)
	}
	if row2.PrevEvidenceSHA256 != row1.SelfHash {
		t.Errorf("row2 prev (%s) != row1 self (%s)", row2.PrevEvidenceSHA256, row1.SelfHash)
	}
}

// ----------------------------------------------------------------------------
// 与 drift 行混写同一条链
// ----------------------------------------------------------------------------

func TestAppendLLMConflictAudit_MixedWithDriftRow_VerifyChainOK(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	// 先写 drift 行
	driftRow := AuditRow{
		TsUTC:          testTsUTC().Format(time.RFC3339Nano),
		EventID:        "evt-drift-001",
		ContractID:     testContractID,
		SystemID:       testSystemID,
		Vendor:         testVendor,
		Declared:       testDeclared,
		Actual:         testActual,
		Verdict:        string(check.VerdictTrial),
		Confidence:     0.5,
		EvidenceSHA256: strings.Repeat("e", 64),
		Kind:           "drift",
	}
	if _, err := AppendJSONL(auditPath, driftRow); err != nil {
		t.Fatalf("append drift row: %v", err)
	}

	// 再写 conflict 行
	d := newDecisionConflict()
	meta := newLLMCallAuditConflict()
	ctx := check.ConflictAuditContext{
		EventID: "evt-conflict-002", ContractID: testContractID, SystemID: testSystemID,
		Vendor: testVendor, Declared: testDeclared, Actual: testActual,
		TsUTC: testTsUTC().Add(time.Second), EvidenceSHA256: strings.Repeat("f", 64),
	}
	if _, err := AppendLLMConflictAudit(auditPath, ctx, d, 0.5, &meta); err != nil {
		t.Fatalf("append conflict row: %v", err)
	}

	if err := VerifyChain(auditPath); err != nil {
		t.Errorf("VerifyChain failed: %v", err)
	}
	data, _ := os.ReadFile(auditPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}
}

// ----------------------------------------------------------------------------
// trial 不被推进：本函数不写 bbolt / 不调 PromoteTrial
// ----------------------------------------------------------------------------

func TestAppendLLMConflictAudit_DoesNotAdvanceTrialStore(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	// 构造一个 conflict 决策（最终 trial + need_human_review=true）
	d := newDecisionConflict()
	if d.FinalVerdict != check.VerdictTrial {
		t.Fatalf("precondition: expected trial decision, got %s", d.FinalVerdict)
	}

	// 落盘 — 没有 TrialStore 可观察，但我们通过验证：
	//   1. 落盘行 kind=llm_conflict（**不**是 drift_*，不是 audit_anchor）；
	//   2. Operator="auto_resolve_conflict"（**不是**"张主任"等真名）；
	//   3. 没有任何状态机推进语义。
	ctx := check.ConflictAuditContext{
		EventID:        testEventID,
		ContractID:     testContractID,
		SystemID:       testSystemID,
		Vendor:         testVendor,
		Declared:       testDeclared,
		Actual:         testActual,
		TsUTC:          testTsUTC(),
		EvidenceSHA256: testEvidenceSHA,
	}
	meta2 := newLLMCallAuditConflict()
	row, err := AppendLLMConflictAudit(auditPath, ctx, d, 0.5, &meta2)
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	// 验证 Operator 是 auto_xxx，不是真名
	if !strings.HasPrefix(row.Operator, "auto_") {
		t.Errorf("Operator should start with 'auto_', got %s", row.Operator)
	}
	// 验证 Kind 是 llm_conflict（不污染状态机）
	if row.Kind != check.ConflictKind {
		t.Errorf("Kind expected %s (trial not promoted), got %s", check.ConflictKind, row.Kind)
	}
	// 验证 Verdict 是 trial（trial 不会被自动变成 confirmed/remedied/re_verified）
	if row.Verdict != string(check.VerdictTrial) {
		t.Errorf("Verdict expected trial, got %s", row.Verdict)
	}
}

// ----------------------------------------------------------------------------
// 空 auditPath / 空 EventID 报错
// ----------------------------------------------------------------------------

func TestAppendLLMConflictAudit_EmptyAuditPath_Errors(t *testing.T) {
	d := newDecisionConflict()
	ctx := check.ConflictAuditContext{
		EventID:        testEventID,
		ContractID:     testContractID,
		SystemID:       testSystemID,
		Vendor:         testVendor,
		Declared:       testDeclared,
		Actual:         testActual,
		TsUTC:          testTsUTC(),
		EvidenceSHA256: testEvidenceSHA,
	}
	_, err := AppendLLMConflictAudit("", ctx, d, 0.5, nil)
	if err == nil {
		t.Error("expected error for empty auditPath")
	}
	if !strings.Contains(err.Error(), "auditPath") {
		t.Errorf("error message should mention auditPath, got: %v", err)
	}
}

func TestAppendLLMConflictAudit_EmptyEventID_Errors(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	d := newDecisionConflict()
	ctx := check.ConflictAuditContext{
		EventID:        "",
		ContractID:     testContractID,
		SystemID:       testSystemID,
		Vendor:         testVendor,
		Declared:       testDeclared,
		Actual:         testActual,
		TsUTC:          testTsUTC(),
		EvidenceSHA256: testEvidenceSHA,
	}
	_, err := AppendLLMConflictAudit(auditPath, ctx, d, 0.5, nil)
	if err == nil {
		t.Error("expected error for empty EventID")
	}
	if !strings.Contains(err.Error(), "EventID") {
		t.Errorf("error message should mention EventID, got: %v", err)
	}
}

// ----------------------------------------------------------------------------
// 5 种决策场景 → Action 字段映射
// ----------------------------------------------------------------------------

func TestAppendLLMConflictAudit_FiveActionScenarios(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	type tc struct {
		name           string
		ruleConfidence float64
		decision       check.LLMConflictDecision
		meta           *llm.LLMCallAudit
		wantAction     string
	}
		metaOK := newLLMCallAuditOK()
	metaConflict := newLLMCallAuditConflict()
	cases := []tc{
		{"high_confidence_no_call", 0.95, newDecisionHigh(), nil, check.ConflictActionRuleVerdictAccepted},
		{"mid_confidence_llm_agree", 0.5, check.ResolveConflict(check.VerdictOK, 0.5, &check.LLMVerdict{
			Verdict: llm.VerdictReVerified, Confidence: 0.85, Audit: metaOK,
		}), &metaOK, check.ConflictActionRuleAndLLMAgree},
		{"mid_confidence_llm_conflict", 0.5, newDecisionConflict(), &metaConflict, check.ConflictActionRuleAndLLMConflict},
		{"low_signal_direct_trial", 0.1, newDecisionLowSignal(), nil, check.ConflictActionLowSignalDirectTrial},
		{"mid_confidence_fallback", 0.5, newDecisionFallback(), nil, check.ConflictActionLLMUnavailableFallback},
	}

	for i, c := range cases {
		ctx := check.ConflictAuditContext{
			EventID:        "evt-" + c.name,
			ContractID:     testContractID,
			SystemID:       testSystemID,
			Vendor:         testVendor,
			Declared:       testDeclared,
			Actual:         testActual,
			TsUTC:          testTsUTC().Add(time.Duration(i) * time.Second),
			EvidenceSHA256: strings.Repeat(string(rune('a'+i)), 64),
		}
		row, err := AppendLLMConflictAudit(auditPath, ctx, c.decision, c.ruleConfidence, c.meta)
		if err != nil {
			t.Fatalf("scenario %s: %v", c.name, err)
		}
		if row.Action != c.wantAction {
			t.Errorf("scenario %s: Action expected %s, got %s", c.name, c.wantAction, row.Action)
		}
	}

	// 验证 5 行 + verify-chain OK
	if err := VerifyChain(auditPath); err != nil {
		t.Errorf("VerifyChain failed: %v", err)
	}
	data, _ := os.ReadFile(auditPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Errorf("expected 5 lines, got %d", len(lines))
	}
}

// ----------------------------------------------------------------------------
// 10 goroutine 并发落盘：append-only 链不被穿插
// ----------------------------------------------------------------------------

func TestAppendLLMConflictAudit_Concurrent10Goroutines_VerifyChainOK(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	d := newDecisionConflict()
	meta := newLLMCallAuditConflict()

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := check.ConflictAuditContext{
				EventID:        "evt-concurrent-" + string(rune('A'+idx)),
				ContractID:     testContractID,
				SystemID:       testSystemID,
				Vendor:         testVendor,
				Declared:       testDeclared,
				Actual:         testActual,
				TsUTC:          testTsUTC().Add(time.Duration(idx) * time.Second),
				EvidenceSHA256: strings.Repeat(string(rune('a'+idx)), 64),
			}
			if _, err := AppendLLMConflictAudit(auditPath, ctx, d, 0.5, &meta); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("goroutine failed: %v", err)
	}

	// 验证 10 行 + verify-chain OK
	data, _ := os.ReadFile(auditPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 10 {
		t.Errorf("expected 10 lines, got %d", len(lines))
	}
	if err := VerifyChain(auditPath); err != nil {
		t.Errorf("VerifyChain failed: %v", err)
	}
}

// ----------------------------------------------------------------------------
// 审计行不含患者可识别字段
// ----------------------------------------------------------------------------

func TestAppendLLMConflictAudit_NoPatientFields(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	d := newDecisionConflict()
	meta := newLLMCallAuditConflict()
	ctx := check.ConflictAuditContext{
		EventID:        testEventID,
		ContractID:     testContractID,
		SystemID:       testSystemID,
		Vendor:         testVendor,
		Declared:       testDeclared,
		Actual:         testActual,
		TsUTC:          testTsUTC(),
		EvidenceSHA256: testEvidenceSHA,
	}
	row, err := AppendLLMConflictAudit(auditPath, ctx, d, 0.5, &meta)
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	body, _ := json.Marshal(row)
	forbidden := []string{"患者", "姓名", "身份证", "病案号", "住院号", "处方号", "patient", "patient_id"}
	for _, kw := range forbidden {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(kw)) {
			t.Errorf("audit row should not contain %q, got: %s", kw, string(body))
		}
	}
}
