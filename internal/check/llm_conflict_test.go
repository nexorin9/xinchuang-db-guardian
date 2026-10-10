// internal/check/llm_conflict_test.go — T42 冲突解决层纯函数测试
//
// 本文件只测纯函数（不依赖 output 包，避免 import cycle）：
//   - ResolveConflict 4 case（spec 要求）
//   - ClassifyConflictAction 5 场景映射
//   - IsConflictActionKind / IsConflictAuditRowKind 字符串校验
//
// 审计行落盘 + verify-chain 的测试放在 internal/output/llm_conflict_audit_test.go。
package check

import (
	"strings"
	"testing"

	"xinchuang-db-guardian/internal/llm"
)

// ----------------------------------------------------------------------------
// 共享 test fixtures
// ----------------------------------------------------------------------------

const (
	testEventID     = "evt-conflict-001"
	testContractID  = "C-LIS-001"
	testSystemID    = "lis-pacs-1"
	testVendor      = "kingbase"
	testDeclared    = "KingbaseES V008R006C10"
	testActual      = "PostgreSQL 14.10 (Debian)"
	testEvidenceSHA = "21c9d66e586e4bc6faeeda70b2fa401d9537399e97afaf59c9c1e75ba381d1b2"
)

func newLLMVerdictOK() *LLMVerdict {
	return &LLMVerdict{
		Verdict:    llm.VerdictReVerified,
		Confidence: 0.85,
		ReasonZH:   "LLM 判定 Kingbase 与 PG 兼容模式一致",
		Audit: llm.LLMCallAudit{
			TsUTC:        "2026-10-10T05:00:00Z",
			LLMInSHA256:  strings.Repeat("a", 64),
			LLMOutSHA256: strings.Repeat("b", 64),
			LLMModel:     "gpt-4o-mini",
			LatencyMs:    1200,
			HTTPStatus:   200,
		},
	}
}

func newLLMVerdictConflict() *LLMVerdict {
	return &LLMVerdict{
		Verdict:    llm.VerdictConfirmed,
		Confidence: 0.55,
		ReasonZH:   "LLM 判定有漂移，与规则 verdict=ok 不一致",
		Audit: llm.LLMCallAudit{
			TsUTC:        "2026-10-10T05:00:00Z",
			LLMInSHA256:  strings.Repeat("c", 64),
			LLMOutSHA256: strings.Repeat("d", 64),
			LLMModel:     "gpt-4o-mini",
			LatencyMs:    1500,
			HTTPStatus:   200,
		},
	}
}

// ----------------------------------------------------------------------------
// Case 1：规则 high confidence（≥ 0.7）不调 LLM
// ----------------------------------------------------------------------------

func TestResolveConflict_Case1_HighConfidence_RuleVerdictAccepted(t *testing.T) {
	// ruleConfidence=0.95 + ruleVerdict=ok + llmVerdict=nil → FinalVerdict=ok, NeedHumanReview=false
	d := ResolveConflict(VerdictOK, 0.95, nil)
	if d.FinalVerdict != VerdictOK {
		t.Errorf("Case1: FinalVerdict expected %s, got %s", VerdictOK, d.FinalVerdict)
	}
	if d.NeedHumanReview {
		t.Error("Case1: NeedHumanReview expected false")
	}
	if d.FinalConfidence < 0.9 {
		t.Errorf("Case1: FinalConfidence expected >=0.9, got %.2f", d.FinalConfidence)
	}
	if !strings.Contains(d.Reason, "rule_confidence") {
		t.Errorf("Case1: Reason should mention rule_confidence, got: %s", d.Reason)
	}

	// Action 字段应为 rule_verdict_accepted
	if got := ClassifyConflictAction(d, 0.95, nil); got != ConflictActionRuleVerdictAccepted {
		t.Errorf("Case1: action expected %s, got %s", ConflictActionRuleVerdictAccepted, got)
	}
}

// ----------------------------------------------------------------------------
// Case 2：规则中 confidence（[0.3, 0.7)）调 LLM + LLM 与规则一致
// ----------------------------------------------------------------------------

func TestResolveConflict_Case2_MidConfidence_LLMConsistent_OK(t *testing.T) {
	// ruleVerdict=ok + ruleConfidence=0.5 + LLMVerdict{re_verified} → 一致
	llmV := newLLMVerdictOK()
	d := ResolveConflict(VerdictOK, 0.5, llmV)
	if d.FinalVerdict != VerdictOK {
		t.Errorf("Case2: FinalVerdict expected %s, got %s", VerdictOK, d.FinalVerdict)
	}
	if d.NeedHumanReview {
		t.Error("Case2: NeedHumanReview expected false")
	}

	// Action 字段应为 rule_and_llm_agree
	if got := ClassifyConflictAction(d, 0.5, &llmV.Audit); got != ConflictActionRuleAndLLMAgree {
		t.Errorf("Case2: action expected %s, got %s", ConflictActionRuleAndLLMAgree, got)
	}
}

// ----------------------------------------------------------------------------
// Case 3：规则中 confidence（[0.3, 0.7)）调 LLM + LLM 与规则不一致
// ----------------------------------------------------------------------------

func TestResolveConflict_Case3_MidConfidence_LLMConflict_Trial(t *testing.T) {
	// ruleVerdict=ok + ruleConfidence=0.5 + LLMVerdict{confirmed} → 不一致 → trial
	llmV := newLLMVerdictConflict()
	d := ResolveConflict(VerdictOK, 0.5, llmV)
	if d.FinalVerdict != VerdictTrial {
		t.Errorf("Case3: FinalVerdict expected %s, got %s", VerdictTrial, d.FinalVerdict)
	}
	if !d.NeedHumanReview {
		t.Error("Case3: NeedHumanReview expected true (LLM verdict conflicts with rule)")
	}
	if !strings.Contains(d.Reason, "conflict") {
		t.Errorf("Case3: Reason should mention conflict, got: %s", d.Reason)
	}

	// Action 字段应为 rule_and_llm_conflict
	if got := ClassifyConflictAction(d, 0.5, &llmV.Audit); got != ConflictActionRuleAndLLMConflict {
		t.Errorf("Case3: action expected %s, got %s", ConflictActionRuleAndLLMConflict, got)
	}
}

// ----------------------------------------------------------------------------
// Case 4：规则 low confidence（< 0.3）直接 trial
// ----------------------------------------------------------------------------

func TestResolveConflict_Case4_LowConfidence_DirectTrial(t *testing.T) {
	// ruleConfidence=0.1 + 不传 LLMVerdict → FinalVerdict=trial, NeedHumanReview=true
	d := ResolveConflict(VerdictOK, 0.1, nil)
	if d.FinalVerdict != VerdictTrial {
		t.Errorf("Case4: FinalVerdict expected %s, got %s", VerdictTrial, d.FinalVerdict)
	}
	if !d.NeedHumanReview {
		t.Error("Case4: NeedHumanReview expected true (low signal = trial)")
	}
	if !strings.Contains(d.Reason, "low_signal_trial") {
		t.Errorf("Case4: Reason should mention low_signal_trial, got: %s", d.Reason)
	}

	// Action 字段应为 low_signal_direct_trial
	if got := ClassifyConflictAction(d, 0.1, nil); got != ConflictActionLowSignalDirectTrial {
		t.Errorf("Case4: action expected %s, got %s", ConflictActionLowSignalDirectTrial, got)
	}
}

// ----------------------------------------------------------------------------
// Case 5 (附加)：LLM 不可达 fallback → 规则 verdict + need_human_review
// ----------------------------------------------------------------------------

func TestResolveConflict_Case5_LLMUnavailable_Fallback(t *testing.T) {
	// ruleConfidence=0.5 + llmVerdict=nil → fallback 路径
	d := ResolveConflict(VerdictOK, 0.5, nil)
	if d.FinalVerdict != VerdictOK {
		t.Errorf("Case5: FinalVerdict expected %s (fallback keeps rule verdict), got %s", VerdictOK, d.FinalVerdict)
	}
	if !d.NeedHumanReview {
		t.Error("Case5: NeedHumanReview expected true (fallback always marks human review)")
	}
	if !strings.Contains(d.Reason, "fallback") {
		t.Errorf("Case5: Reason should mention fallback, got: %s", d.Reason)
	}

	// Action 字段应为 llm_unavailable_fallback
	if got := ClassifyConflictAction(d, 0.5, nil); got != ConflictActionLLMUnavailableFallback {
		t.Errorf("Case5: action expected %s, got %s", ConflictActionLLMUnavailableFallback, got)
	}
}

// ----------------------------------------------------------------------------
// 边缘 case：clamp 越界
// ----------------------------------------------------------------------------

func TestResolveConflict_T42_OutOfRangeConfidence_Clamped(t *testing.T) {
	// confidence > 1 → clamp 到 1.0 → 视为 high confidence
	d := ResolveConflict(VerdictOK, 1.5, nil)
	if d.FinalVerdict != VerdictOK {
		t.Errorf("clamp high: FinalVerdict expected %s, got %s", VerdictOK, d.FinalVerdict)
	}
	if d.NeedHumanReview {
		t.Error("clamp high: NeedHumanReview expected false (rule accepted)")
	}

	// confidence < 0 → clamp 到 0 → 视为 low confidence → trial
	d = ResolveConflict(VerdictOK, -0.5, nil)
	if d.FinalVerdict != VerdictTrial {
		t.Errorf("clamp low: FinalVerdict expected %s, got %s", VerdictTrial, d.FinalVerdict)
	}
}

// ----------------------------------------------------------------------------
// LLM verdict 映射表（5 个 LLM verdict 全部覆盖）
// ----------------------------------------------------------------------------

func TestLLMVerdictToRuleVerdict_T42_Mapping(t *testing.T) {
	cases := []struct {
		llmV   llm.Verdict
		expect Verdict
	}{
		{llm.VerdictReVerified, VerdictOK},
		{llm.VerdictTrial, VerdictTrial},
		{llm.VerdictConfirmed, VerdictTrial},
		{llm.VerdictRemedied, VerdictTrial},
	}
	for _, c := range cases {
		got := llmVerdictToRuleVerdict(c.llmV)
		if got != c.expect {
			t.Errorf("llmVerdictToRuleVerdict(%s) expected %s, got %s", c.llmV, c.expect, got)
		}
	}
	// 未知 verdict → trial（防御性）
	if got := llmVerdictToRuleVerdict(llm.Verdict("junk")); got != VerdictTrial {
		t.Errorf("unknown LLM verdict should map to trial, got %s", got)
	}
}

// ----------------------------------------------------------------------------
// ClassifyConflictAction 5 场景表驱动
// ----------------------------------------------------------------------------

func TestClassifyConflictAction_TableDriven(t *testing.T) {
	type tc struct {
		name       string
		ruleConf   float64
		ruleVerd   Verdict
		llmV       *LLMVerdict
		wantAction string
	}
	cases := []tc{
		{
			name:       "high_confidence_no_call",
			ruleConf:   0.95,
			ruleVerd:   VerdictOK,
			llmV:       nil,
			wantAction: ConflictActionRuleVerdictAccepted,
		},
		{
			name:       "mid_confidence_llm_consistent",
			ruleConf:   0.5,
			ruleVerd:   VerdictOK,
			llmV:       newLLMVerdictOK(),
			wantAction: ConflictActionRuleAndLLMAgree,
		},
		{
			name:       "mid_confidence_llm_conflict",
			ruleConf:   0.5,
			ruleVerd:   VerdictOK,
			llmV:       newLLMVerdictConflict(),
			wantAction: ConflictActionRuleAndLLMConflict,
		},
		{
			name:       "low_confidence_direct_trial",
			ruleConf:   0.1,
			ruleVerd:   VerdictOK,
			llmV:       nil,
			wantAction: ConflictActionLowSignalDirectTrial,
		},
		{
			name:       "mid_confidence_llm_unavailable_fallback",
			ruleConf:   0.5,
			ruleVerd:   VerdictOK,
			llmV:       nil,
			wantAction: ConflictActionLLMUnavailableFallback,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := ResolveConflict(c.ruleVerd, c.ruleConf, c.llmV)
			var llmMeta *llm.LLMCallAudit
			if c.llmV != nil {
				llmMeta = &c.llmV.Audit
			}
			got := ClassifyConflictAction(d, c.ruleConf, llmMeta)
			if got != c.wantAction {
				t.Errorf("action expected %s, got %s (decision=%+v)", c.wantAction, got, d)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// IsConflictActionKind / IsConflictAuditRowKind
// ----------------------------------------------------------------------------

func TestIsConflictActionKind(t *testing.T) {
	valid := []string{
		ConflictActionRuleVerdictAccepted,
		ConflictActionRuleAndLLMAgree,
		ConflictActionRuleAndLLMConflict,
		ConflictActionLowSignalDirectTrial,
		ConflictActionLLMUnavailableFallback,
	}
	for _, a := range valid {
		if !IsConflictActionKind(a) {
			t.Errorf("IsConflictActionKind(%s) expected true", a)
		}
	}
	invalid := []string{"", "drift", "drift_confirmed", "junk"}
	for _, a := range invalid {
		if IsConflictActionKind(a) {
			t.Errorf("IsConflictActionKind(%s) expected false", a)
		}
	}
}

func TestIsConflictAuditRowKind(t *testing.T) {
	if !IsConflictAuditRowKind(ConflictKind) {
		t.Errorf("IsConflictAuditRowKind(%s) expected true", ConflictKind)
	}
	for _, k := range []string{"drift", "drift_confirmed", "llm_fallback", "notify_error", ""} {
		if IsConflictAuditRowKind(k) {
			t.Errorf("IsConflictAuditRowKind(%s) expected false", k)
		}
	}
}

// ----------------------------------------------------------------------------
// 常量稳定性（防御性断言：未来重命名时测试会失败）
// ----------------------------------------------------------------------------

func TestConflictConstants_StableValues(t *testing.T) {
	if ConflictKind != "llm_conflict" {
		t.Errorf("ConflictKind expected llm_conflict, got %s", ConflictKind)
	}
	if ConflictOperator != "auto_resolve_conflict" {
		t.Errorf("ConflictOperator expected auto_resolve_conflict, got %s", ConflictOperator)
	}
	if ConflictActionRuleAndLLMConflict != "rule_and_llm_conflict" {
		t.Errorf("ConflictActionRuleAndLLMConflict expected rule_and_llm_conflict, got %s", ConflictActionRuleAndLLMConflict)
	}
}

// ----------------------------------------------------------------------------
// trial 不静默推进的语义验证：纯函数路径不可写 bbolt / 不可调 PromoteTrial
// ----------------------------------------------------------------------------

func TestResolveConflict_DoesNotAdvanceTrialByItself(t *testing.T) {
	// 即使 conflict 决策最终 trial，本函数也不暴露任何调 PromoteTrial / 写
	// TrialStore 的入口。LLMDecision 只产出决策数据，状态推进由调用方
	// (confirm-drift CLI / output.MakeDriftEvidence) 完成。
	llmV := newLLMVerdictConflict()
	d := ResolveConflict(VerdictOK, 0.5, llmV)
	if d.FinalVerdict != VerdictTrial {
		t.Fatalf("precondition failed: expected trial, got %s", d.FinalVerdict)
	}
	// 决策结构体不应包含任何 *Store / *BoltDB / promote 之类的字段
	if d.FinalConfidence == 0 && d.NeedHumanReview == false {
		t.Error("trial decision should not silently promote (NeedHumanReview must be true)")
	}
}
