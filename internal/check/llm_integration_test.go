// internal/check/llm_integration_test.go — T22 详细测试
//
// 覆盖 T22 spec 要求的 4 case + 区间边界 + fallback + 冲突 + 一致性 + 防御性
// clamp 越界 + nil LLMVerdict + Reason 字段语义 + BuildPrompt 不含患者字段 +
// 不含端口原文 + ShouldConsultLLM 边界。
package check

import (
	"strings"
	"testing"

	"xinchuang-db-guardian/internal/classify"
	"xinchuang-db-guardian/internal/llm"
)

// ----------------------------------------------------------------------------
// ShouldConsultLLM 区间判定
// ----------------------------------------------------------------------------

func TestShouldConsultLLM_HighConfidence_NoCall(t *testing.T) {
	// ruleConfidence ≥ 0.7 → false（不调 LLM）
	for _, c := range []float64{0.7, 0.85, 0.95, 1.0} {
		if ShouldConsultLLM(c) {
			t.Errorf("confidence=%.2f expected false, got true", c)
		}
	}
}

func TestShouldConsultLLM_MidConfidence_Call(t *testing.T) {
	// ruleConfidence ∈ [0.3, 0.7) → true（调 LLM）
	for _, c := range []float64{0.3, 0.45, 0.5, 0.65, 0.699} {
		if !ShouldConsultLLM(c) {
			t.Errorf("confidence=%.2f expected true, got false", c)
		}
	}
}

func TestShouldConsultLLM_LowConfidence_NoCall(t *testing.T) {
	// ruleConfidence < 0.3 → false（不调 LLM，避免误判放大低置信噪声）
	for _, c := range []float64{0.0, 0.1, 0.2, 0.299} {
		if ShouldConsultLLM(c) {
			t.Errorf("confidence=%.2f expected false, got true", c)
		}
	}
}

func TestShouldConsultLLM_ClampOutOfRange(t *testing.T) {
	// 越界值被 clamp 到 [0, 1] 后判定
	if ShouldConsultLLM(-0.5) {
		t.Error("confidence=-0.5 clamped to 0 expected false (low signal)")
	}
	if ShouldConsultLLM(1.5) {
		t.Error("confidence=1.5 clamped to 1 expected false (high signal)")
	}
}

// ----------------------------------------------------------------------------
// ResolveConflict — Case 1：规则 high confidence（≥ 0.7）不调 LLM
// ----------------------------------------------------------------------------

func TestResolveConflict_HighConfidence_AcceptRuleVerdict(t *testing.T) {
	// ruleVerdict=ok, ruleConfidence=0.95 → 不调 LLM，最终采用 rule verdict
	d := ResolveConflict(VerdictOK, 0.95, nil)
	if d.FinalVerdict != VerdictOK {
		t.Errorf("FinalVerdict expected %s, got %s", VerdictOK, d.FinalVerdict)
	}
	if d.NeedHumanReview {
		t.Error("NeedHumanReview expected false")
	}
	if d.FinalConfidence < 0.9 {
		t.Errorf("FinalConfidence expected >=0.9, got %.2f", d.FinalConfidence)
	}
	if !strings.Contains(d.Reason, "rule_confidence") {
		t.Errorf("Reason should mention rule_confidence, got: %s", d.Reason)
	}
}

// 即使传了 LLMVerdict，high confidence 也优先规则
func TestResolveConflict_HighConfidence_IgnoresLLMVerdict(t *testing.T) {
	d := ResolveConflict(VerdictOK, 0.95, &LLMVerdict{
		Verdict:    llm.VerdictConfirmed, // LLM 说有漂移
		Confidence: 0.99,
		ReasonZH:   "LLM 判断有漂移",
	})
	if d.FinalVerdict != VerdictOK {
		t.Errorf("high confidence should ignore LLM, expected %s, got %s", VerdictOK, d.FinalVerdict)
	}
	if d.NeedHumanReview {
		t.Error("NeedHumanReview expected false (rule high confidence)")
	}
}

// ----------------------------------------------------------------------------
// ResolveConflict — Case 2：规则中 confidence（[0.3, 0.7)）调 LLM
// ----------------------------------------------------------------------------

// 规则中调 LLM，rule=ok + LLM=re_verified 一致 → ok
func TestResolveConflict_MidConfidence_LLMConsistent_OK(t *testing.T) {
	d := ResolveConflict(VerdictOK, 0.5, &LLMVerdict{
		Verdict:    llm.VerdictReVerified,
		Confidence: 0.8,
		ReasonZH:   "LLM 也认为通过",
	})
	if d.FinalVerdict != VerdictOK {
		t.Errorf("consistent ok expected %s, got %s", VerdictOK, d.FinalVerdict)
	}
	if d.NeedHumanReview {
		t.Error("NeedHumanReview expected false (consistent)")
	}
	if d.LLMSuggestedAction != llm.VerdictReVerified {
		t.Errorf("LLMSuggestedAction expected %s, got %s", llm.VerdictReVerified, d.LLMSuggestedAction)
	}
	// 一致时取较高 confidence（0.8 > 0.5）
	if d.FinalConfidence < 0.7 {
		t.Errorf("FinalConfidence expected ~0.8, got %.2f", d.FinalConfidence)
	}
}

// 规则中调 LLM，rule=ok + LLM=confirmed 不一致 → trial + need_human_review
func TestResolveConflict_MidConfidence_LLMConflict_Trial(t *testing.T) {
	d := ResolveConflict(VerdictOK, 0.5, &LLMVerdict{
		Verdict:    llm.VerdictConfirmed, // LLM 说有漂移
		Confidence: 0.7,
		ReasonZH:   "LLM 认为有漂移",
	})
	if d.FinalVerdict != VerdictTrial {
		t.Errorf("conflict expected %s, got %s", VerdictTrial, d.FinalVerdict)
	}
	if !d.NeedHumanReview {
		t.Error("NeedHumanReview expected true (conflict)")
	}
	if d.LLMSuggestedAction != llm.VerdictConfirmed {
		t.Errorf("LLMSuggestedAction expected %s, got %s", llm.VerdictConfirmed, d.LLMSuggestedAction)
	}
	if !strings.Contains(d.Reason, "conflict") {
		t.Errorf("Reason should mention conflict, got: %s", d.Reason)
	}
	// 不一致时取较低 confidence（0.5 < 0.7）
	if d.FinalConfidence > 0.6 {
		t.Errorf("FinalConfidence expected <=0.5, got %.2f", d.FinalConfidence)
	}
}

// 规则中调 LLM，rule=trial + LLM=trial 一致 → trial（虽是 trial，但一致也算"双方都没结论"）
// 实际上 trial = trial 一致表示"都需要等复核"，但 NeedHumanReview 还是 true
func TestResolveConflict_MidConfidence_LLMConsistent_Trial(t *testing.T) {
	d := ResolveConflict(VerdictTrial, 0.5, &LLMVerdict{
		Verdict:    llm.VerdictTrial,
		Confidence: 0.6,
		ReasonZH:   "待人工复核",
	})
	if d.FinalVerdict != VerdictTrial {
		t.Errorf("expected %s, got %s", VerdictTrial, d.FinalVerdict)
	}
	// 注意：rule=trial 一致 trial 也是 trial，但 trial 本身就需要复核，
	// 不过一致性判定已通过，NeedHumanReview=false。
	if d.NeedHumanReview {
		t.Error("NeedHumanReview expected false (rule=llm=trial consistent)")
	}
}

// ----------------------------------------------------------------------------
// ResolveConflict — Case 3：规则 low confidence（< 0.3）直接 trial，不调 LLM
// ----------------------------------------------------------------------------

func TestResolveConflict_LowConfidence_DirectTrial(t *testing.T) {
	d := ResolveConflict(VerdictOK, 0.1, &LLMVerdict{
		Verdict:    llm.VerdictReVerified,
		Confidence: 0.9,
		ReasonZH:   "LLM 认为通过",
	})
	if d.FinalVerdict != VerdictTrial {
		t.Errorf("low confidence expected %s, got %s", VerdictTrial, d.FinalVerdict)
	}
	if !d.NeedHumanReview {
		t.Error("NeedHumanReview expected true (low signal)")
	}
	if !strings.Contains(d.Reason, "low_signal_trial") {
		t.Errorf("Reason should mention low_signal_trial, got: %s", d.Reason)
	}
}

func TestResolveConflict_LowConfidence_ZeroConfidence(t *testing.T) {
	d := ResolveConflict(VerdictOK, 0.0, nil)
	if d.FinalVerdict != VerdictTrial {
		t.Errorf("zero confidence expected trial, got %s", d.FinalVerdict)
	}
	if !d.NeedHumanReview {
		t.Error("NeedHumanReview expected true")
	}
}

// ----------------------------------------------------------------------------
// ResolveConflict — Case 4：fallback 路径（LLM 不可达 / nil LLMVerdict）
// ----------------------------------------------------------------------------

func TestResolveConflict_Fallback_NilLLMVerdict_RuleAccepted(t *testing.T) {
	// 规则中 confidence，nil LLMVerdict → fallback 到规则 verdict + need_human_review=true
	d := ResolveConflict(VerdictOK, 0.5, nil)
	if d.FinalVerdict != VerdictOK {
		t.Errorf("fallback expected %s (rule verdict), got %s", VerdictOK, d.FinalVerdict)
	}
	if !d.NeedHumanReview {
		t.Error("NeedHumanReview expected true (fallback path)")
	}
	if !strings.Contains(d.Reason, "fallback") {
		t.Errorf("Reason should mention fallback, got: %s", d.Reason)
	}
}

func TestResolveConflict_Fallback_TrialRulePreserved(t *testing.T) {
	d := ResolveConflict(VerdictTrial, 0.4, nil)
	if d.FinalVerdict != VerdictTrial {
		t.Errorf("fallback expected %s, got %s", VerdictTrial, d.FinalVerdict)
	}
	if !d.NeedHumanReview {
		t.Error("NeedHumanReview expected true")
	}
}

// ----------------------------------------------------------------------------
// BuildPrompt — 内容约束（不携带端口原文 / 患者字段 / 业务敏感数据）
// ----------------------------------------------------------------------------

func TestBuildPrompt_NoActualLeak(t *testing.T) {
	ctx := classify.LLMContext{
		Vendor:       "kingbase",
		ActualTokens: []string{"kingbasees", "v008r006c0010"},
		VendorTokens: []string{"KingbaseES", "V008"},
		PrefixHit:    true,
		TokenOverlap: 1.0,
	}
	prompt := BuildPrompt(ctx)
	// 不应包含典型端口原文（含 PostgreSQL/Debian 等敏感字段）
	forbidden := []string{"PostgreSQL 14", "Debian", "secret", "password", "patient", "患者", "姓名", "身份证"}
	for _, w := range forbidden {
		if strings.Contains(prompt, w) {
			t.Errorf("prompt must not contain %q, got: %s", w, prompt)
		}
	}
	// 应包含 vendor 期望
	if !strings.Contains(prompt, "kingbase") {
		t.Errorf("prompt should contain vendor, got: %s", prompt)
	}
	// 应包含 JSON schema 要求
	if !strings.Contains(prompt, "JSON") {
		t.Errorf("prompt should request JSON output, got: %s", prompt)
	}
}

func TestBuildPrompt_WithVersion(t *testing.T) {
	ctx := classify.LLMContext{
		Vendor:       "dm8",
		ActualTokens: []string{"dm"},
		VendorTokens: []string{"DM", "DAMENG"},
		PrefixHit:    true,
		TokenOverlap: 0.5,
		Version: &classify.VersionMeta{
			Brand: "dm8", Major: 8, Minor: 1, Patch: 0,
		},
	}
	prompt := BuildPrompt(ctx)
	if !strings.Contains(prompt, "版本元数据") {
		t.Errorf("prompt should include version line, got: %s", prompt)
	}
	if !strings.Contains(prompt, "8.1.0") {
		t.Errorf("prompt should include version 8.1.0, got: %s", prompt)
	}
}

func TestBuildPrompt_NoVersion_OmitsVersionLine(t *testing.T) {
	ctx := classify.LLMContext{
		Vendor:       "pg-compat",
		ActualTokens: []string{"postgresql"},
		PrefixHit:    true,
		TokenOverlap: 1.0,
	}
	prompt := BuildPrompt(ctx)
	if strings.Contains(prompt, "版本元数据") {
		t.Errorf("prompt without Version must not contain 版本元数据, got: %s", prompt)
	}
}

// ----------------------------------------------------------------------------
// CombineRuleAndLLM 高层接口
// ----------------------------------------------------------------------------

func TestCombineRuleAndLLM_HighConfidence_NoLLMNeeded(t *testing.T) {
	ctx := classify.LLMContext{Vendor: "kingbase"}
	d, prompt := CombineRuleAndLLM(VerdictOK, 0.95, ctx, nil)
	if d.FinalVerdict != VerdictOK {
		t.Errorf("expected %s, got %s", VerdictOK, d.FinalVerdict)
	}
	if d.NeedHumanReview {
		t.Error("NeedHumanReview expected false")
	}
	if !strings.Contains(prompt, "JSON") {
		t.Errorf("prompt should request JSON, got: %s", prompt)
	}
}

func TestCombineRuleAndLLM_MidConfidence_Fallback(t *testing.T) {
	ctx := classify.LLMContext{Vendor: "kingbase"}
	d, _ := CombineRuleAndLLM(VerdictOK, 0.5, ctx, nil) // nil LLMVerdict → fallback
	if !d.NeedHumanReview {
		t.Error("NeedHumanReview expected true (fallback)")
	}
	if d.FinalVerdict != VerdictOK {
		t.Errorf("fallback should preserve rule verdict %s, got %s", VerdictOK, d.FinalVerdict)
	}
}

// ----------------------------------------------------------------------------
// 防御性：越界 confidence
// ----------------------------------------------------------------------------

func TestResolveConflict_OutOfRangeConfidence_Clamped(t *testing.T) {
	// confidence=1.5 → clamp 到 1.0 → high 区间，规则 verdict 优先
	d := ResolveConflict(VerdictOK, 1.5, &LLMVerdict{
		Verdict:    llm.VerdictConfirmed,
		Confidence: 0.99,
	})
	if d.FinalVerdict != VerdictOK {
		t.Errorf("clamped 1.5 expected %s (rule verdict), got %s", VerdictOK, d.FinalVerdict)
	}
	// confidence=-0.5 → clamp 到 0.0 → low 区间，trial
	d = ResolveConflict(VerdictOK, -0.5, &LLMVerdict{
		Verdict:    llm.VerdictReVerified,
		Confidence: 0.99,
	})
	if d.FinalVerdict != VerdictTrial {
		t.Errorf("clamped -0.5 expected %s (low signal), got %s", VerdictTrial, d.FinalVerdict)
	}
}

// ----------------------------------------------------------------------------
// LLM verdict 映射一致性
// ----------------------------------------------------------------------------

func TestLLMVerdictToRuleVerdict_Mapping(t *testing.T) {
	tests := []struct {
		llmVerdict llm.Verdict
		expected   Verdict
	}{
		{llm.VerdictReVerified, VerdictOK},
		{llm.VerdictTrial, VerdictTrial},
		{llm.VerdictConfirmed, VerdictTrial},
		{llm.VerdictRemedied, VerdictTrial},
		{llm.Verdict("junk"), VerdictTrial}, // 防御性
	}
	for _, tc := range tests {
		got := llmVerdictToRuleVerdict(tc.llmVerdict)
		if got != tc.expected {
			t.Errorf("llmVerdictToRuleVerdict(%s) expected %s, got %s",
				tc.llmVerdict, tc.expected, got)
		}
	}
}

// ----------------------------------------------------------------------------
// 全 4 case T22 spec 覆盖矩阵
// ----------------------------------------------------------------------------

func TestResolveConflict_4Cases_SpecCoverage(t *testing.T) {
	t.Run("Case1_HighConfidence_RuleOnly", func(t *testing.T) {
		d := ResolveConflict(VerdictOK, 0.85, nil)
		if d.FinalVerdict != VerdictOK || d.NeedHumanReview {
			t.Errorf("Case1 expected ok/false, got %s/%v", d.FinalVerdict, d.NeedHumanReview)
		}
	})
	t.Run("Case2_MidConfidence_LLMConsistent", func(t *testing.T) {
		d := ResolveConflict(VerdictOK, 0.5, &LLMVerdict{
			Verdict: llm.VerdictReVerified, Confidence: 0.8,
		})
		if d.FinalVerdict != VerdictOK || d.NeedHumanReview {
			t.Errorf("Case2 expected ok/false, got %s/%v", d.FinalVerdict, d.NeedHumanReview)
		}
	})
	t.Run("Case3_MidConfidence_LLMConflict", func(t *testing.T) {
		d := ResolveConflict(VerdictOK, 0.5, &LLMVerdict{
			Verdict: llm.VerdictConfirmed, Confidence: 0.7,
		})
		if d.FinalVerdict != VerdictTrial || !d.NeedHumanReview {
			t.Errorf("Case3 expected trial/true, got %s/%v", d.FinalVerdict, d.NeedHumanReview)
		}
	})
	t.Run("Case4_LowConfidence_DirectTrial", func(t *testing.T) {
		d := ResolveConflict(VerdictOK, 0.2, &LLMVerdict{
			Verdict: llm.VerdictReVerified, Confidence: 0.9,
		})
		if d.FinalVerdict != VerdictTrial || !d.NeedHumanReview {
			t.Errorf("Case4 expected trial/true, got %s/%v", d.FinalVerdict, d.NeedHumanReview)
		}
	})
}
