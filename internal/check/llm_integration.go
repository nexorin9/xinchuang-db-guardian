// Package check — LLM 兜底 verdict 集成（T22）。
//
// 设计哲学：
//
//	LLM 在本产品里是**兜底解释器**，不是主路径裁定者。规则 confidence 落在
//	不能定论的区间（[0.3, 0.7)）时调用，拿一个 verdict 作为参考意见；规则
//	confidence ≥ 0.7 时**不会**调用 LLM（直接采用规则 verdict）；
//	规则 confidence < 0.3 时**也不**调用 LLM（避免 LLM 误判放大低置信噪声）。
//
//	LLM verdict 与规则 verdict 一致 → 采用该 verdict + need_human_review=false；
//	LLM verdict 与规则 verdict 不一致 → verdict=trial + need_human_review=true，
//	由人工 CLI confirm-drift 推进。
//
//	fallback 语义：LLM 不可达（5xx / 超时 / schema 非法）→ 采用规则 verdict +
//	need_human_review=true。trial 状态**永不静默推进**到 confirmed/remedied/
//	re_verified。
//
//	调用元数据：LLMCallAudit（来自 internal/llm/gateway.go）由调用方落入
//	append-only JSONL 审计链，本文件仅暴露 BuildPrompt + ResolveConflict 纯函数。
//
// 调用方：internal/app/guardian.go 主循环在 confidence ∈ [0.3, 0.7) 时调
//         ShouldConsultLLM(ruleConfidence) 判定 → true 时调 ModelGateway.Call →
//         拿 LLMVerdict → 调 ResolveConflict(ruleVerdict, ruleConfidence,
//         llmVerdict) 拿最终 verdict。
package check

import (
	"fmt"
	"strings"

	"xinchuang-db-guardian/internal/classify"
	"xinchuang-db-guardian/internal/llm"
)

// LLMVerdict — T22 暴露给上层的 LLM 入参 verdict 结构。
//
// 语义：把内部 llm.Verdict 与 confidence 一起包装成对外结构；rule verdict
// 是 VerdictTrial/VerdictOK；LLM verdict 是 llm.Verdict 枚举（trial / confirmed
// / remedied / re_verified）。ResolveConflict 在两者之间做一致性比较时，把
// 规则 verdict "ok" 视作与 LLM 的 "re_verified" 兼容（同为通过），其它不一致
// 即视为需要人工复核。
type LLMVerdict struct {
	// Verdict — LLM 返回的 verdict（trial / confirmed / remedied / re_verified）。
	Verdict llm.Verdict
	// Confidence — LLM 返回的 confidence ∈ [0, 1]。
	Confidence float64
	// ReasonZH — LLM 给的中文理由（≤ 80 汉字，来源 gateway.go SchemaGuidance）。
	ReasonZH string
	// Audit — 来自 llm.LLMCallAudit 的调用元数据，供 caller 落审计行。
	Audit llm.LLMCallAudit
}

// LLMDecision — ResolveConflict 的完整产出。
//
// 字段：
//   - FinalVerdict：最终给到上层 Compare 函数的 verdict（trial 或 ok）；
//   - FinalConfidence：最终 confidence（0.0–1.0）；
//   - NeedHumanReview：是否需要人工复核（true 时不能静默推进）；
//   - LLMSuggestedAction：LLM 给的建议（仅参考，不直接推进）；
//   - Reason：审计可读的理由描述。
type LLMDecision struct {
	FinalVerdict       Verdict
	FinalConfidence    float64
	NeedHumanReview    bool
	LLMSuggestedAction llm.Verdict
	Reason             string
}

// ----------------------------------------------------------------------------
// ShouldConsultLLM — 判定规则 confidence 落在哪个区间，决定要不要调 LLM。
//
// 区间语义（与 spec.md §3.4 + research.md §按需模型接口 一致）：
//
//	ruleConfidence ≥ 0.7  → false（规则已定论，不调 LLM）
//	ruleConfidence ∈ [0.3, 0.7) → true（不能定论，调 LLM 拿参考意见）
//	ruleConfidence < 0.3  → false（低置信度视为漂移信号，直接 trial，避免 LLM 误判放大）
//
// 参数 clamp：ruleConfidence 越界（< 0 或 > 1）会先被 clamp 到 [0, 1]，
// 避免调用方传错值导致判定逻辑跑偏。
// ----------------------------------------------------------------------------
func ShouldConsultLLM(ruleConfidence float64) bool {
	c := clamp01(ruleConfidence)
	if c >= 0.7 {
		return false
	}
	if c < 0.3 {
		return false
	}
	return true
}

// ----------------------------------------------------------------------------
// BuildPrompt — 把 classify.LLMContext 渲染成 LLM 入参 prompt。
//
// 行为：
//   - 携带 vendor 期望 + actual tokens + vendor 期望 tokens + prefix 命中 +
//     token 交集占比 + 可选 version 元数据；
//   - 显式不携带 actual 原字符串（避免敏感端口原文泄漏）；
//   - 不包含患者可识别字段；
//   - 输出末尾固定要求 LLM 输出 JSON {verdict, confidence, reason}。
//
// 本函数为 llm_integration.go 私有 helper，被 CombineRuleAndLLM 间接调用。
// ----------------------------------------------------------------------------
func BuildPrompt(ctx classify.LLMContext) string {
	versionLine := ""
	if ctx.Version != nil {
		versionLine = fmt.Sprintf("版本元数据：%s %d.%d.%d\n", ctx.Version.Brand, ctx.Version.Major, ctx.Version.Minor, ctx.Version.Patch)
	}
	return fmt.Sprintf(
		"请根据以下结构化信息判断数据库厂商一致性。\n"+
			"vendor 期望：%s\n"+
			"actual tokens：%v\n"+
			"vendor 期望 tokens：%v\n"+
			"prefix regex 命中：%v\n"+
			"token 交集占比：%.2f\n"+
			"%s"+
			"请输出 JSON：{verdict, confidence, reason}",
		strings.ToLower(ctx.Vendor), ctx.ActualTokens, ctx.VendorTokens, ctx.PrefixHit, ctx.TokenOverlap, versionLine,
	)
}

// ----------------------------------------------------------------------------
// ResolveConflict — 组合规则 verdict 与 LLM verdict 出最终 LLMDecision。
//
// 行为：
//   1. ruleConfidence ≥ 0.7 → FinalVerdict=ruleVerdict, NeedHumanReview=false
//      （不调 LLM 时也走这条路径，LLMVerdict 可以是 nil）；
//   2. ruleConfidence ∈ [0.3, 0.7) + LLMVerdict 非 nil：
//      a) LLM verdict 与 rule verdict 一致 → FinalVerdict=该 verdict,
//         NeedHumanReview=false；
//      b) LLM verdict 与 rule verdict 不一致 → FinalVerdict=trial,
//         NeedHumanReview=true；
//   3. ruleConfidence < 0.3 → FinalVerdict=trial（低置信度视为漂移信号）,
//      NeedHumanReview=true（不调 LLM，避免 LLM 误判放大低置信噪声）；
//   4. LLMVerdict 为 nil（fallback 路径：5xx / 超时 / schema 非法）→ 采用
//      规则 verdict + NeedHumanReview=true。
//
// 兼容映射：规则 verdict "ok" 视作与 LLM 的 "re_verified" 兼容（同为通过）；
// 规则 verdict "trial" 视作与 LLM 的 "confirmed" 或 "trial" 不一致时冲突，
// 因为 trial 是"待定"，confirmed 是"已确认有漂移"——若规则无法定论而 LLM
// 给出 confirmed，冲突需要人工复核。
//
// FinalConfidence 取法：一致时取 max(ruleConfidence, llmConfidence)；
// 不一致时取 min(ruleConfidence, llmConfidence)，表达"双方都不太确定"。
// fallback 时取 ruleConfidence（LLM 不可信）。
// ----------------------------------------------------------------------------
func ResolveConflict(ruleVerdict Verdict, ruleConfidence float64, llmVerdict *LLMVerdict) LLMDecision {
	c := clamp01(ruleConfidence)

	// 区间 1：规则已定论（confidence ≥ 0.7）→ 不调 LLM，规则 verdict 优先。
	if c >= 0.7 {
		return LLMDecision{
			FinalVerdict:    ruleVerdict,
			FinalConfidence: c,
			NeedHumanReview: false,
			Reason:          fmt.Sprintf("rule_confidence=%.2f>=0.70 rule_verdict=%s accepted", c, ruleVerdict),
		}
	}

	// 区间 3：低置信度（confidence < 0.3）→ 直接 trial，不调 LLM。
	if c < 0.3 {
		return LLMDecision{
			FinalVerdict:    VerdictTrial,
			FinalConfidence: c,
			NeedHumanReview: true,
			Reason:          fmt.Sprintf("rule_confidence=%.2f<0.30 low_signal_trial", c),
		}
	}

	// 区间 2：不能定论（confidence ∈ [0.3, 0.7)），需要调 LLM。
	// LLMVerdict 为 nil → fallback 路径，规则 verdict + need_human_review=true。
	if llmVerdict == nil {
		return LLMDecision{
			FinalVerdict:    ruleVerdict,
			FinalConfidence: c,
			NeedHumanReview: true,
			Reason:          "llm_unavailable fallback to rule_verdict",
		}
	}

	// 一致性判定：把 LLM verdict 映射成规则 verdict。
	llmVerdictNorm := llmVerdictToRuleVerdict(llmVerdict.Verdict)
	if llmVerdictNorm == ruleVerdict {
		// 一致 → 该 verdict + need_human_review=false + 取较高 confidence。
		confidence := c
		if llmVerdict.Confidence > confidence {
			confidence = llmVerdict.Confidence
		}
		return LLMDecision{
			FinalVerdict:       ruleVerdict,
			FinalConfidence:    confidence,
			NeedHumanReview:    false,
			LLMSuggestedAction: llmVerdict.Verdict,
			Reason:             fmt.Sprintf("rule and llm agree on %s", ruleVerdict),
		}
	}

	// 不一致 → trial + need_human_review=true + 取较低 confidence。
	confidence := c
	if llmVerdict.Confidence < confidence {
		confidence = llmVerdict.Confidence
	}
	return LLMDecision{
		FinalVerdict:       VerdictTrial,
		FinalConfidence:    confidence,
		NeedHumanReview:    true,
		LLMSuggestedAction: llmVerdict.Verdict,
		Reason: fmt.Sprintf("rule_verdict=%s llm_verdict=%s conflict -> trial",
			ruleVerdict, llmVerdict.Verdict),
	}
}

// ----------------------------------------------------------------------------
// CombineRuleAndLLM — T22 spec 暴露的高层函数（保留 spec 命名）。
//
// 等价于 ShouldConsultLLM → (可选) llm.Call → ResolveConflict 的封装。
// 调用方传 ModelGateway 引用与 rule verdict；本函数内部决定要不要调 LLM，
// 最终产出 LLMDecision + LLMCallAudit 元数据供 caller 落审计行。
//
// ctx 参数由 classify.BuildLLMContext(portRaw, contract.Vendor, brandMap)
// 构造；brandMap 可为 nil（退化为 token-only 路径）。
//
// 注意：本函数**不**主动调 LLM，只产出决策元数据；真正的 LLM 调用由 caller
// 根据 ShouldConsultLLM(ruleConfidence) 判定后自行发起，调用结果作为
// llmVerdict 参数传入 ResolveConflict。这样设计是为了：
//   1. 单元测试不依赖 LLM 调用；
//   2. LLM 调用元数据由 caller 控制入审计行的格式；
//   3. fallback 路径的 ErrLLMUnavailable 由 caller 决定如何包装。
// ----------------------------------------------------------------------------
func CombineRuleAndLLM(ruleVerdict Verdict, ruleConfidence float64, ctx classify.LLMContext, llmVerdict *LLMVerdict) (LLMDecision, string) {
	prompt := BuildPrompt(ctx)
	decision := ResolveConflict(ruleVerdict, ruleConfidence, llmVerdict)
	return decision, prompt
}

// ----------------------------------------------------------------------------
// 私有 helpers
// ----------------------------------------------------------------------------

// clamp01 — 把 float64 钳到 [0, 1]。
func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// llmVerdictToRuleVerdict — 把 LLM 输出的 verdict 映射到规则 verdict。
//
// 映射语义：
//   - "trial" → VerdictTrial（待定）
//   - "confirmed" → VerdictTrial（"已确认有漂移" 在规则里就是 trial 信号，
//     因为 trial 表示三维不能完全 ok）
//   - "remedied" → VerdictTrial（"已整改" 在规则里也走 trial，因为规则只能
//     对"当下事实"做核对）
//   - "re_verified" → VerdictOK（"已复核通过" 等价于规则 verdict=ok）
//
// 这样映射后，ResolveConflict 的 `ruleVerdict == llmVerdictNorm` 比较就是
// "规则说 ok 且 LLM 说 re_verified = 一致通过；规则说 trial 且 LLM 说
// re_verified = 不一致需复核" 的语义。
func llmVerdictToRuleVerdict(v llm.Verdict) Verdict {
	switch v {
	case llm.VerdictReVerified:
		return VerdictOK
	case llm.VerdictTrial, llm.VerdictConfirmed, llm.VerdictRemedied:
		return VerdictTrial
	default:
		// 未知 verdict → 视为 trial（防御性）
		return VerdictTrial
	}
}
