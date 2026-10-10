// Package check — LLM verdict 与规则 verdict 冲突解决层（T42）。
//
// 设计哲学：
//
//	本文件是 T22 (llm_integration.go) 的**冲突解决层**。T22 提供"是否能调 LLM"
//	+ "决策纯函数 ResolveConflict"；T42 在其基础上补充**审计行分类与构造元数据**，
//	让"规则与 LLM 冲突"这一信号可被 output.AppendLLMConflictAudit（定义在
//	internal/output/llm_conflict_audit.go）写入 append-only JSONL 审计链，
//	供飞检 / 事后复盘 / 告警中心查验。
//
// 冲突策略（与 T22 完全一致；T42 仅在此基础上加审计行分类）：
//
//	ruleConfidence ≥ 0.7    → 不调 LLM，规则 verdict 优先；
//	ruleConfidence ∈ [0.3, 0.7) → 调 LLM：
//	    • LLM verdict 与规则 verdict 一致 → 该 verdict + need_human_review=false；
//	    • LLM verdict 与规则 verdict 不一致 → verdict=trial + need_human_review=true
//	      + 审计行 kind=llm_conflict（由 output.AppendLLMConflictAudit 落盘）；
//	ruleConfidence < 0.3    → 直接 trial（低置信度视为漂移信号），need_human_review=true；
//	LLM 不可达 (fallback)   → 采用规则 verdict + need_human_review=true（**不**写
//	                          llm_conflict 审计行；fallback 走 llm_fallback 审计行）。
//
// 关键不变量：
//   - trial 状态**永不静默推进**到 confirmed/remedied/re_verified —— 所有
//     LLM verdict / 规则 verdict 最终落到 VerdictTrial 时，必须由人工 CLI
//     confirm-drift 推进（spec.md §4 验收故事 + T17 state machine 锁住）；
//   - 冲突审计行只读 output.AppendLLMConflictAudit，**不**直接调 TrialStore /
//     PromoteTrial，保证 trial 状态由 CLI 显式推进；
//   - 冲突审计行**不**写 TrialStore，bbolt TrialStore.GlobalChainHead 不被
//     本函数污染（落 chain head 仅由 output.drift.MakeDriftEvidence 触发）。
//
// 模块边界：
//   - 本包（internal/check）**不**导入 internal/output（避免 import cycle：
//     internal/output → internal/check → internal/output）。审计行构造与落盘
//     在 internal/output/llm_conflict_audit.go 中实现，本文件只负责决策语义
//     与 Action 分类。
//   - 调用方（app/guardian.go 主循环）按如下顺序串联：
//       1. ShouldConsultLLM(ruleConfidence) 判定要不要调 LLM；
//       2. 必要时调 llm.ModelGateway.Call 拿到 LLMVerdict；
//       3. ResolveConflict(ruleVerdict, ruleConfidence, llmVerdict) 拿到 decision；
//       4. 输出端冲突决策 → output.AppendLLMConflictAudit(auditPath, ...) 落审计行。
//
// 兼容映射：
//
//	LLM verdict 与规则 verdict 的语义对齐在 T22 的 llmVerdictToRuleVerdict 中
//	已定义（re_verified ↔ ok；trial/confirmed/remedied ↔ trial）。本文件不重
//	复该映射，直接复用 T22 ResolveConflict。
package check

import (
	"time"

	"xinchuang-db-guardian/internal/llm"
)

// ----------------------------------------------------------------------------
// 常量
// ----------------------------------------------------------------------------

// ConflictKind — 审计行 Kind 字段取值：当 LLM verdict 与规则 verdict 不一致
// 时，决策最终落到 VerdictTrial + NeedHumanReview=true 的那一刻，由
// output.AppendLLMConflictAudit 写入的审计行 Kind 字段。
//
// 与其它 Kind 取值的边界（参考 spec.md §3.3 审计行 schema）：
//   - "drift"                漂移命中（端口/驱动/jdbc 任一不一致，含 trial）
//   - "drift_confirmed"      人工 CLI confirm-drift 推进 trial → confirmed
//   - "drift_remedied"       人工 CLI confirm-drift 推进 trial/confirmed → remedied
//   - "drift_re_verified"    自动 re-verified（驱动换版 + 三维全 ok）
//   - "drift_disputed"       人工 CLI confirm-drift 推进 trial/confirmed → disputed
//   - "llm_conflict"         LLM verdict 与规则 verdict 冲突（**本任务新增**）
//   - "llm_fallback"         LLM 不可达（5xx / 超时 / schema 非法）走规则 verdict
//   - "notify_error"         企微 / SMTP / LLM 出站失败（按错误类型细分）
//   - "probe_error"          连续 3 次握手失败
//   - "scan_error"           驱动扫描失败
//   - "audit_anchor"         链路锚点（保留字段，本任务不写）
const ConflictKind = "llm_conflict"

// ConflictOperator — 审计行 Operator 字段固定值：表示该审计行由自动冲突
// 解决路径产生（区别于人工 confirm-drift 的"张主任"等真名）。
const ConflictOperator = "auto_resolve_conflict"

// ConflictAction — 审计行 Action 字段固定值：表达事件语义。
//
// 可选值：
//   - "rule_verdict_accepted"   规则 high confidence 不调 LLM
//   - "rule_and_llm_agree"      规则中 confidence + LLM verdict 与规则一致
//   - "rule_and_llm_conflict"   规则中 confidence + LLM verdict 与规则不一致 → trial + need_human_review
//   - "low_signal_direct_trial" 规则 low confidence 直接 trial
//   - "llm_unavailable_fallback" LLM 不可达走规则 verdict + need_human_review
const (
	ConflictActionRuleVerdictAccepted   = "rule_verdict_accepted"
	ConflictActionRuleAndLLMAgree       = "rule_and_llm_agree"
	ConflictActionRuleAndLLMConflict    = "rule_and_llm_conflict"
	ConflictActionLowSignalDirectTrial  = "low_signal_direct_trial"
	ConflictActionLLMUnavailableFallback = "llm_unavailable_fallback"
)

// ----------------------------------------------------------------------------
// 类型别名
// ----------------------------------------------------------------------------

// LLMConflictDecision = LLMDecision（T22 的纯函数 ResolveConflict 的产出）。
// 别名仅为 T42 调用方提供语义化命名（避免与 LLM 入参的 LLMVerdict 混淆）。
type LLMConflictDecision = LLMDecision

// ConflictAuditContext — 构造 llm_conflict 审计行所需的最小字段集合。
//
// 该结构体定义在本包（internal/check），由调用方构造后传递给
// output.AppendLLMConflictAudit 落盘。本包**不**导入 output 包（避免循环依赖），
// 由 output 包构造 AuditRow 并写入 JSONL。
type ConflictAuditContext struct {
	EventID    string
	ContractID string
	SystemID   string
	Vendor     string
	Declared   string
	Actual     string

	// TsUTC — 审计行时间戳；调用方传入便于测试确定性。
	TsUTC time.Time

	// EvidenceSHA256 — 来自 DriftEvidence 的三维签名（与漂移审计行共享）。
	EvidenceSHA256 string
}

// ----------------------------------------------------------------------------
// 决策与分类 helpers
// ----------------------------------------------------------------------------

// ClassifyConflictAction — 由 decision + 原始 ruleConfidence 映射出 Action 字段。
//
// 重要：必须用**原始** ruleConfidence（不是 d.FinalConfidence）做区间判定，
// 因为 FinalConfidence 在 LLM 一致场景下会被 clamp 到 max(ruleConf, llmConf)，
// 让 case2（ruleConf=0.5 + LLM 一致）误判为 high-confidence 分支。
//
// 映射规则（与 ResolveConflict 区间语义一致）：
//   - rule_high_confidence (≥0.7) → rule_verdict_accepted
//   - rule_low_confidence (<0.3) → low_signal_direct_trial
//   - mid + LLM nil             → llm_unavailable_fallback
//   - mid + LLM 一致            → rule_and_llm_agree
//   - mid + LLM 不一致           → rule_and_llm_conflict
//
// 该函数为纯函数，便于单元测试断言 5 种决策场景的 Action 字段正确性。
func ClassifyConflictAction(d LLMConflictDecision, ruleConfidence float64, llmMeta *llm.LLMCallAudit) string {
	c := clamp01(ruleConfidence)

	// 区间 1：规则 high confidence（≥0.7）→ rule verdict 优先
	if c >= 0.7 {
		return ConflictActionRuleVerdictAccepted
	}
	// 区间 3：低置信度（<0.3）→ 直接 trial
	if c < 0.3 {
		return ConflictActionLowSignalDirectTrial
	}
	// LLM 不可达 fallback 路径（llmMeta == nil 表示 LLM 未调用或不可达）
	if llmMeta == nil {
		return ConflictActionLLMUnavailableFallback
	}
	// 一致 vs 不一致：靠 NeedHumanReview 判定（ResolveConflict 已设置）
	if d.NeedHumanReview {
		return ConflictActionRuleAndLLMConflict
	}
	return ConflictActionRuleAndLLMAgree
}

// IsConflictActionKind — 校验 Action 字符串是否为合法 conflict action。
func IsConflictActionKind(action string) bool {
	switch action {
	case ConflictActionRuleVerdictAccepted,
		ConflictActionRuleAndLLMAgree,
		ConflictActionRuleAndLLMConflict,
		ConflictActionLowSignalDirectTrial,
		ConflictActionLLMUnavailableFallback:
		return true
	}
	return false
}

// IsConflictAuditRowKind — 校验 Kind 字段是否为 llm_conflict。
func IsConflictAuditRowKind(kind string) bool {
	return kind == ConflictKind
}
