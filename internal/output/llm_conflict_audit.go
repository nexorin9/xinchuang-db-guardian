// Package output — LLM verdict 与规则 verdict 冲突审计行的写入入口（T42）。
//
// 本文件是 internal/check/llm_conflict.go 的输出侧 helper：当 ResolveConflict
// 的产出落到 VerdictTrial + NeedHumanReview=true 时（即规则 verdict 与 LLM
// verdict 不一致），调用本文件的 AppendLLMConflictAudit 把这次冲突事件落
// 审计行（kind=llm_conflict）。
//
// 与 drift / drift_confirmed / drift_remedied / llm_fallback 的关系：
//
//   - kind=llm_conflict 是**冲突观察类**事件，**不**计入 status machine；
//   - 该行**永不**推进 trial → confirmed / remedied / re-verified / disputed；
//     推进 trial 必须由信息科人工通过 CLI confirm-drift 命令确认；
//   - verdict 字段写**最终 decision 的 FinalVerdict**（trial / ok）；
//   - LLMCallAudit 元数据完整落审计行（HTTPStatus / LatencyMs / ErrorKind
//     等，便于事后取证：是一致还是不冲突）。
//
// 为避免 check ↔ output 互相依赖，本文件构造 AuditRow 时直接读 llm.LLMCallAudit
// 字段（output 已 import llm 用于 llm_fallback）；AuditRow 是本包定义类型，
// 不耦合 check 包内部细节。
package output

import (
	"errors"
	"fmt"
	"time"

	"xinchuang-db-guardian/internal/check"
	"xinchuang-db-guardian/internal/llm"
)

// AppendLLMConflictAudit — 把一次 LLM verdict 与规则 verdict 冲突事件写入 JSONL 审计链。
//
// 关键不变量：
//
//  1. **永不自动推进 trial** — 仅追加 1 行 JSONL，**不**写 TrialStore，
//     不调 PromoteTrial，不调 confirm-drift；trial → confirmed / remedied /
//     re_verified / disputed 必须由信息科人工通过 CLI confirm-drift 推进。
//
//  2. **kind 标签独立** — 写 kind=llm_conflict（区别于 drift_* / llm_fallback /
//     notify_error / probe_error / scan_error / audit_anchor），便于 export-evidence
//     按 kind 过滤（冲突类行不进 drift_events.csv / contract_registry.csv，
//     而是独立列在 audit.jsonl + manifest.json）。
//
//  3. **verdict 是最终 decision** — 来自 ResolveConflict 的 FinalVerdict
//     （trial / ok），不是 LLM 原始 verdict；冲突场景下 verdict 必然 = trial
//     （由 check.ResolveConflict 保证）。
//
//  4. **完整 LLMCallAudit 元数据** — LLMInSHA256 / LLMOutSHA256 / LLMModel /
//     LatencyMs 全部落审计行（即使是一致场景也不丢元数据，便于事后取证）。
//
//  5. **append-only 链** — 调 AppendJSONL，自动维护 self_hash 与
//     prev_evidence_sha256 链；审计链整体顺序对所有 kind 一视同仁。
//
// 失败语义：JSONL 写入失败向上抛 error，**不**静默吞错；caller 收到 error
// 后应 slog.Error 记录 reason，由信息科后续补录或重跑确认。
func AppendLLMConflictAudit(
	auditPath string,
	ctx check.ConflictAuditContext,
	decision check.LLMConflictDecision,
	ruleConfidence float64,
	llmMeta *llm.LLMCallAudit,
) (AuditRow, error) {
	if auditPath == "" {
		return AuditRow{}, errors.New("output: AppendLLMConflictAudit auditPath empty")
	}
	if ctx.EventID == "" {
		return AuditRow{}, errors.New("output: AppendLLMConflictAudit EventID empty")
	}

	action := check.ClassifyConflictAction(decision, ruleConfidence, llmMeta)

	tsUTC := ctx.TsUTC
	if tsUTC.IsZero() {
		tsUTC = time.Now().UTC()
	}

	row := AuditRow{
		TsUTC:              tsUTC.UTC().Format(time.RFC3339Nano),
		EventID:            ctx.EventID,
		ContractID:         ctx.ContractID,
		SystemID:           ctx.SystemID,
		Vendor:             ctx.Vendor,
		Declared:           ctx.Declared,
		Actual:             ctx.Actual,
		EvidenceSHA256:     ctx.EvidenceSHA256,
		Verdict:            string(decision.FinalVerdict),
		Confidence:         decision.FinalConfidence,
		Action:             action,
		Operator:           check.ConflictOperator,
		Kind:               check.ConflictKind,
	}
	if llmMeta != nil {
		row.LLMInSHA256 = llmMeta.LLMInSHA256
		row.LLMOutSHA256 = llmMeta.LLMOutSHA256
		row.LLMModel = llmMeta.LLMModel
		row.LatencyMs = llmMeta.LatencyMs
	}

	if written, err := AppendJSONL(auditPath, row); err != nil {
		return AuditRow{}, fmt.Errorf("output: AppendLLMConflictAudit AppendJSONL: %w", err)
	} else if written != 1 {
		return AuditRow{}, fmt.Errorf("output: AppendLLMConflictAudit wrote %d rows, expected 1", written)
	}
	return row, nil
}
