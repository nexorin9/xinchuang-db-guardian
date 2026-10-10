// Package output — LLM 兜底降级审计行的写入入口。
//
// 本文件是 internal/llm/gateway.go 的输出侧 helper：当 ModelGateway.Call
// 返回 ErrLLMUnavailable 或 ErrSchemaViolation 时，caller 调用
// AppendFallbackAudit 把一次"规则无法定论 → 调用 LLM → LLM 不可达"事件
// 落审计行。
//
// 与 drift / drift_confirmed / drift_remedied / drift_re_verified 不同：
//
//   - kind=llm_fallback 是**运维观察类**事件，**不**计入 status machine；
//   - 该行**永不**推进 trial → confirmed / remedied / re-verified / disputed；
//     推进 trial 必须由信息科人工通过 CLI confirm-drift 命令确认；
//   - verdict 字段写**规则 verdict**而非 LLM verdict（fallback 语义）；
//   - LLMCallAudit 元数据完整落审计行（HTTPStatus / LatencyMs / ErrorKind
//     等，便于事后取证：是 schema 非法还是 5xx 还是超时）。
//
// 为避免 llm ↔ output 互相依赖，本包定义的 AppendFallbackAudit 入参为
// 来自 llm 包的窄视图类型（llm.FallbackMetadata / llm.FallbackDriftContext），
// 不耦合 llm 内部私有字段。
package output

import (
	"errors"
	"fmt"
	"time"

	"xinchuang-db-guardian/internal/llm"
)

// AppendFallbackAudit — 把一次 LLM 不可达降级事件写入 JSONL 审计链。
//
// 关键不变量：
//
//  1. **永不自动推进 trial** — 仅追加 1 行 JSONL，**不**写 TrialStore，
//     不调 PromoteTrial，不调 confirm-drift；trial → confirmed / remedied /
//     re-verified / disputed 必须由信息科人工通过 CLI confirm-drift 推进。
//
//  2. **kind 标签独立** — 写 kind=llm_fallback（区别于 drift_* / notify_error
//     / probe_error / scan_error / audit_anchor），便于 export-evidence 按
//     kind 过滤（运维类行不进 drift_events.csv / contract_registry.csv）。
//
//  3. **verdict 是规则 verdict** — 不是 LLM verdict；fallback 路径 verdict
//     字段形如"trial"或"ok"取决于 ResolveConflict 的 FinalVerdict。
//
//  4. **完整 LLMCallAudit 元数据** — LLMInSHA256 / LLMOutSHA256 / LLMModel /
//     LatencyMs / HTTPStatus / ErrorKind 全部落审计行（即使 fallback 也不
//     丢元数据，便于事后取证）。
//
//  5. **append-only 链** — 调 AppendJSONL，自动维护 self_hash 与
//     prev_evidence_sha256 链；审计链整体顺序对所有 kind 一视同仁。
//
// 失败语义：JSONL 写入失败向上抛 error，**不**静默吞错；caller 收到 error
// 后应 slog.Error 记录 reason，由信息科后续补录或重跑确认。
func AppendFallbackAudit(
	auditPath string,
	meta llm.FallbackMetadata,
	ctx llm.FallbackDriftContext,
) (AuditRow, error) {
	if auditPath == "" {
		return AuditRow{}, errors.New("output: AppendFallbackAudit auditPath empty")
	}
	if meta.ErrorKind == "" {
		return AuditRow{}, errors.New("output: AppendFallbackAudit meta.ErrorKind empty; refusing to record non-fallback path")
	}
	if ctx.EventID == "" {
		return AuditRow{}, errors.New("output: AppendFallbackAudit EventID empty")
	}

	// 时间戳：与 LLMCallAudit 的 TsUTC 对齐；为空时落本机时间。
	tsUTC := meta.TsUTC
	if tsUTC == "" {
		tsUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}

	row := AuditRow{
		TsUTC:              tsUTC,
		EventID:            ctx.EventID,
		ContractID:         ctx.ContractID,
		SystemID:           ctx.SystemID,
		Vendor:             ctx.Vendor,
		Declared:           ctx.Declared,
		Actual:             ctx.Actual,
		EvidenceSHA256:     ctx.EvidenceSHA256,
		Verdict:            ctx.RuleVerdict,
		LLMInSHA256:        meta.LLMInSHA256,
		LLMOutSHA256:       meta.LLMOutSHA256,
		LLMModel:           meta.LLMModel,
		LatencyMs:          meta.LatencyMs,
		Action:             "rule_verdict_fallback",
		Operator:           "auto_fallback",
		Kind:               "llm_fallback",
	}

	if written, err := AppendJSONL(auditPath, row); err != nil {
		return AuditRow{}, fmt.Errorf("output: AppendFallbackAudit AppendJSONL: %w", err)
	} else if written != 1 {
		return AuditRow{}, fmt.Errorf("output: AppendFallbackAudit wrote %d rows, expected 1", written)
	}
	return row, nil
}
