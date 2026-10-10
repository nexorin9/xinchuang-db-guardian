// Package app — 守护主循环（contracts.yaml → 三维核对 → re-verified 自动
// 闭环 → audit / wecom / smtp）。
//
// 设计参考 cilium cilium-health/responder/main.go 的守护运行时结构 +
// cilium pkg/datapath/agentliveness/agent_liveness.go:51-63 的周期 Timer
// 注册模式：把"周期性核对 → 异常 → 处置 → 周期核对再次恢复正常"的反馈
// 移植为信创数据库合规漂移守护的工作流。
//
// re-verified 自动闭环接入：
//   - 每次 Compare 完成 → 调 AutoReverify(lastRemediatedSHA, currentSHA, verdict)；
//   - 若 fired=true → 调 PromoteTrial / 写审计行 kind=drift_re_verified
//     operator="auto_reverify", action="re-verified"；
//   - 若 fired=false → 状态保持原样。
//
// 安全边界：
//   - trial / confirmed / remedied / disputed **永不**自动推进；
//   - re-verified 是状态机里**唯一一条自动推进路径**，且仅当 (verdict=ok ∧
//     evidence_sha 变化 ∧ 上次状态=remedied) 三条件全成立时才触发；
//   - 不直连生产回写：每次状态推进都先经 CanTransition 锁。
package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"xinchuang-db-guardian/internal/check"
	"xinchuang-db-guardian/internal/config"
	"xinchuang-db-guardian/internal/output"
)

// AppendReverifyAuditFn 是 ReverifyAuditor.AppendReverifyAudit 的简写签名，
// 便于测试用闭包注入，不依赖 output 包具体类型。
type AppendReverifyAuditFn func(ctx context.Context, evidence check.DriftEvidence) error

// ReverifyAuditor — re-verified 自动闭环的最小审计写入接口。
//
// Guardian 主循环依赖此接口把 fired=true 的 re-verified 事件写入 audit 行；
// 该接口由 cmd 层注入实现（cmd/xinchuang-guardian/cmd_start.go 提供
// AppendJSONL 实现 + kind=drift_re_verified + operator="auto_reverify" +
// action="re-verified"），本包不直接依赖 output.AppendJSONL，便于解耦。
type ReverifyAuditor interface {
	// AppendReverifyAudit — 写一条 kind=drift_re_verified 审计行。
	//
	// 入参 evidence 是已设置好 State=StateReVerified + PrevEvidenceSHA256 +
	// SelfHash 的 DriftEvidence；auditor 只需负责把审计行落到 audit.jsonl 并
	// 维护全局链头。
	AppendReverifyAudit(ctx context.Context, evidence check.DriftEvidence) error
}

// Guardian — 守护主循环的轻量封装。
//
// 当前任务（T21）落地 AutoReverify 的接入骨架；后续 task（T22 / T40 等）
// 在此基础上叠加 LLM 兜底 / errgroup 并行评估。Guardian 不持有真实 I/O
// 资源（驱动目录 / bbolt / audit 文件），这些由 caller 通过接口注入。
type Guardian struct {
	// Contracts — 合同白名单（声明）。
	Contracts []config.ContractV
	// BrandMap — 品牌指纹字典（vendor signature）。
	BrandMap *config.BrandMap
	// TrialStore — trial 状态持久化（用于读 lastRemediatedSHA + 写新 trial）。
	TrialStore *output.TrialStore
	// Auditor — re-verified 审计写入接口（nil 时跳过审计行写入，仅 slog.Info）。
	Auditor ReverifyAuditor
	// Logger — slog handler；nil 时回落 slog.Default()。
	Logger *slog.Logger
	// AutoReverifyEnabled — re-verified 自动闭环总开关；默认 true。
	//
	// 信息科可在 contracts.yaml / 启动 flag 上关闭此开关（运维场景：
	// 飞检前冻结状态机自动推进，避免 evidence 包内多出未审计行）。
	AutoReverifyEnabled bool
}

// NewGuardian — 默认值构造器。
func NewGuardian(
	contracts []config.ContractV,
	brandMap *config.BrandMap,
	store *output.TrialStore,
	auditor ReverifyAuditor,
	logger *slog.Logger,
) *Guardian {
	if logger == nil {
		logger = slog.Default()
	}
	return &Guardian{
		Contracts:           contracts,
		BrandMap:            brandMap,
		TrialStore:          store,
		Auditor:             auditor,
		Logger:              logger,
		AutoReverifyEnabled: true,
	}
}

// MaybeAutoReverify — 在 Compare 完成后判断是否触发 re-verified 自动闭环。
//
// 入参：
//   - ctx: 父 context（用于在 audit 写入时响应 cancel）；
//   - lastEvidence: 上一条 DriftEvidence（从 TrialStore.LoadTrial 读出）；
//     当 lastEvidence.State != StateRemedied 时直接返回 nil（无触发条件）；
//   - currentEvidence: 本次 Compare 后的 DriftEvidence（含新 EvidenceSHA256
//     + verdict）；
//
// 返回：
//   - nil: 未触发 re-verified（fired=false 或 lastEvidence 状态不是 remedied）；
//   - error: 触发后推进状态失败 / 写审计行失败（不静默吞错）；
//
// 行为：
//  1. 守卫检查：AutoReverifyEnabled=false / lastEvidence.State != remedied
//     → 直接返回 nil；
//  2. 调 AutoReverify(lastEvidence.EvidenceSHA256, currentEvidence.EvidenceSHA256,
//     currentEvidence.Verdict)；
//  3. 若 fired=true → 复制 currentEvidence + 设置 Status=StateReVerified
//     + 设置 PrevEvidenceSHA256 = lastEvidence.SelfHash + 重新计算
//     SelfHash（用 ComputeSelfHash(PrevEvidenceSHA256, HashBody(ev))）；
//     调 PromoteTrial 或直接调 SaveTrial + 写审计行 kind=drift_re_verified
//     operator=auto_reverify, action=re-verified；
//  4. 若 fired=false → slog.Debug 记录 reason，返回 nil；
//
// 失败处理：状态推进走 CanTransition 锁；PromoteTrial / SaveTrial 错误
// 不静默吞错（向上抛回 caller 决定如何处理）。
func (g *Guardian) MaybeAutoReverify(
	ctx context.Context,
	lastEvidence check.DriftEvidence,
	currentEvidence check.DriftEvidence,
) error {
	if g == nil {
		return fmt.Errorf("guardian: nil receiver")
	}
	logger := g.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// 1. 守卫检查：自动闭环总开关关闭 → 不触发。
	if !g.AutoReverifyEnabled {
		logger.Debug("reverify_disabled_by_config",
			slog.String("system_id", currentEvidence.SystemID),
			slog.String("event_id", currentEvidence.EventID),
		)
		return nil
	}

	// 2. 守卫检查：上一条状态非 remedied → 不可能"自动从 remedied 推进"。
	if lastEvidence.Status != check.StateRemedied {
		logger.Debug("reverify_skip_last_state_not_remedied",
			slog.String("system_id", currentEvidence.SystemID),
			slog.String("event_id", currentEvidence.EventID),
			slog.String("last_status", string(lastEvidence.Status)),
		)
		return nil
	}

	// 3. 调 AutoReverify（纯函数，不依赖任何 I/O）。
	res := check.AutoReverify(
		lastEvidence.EvidenceSHA256,
		currentEvidence.EvidenceSHA256,
		currentEvidence.Verdict,
	)

	if !res.Fired {
		logger.Debug("reverify_not_fired",
			slog.String("system_id", currentEvidence.SystemID),
			slog.String("event_id", currentEvidence.EventID),
			slog.String("reason", res.Reason),
		)
		return nil
	}

	// 4. fired=true → 构造新 evidence（Status=StateReVerified + 链头维护）。
	//
	// 注意：先更新 TsUTC 再算 SelfHash，保证 SelfHash 覆盖最终落盘的
	// 全部字段。否则 HashBody 与 TsUTC 不一致 → audit verify-chain 报错。
	updated := currentEvidence
	updated.Status = res.NewState
	updated.PrevEvidenceSHA256 = lastEvidence.SelfHash
	updated.TsUTC = time.Now().UTC().Format(time.RFC3339Nano)
	body := check.HashBody(updated)
	updated.SelfHash = check.ComputeSelfHash(updated.PrevEvidenceSHA256, body)

	logger.Info("reverify_fired",
		slog.String("system_id", updated.SystemID),
		slog.String("event_id", updated.EventID),
		slog.String("prev_evidence_sha256", updated.PrevEvidenceSHA256),
		slog.String("self_hash", updated.SelfHash),
		slog.String("reason", res.Reason),
	)

	// 5. 状态推进仍走 CanTransition 锁（即使 AutoReverify 已判定 fired=true，
	//    防御性二次校验防止调用方传错 lastEvidence.Status）。
	if err := check.CanTransition(lastEvidence.Status, updated.Status); err != nil {
		logger.Error("reverify_can_transition_failed",
			slog.String("from", string(lastEvidence.Status)),
			slog.String("to", string(updated.Status)),
			slog.String("err", err.Error()),
		)
		return fmt.Errorf("reverify CanTransition(%s → %s) failed: %w",
			lastEvidence.Status, updated.Status, err)
	}

	// 6. 持久化 + 审计行：TrialStore 写回 + Auditor 写审计行。
	if g.TrialStore != nil {
		if err := g.TrialStore.SaveTrial(updated); err != nil {
			logger.Error("reverify_save_trial_failed",
				slog.String("event_id", updated.EventID),
				slog.String("err", err.Error()),
			)
			return fmt.Errorf("reverify SaveTrial: %w", err)
		}
	}

	if g.Auditor != nil {
		if err := g.Auditor.AppendReverifyAudit(ctx, updated); err != nil {
			logger.Error("reverify_audit_append_failed",
				slog.String("event_id", updated.EventID),
				slog.String("err", err.Error()),
			)
			return fmt.Errorf("reverify AppendReverifyAudit: %w", err)
		}
	}

	return nil
}

// AppendReverifyAuditViaOutput — ReverifyAuditor 的默认 output 包实现。
//
// 该类型把 ReverifyAuditor.AppendReverifyAudit 转发到 output.AppendJSONL，
// 同时填充审计行 operator="auto_reverify" / action="re-verified" / kind=
// "drift_re_verified"。TrialStore.GlobalChainHead 提供 prev_evidence_sha256
// （与 PromoteTrial 行为对齐：跨 trial 链构造）。
//
// 此类型不强制依赖 cmd 层；测试可直接用 NewOutputAuditor(store, auditPath)
// 构造，无需额外的 cmd 包 stub。
type OutputAuditor struct {
	TrialStore  *output.TrialStore
	AuditPath   string
	OperatorTag string // 默认 "auto_reverify"
	ActionTag   string // 默认 "re-verified"
	KindTag     string // 默认 "drift_re_verified"
}

// NewOutputAuditor — 默认值构造器。
func NewOutputAuditor(store *output.TrialStore, auditPath string) *OutputAuditor {
	return &OutputAuditor{
		TrialStore:  store,
		AuditPath:   auditPath,
		OperatorTag: "auto_reverify",
		ActionTag:   "re-verified",
		KindTag:     "drift_re_verified",
	}
}

// AppendReverifyAudit — 实现 ReverifyAuditor 接口。
//
// 行为：
//   - 把 DriftEvidence 转换为 AuditRow（含 trial 链头作为 prev_evidence_sha256）；
//   - operator/action/kind 由 OutputAuditor 默认字段填充；
//   - 调 output.AppendJSONL 写入（已带 AppendLock 互斥）。
func (a *OutputAuditor) AppendReverifyAudit(ctx context.Context, evidence check.DriftEvidence) error {
	if a == nil {
		return fmt.Errorf("output auditor: nil receiver")
	}
	if a.AuditPath == "" {
		return fmt.Errorf("output auditor: empty audit path")
	}
	// 跨 trial 链头：若 evidence.PrevEvidenceSHA256 未填，用 store 的全局链头补上。
	prev := evidence.PrevEvidenceSHA256
	if prev == "" && a.TrialStore != nil {
		head, err := a.TrialStore.GlobalChainHead()
		if err == nil {
			prev = head
		}
	}

	row := output.AuditRow{
		TsUTC:              evidence.TsUTC,
		EventID:            evidence.EventID,
		ContractID:         evidence.ContractID,
		SystemID:           evidence.SystemID,
		Vendor:             evidence.Vendor,
		Declared:           evidence.Declared,
		Actual:             evidence.Actual,
		PortRaw:            evidence.PortRaw,
		DriverSha:          evidence.DriverSha,
		JDBCURL:            evidence.JDBCURL,
		Verdict:            string(evidence.Verdict),
		Confidence:         evidence.Confidence,
		EvidenceSHA256:     evidence.EvidenceSHA256,
		PrevEvidenceSHA256: prev,
		Action:             a.ActionTag,
		Operator:           a.OperatorTag,
		Kind:               a.KindTag,
	}
	// output.AppendJSONL 的 prev 由其内部自动从末行 self_hash 读出；
	// 此处先把 prev 设到 row（兼容直接 verify-chain 读 JSONL 时也能看到 prev）。
	// 若 prev 仍为空，AppendJSONL 会自动从末行读出，二者一致。
	_ = ctx // 当前实现不需要 ctx；保留参数以便未来加 timeout
	_, err := output.AppendJSONL(a.AuditPath, row)
	return err
}
