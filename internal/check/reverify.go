// Package check — 状态机 re-verified 自动检测（驱动重 sha 后下次核对自动）。
//
// 设计参考 cilium pkg/datapath/agentliveness/agent_liveness.go:51-63 的周期
// Timer 注册模式：把"周期性核对 → 异常 → 处置 → 周期核对再次恢复正常"的反馈
// 移植为"周期性核对 → 漂移 → 状态机 → 整改 → 下次核对自动 re-verified"的
// 闭环。
//
// re-verified 是状态机的"自动完成态"：当一条 remedied 的事件在下一次 Compare
// 中 verdict=ok 且 evidence_sha256 发生变化（驱动 jar 换新版本、JDBC URL
// 调整、port_raw 文案变化任一）时，守护自动推进 StateRemedied → StateReVerified，
// **不**经过人工 confirm-drift CLI（这是状态机里唯一一条非 CLI 推进路径，
// 因为 re-verified 是"事实自证"而非"决策"）。
//
// 与人工推进的边界：
//   - confirmed / remedied / disputed 必须由 `confirm-drift --action <...> --operator <姓名>`
//     CLI 触发（spec.md §3.5）；
//   - re-verified 可由 AutoReverify 自动触发，但仍写审计行（operator="auto_reverify"，
//     action="re-verified"），保留完整证据链；
//   - trial 永不自动推进（spec.md §3.1）。
package check

import (
	"errors"
)

// ErrEmptyLastRemediatedSHA — 没有任何先前 remedied 状态可对比。
//
// AutoReverify 在 lastRemediatedSHA 为空时返回 fired=false 而非错误，但调用方
// 若明确依赖此值做"曾经有 remedied 状态"判定，可用本错误信号化。
var ErrEmptyLastRemediatedSHA = errors.New("reverify: empty lastRemediatedSHA")

// ErrEmptyCurrentEvidenceSHA — 当前 evidence_sha256 为空时不应触发 re-verified。
//
// 防御性：Compare() 失败 / 异常路径可能产生空 hash；AutoReverify 把空 hash
// 视作"无证据"，fired=false 避免把损坏证据推上 re-verified 链。
var ErrEmptyCurrentEvidenceSHA = errors.New("reverify: empty currentEvidenceSHA")

// AutoReverifyResult — AutoReverify 调用结果。
//
// 字段语义：
//   - NewState: 若 fired=true 则为 StateReVerified；否则与 input 语义对齐（不变更调用方传入的 State）；
//   - Fired: 是否触发 re-verified 推进；
//   - Reason: fired=false 时记录不触发的根因，便于审计行 / 日志直接引用；
type AutoReverifyResult struct {
	NewState State
	Fired    bool
	Reason   string
}

// 触发 / 不触发的根因常量（写入 Reason 字段）。
const (
	reverifyFiredReason            = "re_verified:verdict_ok_with_new_evidence_sha"
	reverifyNotFiredNoLastRemedied = "no_previous_remedied_state"
	reverifyNotFiredTrialVerdict    = "verdict_trial_skip_reverify"
	reverifyNotFiredSameSHA         = "verdict_ok_but_evidence_sha_unchanged"
	reverifyNotFiredEmptyInputs     = "empty_inputs_defensive_skip"
)

// AutoReverify — 状态机 re-verified 自动检测。
//
// 入参：
//   - lastRemediatedSHA: 上一次 State=remedied 时的 evidence_sha256（从
//     TrialStore.LoadTrial() 取 SelfHash 前的 EvidenceSHA256 字段）；
//     空字符串表示"没有任何先前 remedied 状态"；
//   - currentEvidenceSHA: 本次 Compare() 后得到的 evidence_sha256；
//   - currentVerdict: 本次 Compare() 后得到的 verdict (ok / trial)；
//
// 返回：
//   - AutoReverifyResult{NewState, Fired, Reason}：
//       * verdict=ok 且 lastRemediatedSHA 非空 且 currentEvidenceSHA 非空
//         且 lastRemediatedSHA != currentEvidenceSHA
//         → NewState=StateReVerified, Fired=true
//       * verdict=trial
//         → NewState=StateTrial（不变更调用方传入的状态），Fired=false
//       * verdict=ok 但 lastRemediatedSHA == ""（无先前 remedied 状态）
//         → Fired=false, Reason=no_previous_remedied_state
//       * verdict=ok 但 currentEvidenceSHA == lastRemediatedSHA（驱动未变）
//         → Fired=false, Reason=verdict_ok_but_evidence_sha_unchanged
//       * 任意输入 evidence_sha 为空
//         → Fired=false, Reason=empty_inputs_defensive_skip
//
// 设计要点：
//   - 纯函数：不读 bbolt、不调 audit；调用方负责：
//       1. 从 TrialStore 读 old EventID 对应的 EvidenceSHA256；
//       2. 调 Compare() 取 currentEvidenceSHA + currentVerdict；
//       3. 调 AutoReverify() 判定是否推进；
//       4. 若 fired=true → 调 PromoteTrial() / 写审计行 kind=drift_re_verified
//          operator=auto_reverify, action=re-verified；
//   - 状态推进仍走 CanTransition (remedied → re_verified) 锁；
//     AutoReverify 仅做"是否触发"的判定，不直接改 State 字段。
func AutoReverify(lastRemediatedSHA, currentEvidenceSHA string, currentVerdict Verdict) AutoReverifyResult {
	// 防御性：任一 evidence_sha 为空 → 不触发，避免损坏证据链。
	if lastRemediatedSHA == "" || currentEvidenceSHA == "" {
		return AutoReverifyResult{
			NewState: StateTrial,
			Fired:    false,
			Reason:   reverifyNotFiredEmptyInputs,
		}
	}

	// verdict != ok → 不触发 reverify（trial 信号优先；继续 trial / 等人工 confirm）。
	if currentVerdict != VerdictOK {
		return AutoReverifyResult{
			NewState: StateTrial,
			Fired:    false,
			Reason:   reverifyNotFiredTrialVerdict,
		}
	}

	// verdict=ok + evidence_sha 与上次一致 → 不重复触发（避免告警风暴）。
	if lastRemediatedSHA == currentEvidenceSHA {
		return AutoReverifyResult{
			NewState: StateRemedied, // 仍处于 remedied 状态，未推进
			Fired:    false,
			Reason:   reverifyNotFiredSameSHA,
		}
	}

	// 触发：verdict=ok + evidence_sha 变化 = 整改生效，下一次扫描确认。
	return AutoReverifyResult{
		NewState: StateReVerified,
		Fired:    true,
		Reason:   reverifyFiredReason,
	}
}

// ShouldAutoReverify — AutoReverify 的简化 boolean 版本。
//
// 调用方只需"是否触发"判定时可用本函数；需要 Reason 时用 AutoReverify。
// 行为与 AutoReverify 完全一致，仅返回值类型不同。
func ShouldAutoReverify(lastRemediatedSHA, currentEvidenceSHA string, currentVerdict Verdict) bool {
	return AutoReverify(lastRemediatedSHA, currentEvidenceSHA, currentVerdict).Fired
}
