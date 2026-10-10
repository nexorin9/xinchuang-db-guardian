// Package check — 漂移状态机（trial → confirmed → remedied → re-verified）。
//
// 设计原则：
//   - 状态推进只能由 CLI 人工 confirm-drift 触发，永不静默进 confirmed；
//   - LLM verdict 只入 trial，不直接推进；
//   - 转移图受 transition map 严格限制，非法转移返回错误码 + 不修改 State；
//
// 状态机本身参考 cilium-health 多端口 listener 监听 + 周期 Timer 模式
// （cilium-health/responder/main.go），把"运行期持续核对 → 异常 → 处置"的思路
// 移植为"运行期持续核对 → 漂移命中 → 人工推进状态"的工作流。
package check

import (
	"errors"
	"fmt"
)

// State — 漂移事件的处置状态。
type State string

const (
	// StateTrial — 初次探测命中/规则不能定论；trial 不入 confirmed 永不静默推进。
	StateTrial State = "trial"
	// StateConfirmed — 信息科确认漂移（人工 confirm-drift --action confirmed）。
	StateConfirmed State = "confirmed"
	// StateRemedied — 厂商已整改（人工 confirm-drift --action remedied）。
	StateRemedied State = "remedied"
	// StateReVerified — 整改后下一次 Compare verdict=ok 且 evidence_sha 变化时自动触发。
	StateReVerified State = "re_verified"
	// StateDisputed — 信息科驳回（人工 confirm-drift --action disputed）。
	StateDisputed State = "disputed"
)

// ErrInvalidTransition — 非法转移错误。
type ErrInvalidTransition struct {
	From State
	To   State
}

func (e *ErrInvalidTransition) Error() string {
	return fmt.Sprintf("invalid drift state transition: %s -> %s", e.From, e.To)
}

// IsInvalidTransition — 检查错误是否为非法转移。
func IsInvalidTransition(err error) bool {
	var e *ErrInvalidTransition
	return errors.As(err, &e)
}

// transitionTable — 合法转移图。
//
//	trial       → {confirmed, remedied, disputed}
//	confirmed   → {remedied, disputed}
//	remedied    → {re_verified}
//	re_verified → ∅（终止态）
//	disputed    → {confirmed, remedied}
var transitionTable = map[State]map[State]bool{
	StateTrial: {
		StateConfirmed: true,
		StateRemedied:  true,
		StateDisputed:  true,
	},
	StateConfirmed: {
		StateRemedied: true,
		StateDisputed: true,
	},
	StateRemedied: {
		StateReVerified: true,
	},
	StateReVerified: {},
	StateDisputed: {
		StateConfirmed: true,
		StateRemedied:  true,
	},
}

// CanTransition — 转移合法性校验。
//
// 行为：
//   - 同状态转移（from == to）拒绝（视为无效事件）；
//   - 未列在 transitionTable 的转移返回 *ErrInvalidTransition；
//   - 合法转移返回 nil；
func CanTransition(from, to State) error {
	if from == to {
		return &ErrInvalidTransition{From: from, To: to}
	}
	allowed, ok := transitionTable[from]
	if !ok {
		return &ErrInvalidTransition{From: from, To: to}
	}
	if !allowed[to] {
		return &ErrInvalidTransition{From: from, To: to}
	}
	return nil
}

// AllowedTransitions — 返回 from 状态的所有合法目标（用于 CLI 提示）。
func AllowedTransitions(from State) []State {
	allowed := transitionTable[from]
	out := make([]State, 0, len(allowed))
	for s := range allowed {
		out = append(out, s)
	}
	return out
}

// ValidState — 校验字符串是否为合法的 State。
func ValidState(s string) bool {
	switch State(s) {
	case StateTrial, StateConfirmed, StateRemedied, StateReVerified, StateDisputed:
		return true
	}
	return false
}
