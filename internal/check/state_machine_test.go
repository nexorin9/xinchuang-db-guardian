package check

import (
	"errors"
	"strings"
	"testing"
)

func TestCanTransition_LegalPaths(t *testing.T) {
	legal := []struct {
		from, to State
	}{
		{StateTrial, StateConfirmed},
		{StateTrial, StateRemedied},
		{StateTrial, StateDisputed},
		{StateConfirmed, StateRemedied},
		{StateConfirmed, StateDisputed},
		{StateRemedied, StateReVerified},
		{StateDisputed, StateConfirmed},
		{StateDisputed, StateRemedied},
	}
	for _, c := range legal {
		if err := CanTransition(c.from, c.to); err != nil {
			t.Errorf("合法转移 %s -> %s 应通过，实际报错: %v", c.from, c.to, err)
		}
	}
}

func TestCanTransition_IllegalPaths(t *testing.T) {
	illegal := []struct {
		from, to State
	}{
		{StateTrial, StateReVerified},     // 直接 trial → re_verified 拒绝
		{StateConfirmed, StateTrial},      // back-edge 拒绝
		{StateConfirmed, StateReVerified}, // confirmed 必须先到 remedied
		{StateRemedied, StateTrial},       // back-edge
		{StateRemedied, StateConfirmed},   // 不可从 remedied 回 confirmed
		{StateReVerified, StateRemedied},  // re_verified 终止态
		{StateReVerified, StateConfirmed},
		{StateReVerified, StateTrial},
		{StateDisputed, StateReVerified},  // 必须先到 remedied
		{StateTrial, StateTrial},          // 同状态转移
		{"", StateTrial},                  // 未知 from
	}
	for _, c := range illegal {
		err := CanTransition(c.from, c.to)
		if err == nil {
			t.Errorf("非法转移 %s -> %s 应报错，实际通过", c.from, c.to)
			continue
		}
		if !IsInvalidTransition(err) {
			t.Errorf("非法转移 %s -> %s 错误类型错误: %T %v", c.from, c.to, err, err)
		}
		var ie *ErrInvalidTransition
		if !errors.As(err, &ie) {
			t.Errorf("非法转移错误应实现 ErrInvalidTransition，got %T", err)
		}
	}
}

func TestCanTransition_AllAllowed(t *testing.T) {
	// 验证 AllowedTransitions 与转移图一致。
	for from, allowed := range transitionTable {
		got := AllowedTransitions(from)
		if len(got) != len(allowed) {
			t.Errorf("%s 期望 %d 个合法转移，实际 %d", from, len(allowed), len(got))
		}
	}
}

func TestValidState(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"trial", true},
		{"confirmed", true},
		{"remedied", true},
		{"re_verified", true},
		{"disputed", true},
		{"unknown", false},
		{"", false},
		{"TRIAL", false}, // 大小写敏感
	}
	for _, c := range cases {
		got := ValidState(c.s)
		if got != c.want {
			t.Errorf("ValidState(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// TestErrInvalidTransition_ErrorMessage — 验证 Error() 输出格式含 from/to 状态名。
// 飞检组从证据包里读审计行的 stderr 时依赖此格式做根因定位。
func TestErrInvalidTransition_ErrorMessage(t *testing.T) {
	cases := []struct {
		from, to State
		want     string
	}{
		{StateTrial, StateReVerified, "trial -> re_verified"},
		{StateConfirmed, StateTrial, "confirmed -> trial"},
		{StateReVerified, StateRemedied, "re_verified -> remedied"},
		{"", "trial", " -> trial"},
	}
	for _, c := range cases {
		e := &ErrInvalidTransition{From: c.from, To: c.to}
		msg := e.Error()
		if !strings.Contains(msg, c.want) {
			t.Errorf("Error()=%q 应包含 %q", msg, c.want)
		}
		if !strings.HasPrefix(msg, "invalid drift state transition:") {
			t.Errorf("Error()=%q 应以 'invalid drift state transition:' 开头", msg)
		}
	}
}

// TestCanTransition_ExhaustiveMatrix — 5×5 = 25 个组合穷举验证。
// 锁定 trial 不静默推进 confirmed/re_verified，re_verified 终止，
// 以及所有同状态 + 跨状态非法组合都被拒。
func TestCanTransition_ExhaustiveMatrix(t *testing.T) {
	allStates := []State{
		StateTrial, StateConfirmed, StateRemedied, StateReVerified, StateDisputed,
	}
	// 期望的合法转移对（来自 transitionTable）
	legalSet := map[State]map[State]bool{
		StateTrial:     {StateConfirmed: true, StateRemedied: true, StateDisputed: true},
		StateConfirmed: {StateRemedied: true, StateDisputed: true},
		StateRemedied:  {StateReVerified: true},
		StateReVerified: {},
		StateDisputed:  {StateConfirmed: true, StateRemedied: true},
	}
	for _, from := range allStates {
		for _, to := range allStates {
			wantLegal := legalSet[from][to]
			err := CanTransition(from, to)
			gotLegal := (err == nil)
			if gotLegal != wantLegal {
				t.Errorf("CanTransition(%s -> %s) legal=%v, want %v (err=%v)",
					from, to, gotLegal, wantLegal, err)
			}
		}
	}
}

// TestCanTransition_ReVerifiedIsTerminal — re_verified 是终止态，无任何合法转移。
func TestCanTransition_ReVerifiedIsTerminal(t *testing.T) {
	terminal := StateReVerified
	for _, to := range []State{StateTrial, StateConfirmed, StateRemedied, StateDisputed} {
		if err := CanTransition(terminal, to); err == nil {
			t.Errorf("re_verified -> %s 应被拒绝（终止态），实际通过", to)
		}
	}
	if got := AllowedTransitions(terminal); len(got) != 0 {
		t.Errorf("re_verified 的 AllowedTransitions 应为空，实际 %v", got)
	}
}

// TestCanTransition_AllStatesInTable — 5 个 canonical 状态全部在 transitionTable 中注册。
// 防止后续加新状态时漏登记。
func TestCanTransition_AllStatesInTable(t *testing.T) {
	canonical := []State{
		StateTrial, StateConfirmed, StateRemedied, StateReVerified, StateDisputed,
	}
	for _, s := range canonical {
		if _, ok := transitionTable[s]; !ok {
			t.Errorf("状态 %s 未在 transitionTable 中注册", s)
		}
	}
}

// TestCanTransition_SameStateAlwaysIllegal — 5 个同状态转移全部拒绝（trial→trial, ...）。
// 防止"noop 转移被静默接受"。
func TestCanTransition_SameStateAlwaysIllegal(t *testing.T) {
	all := []State{
		StateTrial, StateConfirmed, StateRemedied, StateReVerified, StateDisputed,
	}
	for _, s := range all {
		err := CanTransition(s, s)
		if err == nil {
			t.Errorf("同状态转移 %s -> %s 应被拒绝，实际通过", s, s)
		} else if !IsInvalidTransition(err) {
			t.Errorf("同状态转移错误类型应为 ErrInvalidTransition，got %T", err)
		}
	}
}

// TestCanTransition_UnknownFromState — 未在 transitionTable 注册的 from 状态拒绝。
func TestCanTransition_UnknownFromState(t *testing.T) {
	cases := []State{"", "unknown", "ghost", "REJECTED", "archived"}
	for _, from := range cases {
		err := CanTransition(from, StateTrial)
		if err == nil {
			t.Errorf("未知 from=%q 应被拒绝", from)
		} else if !IsInvalidTransition(err) {
			t.Errorf("未知 from 错误类型应为 ErrInvalidTransition，got %T", err)
		}
	}
}

// TestCanTransition_BackEdgesRejected — 所有 back-edge（向 trial/早期状态回退）拒绝。
// 防止审计链被改写。
func TestCanTransition_BackEdgesRejected(t *testing.T) {
	// 期望被拒的 back-edge：
	//   confirmed → trial（最严重 — 信息科撤销确认）
	//   remedied → trial
	//   remedied → confirmed（厂商又变更？）
	//   re_verified → trial
	//   disputed → trial
	backEdges := []struct {
		from, to State
	}{
		{StateConfirmed, StateTrial},
		{StateRemedied, StateTrial},
		{StateRemedied, StateConfirmed},
		{StateReVerified, StateTrial},
		{StateDisputed, StateTrial},
	}
	for _, e := range backEdges {
		if err := CanTransition(e.from, e.to); err == nil {
			t.Errorf("back-edge %s -> %s 应被拒绝，实际通过", e.from, e.to)
		}
	}
}

// TestValidState_AllCanonical — 5 个 canonical 状态字符串全部被接受。
func TestValidState_AllCanonical(t *testing.T) {
	canonical := []string{"trial", "confirmed", "remedied", "re_verified", "disputed"}
	for _, s := range canonical {
		if !ValidState(s) {
			t.Errorf("ValidState(%q) 应为 true", s)
		}
	}
}

// TestValidState_RejectsGibberish — 各种乱串都不被接受。
func TestValidState_RejectsGibberish(t *testing.T) {
	gibberish := []string{
		"", "TRIAL", "Trial", "trials", "REJECTED", "ok",
		" trial", "trial ", "trial\n", "tr1al", "trial;",
	}
	for _, s := range gibberish {
		if ValidState(s) {
			t.Errorf("ValidState(%q) 应为 false", s)
		}
	}
}

// TestAllowedTransitions_ReturnsAllAndOnlyAllowed — AllowedTransitions 返回的每个 to
// 都通过 CanTransition 校验；且不漏不多。
func TestAllowedTransitions_ReturnsAllAndOnlyAllowed(t *testing.T) {
	for from, allowed := range transitionTable {
		got := AllowedTransitions(from)
		if len(got) != len(allowed) {
			t.Errorf("%s AllowedTransitions 长度=%d, want %d", from, len(got), len(allowed))
			continue
		}
		for _, to := range got {
			if !allowed[to] {
				t.Errorf("%s AllowedTransitions 含非法目标 %s", from, to)
			}
			if err := CanTransition(from, to); err != nil {
				t.Errorf("%s AllowedTransitions 含 CanTransition 拒绝的 %s: %v", from, to, err)
			}
		}
		// 反向：transitionTable 中的每个 allowed 必须出现在 AllowedTransitions 返回中。
		seen := map[State]bool{}
		for _, s := range got {
			seen[s] = true
		}
		for to := range allowed {
			if !seen[to] {
				t.Errorf("%s transitionTable 含 %s 但 AllowedTransitions 未返回", from, to)
			}
		}
	}
}
