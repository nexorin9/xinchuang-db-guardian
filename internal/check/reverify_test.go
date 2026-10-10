package check

import (
	"strings"
	"testing"
)

// TestAutoReverify_RemediedToOK_NewSHA — 主路径：remedied 状态 + 下次扫描
// verdict=ok + evidence_sha 变化 → 触发 re-verified。
//
// 这是状态机里**唯一一条自动推进路径**：驱动 jar 换新版本 / JDBC URL 调整 /
// port_raw 文案变化任一维度变化，evidence_sha 都不同；守护自动闭环。
func TestAutoReverify_RemediedToOK_NewSHA(t *testing.T) {
	const lastRemediatedSHA = "sha_old_aaa111"
	const currentEvidenceSHA = "sha_new_bbb222"

	res := AutoReverify(lastRemediatedSHA, currentEvidenceSHA, VerdictOK)

	if !res.Fired {
		t.Fatalf("期望 fired=true (remedied → re_verified 自动触发)，实际 fired=false, reason=%q", res.Reason)
	}
	if res.NewState != StateReVerified {
		t.Errorf("期望 NewState=StateReVerified，实际 %q", res.NewState)
	}
	if res.Reason != reverifyFiredReason {
		t.Errorf("期望 Reason=%q，实际 %q", reverifyFiredReason, res.Reason)
	}

	// 状态机仍走 CanTransition 锁（remedied → re_verified 合法）。
	if err := CanTransition(StateRemedied, res.NewState); err != nil {
		t.Errorf("CanTransition(remedied → re_verified) 应合法，实际: %v", err)
	}
}

// TestAutoReverify_RemediedToOK_SameSHA — 不触发：驱动未变化。
//
// 当某次 Compare verdict=ok 但 evidence_sha 与上次 remedied 完全一致时，
// 不应重复推进 re-verified 状态（避免 audit 行噪声 + 告警风暴）。
func TestAutoReverify_RemediedToOK_SameSHA(t *testing.T) {
	const sameSHA = "sha_stable_ccc333"

	res := AutoReverify(sameSHA, sameSHA, VerdictOK)

	if res.Fired {
		t.Fatalf("期望 fired=false (evidence_sha 一致不触发)，实际 fired=true")
	}
	if res.NewState != StateRemedied {
		t.Errorf("期望 NewState=StateRemedied (不推进)，实际 %q", res.NewState)
	}
	if res.Reason != reverifyNotFiredSameSHA {
		t.Errorf("期望 Reason=%q，实际 %q", reverifyNotFiredSameSHA, res.Reason)
	}
}

// TestAutoReverify_TrialVerdict — 不触发：trial 信号优先。
//
// 当前 verdict=trial 时不应触发 re-verified（trial 是"待人工处置"信号，
// 与 re-verified 是两个独立的状态语义）。
func TestAutoReverify_TrialVerdict(t *testing.T) {
	res := AutoReverify("sha_last_ddd444", "sha_current_eee555", VerdictTrial)

	if res.Fired {
		t.Fatalf("期望 fired=false (verdict=trial 不触发 re-verified)，实际 fired=true")
	}
	if res.NewState != StateTrial {
		t.Errorf("期望 NewState=StateTrial，实际 %q", res.NewState)
	}
	if res.Reason != reverifyNotFiredTrialVerdict {
		t.Errorf("期望 Reason=%q，实际 %q", reverifyNotFiredTrialVerdict, res.Reason)
	}
}

// TestAutoReverify_NoPreviousRemediated — 不触发：没有先前 remedied 状态。
//
// 仅当存在 StateRemedied 历史时才能"从 remedied 推进到 re_verified"；
// 若 lastRemediatedSHA 为空（首次扫描 / 仅 trial 历史 / 状态机从未进 remedied）
// 不应触发 re-verified。
func TestAutoReverify_NoPreviousRemediated(t *testing.T) {
	res := AutoReverify("", "sha_current_fff666", VerdictOK)

	if res.Fired {
		t.Fatalf("期望 fired=false (无先前 remedied)，实际 fired=true")
	}
	if res.NewState != StateTrial {
		t.Errorf("期望 NewState=StateTrial，实际 %q", res.NewState)
	}
	// 空输入路径在防御性分支命中 → empty_inputs_defensive_skip。
	if res.Reason != reverifyNotFiredEmptyInputs {
		t.Errorf("期望 Reason=%q，实际 %q", reverifyNotFiredEmptyInputs, res.Reason)
	}
}

// TestAutoReverify_DefensiveEmptyCurrent — 不触发：currentEvidenceSHA 为空。
//
// 防御性：Compare 异常路径可能产生空 hash；AutoReverify 不应把损坏证据
// 推上 re-verified 链。
func TestAutoReverify_DefensiveEmptyCurrent(t *testing.T) {
	res := AutoReverify("sha_last_ggg777", "", VerdictOK)

	if res.Fired {
		t.Fatalf("期望 fired=false (currentEvidenceSHA 空)，实际 fired=true")
	}
	if res.NewState != StateTrial {
		t.Errorf("期望 NewState=StateTrial，实际 %q", res.NewState)
	}
	if res.Reason != reverifyNotFiredEmptyInputs {
		t.Errorf("期望 Reason=%q，实际 %q", reverifyNotFiredEmptyInputs, res.Reason)
	}
}

// TestAutoReverify_DefensiveBothEmpty — 不触发：两个 SHA 都为空。
func TestAutoReverify_DefensiveBothEmpty(t *testing.T) {
	res := AutoReverify("", "", VerdictOK)

	if res.Fired {
		t.Fatalf("期望 fired=false (两个 SHA 都空)，实际 fired=true")
	}
	if res.Reason != reverifyNotFiredEmptyInputs {
		t.Errorf("期望 Reason=%q，实际 %q", reverifyNotFiredEmptyInputs, res.Reason)
	}
}

// TestAutoReverify_TrialVerdictWithEmptyInputs — 不触发：trial + 空输入组合。
//
// 即使 verdict=trial，防御性空检查仍生效；reason 优先返回 trial 分支。
// （注：当前实现先做空检查后做 verdict 检查；若交换顺序 reason 会变。
//  本测试锁定当前实现：空输入优先 defensive_skip，不区分 verdict）。
func TestAutoReverify_TrialVerdictWithEmptyInputs(t *testing.T) {
	res := AutoReverify("", "sha_current_hhh888", VerdictTrial)

	if res.Fired {
		t.Fatalf("期望 fired=false，实际 fired=true")
	}
	if res.Reason != reverifyNotFiredEmptyInputs {
		t.Errorf("空输入优先：期望 Reason=%q，实际 %q", reverifyNotFiredEmptyInputs, res.Reason)
	}
}

// TestShouldAutoReverify_BooleanConsistency — ShouldAutoReverify 与
// AutoReverify.Fired 在所有边界 case 上保持一致。
func TestShouldAutoReverify_BooleanConsistency(t *testing.T) {
	cases := []struct {
		name                  string
		lastRemediatedSHA     string
		currentEvidenceSHA    string
		currentVerdict        Verdict
		wantFired             bool
	}{
		{"remedied→ok_new_sha", "a", "b", VerdictOK, true},
		{"remedied→ok_same_sha", "a", "a", VerdictOK, false},
		{"trial信号优先", "a", "b", VerdictTrial, false},
		{"无先前remedied", "", "b", VerdictOK, false},
		{"currentSHA空", "a", "", VerdictOK, false},
		{"两SHA空", "", "", VerdictOK, false},
		{"trial+空last", "", "b", VerdictTrial, false},
		{"ok+空last+空current", "", "", VerdictOK, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ShouldAutoReverify(c.lastRemediatedSHA, c.currentEvidenceSHA, c.currentVerdict)
			if got != c.wantFired {
				t.Errorf("ShouldAutoReverify() = %v, want %v", got, c.wantFired)
			}
		})
	}
}

// TestAutoReverify_TableDriven_AllPaths — 表驱动覆盖所有 fire / no-fire 路径。
//
// 把 reverify 主路径 + 防御性 + 状态机锁一次性锁死。
func TestAutoReverify_TableDriven_AllPaths(t *testing.T) {
	type want struct {
		fired    bool
		newState State
		reason   string
	}
	cases := []struct {
		name               string
		lastRemediatedSHA  string
		currentEvidenceSHA string
		verdict            Verdict
		want               want
	}{
		{
			name:               "fire:remedied→ok_new_sha_含驱动换版",
			lastRemediatedSHA:  "sha_driverset_v1",
			currentEvidenceSHA: "sha_driverset_v2",
			verdict:            VerdictOK,
			want:               want{fired: true, newState: StateReVerified, reason: reverifyFiredReason},
		},
		{
			name:               "fire:remedied→ok_jdbc_url变更",
			lastRemediatedSHA:  "sha_jdbc_old",
			currentEvidenceSHA: "sha_jdbc_new_port_changed",
			verdict:            VerdictOK,
			want:               want{fired: true, newState: StateReVerified, reason: reverifyFiredReason},
		},
		{
			name:               "no_fire:remedied→ok_same_sha驱动未变",
			lastRemediatedSHA:  "sha_same",
			currentEvidenceSHA: "sha_same",
			verdict:            VerdictOK,
			want:               want{fired: false, newState: StateRemedied, reason: reverifyNotFiredSameSHA},
		},
		{
			name:               "no_fire:trial信号",
			lastRemediatedSHA:  "sha_x",
			currentEvidenceSHA: "sha_y",
			verdict:            VerdictTrial,
			want:               want{fired: false, newState: StateTrial, reason: reverifyNotFiredTrialVerdict},
		},
		{
			name:               "no_fire:无先前remedied",
			lastRemediatedSHA:  "",
			currentEvidenceSHA: "sha_z",
			verdict:            VerdictOK,
			want:               want{fired: false, newState: StateTrial, reason: reverifyNotFiredEmptyInputs},
		},
		{
			name:               "no_fire:currentSHA空防御",
			lastRemediatedSHA:  "sha_w",
			currentEvidenceSHA: "",
			verdict:            VerdictOK,
			want:               want{fired: false, newState: StateTrial, reason: reverifyNotFiredEmptyInputs},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := AutoReverify(c.lastRemediatedSHA, c.currentEvidenceSHA, c.verdict)
			if res.Fired != c.want.fired {
				t.Errorf("Fired = %v, want %v", res.Fired, c.want.fired)
			}
			if res.NewState != c.want.newState {
				t.Errorf("NewState = %q, want %q", res.NewState, c.want.newState)
			}
			if res.Reason != c.want.reason {
				t.Errorf("Reason = %q, want %q", res.Reason, c.want.reason)
			}
			// 锁定 fired=true 必走 CanTransition 合法路径。
			if res.Fired {
				if err := CanTransition(StateRemedied, res.NewState); err != nil {
					t.Errorf("fired=true 时 CanTransition(remedied, %s) 应合法，实际: %v", res.NewState, err)
				}
			}
		})
	}
}

// TestAutoReverify_DoesNotMutateState — 纯函数不变量：AutoReverify 不修改
// 输入参数；多次调用结果一致。
func TestAutoReverify_DoesNotMutateState(t *testing.T) {
	const lastSHA = "sha_x"
	const curSHA = "sha_y"

	r1 := AutoReverify(lastSHA, curSHA, VerdictOK)
	r2 := AutoReverify(lastSHA, curSHA, VerdictOK)
	r3 := AutoReverify(curSHA, lastSHA, VerdictOK) // 反向：仍因 x≠y 触发

	if r1 != r2 {
		t.Errorf("相同输入两次调用结果不同：r1=%+v r2=%+v", r1, r2)
	}
	// 反向调用：curSHA="x" → lastSHA="y" 仍 fired=true（因为 y != x 是变化）。
	if !r3.Fired {
		t.Errorf("反向调用 curSHA=x, lastSHA=y 仍应 fired=true（x≠y），实际 fired=false")
	}
	if r3.Reason != reverifyFiredReason {
		t.Errorf("反向调用期望 Reason=%q，实际 %q", reverifyFiredReason, r3.Reason)
	}

	// 锁定：相同 SHA 调用 → not fired (与方向无关)。
	r4 := AutoReverify(curSHA, curSHA, VerdictOK)
	if r4.Fired {
		t.Errorf("相同 SHA 调用应 not fired，实际 fired=true")
	}
}

// TestAutoReverify_LongSHADoesNotPanic — 边界：超长 SHA / Unicode SHA 不 panic。
func TestAutoReverify_LongSHADoesNotPanic(t *testing.T) {
	longSHA1 := strings.Repeat("a", 4096)
	longSHA2 := strings.Repeat("b", 4096)
	res := AutoReverify(longSHA1, longSHA2, VerdictOK)
	if !res.Fired {
		t.Errorf("长 SHA 触发失败：reason=%q", res.Reason)
	}
	if res.NewState != StateReVerified {
		t.Errorf("长 SHA 期望 StateReVerified，实际 %q", res.NewState)
	}

	// 相同长 SHA → not fired。
	res2 := AutoReverify(longSHA1, longSHA1, VerdictOK)
	if res2.Fired {
		t.Errorf("相同长 SHA 不应触发")
	}
}

// TestAutoReverify_ReasonConstantsStable — 锁定 reason 常量字符串不变；
// 审计行 / log / evidence.zip 内的 reason 字段依赖此稳定性。
func TestAutoReverify_ReasonConstantsStable(t *testing.T) {
	want := map[string]string{
		"fired":             reverifyFiredReason,
		"empty_inputs":      reverifyNotFiredEmptyInputs,
		"trial_verdict":     reverifyNotFiredTrialVerdict,
		"same_sha":          reverifyNotFiredSameSHA,
		"no_previous_remed": reverifyNotFiredNoLastRemedied,
	}
	for k, v := range want {
		if v == "" {
			t.Errorf("reason 常量 %s 为空", k)
		}
	}
	// 锁定 fired_reason 必含 re_verified 字样（运维 grep 友好）。
	if !strings.Contains(reverifyFiredReason, "re_verified") {
		t.Errorf("reverifyFiredReason=%q 应包含 're_verified' 字样", reverifyFiredReason)
	}
}
