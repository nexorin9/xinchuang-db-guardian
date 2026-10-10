// cmd_confirm_test.go — `confirm-drift` 子命令的 CLI 级集成测试。
//
// 覆盖（与 spec.md §4 验收故事对照）：
//   - 缺 --action → cobra flag parse error（exit 4 = exitSubcommandFailed）；
//   - 缺 --operator → cobra flag parse error（exit 4）；
//   - 不存在的 event_id → exit 1 + stderr JSON {"status":"trial_not_found"}；
//   - trial → confirmed 合法路径 → exit 0 + stdout JSON + audit.jsonl +1 行（kind=drift_confirmed）；
//   - trial → remedied 合法路径 → exit 0 + audit.jsonl +1 行（kind=drift_remedied）；
//   - trial → disputed 合法路径 → exit 0 + audit.jsonl +1 行（kind=drift_disputed）；
//   - 非法 action 值 → exit 1 + stderr JSON {"status":"invalid_action"}；
//   - trial → re_verified 非法转移（直接拒绝）→ exit 1 + stderr JSON {"status":"invalid_transition"} + audit.jsonl +1 行（kind=invalid_transition）；
//   - 链验：所有 confirm-drift 后 audit verify-chain exit 0。
//
// 测试替身：dockertest 不可用时用 bbolt 本地 tmpdir；trial store 用同包 OpenTrialStore。
package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xinchuang-db-guardian/internal/check"
	"xinchuang-db-guardian/internal/output"
)

const confirmTestBinary = "xinchuang-guardian-confirm-test"

// buildConfirmBinary — 用 go build 把当前 cmd 包编到 t.TempDir()/binary。
func buildConfirmBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, confirmTestBinary)
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return binPath
}

// seedTrialStore — 写一条 trial 记录到 t.TempDir()/trial.db，返回 event_id + db_path + audit_path。
//
// bbolt 默认会 flock 同一文件 5s 超时；为避免 parent process 与 subprocess 互相争抢，
// seed 完成后立即 Close 释放锁（不是 defer / t.Cleanup）。
func seedTrialStore(t *testing.T, eventID string, state check.State) (dbPath, auditPath string) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "trial.db")
	auditPath = filepath.Join(dir, "audit.jsonl")
	store, err := output.OpenTrialStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	ts := time.Now().UTC()
	ev := check.DriftEvidence{
		EventID:            eventID,
		ContractID:         "c-test",
		SystemID:           "his-core",
		Vendor:             "dm8",
		Declared:           "v8.1",
		Actual:             "DM Database Server V8.1.0",
		PortRaw:            "DM Database Server V8.1.0",
		DriverSha:          "deadbeef",
		JDBCURL:            "jdbc:dm://10.0.0.1:5236/DB",
		Verdict:            check.VerdictTrial,
		Confidence:         0.95,
		EvidenceSHA256:     "evidence-" + eventID,
		Status:             state,
		PrevEvidenceSHA256: "",
		SelfHash:           "",
		TsUTC:              ts.Format(time.RFC3339Nano),
	}
	// 初始化 SelfHash。
	ev = output.MakeDriftEvidence(ev, "")
	if err := store.SaveTrial(ev); err != nil {
		_ = store.Close()
		t.Fatalf("save: %v", err)
	}
	// 立即关闭，释放 bbolt flock；让 subprocess OpenTrialStore 不阻塞。
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}
	return dbPath, auditPath
}

// runConfirm — 调 binary confirm-drift <event_id> --action X --operator Y --db P --file A。
// 返回 stdout / stderr / exit code。
func runConfirm(t *testing.T, bin, eventID, action, operator, dbPath, auditPath string) (string, string, int) {
	t.Helper()
	args := []string{"confirm-drift", eventID}
	if action != "" {
		args = append(args, "--action", action)
	}
	if operator != "" {
		args = append(args, "--operator", operator)
	}
	if dbPath != "" {
		args = append(args, "--db", dbPath)
	}
	if auditPath != "" {
		args = append(args, "--file", auditPath)
	}
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if ee, ok := err.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("exec error: %v", err)
	}
	return stdout.String(), stderr.String(), exitCode
}

// lastJSONLine — 从 stdout 中取最后一行 JSON（slog JSON 日志行先输出，response JSON 在末尾）。
func lastJSONLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			return line
		}
	}
	return strings.TrimSpace(s)
}

// TestConfirmDrift_MissingActionFlag — 缺 --action → cobra required flag parse error → exit 4。
func TestConfirmDrift_MissingActionFlag(t *testing.T) {
	bin := buildConfirmBinary(t)
	dbPath, auditPath := seedTrialStore(t, "evt-001", check.StateTrial)
	_, _, code := runConfirm(t, bin, "evt-001", "", "张主任", dbPath, auditPath)
	if code != 4 {
		t.Fatalf("missing --action: exit code=%d, want 4 (exitSubcommandFailed)", code)
	}
}

// TestConfirmDrift_MissingOperatorFlag — 缺 --operator → cobra required flag parse error → exit 4。
func TestConfirmDrift_MissingOperatorFlag(t *testing.T) {
	bin := buildConfirmBinary(t)
	dbPath, auditPath := seedTrialStore(t, "evt-001", check.StateTrial)
	_, _, code := runConfirm(t, bin, "evt-001", "confirmed", "", dbPath, auditPath)
	if code != 4 {
		t.Fatalf("missing --operator: exit code=%d, want 4 (exitSubcommandFailed)", code)
	}
}

// TestConfirmDrift_TrialNotFound — 不存在的 event_id → exit 1 + stderr trial_not_found。
func TestConfirmDrift_TrialNotFound(t *testing.T) {
	bin := buildConfirmBinary(t)
	dbPath, auditPath := seedTrialStore(t, "evt-real", check.StateTrial)
	stdout, stderr, code := runConfirm(t, bin, "evt-ghost", "confirmed", "张主任", dbPath, auditPath)
	if code != 1 {
		t.Fatalf("not found: exit code=%d, want 1\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &resp); err != nil {
		t.Fatalf("stderr JSON parse: %v\nstderr=%s", err, stderr)
	}
	if resp["status"] != "trial_not_found" {
		t.Fatalf("status=%v, want trial_not_found", resp["status"])
	}
	if resp["event_id"] != "evt-ghost" {
		t.Fatalf("event_id=%v, want evt-ghost", resp["event_id"])
	}
}

// TestConfirmDrift_TrialToConfirmed — 合法 trial → confirmed 路径。
func TestConfirmDrift_TrialToConfirmed(t *testing.T) {
	bin := buildConfirmBinary(t)
	dbPath, auditPath := seedTrialStore(t, "evt-001", check.StateTrial)
	stdout, stderr, code := runConfirm(t, bin, "evt-001", "confirmed", "张主任", dbPath, auditPath)
	if code != 0 {
		t.Fatalf("trial→confirmed: exit code=%d, want 0\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(lastJSONLine(stdout)), &resp); err != nil {
		t.Fatalf("stdout JSON parse: %v\nstdout=%s", err, stdout)
	}
	if resp["status"] != "ok" {
		t.Fatalf("status=%v, want ok", resp["status"])
	}
	if resp["event_id"] != "evt-001" {
		t.Fatalf("event_id=%v, want evt-001", resp["event_id"])
	}
	if resp["from_state"] != "trial" {
		t.Fatalf("from_state=%v, want trial", resp["from_state"])
	}
	if resp["to_state"] != "confirmed" {
		t.Fatalf("to_state=%v, want confirmed", resp["to_state"])
	}
	if resp["operator"] != "张主任" {
		t.Fatalf("operator=%v, want 张主任", resp["operator"])
	}
	if resp["kind"] != "drift_confirmed" {
		t.Fatalf("kind=%v, want drift_confirmed", resp["kind"])
	}

	// audit.jsonl 必须有 1 行。
	rows, err := output.LoadChain(auditPath)
	if err != nil {
		t.Fatalf("LoadChain: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows=%d, want 1", len(rows))
	}
	if rows[0].Kind != "drift_confirmed" {
		t.Fatalf("audit row Kind=%v, want drift_confirmed", rows[0].Kind)
	}
	if rows[0].Action != "confirmed" {
		t.Fatalf("audit row Action=%v, want confirmed", rows[0].Action)
	}
	if rows[0].Operator != "张主任" {
		t.Fatalf("audit row Operator=%v, want 张主任", rows[0].Operator)
	}
	if rows[0].EventID != "evt-001" {
		t.Fatalf("audit row EventID=%v, want evt-001", rows[0].EventID)
	}

	// 审计链校验：exit 0。
	if err := output.VerifyChain(auditPath); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	// store 推进状态确认：再次 LoadTrial 必须 State=confirmed。
	store, err := output.OpenTrialStore(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer store.Close()
	updated, err := store.LoadTrial("evt-001")
	if err != nil {
		t.Fatalf("load after promote: %v", err)
	}
	if updated.Status != check.StateConfirmed {
		t.Fatalf("store Status=%v, want confirmed", updated.Status)
	}
	if updated.PrevEvidenceSHA256 == "" {
		t.Fatalf("prev_evidence_sha256 should be non-empty after PromoteTrial")
	}
}

// TestConfirmDrift_TrialToRemedied — 合法 trial → remedied 路径。
func TestConfirmDrift_TrialToRemedied(t *testing.T) {
	bin := buildConfirmBinary(t)
	dbPath, auditPath := seedTrialStore(t, "evt-002", check.StateTrial)
	stdout, stderr, code := runConfirm(t, bin, "evt-002", "remedied", "李工程师", dbPath, auditPath)
	if code != 0 {
		t.Fatalf("trial→remedied: exit code=%d\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(lastJSONLine(stdout)), &resp); err != nil {
		t.Fatalf("stdout parse: %v", err)
	}
	if resp["kind"] != "drift_remedied" {
		t.Fatalf("kind=%v, want drift_remedied", resp["kind"])
	}
	if resp["to_state"] != "remedied" {
		t.Fatalf("to_state=%v, want remedied", resp["to_state"])
	}
	rows, _ := output.LoadChain(auditPath)
	if len(rows) != 1 || rows[0].Kind != "drift_remedied" {
		t.Fatalf("audit row mismatch: rows=%d first.Kind=%v", len(rows), rows[0].Kind)
	}
}

// TestConfirmDrift_TrialToDisputed — 合法 trial → disputed 路径。
func TestConfirmDrift_TrialToDisputed(t *testing.T) {
	bin := buildConfirmBinary(t)
	dbPath, auditPath := seedTrialStore(t, "evt-003", check.StateTrial)
	stdout, stderr, code := runConfirm(t, bin, "evt-003", "disputed", "王主任", dbPath, auditPath)
	if code != 0 {
		t.Fatalf("trial→disputed: exit code=%d\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(lastJSONLine(stdout)), &resp); err != nil {
		t.Fatalf("stdout parse: %v", stdout)
	}
	if resp["kind"] != "drift_disputed" {
		t.Fatalf("kind=%v, want drift_disputed", resp["kind"])
	}
	rows, _ := output.LoadChain(auditPath)
	if len(rows) != 1 || rows[0].Kind != "drift_disputed" {
		t.Fatalf("audit row mismatch: rows=%d first.Kind=%v", len(rows), rows[0].Kind)
	}
}

// TestConfirmDrift_InvalidActionValue — action 取值非法 → exit 1 + invalid_action。
func TestConfirmDrift_InvalidActionValue(t *testing.T) {
	bin := buildConfirmBinary(t)
	dbPath, auditPath := seedTrialStore(t, "evt-004", check.StateTrial)
	stdout, stderr, code := runConfirm(t, bin, "evt-004", "re_verified", "张主任", dbPath, auditPath)
	// re_verified 字符串本身是合法 State（通过 ValidState），但 trial → re_verified 是非法转移，
	// 故走 invalid_transition 路径而非 invalid_action。
	if code != 1 {
		t.Fatalf("invalid action: exit code=%d, want 1\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &resp); err != nil {
		t.Fatalf("stderr parse: %v", err)
	}
	if resp["status"] != "invalid_transition" {
		t.Fatalf("status=%v, want invalid_transition", resp["status"])
	}
	if resp["from_state"] != "trial" {
		t.Fatalf("from_state=%v, want trial", resp["from_state"])
	}
	if resp["to_state"] != "re_verified" {
		t.Fatalf("to_state=%v, want re_verified", resp["to_state"])
	}

	// audit.jsonl 须有 1 行 kind=invalid_transition（state machine 拒绝事件可追溯）。
	rows, _ := output.LoadChain(auditPath)
	if len(rows) != 1 || rows[0].Kind != "invalid_transition" {
		t.Fatalf("audit row mismatch: rows=%d first.Kind=%v (want 1 invalid_transition)", len(rows), rows[0].Kind)
	}
	if rows[0].Operator != "张主任" {
		t.Fatalf("invalid_transition row Operator=%v, want 张主任", rows[0].Operator)
	}
}

// TestConfirmDrift_InvalidActionJunk — action 字符串不在合法 state 集合 → exit 1 + invalid_action。
func TestConfirmDrift_InvalidActionJunk(t *testing.T) {
	bin := buildConfirmBinary(t)
	dbPath, auditPath := seedTrialStore(t, "evt-005", check.StateTrial)
	stdout, stderr, code := runConfirm(t, bin, "evt-005", "junk_state", "张主任", dbPath, auditPath)
	if code != 1 {
		t.Fatalf("invalid action: exit code=%d, want 1\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &resp); err != nil {
		t.Fatalf("stderr parse: %v", err)
	}
	if resp["status"] != "invalid_action" {
		t.Fatalf("status=%v, want invalid_action", resp["status"])
	}
}

// TestConfirmDrift_BackEdgeRejected — confirmed → trial back-edge 非法转移 → exit 1 + invalid_transition。
func TestConfirmDrift_BackEdgeRejected(t *testing.T) {
	bin := buildConfirmBinary(t)
	dbPath, auditPath := seedTrialStore(t, "evt-006", check.StateConfirmed)
	_, stderr, code := runConfirm(t, bin, "evt-006", "trial", "张主任", dbPath, auditPath)
	// "trial" 本身是合法 State 但不在 ValidState 验证白名单之外...wait, ValidState("trial")=true,
	// 所以走 invalid_transition 路径而非 invalid_action（confirmed → trial 非法）。
	if code != 1 {
		t.Fatalf("back-edge: exit code=%d, want 1\nstderr=%s", code, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &resp); err != nil {
		t.Fatalf("stderr parse: %v", err)
	}
	if resp["status"] != "invalid_transition" {
		t.Fatalf("status=%v, want invalid_transition", resp["status"])
	}
	if resp["from_state"] != "confirmed" {
		t.Fatalf("from_state=%v, want confirmed", resp["from_state"])
	}
	if resp["to_state"] != "trial" {
		t.Fatalf("to_state=%v, want trial", resp["to_state"])
	}
	allowed, ok := resp["allowed"].([]any)
	if !ok || len(allowed) == 0 {
		t.Fatalf("allowed=%v, want non-empty array", resp["allowed"])
	}
}

// TestConfirmDrift_ThreeActionsAuditChain — 3 次 confirm-drift 形成完整审计链。
//
// 第 3 次故意选非法转移（confirmed → confirmed 同状态自循环）以触发 invalid_transition；
// 注：remedied → re_verified 是合法路径（由 T21 自动检测），故本测试不能用。
func TestConfirmDrift_ThreeActionsAuditChain(t *testing.T) {
	bin := buildConfirmBinary(t)
	dbPath, auditPath := seedTrialStore(t, "evt-chain", check.StateTrial)

	// 第 1 次：trial → confirmed。
	_, _, code := runConfirm(t, bin, "evt-chain", "confirmed", "张主任", dbPath, auditPath)
	if code != 0 {
		t.Fatalf("step 1: exit=%d", code)
	}
	// 第 2 次：confirmed → remedied（合法路径）。
	_, _, code = runConfirm(t, bin, "evt-chain", "remedied", "李工程师", dbPath, auditPath)
	if code != 0 {
		t.Fatalf("step 2: exit=%d", code)
	}
	// 第 3 次：confirmed 自循环非法（同状态自循环 → invalid_transition）。
	// 注意：store 现 state=remedied，所以无法直接再 confirm，我们用 seed 路径另起一个 confirmed 状态。
	// 改为更直接：尝试 remedied → confirmed，这是非法转移（remedied 只能 → re_verified）。
	_, stderr, code := runConfirm(t, bin, "evt-chain", "confirmed", "王主任", dbPath, auditPath)
	if code != 1 {
		t.Fatalf("step 3 (illegal remedied→confirmed): exit=%d, want 1\nstderr=%s", code, stderr)
	}

	// audit.jsonl 必须有 3 行（drift_confirmed + drift_remedied + invalid_transition）。
	rows, err := output.LoadChain(auditPath)
	if err != nil {
		t.Fatalf("LoadChain: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("audit rows=%d, want 3", len(rows))
	}
	expectedKinds := []string{"drift_confirmed", "drift_remedied", "invalid_transition"}
	for i, want := range expectedKinds {
		if rows[i].Kind != want {
			t.Fatalf("row[%d].Kind=%v, want %v", i, rows[i].Kind, want)
		}
	}

	// 审计链验：sha256 链完整。
	if err := output.VerifyChain(auditPath); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	// 链链接校验：第 2 行 prev_evidence_sha256 == 第 1 行 self_hash。
	if rows[1].PrevEvidenceSHA256 != rows[0].SelfHash {
		t.Fatalf("chain break: rows[1].prev=%v vs rows[0].self=%v", rows[1].PrevEvidenceSHA256, rows[0].SelfHash)
	}
	if rows[2].PrevEvidenceSHA256 != rows[1].SelfHash {
		t.Fatalf("chain break: rows[2].prev=%v vs rows[1].self=%v", rows[2].PrevEvidenceSHA256, rows[1].SelfHash)
	}

	// store 状态确认：仍 State=remedied（remedied→confirmed 被拒，未推进）。
	store, err := output.OpenTrialStore(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer store.Close()
	final, err := store.LoadTrial("evt-chain")
	if err != nil {
		t.Fatalf("load final: %v", err)
	}
	if final.Status != check.StateRemedied {
		t.Fatalf("final.Status=%v, want remedied (remedied→confirmed 被拒)", final.Status)
	}
}

// TestConfirmDrift_DisputedToConfirmed — disputed → confirmed 合法路径。
func TestConfirmDrift_DisputedToConfirmed(t *testing.T) {
	bin := buildConfirmBinary(t)
	dbPath, auditPath := seedTrialStore(t, "evt-007", check.StateDisputed)
	stdout, stderr, code := runConfirm(t, bin, "evt-007", "confirmed", "张主任", dbPath, auditPath)
	if code != 0 {
		t.Fatalf("disputed→confirmed: exit=%d\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(lastJSONLine(stdout)), &resp); err != nil {
		t.Fatalf("stdout parse: %v", stdout)
	}
	if resp["from_state"] != "disputed" {
		t.Fatalf("from_state=%v, want disputed", resp["from_state"])
	}
	if resp["to_state"] != "confirmed" {
		t.Fatalf("to_state=%v, want confirmed", resp["to_state"])
	}
}

// TestConfirmDrift_Help — --help 输出含 3 个 flag 与状态机说明。
func TestConfirmDrift_Help(t *testing.T) {
	bin := buildConfirmBinary(t)
	cmd := exec.Command(bin, "confirm-drift", "--help")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("--help exit error: %v", err)
	}
	help := stdout.String()
	for _, want := range []string{"--action", "--operator", "--file", "--db", "trial", "remedied", "disputed"} {
		if !strings.Contains(help, want) {
			t.Fatalf("--help missing %q\n%s", want, help)
		}
	}
}

// TestConfirmDrift_HelpRoot — root --help 含 confirm-drift 子命令。
func TestConfirmDrift_HelpRoot(t *testing.T) {
	bin := buildConfirmBinary(t)
	cmd := exec.Command(bin, "--help")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("root --help exit error: %v", err)
	}
	if !strings.Contains(stdout.String(), "confirm-drift") {
		t.Fatalf("root --help missing confirm-drift\n%s", stdout.String())
	}
}