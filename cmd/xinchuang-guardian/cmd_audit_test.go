// cmd_audit_test.go — `audit verify-chain` 子命令的 CLI 级集成测试。
//
// 覆盖：
//   - 缺 --file → cobra flag parse error（exit 4 = exitSubcommandFailed）；
//   - 合法链 → exit 0 + stdout JSON {"status":"ok",...}；
//   - 篡改链 → exit 1 + stderr JSON {"status":"broken","reason":"self_hash_mismatch",...}；
//   - 删除行 → exit 1 + reason="chain_break"；
//   - 插入伪造行（prev=""）→ exit 1 + reason="bad_insert"；
//   - 插入伪造行（prev=垃圾）→ exit 1 + reason="chain_break"；
//   - 文件不存在 → exit 0 + stdout {"status":"empty_chain",...}。
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"xinchuang-db-guardian/internal/output"
)

const auditTestBinary = "xinchuang-db-guardian-audit-test"

// buildBinary — 用 go build 把当前 cmd 包编到 t.TempDir()/binary。
func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, auditTestBinary)
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return binPath
}

// writeTempAuditFile — 用 output.AppendJSONL 落 N 行临时 audit.jsonl，返回路径。
func writeTempAuditFile(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	for i := 0; i < n; i++ {
		row := output.AuditRow{
			TsUTC:              "2026-10-10T05:00:00." + strings.Repeat("0", 9-len("00"+itoa3(i))) + itoa3(i) + "Z",
			EventID:            "evt-test-" + itoa3(i),
			ContractID:         "c-test",
			SystemID:           "sys-test",
			Vendor:             "dm8",
			Declared:           "v8.1",
			Actual:             "DM Database Server V8.1.0",
			Verdict:            "trial",
			Confidence:         0.95,
			EvidenceSHA256:     "sha-" + itoa3(i),
			Kind:               "drift",
		}
		if _, err := output.AppendJSONL(path, row); err != nil {
			t.Fatalf("AppendJSONL row %d: %v", i, err)
		}
	}
	return path
}

// itoa3 — 0..999 转 1..3 位字符串（避免引入 strconv 噪声）。
func itoa3(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	if i < 100 {
		return string(rune('0'+i/10)) + string(rune('0'+i%10))
	}
	return string(rune('0'+i/100)) + string(rune('0'+(i/10)%10)) + string(rune('0'+i%10))
}

// runCmd — 运行二进制并返回 stdout / stderr / exit code。
func runCmd(t *testing.T, bin string, args ...string) (string, string, int) {
	t.Helper()
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

// TestAuditVerifyChain_OK — 合法 3 行链 → exit 0 + status=ok + rows=3。
func TestAuditVerifyChain_OK(t *testing.T) {
	bin := buildBinary(t)
	path := writeTempAuditFile(t, 3)
	stdout, stderr, code := runCmd(t, bin, "audit", "verify-chain", "--file", path)
	if code != 0 {
		t.Fatalf("exit code=%d, want 0\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &resp); err != nil {
		t.Fatalf("unmarshal stdout: %v\n%s", err, stdout)
	}
	if resp["status"] != "ok" {
		t.Errorf("status=%v, want ok", resp["status"])
	}
	if rows, ok := resp["rows"].(float64); !ok || rows != 3 {
		t.Errorf("rows=%v, want 3", resp["rows"])
	}
	if resp["file"] != path {
		t.Errorf("file=%v, want %s", resp["file"], path)
	}
}

// TestAuditVerifyChain_TamperBadChain — 篡改 line 2 → exit 1 + status=broken + reason=self_hash_mismatch。
func TestAuditVerifyChain_TamperBadChain(t *testing.T) {
	bin := buildBinary(t)
	path := writeTempAuditFile(t, 3)
	// 篡改：直接覆盖文件 line 2。
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	var row map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &row); err != nil {
		t.Fatalf("unmarshal line 2: %v", err)
	}
	row["verdict"] = "mismatch"
	tampered, _ := json.Marshal(row)
	lines[1] = string(tampered)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	stdout, stderr, code := runCmd(t, bin, "audit", "verify-chain", "--file", path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout=%s\nstderr=%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "self_hash_mismatch") {
		t.Errorf("stderr missing reason 'self_hash_mismatch': %s", stderr)
	}
	if !strings.Contains(stderr, "line 2") {
		t.Errorf("stderr missing 'line 2': %s", stderr)
	}
}

// TestAuditVerifyChain_NonExistent — 文件不存在 → exit 0 + status=empty_chain。
func TestAuditVerifyChain_NonExistent(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "nope.jsonl")
	stdout, stderr, code := runCmd(t, bin, "audit", "verify-chain", "--file", path)
	if code != 0 {
		t.Fatalf("exit code=%d, want 0\nstderr=%s", code, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, stdout)
	}
	if resp["status"] != "empty_chain" {
		t.Errorf("status=%v, want empty_chain", resp["status"])
	}
}

// TestAuditVerifyChain_MissingFileFlag — 缺 --file → cobra 报 "required flag(s) missing" + exit 非零。
//
// 主入口 main.go 把 cobra 错误通过 logger.Error 写到 stdout（slog JSON），
// 所以测试在 stdout 与 stderr 合并字符串里检查 "required" 与 "file" 关键字。
func TestAuditVerifyChain_MissingFileFlag(t *testing.T) {
	bin := buildBinary(t)
	stdout, stderr, code := runCmd(t, bin, "audit", "verify-chain")
	if code == 0 {
		t.Fatalf("expected non-zero exit on missing --file, got 0\nstdout=%s\nstderr=%s", stdout, stderr)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "required") && !strings.Contains(combined, "file") {
		t.Errorf("output missing 'required' or 'file' hint:\nstdout=%s\nstderr=%s", stdout, stderr)
	}
}

// TestAuditVerifyChain_TamperDeleteLine — 删除 line 2 → exit 1 + reason="chain_break"。
func TestAuditVerifyChain_TamperDeleteLine(t *testing.T) {
	bin := buildBinary(t)
	path := writeTempAuditFile(t, 3)

	// 读原文件，丢弃 line 2，保留 line 1 + line 3 + 末尾空行。
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	// 删除中间行：保留 [line1, line3, trailing-newline-marker]。
	newContent := lines[0] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	stdout, stderr, code := runCmd(t, bin, "audit", "verify-chain", "--file", path)
	if code == 0 {
		t.Fatalf("expected non-zero exit after deleting line 2, got 0\nstdout=%s\nstderr=%s", stdout, stderr)
	}
	combined := stderr
	if !strings.Contains(combined, "chain_break") {
		t.Errorf("stderr missing 'chain_break': %s", combined)
	}
	if !strings.Contains(combined, "audit: line 2") {
		t.Errorf("stderr missing 'audit: line 2' marker: %s", combined)
	}
}

// TestAuditVerifyChain_TamperInsertLine_BadInsert — 在 line 2 后插入伪造行 Lx（prev=""）→
//
//	exit 1 + reason="bad_insert"。
func TestAuditVerifyChain_TamperInsertLine_BadInsert(t *testing.T) {
	bin := buildBinary(t)
	path := writeTempAuditFile(t, 3)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	// 构造伪造行：PrevEvidenceSHA256=""（自发链头）+ self_hash="deadbeef"。
	fake := output.AuditRow{
		TsUTC:              "2026-10-10T05:00:00.005Z",
		EventID:            "evt-fake-cli",
		ContractID:         "c-fake",
		SystemID:           "fake-sys",
		Vendor:             "fake-vendor",
		Declared:           "v9.9",
		Actual:             "fake",
		Verdict:            "trial",
		Confidence:         0.5,
		EvidenceSHA256:     "fake-sha",
		PrevEvidenceSHA256: "", // 关键：prev 为空 → bad_insert
		Kind:               "drift",
		SelfHash:           "deadbeef",
	}
	fakeBytes, _ := json.Marshal(fake)
	newLines := []string{lines[0], lines[1], string(fakeBytes), lines[2], lines[3]}
	if err := os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	stdout, stderr, code := runCmd(t, bin, "audit", "verify-chain", "--file", path)
	if code == 0 {
		t.Fatalf("expected non-zero exit on bad_insert, got 0\nstdout=%s\nstderr=%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "bad_insert") {
		t.Errorf("stderr missing 'bad_insert': %s", stderr)
	}
	if !strings.Contains(stderr, "audit: line 3") {
		t.Errorf("stderr missing 'audit: line 3' marker: %s", stderr)
	}
	// 同时验证 stderr JSON 含 reason="bad_insert"
	var resp map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(strings.Split(stderr, "\n")[0])), &resp); err == nil {
		if resp["reason"] != "bad_insert" {
			t.Errorf("JSON resp.reason=%v, want bad_insert", resp["reason"])
		}
		if lineNo, ok := resp["line"].(float64); !ok || lineNo != 3 {
			t.Errorf("JSON resp.line=%v, want 3", resp["line"])
		}
	}
}

// TestAuditVerifyChain_TamperInsertLine_ChainBreak — 插入伪造行（prev=乱填垃圾）→
//
//	exit 1 + reason="chain_break"（退化路径）。
func TestAuditVerifyChain_TamperInsertLine_ChainBreak(t *testing.T) {
	bin := buildBinary(t)
	path := writeTempAuditFile(t, 3)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	fake := output.AuditRow{
		TsUTC:              "2026-10-10T05:00:00.005Z",
		EventID:            "evt-fake-cli",
		ContractID:         "c-fake",
		SystemID:           "fake-sys",
		Vendor:             "fake-vendor",
		Declared:           "v9.9",
		Actual:             "fake",
		Verdict:            "trial",
		Confidence:         0.5,
		EvidenceSHA256:     "fake-sha",
		PrevEvidenceSHA256: "garbage-junk-not-real-prev",
		Kind:               "drift",
		SelfHash:           "deadbeef",
	}
	fakeBytes, _ := json.Marshal(fake)
	newLines := []string{lines[0], lines[1], string(fakeBytes), lines[2], lines[3]}
	if err := os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	stdout, stderr, code := runCmd(t, bin, "audit", "verify-chain", "--file", path)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout=%s\nstderr=%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "chain_break") {
		t.Errorf("stderr missing 'chain_break': %s", stderr)
	}
	if !strings.Contains(stderr, "audit: line 3") {
		t.Errorf("stderr missing 'audit: line 3' marker: %s", stderr)
	}
}

// TestAuditHelpText — root help 含 audit 子命令路径。
func TestAuditHelpText(t *testing.T) {
	bin := buildBinary(t)
	// audit parent help 应列出 verify-chain 子命令；
	// --file flag 在 verify-chain 子命令的 help 中（不在 audit parent 上）。
	parentHelp, _, _ := runCmd(t, bin, "audit", "--help")
	if !strings.Contains(parentHelp, "verify-chain") {
		t.Errorf("audit --help missing 'verify-chain': %s", parentHelp)
	}

	childHelp, _, _ := runCmd(t, bin, "audit", "verify-chain", "--help")
	if !strings.Contains(childHelp, "--file") {
		t.Errorf("audit verify-chain --help missing '--file': %s", childHelp)
	}
	if !strings.Contains(childHelp, "audit.jsonl") {
		t.Errorf("audit verify-chain --help missing 'audit.jsonl' description: %s", childHelp)
	}
}

// avoid unused-import warnings if a test is removed in future.
var _ = io.EOF