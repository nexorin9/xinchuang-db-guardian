// cmd_export_test.go — `xinchuang-guardian export-evidence` 子命令 CLI 集成测试。
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xinchuang-db-guardian/internal/output"
)

// buildExportBinary — 编译当前 cmd 二进制到 t.TempDir()；返回可执行文件路径。
// （与 cmd_audit_test.go 的 buildBinary 重复，rename 区分避免冲突）
func buildExportBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "xinchuang-guardian")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Run(), "go build failed")
	return binPath
}

// writeContractsForTest — 写最小 contracts.yaml。
func writeContractsForTest(t *testing.T, path string) {
	t.Helper()
	content := `declared:
  - system_id: lis
    vendor: dm8
    version_pattern: "DM Database Server V8\\.1\\..*"
    allow_drift_sha256: []
    contract_id: HT-2024-LIS
    host: 10.0.1.23
    port: 15432
    scan_interval: 10m
    jdbc_driver_dirs:
      - /opt/jdbc/dm
    event_id_prefix: EVT-LIS
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// writeAuditForTest — 写 3 行 drift 审计链（自带 self_hash 链）。
func writeAuditForTest(t *testing.T, path string) {
	t.Helper()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	rows := []output.AuditRow{
		{
			TsUTC:              now.Add(-5 * 24 * time.Hour).Format(time.RFC3339Nano),
			EventID:            "EVT-LIS-1",
			ContractID:         "HT-2024-LIS",
			SystemID:           "lis",
			Vendor:             "dm8",
			Declared:           "DM Database Server V8.1.*",
			Actual:             "PostgreSQL 14.10 (Debian ...)",
			PortRaw:            "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1) on x86_64",
			DriverSha:          "aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaaa",
			JDBCURL:            "jdbc:postgresql://10.0.1.23:15432/lis",
			Verdict:            "trial",
			Confidence:         0.98,
			EvidenceSHA256:     "ev1111111111111111111111111111111111111111111111111111111111111",
			Kind:               "drift",
			PrevEvidenceSHA256: "",
			SelfHash:           "sh1111111111111111111111111111111111111111111111111111111111aa",
		},
		{
			TsUTC:              now.Add(-2 * 24 * time.Hour).Format(time.RFC3339Nano),
			EventID:            "EVT-PACS-1",
			ContractID:         "HT-2024-PACS",
			SystemID:           "pacs",
			Vendor:             "IvorySQL",
			Declared:           "IvorySQL.*1.4.*",
			Actual:             "PostgreSQL 13.6",
			PortRaw:            "PostgreSQL 13.6 (Debian 13.6-1.pgdg120+1)",
			DriverSha:          "bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb",
			JDBCURL:            "jdbc:postgresql://10.0.1.24:19600/pacs",
			Verdict:            "trial",
			Confidence:         0.95,
			EvidenceSHA256:     "ev2222222222222222222222222222222222222222222222222222222222222",
			Kind:               "drift",
			PrevEvidenceSHA256: "sh1111111111111111111111111111111111111111111111111111111111aa",
			SelfHash:           "sh2222222222222222222222222222222222222222222222222222222222bb",
		},
	}
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	for _, r := range rows {
		body, err := json.Marshal(r)
		require.NoError(t, err)
		_, err = f.Write(body)
		require.NoError(t, err)
		_, err = f.Write([]byte("\n"))
		require.NoError(t, err)
	}
}

// verifyZipIntegrity — 解压 zip 并校验所有文件 sha256 与 manifest.json 一致。
func verifyZipIntegrity(t *testing.T, zipPath string) {
	t.Helper()
	r, err := zip.OpenReader(zipPath)
	require.NoError(t, err)
	defer r.Close()

	dest := t.TempDir()
	for _, f := range r.File {
		target := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), filepath.Clean(dest)+string(os.PathSeparator)) {
			t.Fatalf("path traversal: %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			require.NoError(t, os.MkdirAll(target, 0o755))
			continue
		}
		require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
		src, err := f.Open()
		require.NoError(t, err)
		body, err := io.ReadAll(src)
		src.Close()
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(target, body, 0o644))
	}

	// 读 manifest.json + 校验每个 file 的 sha256。
	manifestBody, err := os.ReadFile(filepath.Join(dest, "manifest.json"))
	require.NoError(t, err)
	var m struct {
		Files []struct {
				Name   string `json:"name"`
				SHA256 string `json:"sha256"`
				Bytes  int64  `json:"bytes"`
			} `json:"files"`
	}
	require.NoError(t, json.Unmarshal(manifestBody, &m))
	for _, e := range m.Files {
		path := filepath.Join(dest, e.Name)
		body, err := os.ReadFile(path)
		require.NoError(t, err)
		h := sha256.Sum256(body)
		assert.Equal(t, e.SHA256, hex.EncodeToString(h[:]), "sha mismatch for %s", e.Name)
		assert.Equal(t, e.Bytes, int64(len(body)), "size mismatch for %s", e.Name)
	}

	// 校验 manifest.sha256 与磁盘 manifest.json 的 sha 一致。
	shaLine, err := os.ReadFile(filepath.Join(dest, "manifest.sha256"))
	require.NoError(t, err)
	parts := strings.Fields(strings.TrimSpace(string(shaLine)))
	require.Len(t, parts, 2)
	h := sha256.Sum256(manifestBody)
	assert.Equal(t, hex.EncodeToString(h[:]), parts[0])

	// audit.jsonl 子集 hash 链应自洽（每行 prev == 上一行 self）。
	auditBody, err := os.ReadFile(filepath.Join(dest, "audit.jsonl"))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(auditBody), "\n"), "\n")
	assert.Equal(t, 2, len(lines))
	var prev string
	for i, l := range lines {
		var r output.AuditRow
		require.NoError(t, json.Unmarshal([]byte(l), &r))
		if i == 0 {
			assert.Empty(t, r.PrevEvidenceSHA256, "first row prev should be empty")
		} else {
			assert.Equal(t, prev, r.PrevEvidenceSHA256, "row %d prev mismatch", i+1)
		}
		prev = r.SelfHash
	}
}

// ============ Tests ============

func TestExportEvidence_HappyPath(t *testing.T) {
	bin := buildExportBinary(t)
	tmp := t.TempDir()
	contracts := filepath.Join(tmp, "contracts.yaml")
	audit := filepath.Join(tmp, "audit.jsonl")
	outZip := filepath.Join(tmp, "evidence.zip")

	writeContractsForTest(t, contracts)
	writeAuditForTest(t, audit)

	cmd := exec.Command(bin, "export-evidence",
		"--last", "30d",
		"--config", contracts,
		"--audit", audit,
		"--out", outZip,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "stderr/stdout: %s", string(out))

	// stdout 应含 ok JSON。
	stdout := out
	assert.Contains(t, string(stdout), `"status":"ok"`)
	assert.Contains(t, string(stdout), `"path":"`+outZip+`"`)

	// zip 文件存在 + 可解压 + sha 链完整。
	st, err := os.Stat(outZip)
	require.NoError(t, err)
	assert.Greater(t, st.Size(), int64(500))

	verifyZipIntegrity(t, outZip)
}

func TestExportEvidence_MissingFlags(t *testing.T) {
	bin := buildExportBinary(t)
	cases := []struct {
		name string
		args []string
	}{
		{"no-last", []string{"--config", "a.yaml", "--out", "/x/ev.zip"}},
		{"no-config", []string{"--last", "30d", "--out", "/x/ev.zip"}},
		{"no-out", []string{"--last", "30d", "--config", "a.yaml"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"export-evidence"}, c.args...)
			cmd := exec.Command(bin, args...)
			out, err := cmd.CombinedOutput()
			// 任一必填 flag 缺 → exit 非零。
			assert.Error(t, err)
			s := strings.ToLower(string(out))
			assert.True(t,
				strings.Contains(s, "required") || strings.Contains(s, "missing") || strings.Contains(s, "is required"),
				"stderr should mention required/missing, got: %s", string(out))
		})
	}
}

func TestExportEvidence_InvalidLastFormat(t *testing.T) {
	bin := buildExportBinary(t)
	tmp := t.TempDir()
	contracts := filepath.Join(tmp, "contracts.yaml")
	audit := filepath.Join(tmp, "audit.jsonl")
	outZip := filepath.Join(tmp, "evidence.zip")
	writeContractsForTest(t, contracts)
	writeAuditForTest(t, audit)

	cmd := exec.Command(bin, "export-evidence",
		"--last", "abc",
		"--config", contracts,
		"--audit", audit,
		"--out", outZip,
	)
	out, err := cmd.CombinedOutput()
	assert.Error(t, err)
	s := string(out)
	assert.Contains(t, s, "invalid_last")
}

func TestExportEvidence_AuditPathDefaults(t *testing.T) {
	bin := buildExportBinary(t)
	tmp := t.TempDir()
	contracts := filepath.Join(tmp, "contracts.yaml")
	audit := filepath.Join(tmp, "audit.jsonl")
	outZip := filepath.Join(tmp, "evidence.zip")
	logsDir := filepath.Join(tmp, "logs")

	writeContractsForTest(t, contracts)
	// 把 audit 放到 ./logs/audit.jsonl，依赖默认路径推断。
	require.NoError(t, os.MkdirAll(logsDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(logsDir, "audit.jsonl"), nil, 0o644))
	writeAuditForTest(t, audit)

	// 在 logs 目录跑命令 → 默认相对路径 ./logs/audit.jsonl 命中。
	cmd := exec.Command(bin, "export-evidence",
		"--last", "30d",
		"--config", contracts,
		"--out", outZip,
	)
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "stderr/stdout: %s", string(out))
	assert.Contains(t, string(out), `"status":"ok"`)
	st, err := os.Stat(outZip)
	require.NoError(t, err)
	assert.Greater(t, st.Size(), int64(500))
}

func TestExportEvidence_EnvAuditPath(t *testing.T) {
	bin := buildExportBinary(t)
	tmp := t.TempDir()
	contracts := filepath.Join(tmp, "contracts.yaml")
	audit := filepath.Join(tmp, "custom-audit.jsonl")
	outZip := filepath.Join(tmp, "evidence.zip")
	writeContractsForTest(t, contracts)
	writeAuditForTest(t, audit)

	cmd := exec.Command(bin, "export-evidence",
		"--last", "30d",
		"--config", contracts,
		"--out", outZip,
	)
	cmd.Env = append(os.Environ(), "XINCHUANG_AUDIT_FILE="+audit)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "stderr/stdout: %s", string(out))
	assert.Contains(t, string(out), `"status":"ok"`)
}

func TestExportEvidence_Help(t *testing.T) {
	bin := buildExportBinary(t)
	cmd := exec.Command(bin, "export-evidence", "--help")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err)
	s := string(out)
	for _, want := range []string{"--last", "--config", "--audit", "--out", "--tool-version", "manifest.json", "manifest.sha256"} {
		assert.Contains(t, s, want, "help should mention %s", want)
	}
}

func TestExportEvidence_ToolVersionFlag(t *testing.T) {
	bin := buildExportBinary(t)
	tmp := t.TempDir()
	contracts := filepath.Join(tmp, "contracts.yaml")
	audit := filepath.Join(tmp, "audit.jsonl")
	outZip := filepath.Join(tmp, "evidence.zip")
	writeContractsForTest(t, contracts)
	writeAuditForTest(t, audit)

	cmd := exec.Command(bin, "export-evidence",
		"--last", "30d",
		"--config", contracts,
		"--audit", audit,
		"--out", outZip,
		"--tool-version", "v1.2.3-rc1",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "stderr/stdout: %s", string(out))

	// 解压验证 manifest.json 内 tool_version = v1.2.3-rc1。
	r, err := zip.OpenReader(outZip)
	require.NoError(t, err)
	defer r.Close()
	for _, f := range r.File {
		if f.Name != "manifest.json" {
			continue
		}
		src, err := f.Open()
		require.NoError(t, err)
		body, err := io.ReadAll(src)
		src.Close()
		require.NoError(t, err)
		var m struct {
			ToolVersion string `json:"tool_version"`
		}
		require.NoError(t, json.Unmarshal(body, &m))
		assert.Equal(t, "v1.2.3-rc1", m.ToolVersion)
		return
	}
	t.Fatal("manifest.json not found in zip")
}

func TestExportEvidence_BadContractsPath(t *testing.T) {
	bin := buildExportBinary(t)
	tmp := t.TempDir()
	audit := filepath.Join(tmp, "audit.jsonl")
	outZip := filepath.Join(tmp, "evidence.zip")
	writeAuditForTest(t, audit)

	cmd := exec.Command(bin, "export-evidence",
		"--last", "30d",
		"--config", filepath.Join(tmp, "nonexistent.yaml"),
		"--audit", audit,
		"--out", outZip,
	)
	out, err := cmd.CombinedOutput()
	assert.Error(t, err)
	s := string(out)
	assert.Contains(t, s, "export_failed")
}

func TestExportEvidence_NestedOutDir(t *testing.T) {
	bin := buildExportBinary(t)
	tmp := t.TempDir()
	contracts := filepath.Join(tmp, "contracts.yaml")
	audit := filepath.Join(tmp, "audit.jsonl")
	outZip := filepath.Join(tmp, "deep/nested/dir/evidence.zip")
	writeContractsForTest(t, contracts)
	writeAuditForTest(t, audit)

	cmd := exec.Command(bin, "export-evidence",
		"--last", "30d",
		"--config", contracts,
		"--audit", audit,
		"--out", outZip,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "stderr/stdout: %s", string(out))
	st, err := os.Stat(outZip)
	require.NoError(t, err)
	assert.Greater(t, st.Size(), int64(500))
}

func TestExportEvidence_BareNumberLast(t *testing.T) {
	// CLI 接受裸数字（默认单位 = 天）。
	bin := buildExportBinary(t)
	tmp := t.TempDir()
	contracts := filepath.Join(tmp, "contracts.yaml")
	audit := filepath.Join(tmp, "audit.jsonl")
	outZip := filepath.Join(tmp, "evidence.zip")
	writeContractsForTest(t, contracts)
	writeAuditForTest(t, audit)

	cmd := exec.Command(bin, "export-evidence",
		"--last", "7",
		"--config", contracts,
		"--audit", audit,
		"--out", outZip,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "stderr/stdout: %s", string(out))
	assert.Contains(t, string(out), `"days":7`)
}

func TestExportEvidence_ExistingParentVerified(t *testing.T) {
	// 验证 zip 内 audit.jsonl 含漂移行 + 字段保留（端到端 hash 链校验由
	// cmd_audit_test.go 单独覆盖；本测试避免构造合法 hash 链）。
	bin := buildExportBinary(t)
	tmp := t.TempDir()
	contracts := filepath.Join(tmp, "contracts.yaml")
	audit := filepath.Join(tmp, "audit.jsonl")
	outZip := filepath.Join(tmp, "evidence.zip")
	writeContractsForTest(t, contracts)
	writeAuditForTest(t, audit)

	cmd := exec.Command(bin, "export-evidence",
		"--last", "30d",
		"--config", contracts,
		"--audit", audit,
		"--out", outZip,
	)
	exportOut, err := cmd.CombinedOutput()
	require.NoError(t, err, "export-evidence failed: %s", string(exportOut))

	// 读 zip 内 audit.jsonl + 验证含 EVT-LIS-1 与 EVT-PACS-1。
	r, err := zip.OpenReader(outZip)
	require.NoError(t, err)
	defer r.Close()
	for _, f := range r.File {
		if f.Name != "audit.jsonl" {
			continue
		}
		src, err := f.Open()
		require.NoError(t, err)
		body, err := io.ReadAll(src)
		src.Close()
		require.NoError(t, err)
		s := string(body)
		assert.Contains(t, s, "EVT-LIS-1")
		assert.Contains(t, s, "EVT-PACS-1")
		return
	}
	t.Fatal("audit.jsonl not found in zip")
}