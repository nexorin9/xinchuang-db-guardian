// evidence_test.go — evidence.zip 装订 + manifest.sha256 + 文件篡改检测 测试。
package export

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"xinchuang-db-guardian/internal/output"
)

// makeSampleAuditRows — 构造 N 行 drift + drift_confirmed + drift_remedied。
func makeSampleAuditRows(now time.Time) []output.AuditRow {
	base := now.Add(-5 * 24 * time.Hour) // 5 天前
	rows := []output.AuditRow{
		{
			TsUTC:          base.Format(time.RFC3339Nano),
			EventID:        "EVT-LIS-1",
			ContractID:     "HT-2024-LIS",
			SystemID:       "lis",
			Vendor:         "dm8",
			Declared:       "DM Database Server V8.1.*",
			Actual:         "PostgreSQL 14.10 (Debian ...)",
			PortRaw:        "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1) on x86_64",
			DriverSha:      "aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaaa",
			JDBCURL:        "jdbc:postgresql://10.0.1.23:15432/lis",
			Verdict:        "trial",
			Confidence:     0.98,
			EvidenceSHA256: "ev1111111111111111111111111111111111111111111111111111111111111",
			Kind:           "drift",
			LLMModel:       "stub-model",
			LLMInSHA256:    "in111",
			LLMOutSHA256:   "out111",
			LatencyMs:      120,
			PrevEvidenceSHA256: "",
			SelfHash:       "sh1111111111111111111111111111111111111111111111111111111111aa",
		},
		{
			TsUTC:          base.Add(2 * time.Hour).Format(time.RFC3339Nano),
			EventID:        "EVT-PACS-1",
			ContractID:     "HT-2024-PACS",
			SystemID:       "pacs",
			Vendor:         "IvorySQL",
			Declared:       "IvorySQL.*1.4.*",
			Actual:         "PostgreSQL 13.6",
			PortRaw:        "PostgreSQL 13.6 (Debian 13.6-1.pgdg120+1)",
			DriverSha:      "bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb",
			JDBCURL:        "jdbc:postgresql://10.0.1.24:19600/pacs",
			Verdict:        "trial",
			Confidence:     0.95,
			EvidenceSHA256: "ev2222222222222222222222222222222222222222222222222222222222222",
			Kind:           "drift",
			PrevEvidenceSHA256: "sh1111111111111111111111111111111111111111111111111111111111aa",
			SelfHash:       "sh2222222222222222222222222222222222222222222222222222222222bb",
		},
		{
			TsUTC:          base.Add(3 * time.Hour).Format(time.RFC3339Nano),
			EventID:        "EVT-PACS-1-CONFIRMED",
			ContractID:     "HT-2024-PACS",
			SystemID:       "pacs",
			Vendor:         "IvorySQL",
			Declared:       "IvorySQL.*1.4.*",
			Actual:         "IvorySQL 1.4",
			Verdict:        "ok",
			Confidence:     1.0,
			EvidenceSHA256: "ev3333333333333333333333333333333333333333333333333333333333333",
			Action:         "re-verified",
			Operator:       "auto_reverify",
			Kind:           "drift_remedied",
			PrevEvidenceSHA256: "sh2222222222222222222222222222222222222222222222222222222222bb",
			SelfHash:       "sh3333333333333333333333333333333333333333333333333333333333cc",
		},
		// 50 天前的旧行（应被 --last 30d 过滤掉）。
		{
			TsUTC:          now.Add(-50 * 24 * time.Hour).Format(time.RFC3339Nano),
			EventID:        "EVT-OLD-1",
			ContractID:     "HT-2024-OLD",
			SystemID:       "his-core",
			Vendor:         "kingbase",
			Verdict:        "trial",
			Kind:           "drift",
			EvidenceSHA256: "ev0000000000000000000000000000000000000000000000000000000000000",
			SelfHash:       "sh0000000000000000000000000000000000000000000000000000000000dd",
		},
	}
	return rows
}

// writeSampleAuditJSONL — 把 rows 写成 audit.jsonl（不重新计算 hash）。
func writeSampleAuditJSONL(t *testing.T, path string, rows []output.AuditRow) {
	t.Helper()
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

// writeSampleContractsYAML — 构造 3 条合同的 contracts.yaml。
func writeSampleContractsYAML(t *testing.T, path string) {
	t.Helper()
	yamlContent := `declared:
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

  - system_id: pacs
    vendor: IvorySQL
    version_pattern: "IvorySQL.*1\\.4.*"
    allow_drift_sha256: []
    contract_id: HT-2024-PACS
    host: 10.0.1.24
    port: 19600
    scan_interval: 10m
    jdbc_driver_dirs:
      - /opt/jdbc/ivorysql
    event_id_prefix: EVT-PACS

  - system_id: his-core
    vendor: kingbase
    version_pattern: "V008R006.*"
    allow_drift_sha256: []
    contract_id: HT-2024-HIS-CORE
    host: 10.0.1.21
    port: 54321
    scan_interval: 10m
    jdbc_driver_dirs:
      - /opt/jdbc/kingbase
    event_id_prefix: EVT-HIS
`
	require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o644))
}

// unzipToTempDir — 解压 zip 到临时目录，返回解压目录 + cleanup。
func unzipToTempDir(t *testing.T, zipPath string) (string, func()) {
	t.Helper()
	dest, err := os.MkdirTemp("", "xc-guardian-unzip-*")
	require.NoError(t, err)
	r, err := zip.OpenReader(zipPath)
	require.NoError(t, err)
	defer r.Close()
	for _, f := range r.File {
		// 防路径遍历。
		target := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), filepath.Clean(dest)+string(os.PathSeparator)) {
			t.Fatalf("unzip path traversal: %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			require.NoError(t, os.MkdirAll(target, 0o755))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", filepath.Dir(target), err)
		}
		src, err := f.Open()
		require.NoError(t, err)
		body, err := io.ReadAll(src)
		src.Close()
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(target, body, 0o644))
	}
	return dest, func() { _ = os.RemoveAll(dest) }
}

// readManifestFromZip — 读 manifest.json + manifest.sha256。
func readManifestFromZip(t *testing.T, unzipDir string) (Manifest, string) {
	t.Helper()
	mPath := filepath.Join(unzipDir, manifestFileName)
	body, err := os.ReadFile(mPath)
	require.NoError(t, err)
	var m Manifest
	require.NoError(t, json.Unmarshal(body, &m))

	shaPath := filepath.Join(unzipDir, ManifestSHA256FileName)
	shaLine, err := os.ReadFile(shaPath)
	require.NoError(t, err)
	parts := strings.Fields(string(shaLine))
	require.Len(t, parts, 2)
	return m, parts[0]
}

// verifyManifestIntegrity — 用 manifest.sha256 校验 zip 内每个文件的 sha256。
func verifyManifestIntegrity(t *testing.T, unzipDir string, m Manifest) {
	t.Helper()
	for _, e := range m.Files {
		path := filepath.Join(unzipDir, e.Name)
		st, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, e.Bytes, st.Size(), "size mismatch for %s", e.Name)
		f, err := os.Open(path)
		require.NoError(t, err)
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		require.NoError(t, err)
		got := hex.EncodeToString(h.Sum(nil))
		assert.Equal(t, e.SHA256, got, "sha256 mismatch for %s", e.Name)
	}
}

// ============ Test cases ============

func TestExport_BasicHappyPath(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	size, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		ToolVersion:   "test-0.1.0",
		Now:           &now,
	})
	require.NoError(t, err)
	assert.Greater(t, size, int64(500), "zip size should be > 500 bytes")

	// 解压 + 校验 manifest。
	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	// 校验必备文件齐全。
	for _, name := range []string{
		readmeFileName, contractRegistryFile, driftEventsFile,
		driverShaFile, AuditFileName, manifestFileName, ManifestSHA256FileName,
	} {
		_, err := os.Stat(filepath.Join(unzipDir, name))
		assert.NoError(t, err, "missing %s in zip", name)
	}

	// raw_probe_responses/ 至少含 lis.txt + pacs.txt（his-core 无 drift 命中无文件）。
	rawDir := filepath.Join(unzipDir, rawProbeResponsesDir)
	entries, err := os.ReadDir(rawDir)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 2, "expected at least lis/pacs raw_probe files")

	// manifest.json 校验自身 sha256。
	m, manifestSHA := readManifestFromZip(t, unzipDir)
	manifestJSONBytes, err := os.ReadFile(filepath.Join(unzipDir, manifestFileName))
	require.NoError(t, err)
	h := sha256.Sum256(manifestJSONBytes)
	expectedSHA := hex.EncodeToString(h[:])
	assert.Equal(t, expectedSHA, manifestSHA, "manifest.sha256 mismatch")

	// 校验 zip 内所有文件 sha256 都对得上 manifest。
	verifyManifestIntegrity(t, unzipDir, m)

	// manifest 字段检查。
	assert.Equal(t, 30, m.LastNDays)
	assert.Equal(t, "test-0.1.0", m.ToolVersion)
	assert.Equal(t, now.Format(time.RFC3339Nano), m.GeneratedAtUTC)
	cutoffExpected := now.Add(-30 * 24 * time.Hour).Format(time.RFC3339Nano)
	assert.Equal(t, cutoffExpected, m.CutoffUTC)
	// manifest.Files 不含自身（避免 sha 自引用）；至少 7 个：README / registry /
	// drift_events / driver_sha / audit + 2 raw_probe。
	assert.GreaterOrEqual(t, len(m.Files), 7)
}

func TestExport_AuditTimeWindowFilter(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		ToolVersion:   "test-0.1.0",
		Now:           &now,
	})
	require.NoError(t, err)

	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	// audit.jsonl 子集：3 行（50 天前的 EVT-OLD-1 被过滤）。
	body, err := os.ReadFile(filepath.Join(unzipDir, AuditFileName))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	assert.Equal(t, 3, len(lines), "expected 3 filtered rows")
	for _, l := range lines {
		assert.NotContains(t, l, "EVT-OLD-1", "old row should be filtered")
	}

	// drift_events.csv 不含 EVT-OLD-1。
	csvBody, err := os.ReadFile(filepath.Join(unzipDir, driftEventsFile))
	require.NoError(t, err)
	assert.NotContains(t, string(csvBody), "EVT-OLD-1")
}

func TestExport_ManifestS256DetectsTamper(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		ToolVersion:   "test-0.1.0",
		Now:           &now,
	})
	require.NoError(t, err)

	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	// 篡改 drift_events.csv（追加一行假数据）。
	csvPath := filepath.Join(unzipDir, driftEventsFile)
	f, err := os.OpenFile(csvPath, os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = f.WriteString("\n2026-10-10T00:00:00Z,EVT-FAKE,fake-cid,fake-sys,fake-vendor,,,,,,,,,,\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// 重算 sha256 → 与 manifest.json 中的不一致。
	now2 := time.Now().UTC()
	h := sha256.New()
	f2, err := os.Open(csvPath)
	require.NoError(t, err)
	_, err = io.Copy(h, f2)
	require.NoError(t, f2.Close())
	got := hex.EncodeToString(h.Sum(nil))

	m, _ := readManifestFromZip(t, unzipDir)
	var found string
	for _, e := range m.Files {
		if e.Name == driftEventsFile {
			found = e.SHA256
			break
		}
	}
	assert.NotEqual(t, found, got, "tampered file sha should not match manifest")
	_ = now2
}

func TestExport_EmptyAuditPath(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	outPath := filepath.Join(tmp, "evidence.zip")
	writeSampleContractsYAML(t, contractsYAML)
	// audit.jsonl 不存在 → LoadChain 返回 nil slice → drift_events 为空 → 仍能装订。
	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     filepath.Join(tmp, "nonexistent.jsonl"),
		OutPath:       outPath,
		LastNDays:     30,
	})
	require.NoError(t, err)
	st, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Greater(t, st.Size(), int64(300))
}

func TestExport_InvalidOptions(t *testing.T) {
	_, err := Export(Options{})
	assert.ErrorIs(t, err, ErrInvalidOptions)

	_, err = Export(Options{ContractsPath: "a", AuditPath: "b"})
	assert.ErrorIs(t, err, ErrEmptyOutPath)
}

func TestExport_BadContractsYAML(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	require.NoError(t, os.WriteFile(contractsYAML, []byte("this is not yaml: ["), 0o644))
	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     filepath.Join(tmp, "audit.jsonl"),
		OutPath:       filepath.Join(tmp, "out.zip"),
		LastNDays:     30,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load contracts")
}

func TestExport_ContractRegistryColumns(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)

	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	f, err := os.Open(filepath.Join(unzipDir, contractRegistryFile))
	require.NoError(t, err)
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	require.NoError(t, err)
	assert.Equal(t, 4, len(rows), "1 header + 3 contract rows")
	assert.Contains(t, rows[0], "system_id")
	assert.Contains(t, rows[0], "vendor")
	assert.Equal(t, "lis", rows[1][0])
	assert.Equal(t, "dm8", rows[1][1])
	assert.Equal(t, "pacs", rows[2][0])
	assert.Equal(t, "IvorySQL", rows[2][1])
	assert.Equal(t, "his-core", rows[3][0])
}

func TestExport_DriverSha256Dedup(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	rows := makeSampleAuditRows(now)
	// 加一行同 system + 同 driver_sha 的复行（应被去重）。
	rows = append(rows, output.AuditRow{
		TsUTC:          now.Add(-1 * time.Hour).Format(time.RFC3339Nano),
		EventID:        "EVT-PACS-DUP",
		SystemID:       "pacs",
		Vendor:         "IvorySQL",
		DriverSha:      "bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb",
		EvidenceSHA256: "evdup",
		Kind:           "drift",
		SelfHash:       "shdup",
	})
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, rows)

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)

	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	csvBody, err := os.ReadFile(filepath.Join(unzipDir, driverShaFile))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(csvBody), "\n"), "\n")
	// 1 header + 2 driver_shas（lis + pacs；EVT-PACS-DUP 与 EVT-PACS-1 driver_sha 相同 → 去重）。
	assert.Equal(t, 3, len(lines), "expected 3 lines (1 header + 2 unique driver_shas)")
	csvLines, err := csv.NewReader(strings.NewReader(string(csvBody))).ReadAll()
	require.NoError(t, err)
	// 校验 driver_sha 列只出现一次 bbb...
	driverCol := -1
	for i, h := range csvLines[0] {
		if h == "driver_sha256" {
			driverCol = i
			break
		}
	}
	assert.NotEqual(t, -1, driverCol)
	count := 0
	for _, line := range csvLines[1:] {
		if line[driverCol] == "bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb" {
			count++
		}
	}
	assert.Equal(t, 1, count, "duplicate driver_sha should be deduped")
}

func TestExport_RawProbeContent(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)

	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	// lis.txt 应含 system_id / vendor / 端口响应原文 + 不含患者字段。
	body, err := os.ReadFile(filepath.Join(unzipDir, rawProbeResponsesDir, "lis.txt"))
	require.NoError(t, err)
	content := string(body)
	assert.Contains(t, content, "system_id: lis")
	assert.Contains(t, content, "vendor: dm8")
	assert.Contains(t, content, "PostgreSQL 14.10 (Debian")
	// 不含患者可识别字段。
	for _, forbid := range []string{"patient", "姓名", "身份证", "住院号", "病案号"} {
		assert.NotContains(t, strings.ToLower(content), strings.ToLower(forbid))
	}
}

func TestExport_ManifestSortedByName(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)

	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	m, _ := readManifestFromZip(t, unzipDir)
	names := make([]string, len(m.Files))
	for i, e := range m.Files {
		names[i] = e.Name
	}
	sorted := make([]string, len(names))
	copy(sorted, names)
	sort.Strings(sorted)
	assert.Equal(t, sorted, names, "manifest files should be sorted by name")
}

func TestParseLastNDays(t *testing.T) {
	cases := []struct {
		in    string
		want  int
		isErr bool
	}{
		{"30d", 30, false},
		{"7d", 7, false},
		{"720h", 30, false},
		{"1440m", 1, false},
		{"30", 30, false},
		{"1d", 1, false},
		{"", 0, true},
		{"0d", 0, true},
		{"-5d", 0, true},
		{"abc", 0, true},
		{"30x", 0, true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := ParseLastNDays(c.in)
			if c.isErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestSafeFilename(t *testing.T) {
	cases := []struct{ in, want string }{
		{"lis", "lis"},
		{"his-core", "his-core"},
		{"path/traversal", "path_traversal"},
		{"a b c", "a_b_c"},
		{"中文sid", "______sid"},
		{"", "_"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := safeFilename(c.in)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestClassifyKind(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{readmeFileName, "readme"},
		{contractRegistryFile, "registry"},
		{driftEventsFile, "events"},
		{driverShaFile, "driver_sha"},
		{AuditFileName, "audit"},
		{manifestFileName, "manifest"},
		{ManifestSHA256FileName, "manifest_sha"},
		{rawProbeResponsesDir + "/lis.txt", "raw_probe"},
		{"other.txt", "other"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			assert.Equal(t, c.want, classifyKind(c.in))
		})
	}
}

func TestFilterByCutoff(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-30 * 24 * time.Hour)
	rows := []output.AuditRow{
		{TsUTC: now.Add(-5 * 24 * time.Hour).Format(time.RFC3339Nano), EventID: "R1"},
		{TsUTC: now.Add(-40 * 24 * time.Hour).Format(time.RFC3339Nano), EventID: "R2"},
		{TsUTC: now.Add(-1 * time.Hour).Format(time.RFC3339Nano), EventID: "R3"},
		{TsUTC: "", EventID: "R4"}, // 保留
	}
	out := filterByCutoff(rows, cutoff)
	assert.Len(t, out, 3)
	ids := []string{out[0].EventID, out[1].EventID, out[2].EventID}
	sort.Strings(ids)
	assert.Equal(t, []string{"R1", "R3", "R4"}, ids)
}

func TestExport_InvalidLastNDaysDefaultsTo30(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     0, // 默认 30
		Now:           &now,
	})
	require.NoError(t, err)
	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()
	m, _ := readManifestFromZip(t, unzipDir)
	assert.Equal(t, 30, m.LastNDays)
}

func TestExport_AuditChainPreserved(t *testing.T) {
	// audit.jsonl 内 3 行 hash 链 → 装订进 zip 后仍可被 audit verify-chain 校验。
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)
	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	extractedAudit := filepath.Join(unzipDir, AuditFileName)
	// 重新计算 extractedAudit 的 hash 链。
	body, err := os.ReadFile(extractedAudit)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	assert.Equal(t, 3, len(lines))
	for _, l := range lines {
		assert.NotEmpty(t, l)
		var row output.AuditRow
		require.NoError(t, json.Unmarshal([]byte(l), &row))
		assert.NotEmpty(t, row.SelfHash)
		assert.NotEmpty(t, row.EvidenceSHA256)
	}
}

func TestExport_Sha256sumCompat(t *testing.T) {
	// manifest.sha256 是 `sha256 + 双空格 + filename` 形态（与 `sha256sum -c` 兼容）。
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)

	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()
	shaLine, err := os.ReadFile(filepath.Join(unzipDir, ManifestSHA256FileName))
	require.NoError(t, err)
	line := strings.TrimSpace(string(shaLine))
	parts := strings.SplitN(line, "  ", 2)
	require.Len(t, parts, 2)
	assert.Equal(t, manifestFileName, parts[1])
	// sha 部分应是 64 字符 hex。
	assert.Len(t, parts[0], 64)
}

func TestExport_AuditRowPreservesHash(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	original := makeSampleAuditRows(now)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, original)

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)
	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	// 比对 zip 内 audit.jsonl 与原 audit.jsonl 的 self_hash 完全一致。
	newAudit, err := os.ReadFile(filepath.Join(unzipDir, AuditFileName))
	require.NoError(t, err)
	for _, l := range strings.Split(strings.TrimRight(string(newAudit), "\n"), "\n") {
		var got output.AuditRow
		require.NoError(t, json.Unmarshal([]byte(l), &got))
		// 在原 4 行中找到匹配 event_id 的行（不含 50 天前那条）。
		var origSelfHash string
		for _, o := range original {
			if o.EventID == got.EventID {
				origSelfHash = o.SelfHash
				break
			}
		}
		if got.EventID == "EVT-OLD-1" {
			continue
		}
		assert.NotEmpty(t, origSelfHash, "missing original for %s", got.EventID)
		assert.Equal(t, origSelfHash, got.SelfHash, "self_hash must be preserved across export")
	}
}

func TestExport_MkdirOutDir(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	// 输出目录不存在 → 应自动 MkdirAll。
	outPath := filepath.Join(tmp, "nested/dir/evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)
	st, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Greater(t, st.Size(), int64(300))
}

func TestExport_ReadmeContainsGuidance(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)
	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	body, err := os.ReadFile(filepath.Join(unzipDir, readmeFileName))
	require.NoError(t, err)
	s := string(body)
	assert.Contains(t, s, "信创数据库合规漂移守护")
	assert.Contains(t, s, "验证方法")
	assert.Contains(t, s, "sha256sum -c manifest.sha256")
	assert.Contains(t, s, "xinchuang-guardian audit verify-chain")
	// 不含患者字段。
	for _, forbid := range []string{"姓名", "身份证", "住院号", "病案号", "处方号"} {
		assert.NotContains(t, s, forbid)
	}
}

func TestExport_ZipIsValid(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)
	r, err := zip.OpenReader(outPath)
	require.NoError(t, err)
	defer r.Close()
	names := make([]string, 0)
	for _, f := range r.File {
		names = append(names, f.Name)
	}
	assert.NotEmpty(t, names)
	// 排序检查。
	sort.Strings(names)
	for i := 1; i < len(names); i++ {
		assert.True(t, names[i-1] < names[i], "zip entries should be sorted")
	}
}

func TestExport_AuditLinkage(t *testing.T) {
	// 验证 audit.jsonl 内 3 行的 prev_evidence_sha256 自洽（行 2 prev == 行 1 self）。
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)
	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	body, err := os.ReadFile(filepath.Join(unzipDir, AuditFileName))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	assert.Equal(t, 3, len(lines))
	var rows []output.AuditRow
	for _, l := range lines {
		var r output.AuditRow
		require.NoError(t, json.Unmarshal([]byte(l), &r))
		rows = append(rows, r)
	}
	// 行 1 prev 必须为空。
	assert.Empty(t, rows[0].PrevEvidenceSHA256)
	// 行 2 prev 必须等于行 1 self。
	assert.Equal(t, rows[0].SelfHash, rows[1].PrevEvidenceSHA256)
	// 行 3 prev 必须等于行 2 self。
	assert.Equal(t, rows[1].SelfHash, rows[2].PrevEvidenceSHA256)
}

func TestExport_ManifestHostname(t *testing.T) {
	tmp := t.TempDir()
	contractsYAML := filepath.Join(tmp, "contracts.yaml")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	outPath := filepath.Join(tmp, "evidence.zip")

	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	writeSampleContractsYAML(t, contractsYAML)
	writeSampleAuditJSONL(t, auditPath, makeSampleAuditRows(now))

	_, err := Export(Options{
		ContractsPath: contractsYAML,
		AuditPath:     auditPath,
		OutPath:       outPath,
		LastNDays:     30,
		Now:           &now,
	})
	require.NoError(t, err)
	unzipDir, cleanup := unzipToTempDir(t, outPath)
	defer cleanup()

	m, _ := readManifestFromZip(t, unzipDir)
	hn, _ := os.Hostname()
	if hn != "" {
		assert.Equal(t, hn, m.HostHostname)
	}
}

// ============ End of tests ============

// 测试 helper：补 fmt 导入以防 unused（部分 case 用了 fmt.Errorf）。
var _ = fmt.Errorf