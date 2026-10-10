package check

import (
	"testing"
	"time"

	"xinchuang-db-guardian/internal/config"
	"xinchuang-db-guardian/internal/probe/driver"
	"xinchuang-db-guardian/internal/probe/port"
)

// makeTestBrandMap 与 classify 测试同形态，构造 5 品牌 brandMap。
func makeTestBrandMap(t *testing.T) *config.BrandMap {
	t.Helper()
	brands := []config.VendorSignature{
		{
			Brand:           "kingbase",
			VersionRegex:    []string{`(?i)KingbaseES\s+V\d+R\d+C\d+`},
			JDBCURLPattern:  []string{`jdbc:kingbase8://[^:]+:[0-9]+/[^?]+`},
			SignatureTokens: []string{"kingbasees"},
		},
		{
			Brand:           "dm8",
			VersionRegex:    []string{`(?i)DM\s*(?:8|Database)`},
			JDBCURLPattern:  []string{`jdbc:dm://[^:]+:[0-9]+`},
			SignatureTokens: []string{"dm", "dameng"},
		},
		{
			Brand:           "pg-compat",
			VersionRegex:    []string{`(?i)PostgreSQL\s+\d+\.\d+`},
			JDBCURLPattern:  []string{`jdbc:postgresql://[^:]+:[0-9]+/[^?]+`},
			SignatureTokens: []string{"postgresql"},
		},
	}
	if err := config.ValidateVendorSignatures(brands); err != nil {
		t.Fatalf("validate: %v", err)
	}
	m := config.NewBrandMap()
	m.Set(brands)
	return m
}

func contractFor(systemID, vendor string) config.ContractV {
	return config.ContractV{
		SystemID:          systemID,
		Vendor:            vendor,
		VersionPattern:    `.*`,
		AllowDriftSHA256:  []string{"abc123", "def456"},
		ContractID:        "HT-2024-TEST",
		Host:              "127.0.0.1",
		Port:              5432,
		ScanInterval:      10 * time.Minute,
		JdbcDriverDirs:    []string{"/tmp/jdbc"},
		EventIDPrefix:     "TEST",
	}
}

// ComputeEvidenceSHA256 / ComputeSelfHash 的单元测试已搬到 evidence_test.go
// （T16 拆分 — 独立模块 + 详细测试）；本文件保留 Compare* 系列高层测试。

func TestCompare_AllOK(t *testing.T) {
	bm := makeTestBrandMap(t)
	contract := contractFor("his-core", "kingbase")
	ts := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	portProbe := port.ProbeResult{
		SystemID:  "his-core",
		Brand:     "kingbase",
		Raw:       []byte("KingbaseES V008R006C0010"),
		Timestamp: ts,
	}
	driverScan := &driver.ScanResult{
		SystemID:  "his-core",
		Dir:       "/tmp/jdbc",
		JarFile:   "kingbase8.jar",
		Sha256:    "abc123", // 命中 AllowDriftSHA256
		IsKnown:   true,
		JDBCURLs:  []driver.JdbcURLEvidence{{File: "datasource.xml", LineNo: 5, URL: "jdbc:kingbase8://10.0.1.21:5432/his"}},
		ScannedAt: ts,
	}
	ev := Compare(contract, portProbe, driverScan, bm)
	if ev.Verdict != VerdictOK {
		t.Errorf("三维全一致应 ok，got %s", ev.Verdict)
	}
	if ev.Status != StateTrial {
		t.Errorf("默认 Status 应为 trial，got %s", ev.Status)
	}
	if len(ev.InconsistentDims) != 0 {
		t.Errorf("全一致应无 InconsistentDims，got %v", ev.InconsistentDims)
	}
}

func TestCompare_Dim1FailPortRaw(t *testing.T) {
	bm := makeTestBrandMap(t)
	contract := contractFor("lis", "dm8")
	ts := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	// PG banner in DM8 期望 → 维度 1 fail。
	portProbe := port.ProbeResult{
		SystemID:  "lis",
		Brand:     "pg-compat",
		Raw:       []byte("PostgreSQL 14.10 (Debian)"),
		Timestamp: ts,
	}
	driverScan := &driver.ScanResult{
		SystemID:  "lis",
		Dir:       "/tmp/jdbc",
		JarFile:   "Dm8JdbcDriver.jar",
		Sha256:    "abc123",
		IsKnown:   true,
		JDBCURLs:  []driver.JdbcURLEvidence{{File: "datasource.xml", LineNo: 5, URL: "jdbc:dm://10.0.1.21:5236/lis"}},
		ScannedAt: ts,
	}
	ev := Compare(contract, portProbe, driverScan, bm)
	if ev.Verdict != VerdictTrial {
		t.Errorf("维度 1 fail 应 trial，got %s", ev.Verdict)
	}
	if ev.Status != StateTrial {
		t.Errorf("默认 Status 应为 trial，got %s", ev.Status)
	}
	if len(ev.InconsistentDims) != 1 || ev.InconsistentDims[0] != "port_raw" {
		t.Errorf("InconsistentDims 应含 port_raw，got %v", ev.InconsistentDims)
	}
}

func TestCompare_Dim2FailDriverSha(t *testing.T) {
	bm := makeTestBrandMap(t)
	contract := contractFor("his-core", "kingbase")
	ts := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	portProbe := port.ProbeResult{
		SystemID:  "his-core",
		Brand:     "kingbase",
		Raw:       []byte("KingbaseES V008R006C0010"),
		Timestamp: ts,
	}
	driverScan := &driver.ScanResult{
		SystemID:  "his-core",
		Dir:       "/tmp/jdbc",
		JarFile:   "mystery.jar",
		Sha256:    "unknown-sha", // 不在 AllowDriftSHA256
		IsKnown:   false,
		JDBCURLs:  []driver.JdbcURLEvidence{{File: "datasource.xml", LineNo: 5, URL: "jdbc:kingbase8://10.0.1.21:5432/his"}},
		ScannedAt: ts,
	}
	ev := Compare(contract, portProbe, driverScan, bm)
	if ev.Verdict != VerdictTrial {
		t.Errorf("维度 2 fail 应 trial，got %s", ev.Verdict)
	}
	if len(ev.InconsistentDims) != 1 || ev.InconsistentDims[0] != "driver_sha" {
		t.Errorf("InconsistentDims 应含 driver_sha，got %v", ev.InconsistentDims)
	}
}

func TestCompare_Dim3FailJdbcURL(t *testing.T) {
	bm := makeTestBrandMap(t)
	contract := contractFor("his-core", "kingbase")
	ts := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	portProbe := port.ProbeResult{
		SystemID:  "his-core",
		Brand:     "kingbase",
		Raw:       []byte("KingbaseES V008R006C0010"),
		Timestamp: ts,
	}
	driverScan := &driver.ScanResult{
		SystemID:  "his-core",
		Dir:       "/tmp/jdbc",
		JarFile:   "kingbase8.jar",
		Sha256:    "abc123",
		IsKnown:   true,
		JDBCURLs:  []driver.JdbcURLEvidence{{File: "datasource.xml", LineNo: 5, URL: "jdbc:postgresql://10.0.1.21:5432/his"}}, // PG URL in kingbase 期望
		ScannedAt: ts,
	}
	ev := Compare(contract, portProbe, driverScan, bm)
	if ev.Verdict != VerdictTrial {
		t.Errorf("维度 3 fail 应 trial，got %s", ev.Verdict)
	}
	if len(ev.InconsistentDims) != 1 || ev.InconsistentDims[0] != "jdbc_url" {
		t.Errorf("InconsistentDims 应含 jdbc_url，got %v", ev.InconsistentDims)
	}
}

func TestCompare_AllFail(t *testing.T) {
	bm := makeTestBrandMap(t)
	contract := contractFor("his-core", "dm8")
	ts := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	portProbe := port.ProbeResult{
		SystemID:  "his-core",
		Brand:     "pg-compat",
		Raw:       []byte("PostgreSQL 14.10"),
		Timestamp: ts,
	}
	driverScan := &driver.ScanResult{
		SystemID:  "his-core",
		Dir:       "/tmp/jdbc",
		JarFile:   "x.jar",
		Sha256:    "unknown",
		IsKnown:   false,
		JDBCURLs:  []driver.JdbcURLEvidence{{File: "d.xml", LineNo: 1, URL: "jdbc:postgresql://10.0.1.21:5432/his"}},
		ScannedAt: ts,
	}
	ev := Compare(contract, portProbe, driverScan, bm)
	if ev.Verdict != VerdictTrial {
		t.Errorf("三维全 fail 应 trial，got %s", ev.Verdict)
	}
	if len(ev.InconsistentDims) != 3 {
		t.Errorf("全 fail 应有 3 个 InconsistentDims，got %v", ev.InconsistentDims)
	}
}

func TestCompare_EvidenceSHA_Deterministic(t *testing.T) {
	bm := makeTestBrandMap(t)
	contract := contractFor("his-core", "kingbase")
	ts := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	portProbe := port.ProbeResult{
		SystemID:  "his-core",
		Brand:     "pg-compat",
		Raw:       []byte("PostgreSQL 14.10"),
		Timestamp: ts,
	}
	driverScan := &driver.ScanResult{
		SystemID: "his-core",
		Dir:     "/tmp/jdbc",
		Sha256:  "abc123",
		JDBCURLs: []driver.JdbcURLEvidence{
			{File: "a.xml", LineNo: 1, URL: "jdbc:kingbase8://10.0.1.21:5432/his"},
			{File: "b.xml", LineNo: 2, URL: "jdbc:kingbase8://10.0.1.21:5432/his"},
		},
		ScannedAt: ts,
	}
	ev1 := Compare(contract, portProbe, driverScan, bm)
	ev2 := Compare(contract, portProbe, driverScan, bm)
	if ev1.EvidenceSHA256 != ev2.EvidenceSHA256 {
		t.Errorf("相同输入两次 Compare 应有相同 evidence_sha，got %s vs %s", ev1.EvidenceSHA256, ev2.EvidenceSHA256)
	}
	if len(ev1.EvidenceSHA256) != 64 {
		t.Errorf("evidence_sha 应为 64 字符 hex，got %d", len(ev1.EvidenceSHA256))
	}
}

func TestCompare_NilDriverScan(t *testing.T) {
	bm := makeTestBrandMap(t)
	contract := contractFor("his-core", "kingbase")
	ts := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	portProbe := port.ProbeResult{
		SystemID:  "his-core",
		Brand:     "kingbase",
		Raw:       []byte("KingbaseES V008R006C0010"),
		Timestamp: ts,
	}
	// nil driverScan → 维度 2 与 3 视为不存在；维度 1 决定 verdict。
	ev := Compare(contract, portProbe, nil, bm)
	if ev.Verdict != VerdictOK {
		t.Errorf("nil driverScan + 维度 1 match 应 ok，got %s", ev.Verdict)
	}
	if ev.DriverSha != "" {
		t.Errorf("nil driverScan DriverSha 应为空，got %s", ev.DriverSha)
	}
}

func TestCompare_ErrProbeUsesErrMessage(t *testing.T) {
	bm := makeTestBrandMap(t)
	contract := contractFor("his-core", "kingbase")
	ts := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	portProbe := port.ProbeResult{
		SystemID:  "his-core",
		Brand:     "kingbase",
		Raw:       nil,
		Err:       &probeErrorSim{"dial tcp: connection refused"},
		Timestamp: ts,
	}
	ev := Compare(contract, portProbe, nil, bm)
	// ErrProbeUsesErrMessage → actual = error message → classify mismatch → trial。
	if ev.Verdict != VerdictTrial {
		t.Errorf("err probe + dim1 mismatch 应 trial，got %s", ev.Verdict)
	}
	if !contains(ev.Actual, "connection refused") {
		t.Errorf("Actual 应包含错误信息，got %s", ev.Actual)
	}
}

// probeErrorSim 模拟 probe 失败时携带的错误。
type probeErrorSim struct{ msg string }

func (e *probeErrorSim) Error() string { return e.msg }

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
