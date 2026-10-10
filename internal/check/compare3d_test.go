// Package check — Compare3D 详细测试（T15 拆分）。
//
// 目标：把 T7 高层 Compare() 内部的三维核对抽到独立函数 Compare3D 后，
// 对每个维度独立构造 fixture 并断言 verdict + InconsistentDims。
//
// 三维独立 fail case + 全 fail + 全 pass + 边缘 case（nil driverScan /
// 空 portRaw / 未知 brand / 空 vendor.VersionRegex / driverSha 大小写 /
// 含空格 jdbcURL 等）。
package check

import (
	"strings"
	"testing"
	"time"

	"xinchuang-db-guardian/internal/config"
	"xinchuang-db-guardian/internal/probe/driver"
	"xinchuang-db-guardian/internal/probe/port"
)

// kbVendor / dmVendor / pgVendor / ogVendor — Compare3D 测试用固定 vendor fixture。
func kbVendor() config.VendorSignature {
	return config.VendorSignature{
		Brand:           "kingbase",
		VersionRegex:    []string{`(?i)KingbaseES\s+V\d+R\d+C\d+`},
		JDBCURLPattern:  []string{`jdbc:kingbase8://[^:]+:[0-9]+/[^?]+`},
		SignatureTokens: []string{"kingbasees"},
	}
}

func dmVendor() config.VendorSignature {
	return config.VendorSignature{
		Brand:           "dm8",
		VersionRegex:    []string{`(?i)DM\s*(?:8|Database)`},
		JDBCURLPattern:  []string{`jdbc:dm://[^:]+:[0-9]+`},
		SignatureTokens: []string{"dm", "dameng"},
	}
}

func pgVendor() config.VendorSignature {
	return config.VendorSignature{
		Brand:           "pg-compat",
		VersionRegex:    []string{`(?i)PostgreSQL\s+\d+\.\d+`},
		JDBCURLPattern:  []string{`jdbc:postgresql://[^:]+:[0-9]+/[^?]+`},
		SignatureTokens: []string{"postgresql"},
	}
}

// contractFor3D — 简化版 contract，AllowDriftSHA256 默认 ["abc123", "def456"]。
func contractFor3D(systemID, vendor string) config.ContractV {
	return config.ContractV{
		SystemID:         systemID,
		Vendor:           vendor,
		VersionPattern:   `.*`,
		AllowDriftSHA256: []string{"abc123", "def456"},
		ContractID:       "HT-2024-3D",
		Host:             "127.0.0.1",
		Port:             5432,
		ScanInterval:     10 * time.Minute,
		JdbcDriverDirs:   []string{"/tmp/jdbc"},
		EventIDPrefix:    "T3D",
	}
}

// portProbeFor — 简化版 portProbe 构造。
func portProbeFor(systemID, brand, raw string) port.ProbeResult {
	return port.ProbeResult{
		SystemID:  systemID,
		Brand:     brand,
		Raw:       []byte(raw),
		Timestamp: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
	}
}

// driverScanFor — 简化版 driverScan 构造（任意字段为零值表示"无证据"）。
func driverScanFor(systemID, sha string, jdbcURLs []driver.JdbcURLEvidence) *driver.ScanResult {
	return &driver.ScanResult{
		SystemID:  systemID,
		Dir:       "/tmp/jdbc",
		Sha256:    sha,
		IsKnown:   true,
		JDBCURLs:  jdbcURLs,
		ScannedAt: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
	}
}

// ==================== 三维独立 fail case ====================

// TestCompare3D_Dim1FailPortRawOnly — 维度 1 单独失败；维度 2/3 ok。
// vendor=kingbase 但 portRaw=PostgreSQL banner → 仅 port_raw fail。
func TestCompare3D_Dim1FailPortRawOnly(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "pg-compat", "PostgreSQL 14.10 (Debian)")
	driverScan := driverScanFor("his-core", "abc123", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "jdbc:kingbase8://10.0.1.21:5432/his"},
	})

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictTrial {
		t.Fatalf("dim1 fail 应 VerdictTrial，got %s", verdict)
	}
	if len(fails) != 1 || fails[0] != "port_raw" {
		t.Errorf("InconsistentDims 应仅含 port_raw，got %v", fails)
	}
}

// TestCompare3D_Dim2FailDriverShaOnly — 维度 2 单独失败（driverSha 不在白名单）。
func TestCompare3D_Dim2FailDriverShaOnly(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
	driverScan := driverScanFor("his-core", "unknown-sha-zzz", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "jdbc:kingbase8://10.0.1.21:5432/his"},
	})

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictTrial {
		t.Fatalf("dim2 fail 应 VerdictTrial，got %s", verdict)
	}
	if len(fails) != 1 || fails[0] != "driver_sha" {
		t.Errorf("InconsistentDims 应仅含 driver_sha，got %v", fails)
	}
}

// TestCompare3D_Dim3FailJdbcURLOnly — 维度 3 单独失败（JDBC URL 不命中 vendor pattern）。
func TestCompare3D_Dim3FailJdbcURLOnly(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
	driverScan := driverScanFor("his-core", "abc123", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "jdbc:postgresql://10.0.1.21:5432/his"}, // PG URL in kingbase 期望
	})

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictTrial {
		t.Fatalf("dim3 fail 应 VerdictTrial，got %s", verdict)
	}
	if len(fails) != 1 || fails[0] != "jdbc_url" {
		t.Errorf("InconsistentDims 应仅含 jdbc_url，got %v", fails)
	}
}

// ==================== 三维全 fail case ====================

// TestCompare3D_AllFail — vendor=dm8 但 portRaw=PostgreSQL + driverSha=unknown + PG JDBC URL。
func TestCompare3D_AllFail(t *testing.T) {
	v := dmVendor()
	c := contractFor3D("his-core", "dm8")
	portProbe := portProbeFor("his-core", "pg-compat", "PostgreSQL 14.10")
	driverScan := driverScanFor("his-core", "unknown-sha-zzz", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "jdbc:postgresql://10.0.1.21:5432/his"},
	})

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictTrial {
		t.Fatalf("三维全 fail 应 VerdictTrial，got %s", verdict)
	}
	if len(fails) != 3 {
		t.Fatalf("InconsistentDims 应有 3 个，got %v", fails)
	}
	// 维度顺序：port_raw → driver_sha → jdbc_url
	expected := []string{"port_raw", "driver_sha", "jdbc_url"}
	for i, dim := range expected {
		if fails[i] != dim {
			t.Errorf("InconsistentDims[%d] 应为 %q，got %q", i, dim, fails[i])
		}
	}
}

// TestCompare3D_Dim1AndDim3Fail — 维度 1+3 失败（典型 PG banner in DM 期望场景）。
func TestCompare3D_Dim1AndDim3Fail(t *testing.T) {
	v := dmVendor()
	c := contractFor3D("lis", "dm8")
	portProbe := portProbeFor("lis", "pg-compat", "PostgreSQL 14.10 (Debian)")
	driverScan := driverScanFor("lis", "abc123", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "jdbc:postgresql://10.0.1.21:5236/lis"}, // PG URL in DM 期望
	})

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictTrial {
		t.Fatalf("dim1+dim3 fail 应 VerdictTrial，got %s", verdict)
	}
	if len(fails) != 2 {
		t.Fatalf("InconsistentDims 应有 2 个，got %v", fails)
	}
	if fails[0] != "port_raw" || fails[1] != "jdbc_url" {
		t.Errorf("InconsistentDims 应为 [port_raw, jdbc_url]，got %v", fails)
	}
}

// ==================== 三维全 pass case ====================

// TestCompare3D_AllPass — vendor=kingbase + portRaw=KingbaseES + driverSha 在白名单 + kingbase8 JDBC URL。
func TestCompare3D_AllPass(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
	driverScan := driverScanFor("his-core", "abc123", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "jdbc:kingbase8://10.0.1.21:5432/his"},
	})

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictOK {
		t.Fatalf("三维全 ok 应 VerdictOK，got %s", verdict)
	}
	if len(fails) != 0 {
		t.Errorf("三维全 ok 应无 InconsistentDims，got %v", fails)
	}
}

// TestCompare3D_AllPass_PGCompat — PG 兼容族：PostgreSQL banner + PG JDBC URL。
func TestCompare3D_AllPass_PGCompat(t *testing.T) {
	v := pgVendor()
	c := contractFor3D("his-bak", "pg-compat")
	c.AllowDriftSHA256 = []string{"pg-sha-001"}
	portProbe := portProbeFor("his-bak", "pg-compat", "PostgreSQL 14.10 (Debian 14.10-1)")
	driverScan := driverScanFor("his-bak", "pg-sha-001", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "jdbc:postgresql://10.0.1.21:5432/his-bak"},
	})

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictOK {
		t.Fatalf("PG 三维全 ok 应 VerdictOK，got %s", verdict)
	}
	if len(fails) != 0 {
		t.Errorf("PG 三维全 ok 应无 InconsistentDims，got %v", fails)
	}
}

// ==================== 边缘 case ====================

// TestCompare3D_NilDriverScan — nil driverScan → 维度 2/3 视为"无证据"，**不**计为失败。
// 若维度 1 也 ok → verdict=ok；若维度 1 fail → 仅 port_raw fail。
func TestCompare3D_NilDriverScan(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")

	t.Run("维度1ok + nil driver → ok", func(t *testing.T) {
		portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
		verdict, fails := Compare3D(portProbe, nil, v, c)
		if verdict != VerdictOK {
			t.Errorf("维度 1 ok + nil driverScan 应 ok，got %s", verdict)
		}
		if len(fails) != 0 {
			t.Errorf("nil driverScan 不应有 InconsistentDims，got %v", fails)
		}
	})

	t.Run("维度1fail + nil driver → 仅 port_raw", func(t *testing.T) {
		portProbe := portProbeFor("his-core", "pg-compat", "PostgreSQL 14.10")
		verdict, fails := Compare3D(portProbe, nil, v, c)
		if verdict != VerdictTrial {
			t.Errorf("维度 1 fail + nil driverScan 应 trial，got %s", verdict)
		}
		if len(fails) != 1 || fails[0] != "port_raw" {
			t.Errorf("InconsistentDims 应仅含 port_raw，got %v", fails)
		}
	})
}

// TestCompare3D_EmptyDriverSha — driverScan 非 nil 但 Sha256="" → 维度 2 视为"无证据"。
func TestCompare3D_EmptyDriverSha(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
	// driverScan 非 nil 但 Sha256 为空 + jdbcURLs 为空 → 维度 2/3 均无证据
	driverScan := &driver.ScanResult{
		SystemID:  "his-core",
		Dir:       "/tmp/jdbc",
		Sha256:    "",
		IsKnown:   false,
		JDBCURLs:  nil,
		ScannedAt: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
	}

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictOK {
		t.Errorf("空 driverSha + 空 jdbcURLs 应 ok，got %s", verdict)
	}
	if len(fails) != 0 {
		t.Errorf("空 driverSha + 空 jdbcURLs 应无 InconsistentDims，got %v", fails)
	}
}

// TestCompare3D_DriverShaCaseInsensitive — AllowDriftSHA256 集合大小写不敏感。
func TestCompare3D_DriverShaCaseInsensitive(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	c.AllowDriftSHA256 = []string{"ABC123", "DEF456"} // 大写
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
	driverScan := driverScanFor("his-core", "abc123", nil) // 小写应仍命中

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictOK {
		t.Errorf("driverSha 大小写不敏感应 ok，got %s", verdict)
	}
	if len(fails) != 0 {
		t.Errorf("大小写不敏感应无 InconsistentDims，got %v", fails)
	}
}

// TestCompare3D_DriverShaWithWhitespace — driverSha 含前后空格仍命中白名单。
func TestCompare3D_DriverShaWithWhitespace(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	c.AllowDriftSHA256 = []string{"abc123"}
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
	// driverScan.Sha256 含前后空格 → ToLower + TrimSpace 后应命中
	driverScan := driverScanFor("his-core", "  abc123  ", nil)

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictOK {
		t.Errorf("driverSha 含空格应 ok，got %s", verdict)
	}
	if len(fails) != 0 {
		t.Errorf("含空格应无 InconsistentDims，got %v", fails)
	}
}

// TestCompare3D_EmptyPortRaw — portRaw="" + 无 Err → 走 unknown 路径。
func TestCompare3D_EmptyPortRaw(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := port.ProbeResult{
		SystemID:  "his-core",
		Brand:     "kingbase",
		Raw:       nil,
		Err:       nil,
		Timestamp: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
	}
	driverScan := driverScanFor("his-core", "abc123", nil)

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	// 空 portRaw → port_raw fail
	if verdict != VerdictTrial {
		t.Errorf("空 portRaw 应 trial，got %s", verdict)
	}
	if len(fails) != 1 || fails[0] != "port_raw" {
		t.Errorf("InconsistentDims 应含 port_raw，got %v", fails)
	}
}

// TestCompare3D_PortProbeErrMessage — portRaw 为空但 Err 非空 → actual=err.Error() → 走比对。
func TestCompare3D_PortProbeErrMessage(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := port.ProbeResult{
		SystemID:  "his-core",
		Brand:     "kingbase",
		Raw:       nil,
		Err:       &probeErrorSim3D{"dial tcp: connection refused"},
		Timestamp: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
	}
	driverScan := driverScanFor("his-core", "abc123", nil)

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	// err.Error() 不含 KingbaseES 等关键字 → port_raw fail
	if verdict != VerdictTrial {
		t.Errorf("portProbe 失败应 trial，got %s", verdict)
	}
	if len(fails) != 1 || fails[0] != "port_raw" {
		t.Errorf("InconsistentDims 应含 port_raw，got %v", fails)
	}
}

// TestCompare3D_VendorEmptyVersionRegex — vendor.VersionRegex 为空 → 走 token 命中或 unknown。
func TestCompare3D_VendorEmptyVersionRegex(t *testing.T) {
	v := config.VendorSignature{
		Brand:           "kingbase",
		VersionRegex:    []string{}, // 空
		JDBCURLPattern:  []string{`jdbc:kingbase8://[^:]+:[0-9]+/[^?]+`},
		SignatureTokens: []string{"kingbasees"},
	}
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
	driverScan := driverScanFor("his-core", "abc123", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "jdbc:kingbase8://10.0.1.21:5432/his"},
	})

	// VersionRegex 为空 + SignatureTokens 有 "kingbasees" → token 层应命中 → match
	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictOK {
		t.Errorf("空 VersionRegex + token 命中应 ok，got %s (fails=%v)", verdict, fails)
	}
}

// TestCompare3D_VendorNoSignatureTokens — vendor.SignatureTokens 也为空 → 走 unknown → fail。
func TestCompare3D_VendorNoSignatureTokens(t *testing.T) {
	v := config.VendorSignature{
		Brand:           "kingbase",
		VersionRegex:    []string{},
		JDBCURLPattern:  []string{`jdbc:kingbase8://[^:]+:[0-9]+/[^?]+`},
		SignatureTokens: []string{}, // 空
	}
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
	driverScan := driverScanFor("his-core", "abc123", nil)

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	// VersionRegex + SignatureTokens 都为空 → unknown → port_raw fail
	if verdict != VerdictTrial {
		t.Errorf("空 VersionRegex + 空 SignatureTokens 应 trial，got %s", verdict)
	}
	if len(fails) != 1 || fails[0] != "port_raw" {
		t.Errorf("InconsistentDims 应含 port_raw，got %v", fails)
	}
}

// TestCompare3D_MultipleJdbcURLs_AtLeastOneMatch — 多条 jdbcURL 时，任一命中即视为 ok。
func TestCompare3D_MultipleJdbcURLs_AtLeastOneMatch(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
	driverScan := driverScanFor("his-core", "abc123", []driver.JdbcURLEvidence{
		{File: "a.xml", LineNo: 1, URL: "jdbc:oracle:thin:@host:1521:sid"},
		{File: "b.xml", LineNo: 2, URL: "jdbc:kingbase8://10.0.1.21:5432/his"}, // 命中
		{File: "c.xml", LineNo: 3, URL: "jdbc:dm://host:5236/dm"},
	})

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictOK {
		t.Errorf("多条 jdbcURL 有一条命中应 ok，got %s (fails=%v)", verdict, fails)
	}
	if len(fails) != 0 {
		t.Errorf("任一命中应无 InconsistentDims，got %v", fails)
	}
}

// TestCompare3D_WhitespacePortRaw — portRaw 全空白 → 走 unknown 路径 → fail。
func TestCompare3D_WhitespacePortRaw(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "kingbase", "   \t\n  ")
	driverScan := driverScanFor("his-core", "abc123", nil)

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictTrial {
		t.Errorf("全空白 portRaw 应 trial，got %s", verdict)
	}
	if len(fails) != 1 || fails[0] != "port_raw" {
		t.Errorf("InconsistentDims 应含 port_raw，got %v", fails)
	}
}

// TestCompare3D_JdbcURLWithLeadingTrailingSpace — jdbcURL 含空格仍能命中 regex。
func TestCompare3D_JdbcURLWithLeadingTrailingSpace(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
	driverScan := driverScanFor("his-core", "abc123", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "  jdbc:kingbase8://10.0.1.21:5432/his  "},
	})

	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictOK {
		t.Errorf("jdbcURL 含空格应 ok（regex 容忍），got %s (fails=%v)", verdict, fails)
	}
}

// TestCompare3D_Deterministic — 同一输入两次 Compare3D 应返回相同 verdict + fails。
func TestCompare3D_Deterministic(t *testing.T) {
	v := dmVendor()
	c := contractFor3D("lis", "dm8")
	portProbe := portProbeFor("lis", "pg-compat", "PostgreSQL 14.10 (Debian)")
	driverScan := driverScanFor("lis", "unknown-sha", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "jdbc:postgresql://10.0.1.21:5236/lis"},
	})

	v1, f1 := Compare3D(portProbe, driverScan, v, c)
	v2, f2 := Compare3D(portProbe, driverScan, v, c)
	if v1 != v2 {
		t.Errorf("verdict 不确定性：%s vs %s", v1, v2)
	}
	if len(f1) != len(f2) {
		t.Fatalf("InconsistentDims 长度不一致：%v vs %v", f1, f2)
	}
	for i := range f1 {
		if f1[i] != f2[i] {
			t.Errorf("InconsistentDims[%d] 不一致：%q vs %q", i, f1[i], f2[i])
		}
	}
}

// TestCompare3D_VendorSignatureUsed — Compare3D 不读 BrandMap，只用传入 vendor。
// 即使 brandMap 为 nil，Compare3D 也能正常工作。
func TestCompare3D_VendorSignatureUsed(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C0010")
	driverScan := driverScanFor("his-core", "abc123", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "jdbc:kingbase8://10.0.1.21:5432/his"},
	})

	// 直接传 vendor，不依赖 BrandMap。
	verdict, fails := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictOK {
		t.Errorf("独立 vendor 入参应 ok，got %s (fails=%v)", verdict, fails)
	}
}

// TestCompare3D_MultiDimOrdering — 三维全 fail 时 InconsistentDims 顺序固定。
func TestCompare3D_MultiDimOrdering(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := portProbeFor("his-core", "pg-compat", "PostgreSQL 14.10")
	driverScan := driverScanFor("his-core", "unknown-sha", []driver.JdbcURLEvidence{
		{File: "ds.xml", LineNo: 5, URL: "jdbc:postgresql://10.0.1.21:5432/his"},
	})

	_, fails := Compare3D(portProbe, driverScan, v, c)
	want := []string{"port_raw", "driver_sha", "jdbc_url"}
	if len(fails) != len(want) {
		t.Fatalf("len(fails)=%d，want %d", len(fails), len(want))
	}
	for i := range want {
		if fails[i] != want[i] {
			t.Errorf("fails[%d]=%q，want %q", i, fails[i], want[i])
		}
	}
}

// TestCompare3D_PG_15Cases — 5 品牌 × 3 case = 15 case 对照测试。
// kingbase × 3 / dm8 × 3 / openGauss × 3 / IvorySQL × 3 / pg-compat × 3。
func TestCompare3D_PG_15Cases(t *testing.T) {
	type tc struct {
		vendor config.VendorSignature
		actual string
		want   bool // true=match, false=mismatch
	}
	cases := []tc{
		// kingbase × 3
		{kbVendor(), "KingbaseES V008R006C0010", true},
		{kbVendor(), "KingbaseES V008R006C10B0010 (PostgreSQL 13.6 compatible)", true},
		{kbVendor(), "KingbaseES V007R006C0030", true},
		// dm8 × 3
		{dmVendor(), "DM Database Server V8.1.0", true},
		{dmVendor(), "DM Database Server V8.1.2-Build(12345)", true},
		{dmVendor(), "DM8 Database", true},
		// openGauss × 3（自定义 vendor）
		{config.VendorSignature{
			Brand: "opengauss", VersionRegex: []string{`(?i)openGauss\s+\d+\.\d+`},
			JDBCURLPattern: []string{`jdbc:opengauss://[^:]+:[0-9]+/[^?]+`},
			SignatureTokens: []string{"opengauss"},
		}, "openGauss 5.0.0 build 12345", true},
		{config.VendorSignature{
			Brand: "opengauss", VersionRegex: []string{`(?i)openGauss\s+\d+\.\d+`},
			JDBCURLPattern: []string{`jdbc:opengauss://[^:]+:[0-9]+/[^?]+`},
			SignatureTokens: []string{"opengauss"},
		}, "openGauss 3.0.0", true},
		{config.VendorSignature{
			Brand: "opengauss", VersionRegex: []string{`(?i)openGauss\s+\d+\.\d+`},
			JDBCURLPattern: []string{`jdbc:opengauss://[^:]+:[0-9]+/[^?]+`},
			SignatureTokens: []string{"opengauss"},
		}, "openGauss 5.0.0 (compatible with PostgreSQL 14)", true},
		// IvorySQL × 3
		{config.VendorSignature{
			Brand: "ivorysql", VersionRegex: []string{`(?i)IvorySQL\s+\d+\.\d+`},
			JDBCURLPattern: []string{`jdbc:ivorysql://[^:]+:[0-9]+/[^?]+`},
			SignatureTokens: []string{"ivorysql"},
		}, "IvorySQL 1.4 on x86_64", true},
		{config.VendorSignature{
			Brand: "ivorysql", VersionRegex: []string{`(?i)IvorySQL\s+\d+\.\d+`},
			JDBCURLPattern: []string{`jdbc:ivorysql://[^:]+:[0-9]+/[^?]+`},
			SignatureTokens: []string{"ivorysql"},
		}, "IvorySQL 1.2 (based on PostgreSQL 13)", true},
		{config.VendorSignature{
			Brand: "ivorysql", VersionRegex: []string{`(?i)IvorySQL\s+\d+\.\d+`},
			JDBCURLPattern: []string{`jdbc:ivorysql://[^:]+:[0-9]+/[^?]+`},
			SignatureTokens: []string{"ivorysql"},
		}, "IvorySQL 1.4 (瀚高)", true},
		// pg-compat × 3
		{pgVendor(), "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1)", true},
		{pgVendor(), "PostgreSQL 13.6", true},
		{pgVendor(), "PostgreSQL 11.2", true},
	}

	for i, c := range cases {
		// 不传 driverScan → 维度 2/3 视为无证据；只看维度 1
		portProbe := portProbeFor("sys", c.vendor.Brand, c.actual)
		verdict, fails := Compare3D(portProbe, nil, c.vendor, contractFor3D("sys", c.vendor.Brand))
		expected := VerdictOK
		if !c.want {
			expected = VerdictTrial
		}
		if verdict != expected {
			t.Errorf("case %d (vendor=%s, actual=%q): verdict=%s, want %s",
				i, c.vendor.Brand, c.actual, verdict, expected)
		}
		_ = fails // fails 在 ok 时为 nil；trial 时至少含 port_raw
	}
}

// TestCompare3D_PG_15Cases_PG_BannerInDM8 — 反误判：PG 14.10 banner 在 DM8 期望下 mismatch。
func TestCompare3D_PG_15Cases_PG_BannerInDM8(t *testing.T) {
	v := dmVendor()
	portProbe := portProbeFor("lis", "pg-compat", "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1)")
	verdict, fails := Compare3D(portProbe, nil, v, contractFor3D("lis", "dm8"))
	if verdict != VerdictTrial {
		t.Errorf("PG banner in DM 期望应 mismatch，got %s", verdict)
	}
	if len(fails) != 1 || fails[0] != "port_raw" {
		t.Errorf("InconsistentDims 应仅含 port_raw，got %v", fails)
	}
}

// TestCompare3D_PG_15Cases_FakeKingbase — Kingbase 伪 Kingbase：含 PostgreSQL 但无 KingbaseES。
func TestCompare3D_PG_15Cases_FakeKingbase(t *testing.T) {
	v := kbVendor()
	portProbe := portProbeFor("his-core", "kingbase", "PostgreSQL 13.6 (Kingbase Marketing Wrapper)")
	verdict, fails := Compare3D(portProbe, nil, v, contractFor3D("his-core", "kingbase"))
	if verdict != VerdictTrial {
		t.Errorf("PostgreSQL-only 伪 Kingbase 应 mismatch，got %s", verdict)
	}
	if len(fails) != 1 || fails[0] != "port_raw" {
		t.Errorf("InconsistentDims 应仅含 port_raw，got %v", fails)
	}
}

// TestCompare3D_PG_15Cases_RealKingbaseWithPGCompat — 真 Kingbase + PG 兼容模式 → match。
func TestCompare3D_PG_15Cases_RealKingbaseWithPGCompat(t *testing.T) {
	v := kbVendor()
	portProbe := portProbeFor("his-core", "kingbase", "KingbaseES V008R006C10B0010 (PostgreSQL 13.6 compatible)")
	verdict, fails := Compare3D(portProbe, nil, v, contractFor3D("his-core", "kingbase"))
	if verdict != VerdictOK {
		t.Errorf("真 Kingbase + PG 兼容应 match，got %s (fails=%v)", verdict, fails)
	}
}

// ==================== 不变量 ====================

// TestCompare3D_InconsistentDimsNeverContainsUnknown — InconsistentDims 仅含已知 dim 名。
func TestCompare3D_InconsistentDimsNeverContainsUnknown(t *testing.T) {
	knownDims := map[string]bool{"port_raw": true, "driver_sha": true, "jdbc_url": true}

	// 跑若干组合
	v := kbVendor()
	cases := []struct {
		probe port.ProbeResult
		ds    *driver.ScanResult
	}{
		{portProbeFor("a", "pg-compat", "PostgreSQL 14"), nil},
		{portProbeFor("a", "kingbase", "KingbaseES V8R6C10"), driverScanFor("a", "zzz", nil)},
		{portProbeFor("a", "kingbase", "KingbaseES V8R6C10"), driverScanFor("a", "abc123", []driver.JdbcURLEvidence{
			{File: "x", LineNo: 1, URL: "jdbc:pg://h:1/d"},
		})},
	}

	for i, tc := range cases {
		_, fails := Compare3D(tc.probe, tc.ds, v, contractFor3D("his-core", "kingbase"))
		for _, f := range fails {
			if !knownDims[f] {
				t.Errorf("case %d: InconsistentDims 含未知维度 %q", i, f)
			}
		}
	}
}

// TestCompare3D_NilPortProbeRaw_NoPanic — portProbe.Raw=nil + Err=nil + 其它非空 → 不 panic。
func TestCompare3D_NilPortProbeRaw_NoPanic(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	portProbe := port.ProbeResult{
		SystemID:  "his-core",
		Brand:     "kingbase",
		Raw:       nil,
		Err:       nil,
		Timestamp: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
	}
	driverScan := driverScanFor("his-core", "abc123", nil)

	// 不应 panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Compare3D 不应 panic：%v", r)
		}
	}()
	_, _ = Compare3D(portProbe, driverScan, v, c)
}

// TestCompare3D_LongActual_NoPanic — 长 portRaw（4KB+）不 panic。
func TestCompare3D_LongActual_NoPanic(t *testing.T) {
	v := kbVendor()
	c := contractFor3D("his-core", "kingbase")
	longRaw := strings.Repeat("KingbaseES V008R006C0010 padding ", 200) // ~5KB
	portProbe := portProbeFor("his-core", "kingbase", longRaw)
	driverScan := driverScanFor("his-core", "abc123", nil)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Compare3D 长 portRaw 不应 panic：%v", r)
		}
	}()
	verdict, _ := Compare3D(portProbe, driverScan, v, c)
	if verdict != VerdictOK {
		t.Errorf("长 KingbaseES banner 应 ok，got %s", verdict)
	}
}

// probeErrorSim3D — 模拟 probe 失败时的 error 类型。
type probeErrorSim3D struct{ msg string }

func (e *probeErrorSim3D) Error() string { return e.msg }