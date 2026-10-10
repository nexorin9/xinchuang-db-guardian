//go:build integration
// +build integration

// Package integration_test — dockertest 集成测试与对照测试集合。
//
// Build tag: integration — 默认 go test 不跑；显式 -tags=integration 启用。
//
// 本文件聚焦协议层真实握手 vs 容器层真实握手的一致性：
//  1) dockertest 拉 postgres:14 容器 + port.Handshake 真实握手 → brand=pg-compat；
//  2) dockertest 拉 postgres:14 容器（声明成 kingbase 制造漂移）→ check.Compare
//     真实三维核对 → verdict=trial；
//  3) dockertest 不可用 / 沙箱无 docker 时所有测试 t.Skip 优雅跳过，不阻断其他包；
//  4) Kingbase dev 容器集成测试：仅在 KINGBASE_DEV_IMAGE 环境变量设置时启用
//     （商业镜像需用户从供应商处获取并设置）；不设置 → t.Skip。
//
// 与 cmd/xinchuang-guardian/smoke_dockertest_test.go 的关系：
//   - 那个文件是端到端 smoke（PG 容器 + 桩 LLM + 守护 → evidence.zip）；
//   - 本文件聚焦**单点协议层**：handshake 品牌识别 + 三维核对 trial 状态机
//     + version strings fixture 与 brand classifier 的契约一致性。
package integration_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"xinchuang-db-guardian/internal/check"
	"xinchuang-db-guardian/internal/config"
	"xinchuang-db-guardian/internal/probe/driver"
	"xinchuang-db-guardian/internal/probe/port"
	"xinchuang-db-guardian/internal/probe/version"
)

// dockerAvailable — 探测 docker daemon 可用性。
//
// 探测策略：exec `docker info`；不可执行或非零退出 → false。
// 沙箱 / CI 无 docker 时返回 false，测试 t.Skip。
func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// pullPostgresContainer — 起 postgres:14 容器，返回 host + portStr + cleanup。
//
// 容器特性：
//   - 公开 5432/tcp；
//   - POSTGRES_PASSWORD=postgrespw（探测用，业务无关）；
//   - AutoRemove=true，cleanup 时 docker rm -f；
//   - pool.Retry 等端口就绪后再返回。
func pullPostgresContainer(t *testing.T) (host, portStr string, portNum int, cleanup func()) {
	t.Helper()
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("dockertest.NewPool 失败（docker socket 不可访问）: %v", err)
	}
	pool.MaxWait = 60 * time.Second

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "14",
		Env: []string{
			"POSTGRES_PASSWORD=postgrespw",
			"POSTGRES_USER=postgres",
			"POSTGRES_DB=postgres",
		},
		ExposedPorts: []string{"5432/tcp"},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Skipf("postgres:14 容器拉起失败: %v", err)
	}

	cleanup = func() { _ = pool.Purge(resource) }

	hostPort := resource.GetHostPort("5432/tcp")
	var hostOnly, portOnly string
	if _, splitErr := fmt.Sscanf(hostPort, "%s:%s", &hostOnly, &portOnly); splitErr != nil {
		// fallback: 用 net.SplitHostPort
		h, p, sErr := net.SplitHostPort(hostPort)
		if sErr != nil {
			cleanup()
			t.Fatalf("splitHostPort(%q): %v", hostPort, sErr)
		}
		hostOnly, portOnly = h, p
	}
	portNum = 0
	if _, err := fmt.Sscanf(portOnly, "%d", &portNum); err != nil {
		cleanup()
		t.Fatalf("parse port %q: %v", portOnly, err)
	}

	// 等端口可连接
	if err := pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort(hostOnly, portOnly), 2*time.Second)
		if dialErr != nil {
			return dialErr
		}
		_ = conn.Close()
		return nil
	}); err != nil {
		cleanup()
		t.Skipf("postgres 端口 %s 60s 内未就绪: %v", hostPort, err)
	}

	return hostOnly, portOnly, portNum, cleanup
}

// TestDockerIntegration_AvailableOrSkip — 探测 docker 可用性并 t.Skip。
//
// 作为所有 dockertest 测试的前置 sanity 检查；调用方也可独立使用本探测。
func TestDockerIntegration_AvailableOrSkip(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker daemon 不可用；跳过 dockertest 集成测试（CI 无 docker 时常见）")
	}
	// 可用即通过；本测试主要起 gate 作用。
	t.Log("docker daemon 可用")
}

// TestDockerIntegration_PG14Handshake_RealContainer — 真实 postgres:14 容器握手 → brand=pg-compat。
//
// 验收：
//   - 容器可达；
//   - port.Handshake 解析返回 Raw 含 'PostgreSQL' 关键字（PG 14.x 默认 banner）；
//   - classifyPGBanner 派生 brand = BrandPGCompat；
//   - version.Parse 提取出 Major=14（容器版本）。
func TestDockerIntegration_PG14Handshake_RealContainer(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker daemon 不可用；跳过 dockertest 集成测试")
	}

	host, portStr, _, cleanup := pullPostgresContainer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hsResult, hsErr := port.Handshake(ctx, net.JoinHostPort(host, portStr))
	require.NoError(t, hsErr, "real postgres:14 容器握手失败")
	require.NotEmpty(t, hsResult.Raw)
	require.Equal(t, port.BrandPGCompat, hsResult.Brand,
		"真实 PG 14 容器应被识别为 pg-compat")

	// Raw 必须含 PostgreSQL 关键字（real banner），从而 classifier 命中 pg-compat。
	rawStr := string(hsResult.Raw)
	require.Contains(t, rawStr, "PostgreSQL", "真实 PG banner 应含 PostgreSQL 关键字")

	// version.Parse 提取 Major。
	parsed := version.Parse(string(hsResult.Raw), port.BrandPGCompat)
	require.True(t, parsed.ParsedOK, "真实 PG banner 应能被 version.Parse 解析")
	require.GreaterOrEqual(t, parsed.Major, 11, "PG Major 版本应 ≥ 11")
	require.Contains(t, parsed.Raw, "PostgreSQL")
}

// TestDockerIntegration_PG14Handshake_DeclaredKingbaseMakesDrift —
// 真实 postgres:14 容器 + 声明 vendor=kingbase + 真实三维核对 → verdict=trial。
//
// 端到端协议：声明 PG 容器为 kingbase，握手识别为 pg-compat，三维核对产出 trial。
func TestDockerIntegration_PG14Handshake_DeclaredKingbaseMakesDrift(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker daemon 不可用；跳过 dockertest 集成测试")
	}

	host, portStr, portNum, cleanup := pullPostgresContainer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hsResult, err := port.Handshake(ctx, net.JoinHostPort(host, portStr))
	require.NoError(t, err)
	require.Equal(t, port.BrandPGCompat, hsResult.Brand)

	// 构造 contracts.yaml / vendor_signatures.yaml 临时内容
	contracts, brands := makeDeclaredKingbaseConfig(t, host, portStr, portNum)
	require.Len(t, contracts, 1)
	require.Equal(t, "intg-pg-drift", contracts[0].SystemID)
	require.Equal(t, "kingbase", contracts[0].Vendor)

	// brandMap 应含 kingbase
	brandMap := config.NewBrandMap()
	brandMap.Set(brands)
	kbVS, ok := brandMap.Get("kingbase")
	require.True(t, ok, "brandMap.Get('kingbase') 必须命中")

	// 真实三维核对
	probeResult := port.ProbeResult{
		SystemID: contracts[0].SystemID,
		Raw:      hsResult.Raw,
		Brand:    hsResult.Brand,
	}

	driverScan := &driver.ScanResult{
		Dir:       "/tmp/none",
		ScannedAt: time.Now().UTC(),
		JDBCURLs:  []driver.JdbcURLEvidence{},
	}
	verdict, inconsistentDims := check.Compare3D(probeResult, driverScan, kbVS, contracts[0])
	require.Equal(t, check.VerdictTrial, verdict, "PG banner 在 kbase 期望下必须产出 trial")
	require.Contains(t, inconsistentDims, "port_raw", "不一致维度必含 port_raw")

	// evidence 计算
	evidence := check.DriftEvidence{
		EventID:    "INTG-DRIFT-1",
		ContractID: contracts[0].ContractID,
		SystemID:   contracts[0].SystemID,
		Vendor:     contracts[0].Vendor,
		Declared:   contracts[0].VersionPattern,
		Actual:     string(hsResult.Raw),
		PortRaw:    string(hsResult.Raw),
		JDBCURL:    fmt.Sprintf("jdbc:kingbase8://%s:%d/intg", host, portNum),
		Verdict:    verdict,
		Confidence: 0.98,
		Status:     check.StateTrial,
	}
	ts := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	evidence.EvidenceSHA256 = check.ComputeEvidenceSHA256(
		evidence.PortRaw, "", evidence.JDBCURL, evidence.SystemID, ts,
	)

	// evidence_sha256 64-hex + 不全 0
	require.Len(t, evidence.EvidenceSHA256, 64)
	require.NotEqual(t, strings.Repeat("0", 64), evidence.EvidenceSHA256)
}

// TestDockerIntegration_KingbaseDevContainer — 真实 Kingbase dev 容器握手（可选）。
//
// 默认 t.Skip；仅当环境变量 KINGBASE_DEV_IMAGE 设置（如 "registry.local/kbdev:1.0"）
// 时启用。镜像拉取可能慢；用户从供应商处获取并自行设置。
func TestDockerIntegration_KingbaseDevContainer(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker daemon 不可用；跳过 dockertest 集成测试")
	}
	image := os.Getenv("KINGBASE_DEV_IMAGE")
	if image == "" {
		t.Skip("KINGBASE_DEV_IMAGE 未设置；跳过 Kingbase dev 容器集成测试（商业镜像需用户提供）")
	}

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	pool.MaxWait = 90 * time.Second

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: splitImageRepository(image),
		Tag:        splitImageTag(image),
		Env: []string{
			"KB_USER=kingbase",
			"KB_PASSWORD=kingpass",
		},
		ExposedPorts: []string{"54321/tcp"},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
	})
	require.NoError(t, err, "Kingbase dev 容器拉起失败")
	defer func() { _ = pool.Purge(resource) }()

	hostPort := resource.GetHostPort("54321/tcp")
	require.NotEmpty(t, hostPort, "Kingbase 容器端口映射失败")

	if err := pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", hostPort, 2*time.Second)
		if dialErr != nil {
			return dialErr
		}
		_ = conn.Close()
		return nil
	}); err != nil {
		t.Skipf("Kingbase dev 端口 %s 90s 内未就绪: %v", hostPort, err)
	}

	host, portStr, _ := net.SplitHostPort(hostPort)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hsResult, err := port.Handshake(ctx, net.JoinHostPort(host, portStr))
	require.NoError(t, err, "Kingbase dev 容器握手失败")
	require.Equal(t, port.BrandKingbaseES, hsResult.Brand,
		"Kingbase dev 容器应被识别为 kingbase（而非 pg-compat）")

	rawStr := string(hsResult.Raw)
	require.True(t,
		strings.Contains(rawStr, "KingbaseES") || strings.Contains(rawStr, "kingbase"),
		"Kingbase dev 容器 banner 应含 KingbaseES 关键字")
}

// TestDockerIntegration_VersusLocalMock — 真实容器 vs 本地 mock 协议一致性。
//
// 验证：本地 PG wire mock 与真实 postgres:14 容器在 port.Handshake 层品牌识别一致；
// 防止「mock 通过 + 真实容器失败」的协议漂移。
func TestDockerIntegration_VersusLocalMock(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker daemon 不可用；跳过 dockertest 集成测试")
	}

	// 1. 本地 mock 起的容器（实际就是 PG wire mock server）
	mockSrv := newPGWireMock(t, "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1)")
	defer mockSrv.Stop()

	mockCtx, mockCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer mockCancel()
	mockResult, err := port.Handshake(mockCtx, mockSrv.Addr())
	require.NoError(t, err)
	require.Equal(t, port.BrandPGCompat, mockResult.Brand, "本地 mock 应被识别为 pg-compat")

	// 2. 真实容器
	host, portStr, _, c2cleanup := pullPostgresContainer(t)
	defer c2cleanup()

	realCtx, realCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer realCancel()
	realResult, err := port.Handshake(realCtx, net.JoinHostPort(host, portStr))
	require.NoError(t, err)
	require.Equal(t, port.BrandPGCompat, realResult.Brand,
		"真实 postgres:14 容器应被识别为 pg-compat")

	// 两个 brand 必须一致
	require.Equal(t, mockResult.Brand, realResult.Brand,
		"本地 mock vs 真实容器 brand 不一致 — 协议漂移")

	// Raw 都含 "PostgreSQL" 关键字（真实 PG banner 必有）
	require.Contains(t, string(mockResult.Raw), "PostgreSQL")
	require.Contains(t, string(realResult.Raw), "PostgreSQL")
}

// ----- 工具函数 -----

// makeDeclaredKingbaseConfig — 构造一份临时 contracts + vendor 配置（声明 PG 容器为 kingbase）。
func makeDeclaredKingbaseConfig(t *testing.T, host, portStr string, portNum int) ([]config.ContractV, []config.VendorSignature) {
	t.Helper()

	contractsYAML := fmt.Sprintf(`declared:
  - system_id: intg-pg-drift
    vendor: kingbase
    version_pattern: "V008R006C10.*"
    allow_drift_sha256: []
    contract_id: INTG-DRIFT
    host: %s
    port: %d
    scan_interval: 1s
    jdbc_driver_dirs:
      - /tmp/none
    event_id_prefix: INTG-DRIFT
`, host, portNum)

	contractsPath := filepath.Join(t.TempDir(), "contracts.yaml")
	require.NoError(t, os.WriteFile(contractsPath, []byte(contractsYAML), 0o644))

	contracts, err := config.LoadContracts(contractsPath)
	require.NoError(t, err)

	vendorYAML := `brands:
  - brand: kingbase
    version_regex:
      - "(?i)KingbaseES\s+V\d+R\d+C\d+"
    jdbc_url_pattern:
      - "jdbc:kingbase8://[^:]+:[0-9]+/[^?]+"
    signature_tokens:
      - "KingbaseES"
      - "V008"
    known_jar_sha256: []
`
	vendorPath := filepath.Join(t.TempDir(), "vendor_signatures.yaml")
	require.NoError(t, os.WriteFile(vendorPath, []byte(vendorYAML), 0o644))

	brands, err := config.LoadVendorSignatures(vendorPath)
	require.NoError(t, err)
	return contracts, brands
}

func splitImageRepository(image string) string {
	if idx := strings.LastIndex(image, ":"); idx >= 0 {
		return image[:idx]
	}
	return image
}

func splitImageTag(image string) string {
	if idx := strings.LastIndex(image, ":"); idx >= 0 {
		return image[idx+1:]
	}
	return "latest"
}

// pgWireMock — 自建 PG wire mock（与 internal/probe/port 内的同名辅助函数独立，
// 避免跨包复用 _test.go 私有 helper）。
type pgWireMock struct {
	listener net.Listener
	version  string
	served   int
	mu       sync.Mutex
}

func newPGWireMock(t *testing.T, version string) *pgWireMock {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &pgWireMock{listener: ln, version: version}
	go s.acceptLoop()
	return s
}

func (s *pgWireMock) Addr() string { return s.listener.Addr().String() }

func (s *pgWireMock) Stop() { _ = s.listener.Close() }

func (s *pgWireMock) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.served++
		s.mu.Unlock()
		go s.serve(conn)
	}
}

func (s *pgWireMock) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	qBuf := make([]byte, 256)
	n, err := conn.Read(qBuf)
	if err != nil || n == 0 || qBuf[0] != 'Q' {
		return
	}
	readyForQuery := []byte{'Z', 0, 0, 0, 5, 'I'}
	banner := []byte(s.version)
	reply := append([]byte{}, banner...)
	reply = append(reply, '\n')
	reply = append(reply, readyForQuery...)
	_, _ = conn.Write(reply)
}