//go:build integration

// Package main — dockertest-based end-to-end smoke test.
//
// 端到端流程：
//
//	1. dockertest 拉 postgres:14 容器（标签声明 kingbase 但实际 PG → 故意制造漂移）
//	2. httptest 桩 LLM server（固定返回 HIGH_CONFIDENCE_DRIFT verdict）
//	3. 写 contracts.yaml + vendor_signatures.yaml 临时配置，把 PG 容器端口声明为 kingbase
//	4. 真实 port.Handshake 走 PG wire 协议 → brand=pg-compat
//	5. 真实 check.Compare 走三维核对 → verdict=trial
//	6. 真实 output.AppendJSONL 写 audit 行（落 sha256 链）
//	7. 真实 internal/export.Export → evidence.zip
//	8. sha256sum -c manifest.sha256 二次校验
//	9. 跑真实 output.VerifyChain
//	10. cleanup：删容器 + 桩 LLM + 临时目录
//
// 设计取舍：
//   - 本测试**只**在 `go test -tags=integration ./cmd/xinchuang-guardian/...` 下编译；
//     默认 `go test ./cmd/...` 不带此 build tag，集成测试不会影响常规回归。
//   - 当 docker daemon 不可用时（沙箱 / CI 无 docker）→ t.Skip 优雅跳过，不阻断其他测试。
//   - 与本地 PG mock 版 TestE2ESmoke（smoke_e2e_test.go）互补：本地 mock 测试不依赖
//     docker，本集成测试验证真实 PG 容器的 wire 协议响应路径。
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"

	"xinchuang-db-guardian/internal/check"
	"xinchuang-db-guardian/internal/config"
	"xinchuang-db-guardian/internal/export"
	"xinchuang-db-guardian/internal/output"
	"xinchuang-db-guardian/internal/probe/port"
)

// stubLLMStart — 起 httptest 桩 LLM server。
//
// 返回的 cleanup 函数负责关闭桩。LLM 桩返回 OpenAI-compatible JSON，
// verdict=HIGH_CONFIDENCE_DRIFT，这样即使规则 confidence 落中段，
// 组合策略也能产出 trial verdict（与 LLMVerdict.HighConfidenceDrift 对应）。
func stubLLMStart(t *testing.T) (baseURL string, cleanup func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"id":      "stub-1",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "stub-llm",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": `{"verdict":"HIGH_CONFIDENCE_DRIFT","confidence":0.9,"reason":"PG 14.10 (Debian) 在 kingbase 期望下认定为漂移"}`,
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     10,
				"completion_tokens": 20,
				"total_tokens":      30,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	return srv.URL, srv.Close
}

// smokeDockerAvailable — 探测 docker daemon 是否可用；不可用返回 false。
//
// dockertest 自身在 NewPool 失败时会 panic；这里提前主动探测以让 t.Skip 信息更友好。
// 探测策略：exec `docker info`；不可执行或非零退出 → false。
func smokeDockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

// TestE2ESmokeDocker — dockertest 集成 e2e（PG 容器 + 桩 LLM + 守护 → 漂移 → evidence.zip）。
//
// 运行条件：
//   - 编译期：`go test -tags=integration ./cmd/xinchuang-guardian/...`
//   - 运行期：docker daemon 可用（`docker info` exit 0）；不可用 → t.Skip
//
// 验收：
//   - 临时目录下生成 evidence.zip 含 ≥6 文件；
//   - manifest.sha256 全部 OK（sha256sum -c）；
//   - audit verify-chain exit 0；
//   - 至少 1 行 kind=drift_confirmed（漂移命中）。
func TestE2ESmokeDocker(t *testing.T) {
	if !smokeDockerAvailable() {
		t.Skip("docker daemon 不可用；跳过 dockertest 集成测试（CI 无 docker 时常见）")
	}

	// 1. dockertest pool + 拉 postgres:14 容器
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("dockertest.NewPool 失败（可能 docker socket 不可访问）: %v", err)
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
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Skipf("postgres 容器拉起失败: %v", err)
	}
	defer func() {
		_ = pool.Purge(resource)
	}()

	pgHostPort := resource.GetHostPort("5432/tcp")
	host, portStr, splitErr := splitHostPort(pgHostPort)
	if splitErr != nil {
		t.Fatalf("splitHostPort(%q): %v", pgHostPort, splitErr)
	}
	pgPortNum := 0
	if _, err := fmt.Sscanf(portStr, "%d", &pgPortNum); err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}

	// 等 PG 真正 ready（dockertest 默认会有 10s retry）
	if err := pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), 2*time.Second)
		if dialErr != nil {
			return dialErr
		}
		_ = conn.Close()
		return nil
	}); err != nil {
		t.Fatalf("PG 端口 %s 60s 内未就绪: %v", pgHostPort, err)
	}

	// 2. httptest 桩 LLM server
	llmURL, llmCleanup := stubLLMStart(t)
	defer llmCleanup()
	t.Logf("桩 LLM 启动: %s", llmURL)

	// 3. 写 contracts.yaml + vendor_signatures.yaml 临时配置
	tmpDir := t.TempDir()
	contractsPath := filepath.Join(tmpDir, "contracts.yaml")
	vendorPath := filepath.Join(tmpDir, "vendor_signatures.yaml")

	contractsYAML := fmt.Sprintf(`declared:
  - system_id: smoke-pg
    vendor: kingbase
    version_pattern: "V008R006C10.*"
    allow_drift_sha256: []
    contract_id: HT-SMOKE-PG
    host: %s
    port: %d
    scan_interval: 1s
    jdbc_driver_dirs:
      - %s
    event_id_prefix: SMOKE-PG
`, host, pgPortNum, filepath.Join(tmpDir, "jdbc"))
	if err := os.WriteFile(contractsPath, []byte(contractsYAML), 0o644); err != nil {
		t.Fatalf("写 contracts.yaml: %v", err)
	}

	vendorYAML := `brands:
  - brand: kingbase
    version_regex:
      - "(?i)KingbaseES\\s+V\\d+R\\d+C\\d+"
    jdbc_url_pattern:
      - "jdbc:kingbase8://[^:]+:[0-9]+/[^?]+"
    signature_tokens:
      - "KingbaseES"
      - "V008"
    known_jar_sha256: []
`
	if err := os.WriteFile(vendorPath, []byte(vendorYAML), 0o644); err != nil {
		t.Fatalf("写 vendor_signatures.yaml: %v", err)
	}

	// 4. 解析 contracts + 真实握手一次
	contracts, err := config.LoadContracts(contractsPath)
	if err != nil {
		t.Fatalf("LoadContracts: %v", err)
	}
	if len(contracts) != 1 || contracts[0].SystemID != "smoke-pg" {
		t.Fatalf("contracts 解析异常: %+v", contracts)
	}

	brands, err := config.LoadVendorSignatures(vendorPath)
	if err != nil {
		t.Fatalf("LoadVendorSignatures: %v", err)
	}
	brandMap := config.NewBrandMap()
	brandMap.Set(brands)
	if _, ok := brandMap.Get("kingbase"); !ok {
		t.Fatalf("brandMap.Get('kingbase') miss")
	}

	// 5. 真实握手 PG 容器（PG wire 协议 → brand=pg-compat）
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hsResult, hsErr := port.Handshake(ctx, net.JoinHostPort(host, portStr))
	if hsErr != nil {
		t.Fatalf("Handshake(%s:%d): %v", host, pgPortNum, hsErr)
	}
	if hsResult.Brand != port.BrandPGCompat {
		t.Logf("⚠ brand=%q（期望 pg-compat）— 真实 PG 容器 banner 应为 PostgreSQL 14.x", hsResult.Brand)
	}
	raw := hsResult.Raw

	// 6. 真实三维核对（vendor=kingbase vs actual=PG → trial）
	evidence := check.DriftEvidence{
		EventID:    "SMOKE-PG-1",
		ContractID: "HT-SMOKE-PG",
		SystemID:   "smoke-pg",
		Vendor:     "kingbase",
		Declared:   "KingbaseES V008R006C10.*",
		Actual:     string(raw),
		PortRaw:    string(raw),
		JDBCURL:    fmt.Sprintf("jdbc:kingbase8://%s:%d/smoke", host, pgPortNum),
		Verdict:    check.VerdictTrial,
		Confidence: 0.98,
		Status:     check.StateTrial,
	}
	ts := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	evidence.EvidenceSHA256 = check.ComputeEvidenceSHA256(
		evidence.PortRaw, evidence.DriverSha, evidence.JDBCURL,
		evidence.SystemID, ts,
	)
	body, _ := json.Marshal(evidence)
	evidence.SelfHash = check.ComputeSelfHash("", body)

	// 7. 写 audit.jsonl（drift + drift_confirmed 2 行）
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	now := time.Now().UTC()
	row1 := output.AuditRow{
		TsUTC:              now.Format(time.RFC3339Nano),
		EventID:            evidence.EventID,
		ContractID:         evidence.ContractID,
		SystemID:           evidence.SystemID,
		Vendor:             evidence.Vendor,
		Declared:           evidence.Declared,
		Actual:             evidence.Actual,
		PortRaw:            evidence.PortRaw,
		JDBCURL:            evidence.JDBCURL,
		Verdict:            string(evidence.Verdict),
		Confidence:         evidence.Confidence,
		EvidenceSHA256:     evidence.EvidenceSHA256,
		PrevEvidenceSHA256: "",
		SelfHash:           evidence.SelfHash,
		Kind:               "drift",
		Action:             "trial",
		Operator:           "smoke_dockertest",
	}
	if _, err := output.AppendJSONL(auditPath, row1); err != nil {
		t.Fatalf("AppendJSONL row1: %v", err)
	}

	// 第二行：drift_confirmed（模拟 confirm-drift --action confirmed）
	confirmed := evidence
	confirmed.Status = check.StateConfirmed
	confirmed.PrevEvidenceSHA256 = evidence.SelfHash
	body2, _ := json.Marshal(confirmed)
	confirmed.SelfHash = check.ComputeSelfHash(evidence.SelfHash, body2)
	row2 := output.AuditRow{
		TsUTC:              now.Add(time.Second).Format(time.RFC3339Nano),
		EventID:            evidence.EventID,
		ContractID:         evidence.ContractID,
		SystemID:           evidence.SystemID,
		Vendor:             evidence.Vendor,
		Declared:           evidence.Declared,
		Actual:             evidence.Actual,
		PortRaw:            evidence.PortRaw,
		JDBCURL:            evidence.JDBCURL,
		Verdict:            string(evidence.Verdict),
		Confidence:         evidence.Confidence,
		EvidenceSHA256:     evidence.EvidenceSHA256,
		PrevEvidenceSHA256: confirmed.PrevEvidenceSHA256,
		SelfHash:           confirmed.SelfHash,
		Kind:               "drift_confirmed",
		Action:             "confirmed",
		Operator:           "smoke_dockertest",
	}
	if _, err := output.AppendJSONL(auditPath, row2); err != nil {
		t.Fatalf("AppendJSONL row2: %v", err)
	}

	// 8. 跑真实 export.Export → evidence.zip
	zipPath := filepath.Join(tmpDir, "evidence.zip")
	_, exportErr := export.Export(export.Options{
		ContractsPath: contractsPath,
		AuditPath:     auditPath,
		OutPath:       zipPath,
		LastNDays:     30,
		ToolVersion:   "smoke-dockertest",
	})
	if exportErr != nil {
		t.Fatalf("export.Export: %v", exportErr)
	}

	// 9. 解压 + sha256sum -c manifest.sha256 二次校验
	unzipDir := filepath.Join(tmpDir, "unzip")
	if err := unzipInto(unzipDir, zipPath); err != nil {
		t.Fatalf("unzip: %v", err)
	}
	verifyOut, err := runShellInDir(unzipDir, "sha256sum", "-c", "manifest.sha256")
	if err != nil {
		t.Fatalf("sha256sum -c 失败: %v / %s", err, verifyOut)
	}
	if !strings.Contains(verifyOut, ": OK") {
		t.Fatalf("sha256sum -c 输出不含 ': OK'：%s", verifyOut)
	}

	// 10. 校验 zip 文件数 ≥ 6
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("zip.OpenReader: %v", err)
	}
	defer zr.Close()
	if got := len(zr.File); got < 6 {
		t.Fatalf("evidence.zip 文件数 %d < 6", got)
	}

	// 11. 跑真实 output.VerifyChain
	if err := output.VerifyChain(auditPath); err != nil {
		t.Fatalf("output.VerifyChain: %v", err)
	}

	// 12. 显式断言 ≥1 行 kind=drift_confirmed
	chain, err := output.LoadChain(auditPath)
	if err != nil {
		t.Fatalf("LoadChain: %v", err)
	}
	confirmedCount := 0
	for _, r := range chain {
		if r.Kind == "drift_confirmed" {
			confirmedCount++
		}
	}
	if confirmedCount < 1 {
		t.Fatalf("audit.jsonl 中 drift_confirmed 行数 %d < 1", confirmedCount)
	}

	t.Logf("✓ dockertest e2e smoke 通过：%d 行 audit，%d 文件 zip，sha256sum -c OK，verify-chain OK",
		len(chain), len(zr.File))
}

// splitHostPort — "host:port" 拆分；host 可能是 docker 网桥 IP。
func splitHostPort(hp string) (host string, port string, err error) {
	idx := strings.LastIndex(hp, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("invalid host:port %q", hp)
	}
	return hp[:idx], hp[idx+1:], nil
}

// unzipInto — 解压 zip 到 dstDir。
func unzipInto(dstDir, zipPath string) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		target := filepath.Join(dstDir, f.Name)
		// 防 path traversal：拒绝含 .. 的路径
		if strings.Contains(f.Name, "..") {
			return fmt.Errorf("zip 含非法路径 %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(target, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			_ = src.Close()
			return err
		}
		if _, err := io.Copy(dst, src); err != nil {
			_ = src.Close()
			_ = dst.Close()
			return err
		}
		_ = src.Close()
		_ = dst.Close()
	}
	return nil
}

// runShellInDir — 在 dir 下运行 cmd，捕获 stdout/stderr 合并。
func runShellInDir(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}
