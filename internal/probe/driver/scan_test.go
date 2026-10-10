package driver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ----- 测试工具 -----

// captureHook 收集 DriverScanner 发出的 AuditRow；线程安全。
type captureHook struct {
	mu   sync.Mutex
	rows []AuditRow
}

func (h *captureHook) hook(r AuditRow) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rows = append(h.rows, r)
}

func (h *captureHook) snapshot() []AuditRow {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]AuditRow, len(h.rows))
	copy(out, h.rows)
	return out
}

func (h *captureHook) countOf(k AuditKind) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.rows {
		if r.Kind == k {
			n++
		}
	}
	return n
}

// makeJar 写入一个内容固定的 jar 文件；返回文件路径与 sha256 期望值。
func makeJar(t *testing.T, dir, name, content string) (string, string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write jar %q: %v", p, err)
	}
	h := sha256.Sum256([]byte(content))
	return p, hex.EncodeToString(h[:])
}

// makeConfig 写入一个含 JDBC URL 的 datasource 配置文件。
func makeConfig(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write config %q: %v", p, err)
	}
	return p
}

// discardLogger 静默 logger；避免测试输出污染。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// ----- 单元测试 -----

// TestHashFileStable 同一 jar 三次 sha 一致。
func TestHashFileStable(t *testing.T) {
	dir := t.TempDir()
	p, expected := makeJar(t, dir, "kingbase-driver.jar", "kingbase-driver-v1.0.0")

	s1, err := ComputeJarSHA256(p)
	if err != nil {
		t.Fatalf("first hash: %v", err)
	}
	s2, err := ComputeJarSHA256(p)
	if err != nil {
		t.Fatalf("second hash: %v", err)
	}
	s3, err := ComputeJarSHA256(p)
	if err != nil {
		t.Fatalf("third hash: %v", err)
	}
	if s1 != expected || s2 != expected || s3 != expected {
		t.Fatalf("hash mismatch: s1=%s s2=%s s3=%s expected=%s", s1, s2, s3, expected)
	}
	if s1 != s2 || s2 != s3 {
		t.Fatalf("hash unstable across calls")
	}
}

// TestHashFileRefusesSymlink 拒绝 symlink。
func TestHashFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.jar")
	if err := os.WriteFile(target, []byte("real-content"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.jar")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	if _, err := ComputeJarSHA256(link); err == nil {
		t.Fatalf("expected error for symlink, got nil")
	}
}

// TestExtractJdbcURLs4Forms 验证 4 形态（pg / dm / oracle / kingbase）抽取命中。
func TestExtractJdbcURLs4Forms(t *testing.T) {
	dir := t.TempDir()
	// 写一个 datasource.xml，含 4 种 driver URL
	content := `<?xml version="1.0" encoding="UTF-8"?>
<datasource>
  <pg> jdbc:postgresql://10.0.1.21:5432/his_core </pg>
  <dm> jdbc:dm://10.0.1.22:5236/dm8_db </dm>
  <oracle> jdbc:oracle:thin:@10.0.1.23:1521:ORCL </oracle>
  <kingbase> jdbc:kingbase8://10.0.1.24:54321/emr_db </kingbase>
</datasource>
`
	_ = makeConfig(t, dir, "datasource.xml", content)

	urls := ExtractJdbcURLs(dir)
	if len(urls) < 4 {
		t.Fatalf("expected ≥4 URLs, got %d: %+v", len(urls), urls)
	}

	wantPrefixes := map[string]bool{
		"jdbc:postgresql://": false,
		"jdbc:dm://":         false,
		"jdbc:oracle:thin:@": false,
		"jdbc:kingbase8://":  false,
	}
	for _, u := range urls {
		for p := range wantPrefixes {
			if strings.HasPrefix(u.URL, p) {
				wantPrefixes[p] = true
			}
		}
	}
	for p, found := range wantPrefixes {
		if !found {
			t.Errorf("missing JDBC URL with prefix %s; got: %+v", p, urls)
		}
	}
}

// TestExtractJdbcURLsProperties 验证 *.properties 文件抽取。
func TestExtractJdbcURLsProperties(t *testing.T) {
	dir := t.TempDir()
	content := `spring.datasource.url=jdbc:postgresql://10.0.1.21:5432/his_core
spring.datasource.username=his_app
spring.datasource.password=***
`
	_ = makeConfig(t, dir, "application.properties", content)

	urls := ExtractJdbcURLs(dir)
	if len(urls) != 1 {
		t.Fatalf("expected 1 URL from properties, got %d: %+v", len(urls), urls)
	}
	if urls[0].URL != "jdbc:postgresql://10.0.1.21:5432/his_core" {
		t.Errorf("unexpected URL: %s", urls[0].URL)
	}
	if urls[0].LineNo != 1 {
		t.Errorf("expected line 1, got %d", urls[0].LineNo)
	}
}

// TestExtractJdbcURLsYAML 验证 *.yml 抽取。
func TestExtractJdbcURLsYAML(t *testing.T) {
	dir := t.TempDir()
	content := `spring:
  datasource:
    url: jdbc:dm://10.0.1.22:5236/dm8_db
    username: dm_user
`
	_ = makeConfig(t, dir, "application.yml", content)

	urls := ExtractJdbcURLs(dir)
	if len(urls) != 1 {
		t.Fatalf("expected 1 URL from yml, got %d: %+v", len(urls), urls)
	}
	if urls[0].URL != "jdbc:dm://10.0.1.22:5236/dm8_db" {
		t.Errorf("unexpected URL: %s", urls[0].URL)
	}
}

// TestExtractJdbcURLsNone 验证无 jdbc URL 时返回空（非 nil）。
func TestExtractJdbcURLsNone(t *testing.T) {
	dir := t.TempDir()
	_ = makeConfig(t, dir, "logback.xml", "<configuration/>")

	urls := ExtractJdbcURLs(dir)
	if len(urls) != 0 {
		t.Fatalf("expected 0 URLs, got %d", len(urls))
	}
}

// TestScanAllIncludesKnownAndUnknown 已知 + 未知 sha 都入 ScanResult；未知触发 warn + hook。
func TestScanAllIncludesKnownAndUnknown(t *testing.T) {
	dir := t.TempDir()
	_, knownSHA := makeJar(t, dir, "known.jar", "known-content")
	_, unknownSHA := makeJar(t, dir, "unknown.jar", "unknown-content")
	// 放一个非 jar 文件，确保不被纳入 ScanResult
	_ = makeConfig(t, dir, "README.md", "irrelevant")

	cfg := DriverScannerConfig{
		SystemID:         "his-core",
		Dirs:             []string{dir},
		AllowDriftSHA256: map[string]bool{knownSHA: true},
		RescanDebounce:   50 * time.Millisecond,
		Hook:             (&captureHook{}).hook,
		Logger:           discardLogger(),
	}
	hookRec := &captureHook{}
	cfg.Hook = hookRec.hook
	s := NewDriverScanner(cfg)

	results, err := s.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 ScanResult (known + unknown), got %d", len(results))
	}

	known := 0
	unknown := 0
	for _, r := range results {
		if r.IsKnown {
			known++
		} else {
			unknown++
		}
	}
	if known != 1 || unknown != 1 {
		t.Errorf("known=%d unknown=%d (expected 1,1)", known, unknown)
	}

	// 验证 unknown jar 触发了 1 条 driver_sha_unexpected
	if got := hookRec.countOf(AuditKindDriverSHAUnexpected); got != 1 {
		t.Errorf("expected 1 driver_sha_unexpected audit row, got %d", got)
	}

	// 验证 raw SHA 与期望一致
	for _, r := range results {
		if r.JarFile == "unknown.jar" && r.Sha256 != unknownSHA {
			t.Errorf("unknown.jar sha mismatch: got %s, want %s", r.Sha256, unknownSHA)
		}
		if r.JarFile == "known.jar" && r.Sha256 != knownSHA {
			t.Errorf("known.jar sha mismatch: got %s, want %s", r.Sha256, knownSHA)
		}
	}
}

// TestScanAllMultipleDirs 多目录扫描结果聚合。
func TestScanAllMultipleDirs(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	_, knownA := makeJar(t, dirA, "a.jar", "a-content")
	_, knownB := makeJar(t, dirB, "b.jar", "b-content")

	cfg := DriverScannerConfig{
		SystemID:         "multi-dir-test",
		Dirs:             []string{dirA, dirB},
		AllowDriftSHA256: map[string]bool{knownA: true, knownB: true},
		RescanDebounce:   50 * time.Millisecond,
		Hook:             (&captureHook{}).hook,
		Logger:           discardLogger(),
	}
	s := NewDriverScanner(cfg)

	results, err := s.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results (one per dir), got %d", len(results))
	}
	for _, r := range results {
		if !r.IsKnown {
			t.Errorf("expected all jars known; got unknown: %+v", r)
		}
	}
}

// TestScanAllMissingDir 目录不存在 → scan_error 审计行 + 不中断其他目录。
func TestScanAllMissingDir(t *testing.T) {
	good := t.TempDir()
	_, knownSHA := makeJar(t, good, "g.jar", "g-content")
	cfg := DriverScannerConfig{
		SystemID:         "missing-dir-test",
		Dirs:             []string{"/this/path/does/not/exist/anywhere", good},
		AllowDriftSHA256: map[string]bool{knownSHA: true},
		RescanDebounce:   50 * time.Millisecond,
		Hook:             (&captureHook{}).hook,
		Logger:           discardLogger(),
	}
	hookRec := &captureHook{}
	cfg.Hook = hookRec.hook
	s := NewDriverScanner(cfg)

	results, err := s.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("ScanAll should not return error (per-dir errors are recovered), got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result (only from good dir), got %d", len(results))
	}
	if hookRec.countOf(AuditKindScanError) != 1 {
		t.Errorf("expected 1 scan_error audit row from missing dir, got %d", hookRec.countOf(AuditKindScanError))
	}
}

// TestScanAllSkipsSymlinkAndDir 跳过目录与符号链接。
func TestScanAllSkipsSymlinkAndDir(t *testing.T) {
	dir := t.TempDir()
	// 创建一个子目录
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	// 创建一个 .jar 但其实是符号链接
	target, _ := makeJar(t, dir, "real.jar", "real")
	link := filepath.Join(dir, "link.jar")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	// 一个真实 jar
	_, sha := makeJar(t, dir, "real2.jar", "real2")

	cfg := DriverScannerConfig{
		SystemID:         "symlink-test",
		Dirs:             []string{dir},
		AllowDriftSHA256: map[string]bool{sha: true},
		RescanDebounce:   50 * time.Millisecond,
		Hook:             (&captureHook{}).hook,
		Logger:           discardLogger(),
	}
	s := NewDriverScanner(cfg)

	results, err := s.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	// 应该跳过 subdir、link.jar；只处理 real.jar + real2.jar
	if len(results) != 2 {
		t.Fatalf("expected 2 ScanResult (real.jar + real2.jar, skip subdir/link.jar), got %d: %+v", len(results), results)
	}
	for _, r := range results {
		if r.JarFile == "link.jar" {
			t.Errorf("symlink.jar should be skipped, got: %+v", r)
		}
	}
}

// TestScanAllEmptyDirs 空目录返回空结果。
func TestScanAllEmptyDirs(t *testing.T) {
	dir := t.TempDir()
	cfg := DriverScannerConfig{
		SystemID:       "empty-test",
		Dirs:           []string{dir},
		RescanDebounce: 50 * time.Millisecond,
		Hook:           (&captureHook{}).hook,
		Logger:         discardLogger(),
	}
	s := NewDriverScanner(cfg)

	results, err := s.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results from empty dir, got %d", len(results))
	}
}

// TestScanAllEmptyDirsList 空 dirs 列表不 panic。
func TestScanAllEmptyDirsList(t *testing.T) {
	cfg := DriverScannerConfig{
		SystemID:       "no-dirs-test",
		Dirs:           nil,
		RescanDebounce: 50 * time.Millisecond,
		Hook:           (&captureHook{}).hook,
		Logger:         discardLogger(),
	}
	s := NewDriverScanner(cfg)

	results, err := s.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

// TestDefaultConfig 验证默认配置参数。
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultDriverScannerConfig("sys-x", []string{"/tmp/a", "/tmp/b"}, []string{"sha1", "sha2"})
	if cfg.SystemID != "sys-x" {
		t.Errorf("SystemID = %q", cfg.SystemID)
	}
	if len(cfg.Dirs) != 2 || cfg.Dirs[0] != "/tmp/a" || cfg.Dirs[1] != "/tmp/b" {
		t.Errorf("Dirs not preserved: %+v", cfg.Dirs)
	}
	if cfg.RescanDebounce != 30*time.Second {
		t.Errorf("default debounce should be 30s, got %v", cfg.RescanDebounce)
	}
	if cfg.RescanInterval != 30*time.Minute {
		t.Errorf("default interval should be 30m, got %v", cfg.RescanInterval)
	}
	if !cfg.AllowDriftSHA256["sha1"] || !cfg.AllowDriftSHA256["sha2"] {
		t.Errorf("AllowDriftSHA256 not set: %+v", cfg.AllowDriftSHA256)
	}
}

// TestSetAllowDriftSHA256HotReload 运行时更新 allow 集合 → 之前 unknown 变 known。
func TestSetAllowDriftSHA256HotReload(t *testing.T) {
	dir := t.TempDir()
	_, unknownSHA := makeJar(t, dir, "x.jar", "x-content")

	cfg := DriverScannerConfig{
		SystemID:         "hot-reload",
		Dirs:             []string{dir},
		AllowDriftSHA256: map[string]bool{},
		RescanDebounce:   50 * time.Millisecond,
		Hook:             (&captureHook{}).hook,
		Logger:           discardLogger(),
	}
	s := NewDriverScanner(cfg)

	results1, _ := s.ScanAll(context.Background())
	if len(results1) != 1 || results1[0].IsKnown {
		t.Fatalf("expected unknown, got %+v", results1)
	}

	// 信息科修订 contracts.yaml 后重载
	s.SetAllowDriftSHA256([]string{unknownSHA})
	results2, _ := s.ScanAll(context.Background())
	if len(results2) != 1 || !results2[0].IsKnown {
		t.Fatalf("expected known after hot reload, got %+v", results2)
	}
}

// TestSetDirsHotReload 运行时更新 dirs 列表。
func TestSetDirsHotReload(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	_, shaA := makeJar(t, dirA, "a.jar", "a")
	_, shaB := makeJar(t, dirB, "b.jar", "b")

	cfg := DriverScannerConfig{
		SystemID:         "dir-reload",
		Dirs:             []string{dirA},
		AllowDriftSHA256: map[string]bool{shaA: true, shaB: true},
		RescanDebounce:   50 * time.Millisecond,
		Hook:             (&captureHook{}).hook,
		Logger:           discardLogger(),
	}
	s := NewDriverScanner(cfg)

	r1, _ := s.ScanAll(context.Background())
	if len(r1) != 1 || r1[0].JarFile != "a.jar" {
		t.Fatalf("first scan: %+v", r1)
	}

	s.SetDirs([]string{dirA, dirB})
	r2, _ := s.ScanAll(context.Background())
	if len(r2) != 2 {
		t.Fatalf("after SetDirs: expected 2 results, got %d", len(r2))
	}
}

// TestFsnotifyDebounce fsnotify 事件合并为 1 次重扫（用 100ms 短 debounce）。
func TestFsnotifyDebounce(t *testing.T) {
	dir := t.TempDir()
	cfg := DriverScannerConfig{
		SystemID:         "debounce-test",
		Dirs:             []string{dir},
		AllowDriftSHA256: map[string]bool{},
		RescanInterval:   0, // 关闭定时器
		RescanDebounce:   100 * time.Millisecond,
		Hook:             (&captureHook{}).hook,
		Logger:           discardLogger(),
	}
	s := NewDriverScanner(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Run(ctx)
	}()

	// 等 Run 启动 + 完成初始扫描
	time.Sleep(50 * time.Millisecond)
	baseline := s.RescanCount()

	// 100ms 内连续 3 次写入；debounce 把它们合并为 1 次重扫
	for i := 0; i < 3; i++ {
		_ = os.WriteFile(filepath.Join(dir, "burst"+string(rune('a'+i))+".jar"), []byte("burst"), 0o644)
		time.Sleep(10 * time.Millisecond)
	}

	// 等 debounce 窗口结束 + Run 处理完
	time.Sleep(250 * time.Millisecond)
	cancel()
	<-done

	delta := s.RescanCount() - baseline
	// baseline 通常 = 1 (initial scan)
	// delta 应 = 1 (3 事件合并为 1 次重扫)；允许有 1 次误差以应对某些平台事件过于密集
	if delta < 1 || delta > 2 {
		t.Errorf("expected 1 debounced rescan, got %d (baseline=%d now=%d)", delta, baseline, s.RescanCount())
	}
}

// TestRunStopsOnContextCancel ctx cancel 后 Run 干净退出。
func TestRunStopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	cfg := DriverScannerConfig{
		SystemID:         "ctx-cancel",
		Dirs:             []string{dir},
		AllowDriftSHA256: map[string]bool{},
		RescanInterval:   0,
		RescanDebounce:   50 * time.Millisecond,
		Hook:             (&captureHook{}).hook,
		Logger:           discardLogger(),
	}
	s := NewDriverScanner(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not exit within 2s after ctx cancel")
	}
}

// TestScanDirPureSync 单目录 ScanDir 同步路径（不依赖 fsnotify）。
func TestScanDirPureSync(t *testing.T) {
	dir := t.TempDir()
	_, sha := makeJar(t, dir, "p.jar", "p")
	makeConfig(t, dir, "ds.xml", `<url>jdbc:postgresql://10.0.1.1:5432/db</url>`)

	cfg := DriverScannerConfig{
		SystemID:         "sync-test",
		Dirs:             []string{dir},
		AllowDriftSHA256: map[string]bool{sha: true},
		RescanDebounce:   50 * time.Millisecond,
		Hook:             (&captureHook{}).hook,
		Logger:           discardLogger(),
	}
	s := NewDriverScanner(cfg)

	rs, err := s.ScanDir(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("expected 1 ScanResult, got %d", len(rs))
	}
	if !rs[0].IsKnown {
		t.Errorf("expected known")
	}
	if len(rs[0].JDBCURLs) != 1 || rs[0].JDBCURLs[0].URL != "jdbc:postgresql://10.0.1.1:5432/db" {
		t.Errorf("expected 1 JDBC URL, got %+v", rs[0].JDBCURLs)
	}
}

// TestJdbcURLRegexEdgeCases 验证 regex 对形态边界的处理。
func TestJdbcURLRegexEdgeCases(t *testing.T) {
	cases := []struct {
		input   string
		wantHit bool
	}{
		{`jdbc:postgresql://10.0.1.1:5432/db`, true},
		{`jdbc:dm://10.0.1.1:5236/db`, true},
		{`jdbc:oracle:thin:@10.0.1.1:1521:ORCL`, true},   // Oracle thin:SID
		{`jdbc:oracle:thin:@10.0.1.1:1521/ORCL`, true},   // Oracle thin:service
		{`jdbc:kingbase8://10.0.1.1:54321/db?param=v`, true},
		{`<url>jdbc:postgresql://10.0.1.1:5432/db</url>`, true}, // 含 XML 标签
		{`comment jdbc:postgresql://10.0.1.1:5432/db tail`, true},
		{`jdbc:mysql://10.0.1.1:3306/db`, true}, // mysql 也匹配（driver 名含字母数字）
		{`not a jdbc url`, false},
		{``, false},
	}
	for _, tc := range cases {
		got := jdbcURLRegex.FindString(tc.input)
		hit := got != ""
		if hit != tc.wantHit {
			t.Errorf("input=%q: hit=%v want=%v (got=%q)", tc.input, hit, tc.wantHit, got)
		}
	}
}

// TestScanAllContextCancel 中途 ctx cancel 不 panic。
func TestScanAllContextCancel(t *testing.T) {
	dir := t.TempDir()
	makeJar(t, dir, "a.jar", "a")
	cfg := DriverScannerConfig{
		SystemID:         "ctx-cancel-scan",
		Dirs:             []string{dir},
		AllowDriftSHA256: map[string]bool{},
		RescanDebounce:   50 * time.Millisecond,
		Hook:             (&captureHook{}).hook,
		Logger:           discardLogger(),
	}
	s := NewDriverScanner(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立刻取消

	_, _ = s.ScanAll(ctx) // 不 panic 即可
}