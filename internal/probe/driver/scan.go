// Package driver 负责驱动目录监听、jar sha256 计算与 JDBC URL 抽取。
//
// 设计参考 cilium tools/cloud-dep-check/main.go:62-93 的 binaries[i].allowed 列表
// 校验思路：把"目录里所有 jar"看作 binary pool，每个 jar 的 sha 与合同白名单
// `contracts.yaml` 的 allow_drift_sha256 比对；不在集合 → slog.Warn
// 'driver_sha_unexpected'（不直接入 drift，由三维核对模块判定）。
//
// 设计参考 cilium pkg/datapath/agentliveness/agent_liveness.go:51-63 的周期 Timer 风格：
// DriverScanner 既支持 fsnotify 实时触发，也保留定时重扫（默认 30 分钟）兜底，
// 单次 Write/Create/Remove 后 30 秒 debounce，期间多次事件合并为 1 次重扫。
package driver

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// AuditKind 描述 DriverScanner 可发出的告警类别。
type AuditKind string

const (
	// AuditKindDriverSHAUnexpected jar sha 不在 contracts.yaml allow_drift_sha256 中。
	// 注意：本包只产出告警元数据；trial 状态机的推进由 internal/check 负责。
	AuditKindDriverSHAUnexpected AuditKind = "driver_sha_unexpected"

	// AuditKindScanError 扫描过程出错（目录不存在/权限拒绝/io 失败）。
	AuditKindScanError AuditKind = "scan_error"
)

// AuditRow 是 DriverScanner 产出的事件元数据；下游 audit writer 负责 sha256 链。
type AuditRow struct {
	Kind      AuditKind
	SystemID  string
	Dir       string
	JarFile   string
	Sha256    string
	IsKnown   bool
	Err       string
	Timestamp time.Time
}

// AuditHook 是消费侧回调（测试用 in-memory recorder，生产用 audit appender）。
type AuditHook func(AuditRow)

// JdbcURLEvidence 记录一条 JDBC URL 抽取结果（来源文件 + 行号 + 原文）。
type JdbcURLEvidence struct {
	File   string
	LineNo int
	URL    string
}

// ScanResult 描述一次完整扫描的产出（每个 jar 一条；驱动目录级别聚合）。
type ScanResult struct {
	SystemID  string
	Dir       string
	JarFile   string
	Sha256    string
	IsKnown   bool
	JDBCURLs  []JdbcURLEvidence
	ScannedAt time.Time
}

// DriverScannerConfig 描述 DriverScanner 的可调参数。
type DriverScannerConfig struct {
	// SystemID 是 contracts.yaml 中的 system_id，用于审计行定位。
	SystemID string

	// Dirs 是该 system 的驱动目录列表（contracts.yaml JdbcDriverDirs 字段）。
	Dirs []string

	// AllowDriftSHA256 是该 system 允许的 jar sha 集合（contracts.yaml 同步传入）。
	AllowDriftSHA256 map[string]bool

	// RescanInterval 定时重扫间隔；默认 30 分钟；<= 0 关闭定时。
	RescanInterval time.Duration

	// RescanDebounce fsnotify 事件合并窗口；默认 30 秒；测试可调小。
	RescanDebounce time.Duration

	// Hook 消费扫描产出与告警行；nil 时静默丢弃（dry run 用）。
	Hook AuditHook

	// Logger 注入；nil 时回落到 slog.Default()。
	Logger *slog.Logger
}

// DefaultDriverScannerConfig 返回生产环境默认值。
func DefaultDriverScannerConfig(systemID string, dirs []string, allow []string) DriverScannerConfig {
	return DriverScannerConfig{
		SystemID:         systemID,
		Dirs:             dirs,
		AllowDriftSHA256: toSet(allow),
		RescanInterval:   30 * time.Minute,
		RescanDebounce:   30 * time.Second,
	}
}

// toSet 把字符串切片转 map[string]bool；nil/空切片返回 nil（表示空集合）。
func toSet(s []string) map[string]bool {
	if len(s) == 0 {
		return nil
	}
	out := make(map[string]bool, len(s))
	for _, v := range s {
		out[v] = true
	}
	return out
}

// DriverScanner 是 driver 包对外主类型：周期性 + fsnotify 触发重扫，
// 对每个 .jar 计算 sha256，并从周边 .xml/.properties/.yml 抽取 JDBC URL。
type DriverScanner struct {
	cfg DriverScannerConfig

	mu          sync.Mutex
	lastRescan  time.Time
	rescanCount int
}

// NewDriverScanner 构造 scanner；不启动 goroutine，需显式 Run。
func NewDriverScanner(cfg DriverScannerConfig) *DriverScanner {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RescanDebounce <= 0 {
		cfg.RescanDebounce = 30 * time.Second
	}
	if cfg.AllowDriftSHA256 == nil {
		cfg.AllowDriftSHA256 = map[string]bool{}
	}
	return &DriverScanner{cfg: cfg}
}

// SetAllowDriftSHA256 在运行时更新 allow 集合（contracts.yaml 重载时调用）。
func (s *DriverScanner) SetAllowDriftSHA256(allow []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.AllowDriftSHA256 = toSet(allow)
}

// SetDirs 在运行时更新目录列表（contracts.yaml 重载时调用）。
func (s *DriverScanner) SetDirs(dirs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Dirs = append([]string{}, dirs...)
}

// RescanCount 返回自启动以来的重扫次数（测试用）。
func (s *DriverScanner) RescanCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rescanCount
}

// Run 启动 fsnotify 监听 + 定时重扫；<-ctx.Done() 优雅退出。
//
// 流程：
//  1. 先做一次初始扫描（保证上线即可拿到 sha + JDBC URL）；
//  2. fsnotify 监听每个目录；任一事件触发后 30s debounce → 一次完整重扫；
//  3. 定时器兜底（默认 30 分钟）。
func (s *DriverScanner) Run(ctx context.Context) error {
	// 启动前先扫一次
	if _, err := s.ScanAll(ctx); err != nil {
		s.cfg.Logger.Warn("driver_scanner_initial_scan_failed", "err", err.Error())
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify new watcher: %w", err)
	}
	defer w.Close()

	// 加入所有目录监听
	added := make(map[string]bool)
	for _, d := range s.cfg.Dirs {
		if d == "" {
			continue
		}
		if added[d] {
			continue
		}
		if err := w.Add(d); err != nil {
			s.emitError(d, fmt.Errorf("fsnotify watch %q: %w", d, err))
			continue
		}
		added[d] = true
	}

	stopCh := make(chan struct{})
	var debounceTimer *time.Timer
	var debounceC <-chan time.Time

	rescanTicker := time.NewTimer(0)
	if s.cfg.RescanInterval > 0 {
		rescanTicker = time.NewTimer(s.cfg.RescanInterval)
	} else {
		// 立刻停掉定时器
		if !rescanTicker.Stop() {
			<-rescanTicker.C
		}
	}

	go func() {
		defer close(stopCh)
		for {
			select {
			case <-ctx.Done():
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				// 只关心我们注册的目录；Create/Write/Remove/Rename/Chmod 都触发重扫
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) == 0 {
					continue
				}
				s.cfg.Logger.Info("driver_scanner_fsnotify_event", "file", ev.Name, "op", ev.Op.String())
				// 重置 debounce 定时器（合并同一窗口内多次事件）
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.NewTimer(s.cfg.RescanDebounce)
				debounceC = debounceTimer.C
			case <-debounceC:
				if _, err := s.ScanAll(ctx); err != nil {
					s.cfg.Logger.Warn("driver_scanner_debounced_scan_failed", "err", err.Error())
				}
			case <-rescanTicker.C:
				if _, err := s.ScanAll(ctx); err != nil {
					s.cfg.Logger.Warn("driver_scanner_periodic_scan_failed", "err", err.Error())
				}
				if s.cfg.RescanInterval > 0 {
					rescanTicker.Reset(s.cfg.RescanInterval)
				}
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				s.emitError("", err)
			}
		}
	}()

	<-ctx.Done()
	<-stopCh
	return nil
}

// emitError 把内部错误转成审计行；便于信息科定位。
func (s *DriverScanner) emitError(dir string, err error) {
	if s.cfg.Hook == nil {
		return
	}
	s.cfg.Hook(AuditRow{
		Kind:      AuditKindScanError,
		SystemID:  s.cfg.SystemID,
		Dir:       dir,
		Err:       err.Error(),
		Timestamp: time.Now().UTC(),
	})
}

// ScanAll 同步扫描所有目录；返回全部 ScanResult。
// 用于：(a) 启动期初始扫描；(b) 30s debounce 后重扫；(c) 定时兜底。
func (s *DriverScanner) ScanAll(ctx context.Context) ([]ScanResult, error) {
	s.mu.Lock()
	s.lastRescan = time.Now().UTC()
	s.rescanCount++
	s.mu.Unlock()

	dirs := append([]string{}, s.cfg.Dirs...)
	out := make([]ScanResult, 0, 8)
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		rs, err := s.ScanDir(ctx, d)
		if err != nil {
			s.emitError(d, err)
			continue
		}
		out = append(out, rs...)
	}
	return out, nil
}

// ScanDir 同步扫描单个目录；返回该目录全部 ScanResult。
// 单目录出错不中断其他目录；结果中每个 .jar 对应一条 ScanResult。
func (s *DriverScanner) ScanDir(ctx context.Context, dir string) ([]ScanResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read driver dir %q: %w", dir, err)
	}

	var out []ScanResult
	for _, e := range entries {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		// 跳过目录与符号链接（spec 要求：lstat 排除 symlink）
		if e.IsDir() {
			continue
		}
		fullPath := filepath.Join(dir, e.Name())
		info, err := os.Lstat(fullPath)
		if err != nil {
			s.emitError(dir, fmt.Errorf("lstat %q: %w", fullPath, err))
			continue
		}
		// 排除符号链接
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".jar") {
			// 非 .jar 文件仍可能被抽取 JDBC URL（datasource.xml / *.properties）
			// 但 ScanResult 只对 jar 出，本函数不处理配置文件；见 ScanDirExtractURLs
			continue
		}
		sha, err := hashFile(fullPath)
		if err != nil {
			s.emitError(dir, fmt.Errorf("sha256 %q: %w", fullPath, err))
			continue
		}
		isKnown := s.cfg.AllowDriftSHA256[sha]
		if !isKnown {
			s.cfg.Logger.Warn("driver_sha_unexpected",
				"system_id", s.cfg.SystemID,
				"jar", e.Name(),
				"sha256", sha,
			)
			if s.cfg.Hook != nil {
				s.cfg.Hook(AuditRow{
					Kind:      AuditKindDriverSHAUnexpected,
					SystemID:  s.cfg.SystemID,
					Dir:       dir,
					JarFile:   e.Name(),
					Sha256:    sha,
					IsKnown:   false,
					Timestamp: time.Now().UTC(),
				})
			}
		}
		out = append(out, ScanResult{
			SystemID:  s.cfg.SystemID,
			Dir:       dir,
			JarFile:   e.Name(),
			Sha256:    sha,
			IsKnown:   isKnown,
			JDBCURLs:  ExtractJdbcURLs(dir),
			ScannedAt: time.Now().UTC(),
		})
	}
	return out, nil
}

// hashFile 计算文件 sha256；lstat 排除 symlink（已在调用方处理）。
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("io.Copy %q: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// jdbcURLRegex 匹配 JDBC URL。
// 覆盖两种形态：
//  1. 标准 `jdbc:<driver>://<host>:<port>/<db>`（pg / dm / kingbase / mysql …）；
//  2. Oracle thin 客户端 `jdbc:oracle:thin:@<host>:<port>:<sid>` 或
//     `jdbc:oracle:thin:@<host>:<port>/<service>`。
//
// 说明：仅依赖端口前的固定字符 `://` 或 `:thin:@`，避免误吃 HTML/XML 文本。
var jdbcURLRegex = regexp.MustCompile(`jdbc:[a-zA-Z0-9]+:(?://[^:\s'"]+:[0-9]+/[a-zA-Z0-9_]+|thin:@[^:\s'"]+:[0-9]+[:/][a-zA-Z0-9_]+)`)

// configFileSuffixes 信息科常见的驱动配置文件后缀（信息科按场景任选）。
var configFileSuffixes = []string{".xml", ".properties", ".yml", ".yaml"}

// ExtractJdbcURLs 在 dir 下扫描 datasource.xml / *.properties / *.yml / *.yaml，
// 用 jdbcURLRegex 抽取所有 JDBC URL（含行号）。
//
// 注意：本函数不递归（驱动目录多为平面布局）；如需递归由 caller 自行处理。
func ExtractJdbcURLs(dir string) []JdbcURLEvidence {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []JdbcURLEvidence
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)
		matched := false
		for _, suf := range configFileSuffixes {
			if strings.HasSuffix(lower, suf) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		// 跳过 jar 文件（虽然不该匹配 configFileSuffixes，但防御性跳过）
		if strings.HasSuffix(lower, ".jar") {
			continue
		}
		fullPath := filepath.Join(dir, name)
		urls := scanFileForJdbcURLs(fullPath)
		out = append(out, urls...)
	}
	return out
}

// scanFileForJdbcURLs 读取单文件并逐行匹配 jdbcURLRegex。
// 行号 1-indexed（与编辑器/IDE 一致）。
func scanFileForJdbcURLs(path string) []JdbcURLEvidence {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []JdbcURLEvidence
	sc := bufio.NewScanner(f)
	// 驱动配置文件单行可能很长（连接串 + 参数），调大缓冲
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		matches := jdbcURLRegex.FindAllString(line, -1)
		for _, m := range matches {
			out = append(out, JdbcURLEvidence{
				File:   path,
				LineNo: lineNo,
				URL:    m,
			})
		}
	}
	return out
}

// ComputeJarSHA256 是公开入口（供 internal/check 模块调用），对单个 .jar 算 sha。
func ComputeJarSHA256(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("lstat %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to hash symlink %q", path)
	}
	return hashFile(path)
}