// Package config 解析信息科编辑的合同白名单与品牌特征字典。
//
// 设计参考 cilium tools/cloud-dep-check/main.go:39-51 的 cloudSDKs map 模式：
// 声明白名单（key=品牌 → value=前缀/版本/SHA 集合）是产品的权威输入。
// 本项目把这一模式扩展为：(1) contracts.yaml 每条 system 元数据（host/port/jdbc dir）；
// (2) vendor_signatures.yaml 每品牌的版本 regex / 已知 jar sha / JDBC URL 模式 / 签名 tokens。
package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/fsnotify/fsnotify"
)

// ContractV 描述一条院内声明数据库的合同（声明 ≠ 事实）。
//
// 字段语义：
//   - SystemID: 全院唯一标识（如 his-core / emr / lis / pacs …），用于审计行 + 告警卡片；
//   - Vendor: 合同声明品牌（kingbase / dm8 / openGauss / IvorySQL / pg-compat …）；
//   - VersionPattern: 期望版本正则（与 VendorSignature.VersionRegex 联合判定）；
//   - AllowDriftSHA256: 允许的驱动 jar sha 集合（不在集合 → slog.Warn 'driver_sha_unexpected'）；
//   - ContractID: 商务合同/合同编号（HT-2024-HIS-001 之类）；
//   - Host/Port: 信息科登记的声明连接目标；
//   - ScanInterval: 端口探测周期（默认 10m，可被 system 覆盖）；
//   - JdbcDriverDirs: 该 system 的驱动目录（监听 fsnotify）；
//   - EventIDPrefix: 漂移事件 ID 前缀（审计行定位）。
type ContractV struct {
	SystemID          string        `yaml:"system_id" json:"system_id"`
	Vendor            string        `yaml:"vendor" json:"vendor"`
	VersionPattern    string        `yaml:"version_pattern" json:"version_pattern"`
	AllowDriftSHA256  []string      `yaml:"allow_drift_sha256" json:"allow_drift_sha256"`
	ContractID        string        `yaml:"contract_id" json:"contract_id"`
	Host              string        `yaml:"host" json:"host"`
	Port              int           `yaml:"port" json:"port"`
	ScanInterval      time.Duration `yaml:"scan_interval" json:"scan_interval"`
	JdbcDriverDirs    []string      `yaml:"jdbc_driver_dirs" json:"jdbc_driver_dirs"`
	EventIDPrefix     string        `yaml:"event_id_prefix" json:"event_id_prefix"`
}

// contractsFile 顶层结构（一份 contracts.yaml 同时承载多家 system 的合同）。
type contractsFile struct {
	Declared []ContractV `yaml:"declared"`
}

// LoadContracts 解析 contracts.yaml；空文件或缺 declared 节点视作 0 条 + nil。
func LoadContracts(path string) ([]ContractV, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read contracts.yaml %q: %w", path, err)
	}
	return ParseContracts(data)
}

// ParseContracts 从 YAML 字节解析；单元测试友好。
func ParseContracts(data []byte) ([]ContractV, error) {
	if len(bytesTrimSpace(data)) == 0 {
		return nil, nil
	}
	var f contractsFile
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(false) // 允许新增字段（向前兼容信息科后续追加）
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse contracts.yaml: %w", err)
	}
	return f.Declared, nil
}

// ValidateContracts 检查 12 条 system 的合规性：
// - SystemID 唯一；
// - host 通过 net.ParseIP（支持 v4 / v6）；
// - port ∈ [1, 65535]；
// - version_pattern 通过 regexp.Compile；
// - vendor 不空且 vendor_signatures.yaml 后续载入后必含此品牌（仅警告不阻断）。
//
// 任一失败立即返回 fmt.Errorf，错误信息含 system_id + 字段名，便于信息科定位。
func ValidateContracts(cs []ContractV) error {
	seen := make(map[string]string, len(cs))
	for i := range cs {
		c := &cs[i]
		if strings.TrimSpace(c.SystemID) == "" {
			return fmt.Errorf("contract[%d]: system_id empty", i)
		}
		if _, dup := seen[c.SystemID]; dup {
			return fmt.Errorf("contract[%d]: duplicate system_id %q", i, c.SystemID)
		}
		seen[c.SystemID] = c.Vendor

		if strings.TrimSpace(c.Vendor) == "" {
			return fmt.Errorf("contract[%d] %q: vendor empty", i, c.SystemID)
		}
		if strings.TrimSpace(c.Host) == "" {
			return fmt.Errorf("contract[%d] %q: host empty", i, c.SystemID)
		}
		// host 接受 IP（v4/v6），域名暂不支持（信息科登记 IP 即可）。
		ip := net.ParseIP(c.Host)
		if ip == nil {
			return fmt.Errorf("contract[%d] %q: invalid host %q (expect v4/v6 IP)", i, c.SystemID, c.Host)
		}
		if c.Port < 1 || c.Port > 65535 {
			return fmt.Errorf("contract[%d] %q: port %d out of range [1, 65535]", i, c.SystemID, c.Port)
		}
		if strings.TrimSpace(c.VersionPattern) != "" {
			if _, err := regexp.Compile(c.VersionPattern); err != nil {
				return fmt.Errorf("contract[%d] %q: version_pattern %q compile: %w", i, c.SystemID, c.VersionPattern, err)
			}
		}
		if strings.TrimSpace(c.ContractID) == "" {
			return fmt.Errorf("contract[%d] %q: contract_id empty", i, c.SystemID)
		}
		if strings.TrimSpace(c.EventIDPrefix) == "" {
			return fmt.Errorf("contract[%d] %q: event_id_prefix empty", i, c.SystemID)
		}
	}
	return nil
}

// ContractsHolder 是线程安全的 in-memory 合同白名单：守护启动时载入，
// fsnotify 收到变更后 Reload() 重新填充（reload 不影响在跑的 scan goroutine）。
type ContractsHolder struct {
	mu   sync.RWMutex
	data []ContractV
}

// NewContractsHolder 构造空 holder。
func NewContractsHolder() *ContractsHolder { return &ContractsHolder{} }

// Set 覆盖性写入（启动期 / 重载期使用）。
func (h *ContractsHolder) Set(cs []ContractV) {
	h.mu.Lock()
	// 拷贝避免外部修改影响
	out := make([]ContractV, len(cs))
	copy(out, cs)
	h.data = out
	h.mu.Unlock()
}

// Snapshot 返回不可变拷贝（调用方请勿修改）。
func (h *ContractsHolder) Snapshot() []ContractV {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]ContractV, len(h.data))
	copy(out, h.data)
	return out
}

// WatchContracts 用 fsnotify 监听 yaml 变更 + 协程自动重载；
// 重载失败仅 slog.Error 不影响守护。
//
// 设计参考 cilium healthz 的「外部资源变化 → 重载 in-memory state」思路；
// 不止实现 fsnotify.Operations = CREATE / WRITE / REMOVE。
func WatchContracts(path string, h *ContractsHolder, onError func(error)) (stop func(), err error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("fsnotify new watcher: %w", err)
	}
	dir := parentDir(path)
	if dir == "" {
		dir = "."
	}
	if err := w.Add(dir); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("fsnotify watch %q: %w", dir, err)
	}

	stopCh := make(chan struct{})
	go func() {
		defer w.Close()
		var debounceC <-chan time.Time
		for {
			select {
			case <-stopCh:
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if ev.Name != path {
					continue
				}
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
					continue
				}
				// 30s debounce：每次事件重置 timer，最后一次事件后 30s 真正触发重载
				debounceC = time.After(30 * time.Second)
				// 用单独 goroutine 等待，到点执行 Reload
				go func() {
					<-debounceC
					cs, err := LoadContracts(path)
					if err != nil {
						if onError != nil {
							onError(err)
						}
						return
					}
					if err := ValidateContracts(cs); err != nil {
						if onError != nil {
							onError(err)
						}
						return
					}
					h.Set(cs)
				}()
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				if onError != nil {
					onError(err)
				}
			}
		}
	}()

	return func() { close(stopCh) }, nil
}

// parentDir 等价 filepath.Dir 但不依赖路径分隔符转换。
func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return ""
}

// bytesTrimSpace 避免 import bytes 的小工具。
func bytesTrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
