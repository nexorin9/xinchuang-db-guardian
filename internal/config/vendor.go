// Package config — vendor signature 解析（品牌指纹字典）。
//
// 设计参考 cilium tools/cloud-dep-check/main.go:39-51 的 cloudSDKs map：
// 把声明白名单从 yaml 解出为 key=品牌 → value=签名集。融合后扩展为：
// - VersionRegex []string：版本字符串前缀 + token 联合识别；
// - KnownJarSHA256 []string：信息科登记的允许 jar sha；
// - JDBCURLPattern []string：JDBC URL 模式（如 jdbc:kingbase8://…）；
// - SignatureTokens []string：作为 LLM 入参时携带上下文（不含端口原文）。
package config

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// VendorSignature 一个品牌的签名集合（事实指纹字典）。
type VendorSignature struct {
	Brand           string   `yaml:"brand" json:"brand"`
	VersionRegex    []string `yaml:"version_regex" json:"version_regex"`
	KnownJarSHA256  []string `yaml:"known_jar_sha256" json:"known_jar_sha256"`
	JDBCURLPattern  []string `yaml:"jdbc_url_pattern" json:"jdbc_url_pattern"`
	SignatureTokens []string `yaml:"signature_tokens" json:"signature_tokens"`
}

// vendorSignaturesFile 顶层结构：brand 节点 + 该品牌的签名细则。
type vendorSignaturesFile struct {
	Brands []VendorSignature `yaml:"brands"`
}

// BrandMap 是 key=brand → value=VendorSignature 的索引；守护启动期一次性载入。
type BrandMap struct {
	mu  sync.RWMutex
	idx map[string]VendorSignature
}

// NewBrandMap 构造空索引。
func NewBrandMap() *BrandMap { return &BrandMap{idx: make(map[string]VendorSignature)} }

// Set 覆盖性写入。
func (m *BrandMap) Set(brands []VendorSignature) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idx = make(map[string]VendorSignature, len(brands))
	for _, b := range brands {
		m.idx[b.Brand] = b
	}
}

// Get 按 brand 取签名；不存在时返回 false。
func (m *BrandMap) Get(brand string) (VendorSignature, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.idx[brand]
	return v, ok
}

// Snapshot 返回全部品牌的快照（不可变拷贝）。
func (m *BrandMap) Snapshot() []VendorSignature {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]VendorSignature, 0, len(m.idx))
	for _, v := range m.idx {
		out = append(out, v)
	}
	return out
}

// LoadVendorSignatures 从 yaml 文件解析品牌指纹。
func LoadVendorSignatures(path string) ([]VendorSignature, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vendor_signatures.yaml %q: %w", path, err)
	}
	return ParseVendorSignatures(data)
}

// ParseVendorSignatures 从 yaml 字节解析。
func ParseVendorSignatures(data []byte) ([]VendorSignature, error) {
	if len(bytesTrimSpace(data)) == 0 {
		return nil, nil
	}
	var f vendorSignaturesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse vendor_signatures.yaml: %w", err)
	}
	return f.Brands, nil
}

// ValidateVendorSignatures：每品牌至少 1 条 VersionRegex + 1 条 JDBCURLPattern + 1 条 SignatureTokens。
// regex 必须能 regexp.Compile；任一缺失/不合法返回 fmt.Errorf，错误信息含品牌名。
// 额外校验：品牌名唯一（不区分大小写）、品牌名非纯空白、驱动 sha 可空。
func ValidateVendorSignatures(brands []VendorSignature) error {
	if len(brands) == 0 {
		return fmt.Errorf("vendor_signatures: no brands declared")
	}
	seen := make(map[string]int, len(brands))
	for i := range brands {
		b := &brands[i]
		if strings.TrimSpace(b.Brand) == "" {
			return fmt.Errorf("vendor_signature[%d]: brand empty", i)
		}
		if key := strings.ToLower(strings.TrimSpace(b.Brand)); key != "" {
			if prev, ok := seen[key]; ok {
				return fmt.Errorf("vendor_signature %q: duplicate brand (also at index %d)", b.Brand, prev)
			}
			seen[key] = i
		}
		if len(b.VersionRegex) == 0 {
			return fmt.Errorf("vendor_signature %q: version_regex empty", b.Brand)
		}
		for j, rx := range b.VersionRegex {
			if _, err := regexp.Compile(rx); err != nil {
				return fmt.Errorf("vendor_signature %q: version_regex[%d] %q compile: %w", b.Brand, j, rx, err)
			}
		}
		if len(b.JDBCURLPattern) == 0 {
			return fmt.Errorf("vendor_signature %q: jdbc_url_pattern empty", b.Brand)
		}
		if len(b.SignatureTokens) == 0 {
			return fmt.Errorf("vendor_signature %q: signature_tokens empty", b.Brand)
		}
	}
	return nil
}

// LoadAndValidate 加载 + 校验 + 入 map。
func LoadAndValidate(path string, m *BrandMap, logger *slog.Logger) error {
	brands, err := LoadVendorSignatures(path)
	if err != nil {
		return err
	}
	if err := ValidateVendorSignatures(brands); err != nil {
		return err
	}
	m.Set(brands)
	if logger != nil {
		logger.Info("vendor_signatures_loaded", slog.Int("brand_count", len(brands)))
	}
	return nil
}
