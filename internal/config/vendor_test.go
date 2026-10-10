// 单元测试：vendor_signatures.yaml 解析 + 5 品牌校验 + BrandMap 索引。
package config

import (
	"path/filepath"
	"strings"
	"testing"
)

const sampleVendorYAML = `
brands:
  - brand: kingbase
    version_regex:
      - "(?i)KingbaseES\\s+V\\d+R\\d+C\\d+"
    jdbc_url_pattern:
      - "jdbc:kingbase8://[^:]+:[0-9]+/[^?]+"
    signature_tokens:
      - "KingbaseES"
      - "V008"
    known_jar_sha256: []
  - brand: dm8
    version_regex:
      - "(?i)DM\\s+Database\\s+Server\\s+V\\d"
      - "(?i)DAMENG\\s+V\\d"
    jdbc_url_pattern:
      - "jdbc:dm://[^:]+:[0-9]+"
    signature_tokens:
      - "DM"
      - "DAMENG"
    known_jar_sha256: []
  - brand: openGauss
    version_regex:
      - "(?i)openGauss\\s+\\d+\\.\\d+\\.\\d+"
    jdbc_url_pattern:
      - "jdbc:opengauss://[^:]+:[0-9]+/[^?]+"
    signature_tokens:
      - "openGauss"
    known_jar_sha256: []
  - brand: IvorySQL
    version_regex:
      - "(?i)IvorySQL\\s+\\d+\\.\\d+"
    jdbc_url_pattern:
      - "jdbc:ivorysql://[^:]+:[0-9]+/[^?]+"
    signature_tokens:
      - "IvorySQL"
    known_jar_sha256: []
  - brand: pg-compat
    version_regex:
      - "PostgreSQL\\s+\\d+\\.\\d+(\\.\\d+)?"
    jdbc_url_pattern:
      - "jdbc:postgresql://[^:]+:[0-9]+/[^?]+"
    signature_tokens:
      - "PostgreSQL"
    known_jar_sha256: []
`

func TestParseVendorSignatures5Brands(t *testing.T) {
	bs, err := ParseVendorSignatures([]byte(sampleVendorYAML))
	if err != nil {
		t.Fatalf("ParseVendorSignatures: %v", err)
	}
	if len(bs) != 5 {
		t.Fatalf("len = %d, want 5", len(bs))
	}
	if bs[0].Brand != "kingbase" {
		t.Fatalf("bs[0] brand = %q, want kingbase", bs[0].Brand)
	}
	if len(bs[0].VersionRegex) != 1 || len(bs[0].JDBCURLPattern) != 1 {
		t.Fatalf("bs[0] 字段不全: %+v", bs[0])
	}
}

func TestValidateVendorSignaturesOK(t *testing.T) {
	bs, _ := ParseVendorSignatures([]byte(sampleVendorYAML))
	if err := ValidateVendorSignatures(bs); err != nil {
		t.Fatalf("ValidateVendorSignatures: %v", err)
	}
}

func TestValidateVendorSignaturesBadRegex(t *testing.T) {
	yaml := `
brands:
  - brand: bad
    version_regex:
      - "[unclosed"
    jdbc_url_pattern:
      - "jdbc:x://.*"
    signature_tokens:
      - "X"
    known_jar_sha256: []
`
	bs, _ := ParseVendorSignatures([]byte(yaml))
	if err := ValidateVendorSignatures(bs); err == nil {
		t.Fatal("坏 regex 期望错误")
	} else if !strings.Contains(err.Error(), "compile") {
		t.Fatalf("错误信息应含 'compile'，实际 %q", err.Error())
	}
}

func TestValidateVendorSignaturesMissingTokens(t *testing.T) {
	yaml := `
brands:
  - brand: bad
    version_regex:
      - "X"
    jdbc_url_pattern:
      - "jdbc:x://.*"
    signature_tokens: []
    known_jar_sha256: []
`
	bs, _ := ParseVendorSignatures([]byte(yaml))
	if err := ValidateVendorSignatures(bs); err == nil {
		t.Fatal("缺 signature_tokens 期望错误")
	} else if !strings.Contains(err.Error(), "signature_tokens") {
		t.Fatalf("错误信息应含 'signature_tokens'，实际 %q", err.Error())
	}
}

func TestValidateVendorSignaturesMissingJDBC(t *testing.T) {
	yaml := `
brands:
  - brand: bad
    version_regex:
      - "X"
    jdbc_url_pattern: []
    signature_tokens:
      - "T"
    known_jar_sha256: []
`
	bs, _ := ParseVendorSignatures([]byte(yaml))
	if err := ValidateVendorSignatures(bs); err == nil {
		t.Fatal("缺 jdbc_url_pattern 期望错误")
	}
}

func TestValidateVendorSignaturesMissingVersion(t *testing.T) {
	yaml := `
brands:
  - brand: bad
    version_regex: []
    jdbc_url_pattern:
      - "jdbc:x://.*"
    signature_tokens:
      - "T"
    known_jar_sha256: []
`
	bs, _ := ParseVendorSignatures([]byte(yaml))
	if err := ValidateVendorSignatures(bs); err == nil {
		t.Fatal("缺 version_regex 期望错误")
	}
}

func TestValidateVendorSignaturesEmptyBrand(t *testing.T) {
	yaml := `
brands:
  - {brand: "", version_regex: ["x"], jdbc_url_pattern: ["jdbc:x://"], signature_tokens: ["t"]}
`
	bs, _ := ParseVendorSignatures([]byte(yaml))
	if err := ValidateVendorSignatures(bs); err == nil {
		t.Fatal("空 brand 期望错误")
	}
}

func TestBrandMapGetSetSnapshot(t *testing.T) {
	bs, _ := ParseVendorSignatures([]byte(sampleVendorYAML))
	m := NewBrandMap()
	m.Set(bs)

	if _, ok := m.Get("kingbase"); !ok {
		t.Fatal("BrandMap.Get(kingbase) 期望存在")
	}
	if _, ok := m.Get("not-existing"); ok {
		t.Fatal("BrandMap.Get(not-existing) 期望不存在")
	}

	snap := m.Snapshot()
	if len(snap) != 5 {
		t.Fatalf("Snapshot len = %d, want 5", len(snap))
	}

	// 覆盖性 Set
	bs2, _ := ParseVendorSignatures([]byte(`
brands:
  - {brand: "only", version_regex: ["v"], jdbc_url_pattern: ["jdbc:o://"], signature_tokens: ["o"]}
`))
	m.Set(bs2)
	if _, ok := m.Get("kingbase"); ok {
		t.Fatal("重 Set 后 kingbase 应不存在")
	}
	if _, ok := m.Get("only"); !ok {
		t.Fatal("重 Set 后 only 应存在")
	}
}

func TestLoadVendorSignaturesFromExample(t *testing.T) {
	path := filepath.Join("..", "..", "config", "vendor_signatures.example.yaml")
	bs, err := LoadVendorSignatures(path)
	if err != nil {
		t.Fatalf("LoadVendorSignatures(example): %v", err)
	}
	if len(bs) != 5 {
		t.Fatalf("example 应有 5 个品牌，实际 %d", len(bs))
	}
	if err := ValidateVendorSignatures(bs); err != nil {
		t.Fatalf("example 应通过校验: %v", err)
	}
	required := []string{"kingbase", "dm8", "openGauss", "IvorySQL", "pg-compat"}
	have := map[string]bool{}
	for _, b := range bs {
		have[b.Brand] = true
	}
	for _, want := range required {
		if !have[want] {
			t.Fatalf("example 缺品牌 %q", want)
		}
	}
}

func TestBadVendorYAMLFriendlyError(t *testing.T) {
	_, err := ParseVendorSignatures([]byte("brands: [[["))
	if err == nil {
		t.Fatal("坏 yaml 期望错误")
	}
}

func TestLoadAndValidate(t *testing.T) {
	path := filepath.Join("..", "..", "config", "vendor_signatures.example.yaml")
	m := NewBrandMap()
	if err := LoadAndValidate(path, m, nil); err != nil {
		t.Fatalf("LoadAndValidate: %v", err)
	}
	if _, ok := m.Get("kingbase"); !ok {
		t.Fatal("LoadAndValidate 后 kingbase 应存在")
	}
}

// 详细实现层扩展（Task 18）：覆盖 5 品牌完整解析 + 异常 brand 拒绝 + 鲁棒性边界。

func TestParseVendorSignatures_EmptyData(t *testing.T) {
	bs, err := ParseVendorSignatures([]byte(""))
	if err != nil {
		t.Fatalf("空数据期望 nil err，实际 %v", err)
	}
	if len(bs) != 0 {
		t.Fatalf("空数据期望 0 brands，实际 %d", len(bs))
	}
}

func TestParseVendorSignatures_OnlyWhitespace(t *testing.T) {
	bs, err := ParseVendorSignatures([]byte("   \n\t  "))
	if err != nil {
		t.Fatalf("纯空白期望 nil err，实际 %v", err)
	}
	if len(bs) != 0 {
		t.Fatalf("纯空白期望 0 brands，实际 %d", len(bs))
	}
}

func TestValidateVendorSignatures_DuplicateBrand(t *testing.T) {
	yamlData := `
brands:
  - brand: kingbase
    version_regex: ["(?i)kb"]
    jdbc_url_pattern: ["jdbc:kingbase8://.*"]
    signature_tokens: ["KingbaseES"]
  - brand: Kingbase
    version_regex: ["(?i)kb2"]
    jdbc_url_pattern: ["jdbc:kingbase8://.*"]
    signature_tokens: ["KingbaseES"]
`
	bs, _ := ParseVendorSignatures([]byte(yamlData))
	err := ValidateVendorSignatures(bs)
	if err == nil {
		t.Fatal("重复品牌名（大小写不敏感）期望错误")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("错误信息应含 'duplicate'，实际 %q", err.Error())
	}
}

func TestValidateVendorSignatures_WhitespaceBrand(t *testing.T) {
	yamlData := `
brands:
  - brand: "   "
    version_regex: ["(?i)x"]
    jdbc_url_pattern: ["jdbc:x://"]
    signature_tokens: ["x"]
`
	bs, _ := ParseVendorSignatures([]byte(yamlData))
	if err := ValidateVendorSignatures(bs); err == nil {
		t.Fatal("纯空白 brand 期望错误")
	} else if !strings.Contains(err.Error(), "brand empty") {
		t.Fatalf("错误信息应含 'brand empty'，实际 %q", err.Error())
	}
}

func TestValidateVendorSignatures_KnownJarSHA256EmptyAllowed(t *testing.T) {
	yamlData := `
brands:
  - brand: kingbase
    version_regex: ["(?i)KingbaseES"]
    jdbc_url_pattern: ["jdbc:kingbase8://.*"]
    signature_tokens: ["KingbaseES"]
    known_jar_sha256: []
`
	bs, _ := ParseVendorSignatures([]byte(yamlData))
	if err := ValidateVendorSignatures(bs); err != nil {
		t.Fatalf("known_jar_sha256 空允许: %v", err)
	}
}

func TestValidateVendorSignatures_KnownJarSHA256Populated(t *testing.T) {
	yamlData := `
brands:
  - brand: kingbase
    version_regex: ["(?i)KingbaseES"]
    jdbc_url_pattern: ["jdbc:kingbase8://.*"]
    signature_tokens: ["KingbaseES"]
    known_jar_sha256:
      - "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
`
	bs, _ := ParseVendorSignatures([]byte(yamlData))
	if err := ValidateVendorSignatures(bs); err != nil {
		t.Fatalf("populated known_jar_sha256 应通过: %v", err)
	}
	if len(bs[0].KnownJarSHA256) != 1 {
		t.Fatalf("known_jar_sha256 长度 = %d, want 1", len(bs[0].KnownJarSHA256))
	}
}

func TestLoadVendorSignatures_MissingFile(t *testing.T) {
	_, err := LoadVendorSignatures("/tmp/does-not-exist-xcg-vendor.yaml")
	if err == nil {
		t.Fatal("文件不存在期望错误")
	}
	if !strings.Contains(err.Error(), "read vendor_signatures.yaml") {
		t.Fatalf("错误信息应含 'read vendor_signatures.yaml'，实际 %q", err.Error())
	}
}

func TestValidateVendorSignatures_5BrandsTokensDistinct(t *testing.T) {
	bs, err := ParseVendorSignatures([]byte(sampleVendorYAML))
	if err != nil {
		t.Fatalf("ParseVendorSignatures: %v", err)
	}
	if err := ValidateVendorSignatures(bs); err != nil {
		t.Fatalf("ValidateVendorSignatures: %v", err)
	}
	// 每个品牌 signature_tokens 与 jdbc_url_pattern 互不相同（覆盖各品牌指纹差异）
	wantBrands := map[string]struct {
		tokensContain string
		jdbcPrefix    string
	}{
		"kingbase":   {"KingbaseES", "jdbc:kingbase8://"},
		"dm8":        {"DM", "jdbc:dm://"},
		"openGauss":  {"openGauss", "jdbc:opengauss://"},
		"IvorySQL":   {"IvorySQL", "jdbc:ivorysql://"},
		"pg-compat":  {"PostgreSQL", "jdbc:postgresql://"},
	}
	for _, b := range bs {
		want, ok := wantBrands[b.Brand]
		if !ok {
			t.Fatalf("意外品牌 %q", b.Brand)
		}
		foundToken := false
		for _, tok := range b.SignatureTokens {
			if tok == want.tokensContain {
				foundToken = true
				break
			}
		}
		if !foundToken {
			t.Fatalf("品牌 %q 缺 token %q", b.Brand, want.tokensContain)
		}
		foundJdbc := false
		for _, j := range b.JDBCURLPattern {
			if strings.HasPrefix(j, want.jdbcPrefix) {
				foundJdbc = true
				break
			}
		}
		if !foundJdbc {
			t.Fatalf("品牌 %q 缺 jdbc prefix %q", b.Brand, want.jdbcPrefix)
		}
	}
}

func TestBrandMap_ConcurrentReadAndWrite(t *testing.T) {
	m := NewBrandMap()
	bs, _ := ParseVendorSignatures([]byte(sampleVendorYAML))
	m.Set(bs)

	// 10 goroutine 并发读 + 1 goroutine 写
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				if _, ok := m.Get("kingbase"); !ok {
					t.Errorf("kingbase 在并发读中消失")
				}
			}
			done <- struct{}{}
		}()
	}
	go func() {
		// 重新 Set 不影响读
		m.Set(bs)
		done <- struct{}{}
	}()
	for i := 0; i < 11; i++ {
		<-done
	}
}

func TestVendorSignature_SignatureTokensAsLLMContext(t *testing.T) {
	bs, _ := ParseVendorSignatures([]byte(sampleVendorYAML))
	kb, ok := indexByBrand(bs, "kingbase")
	if !ok {
		t.Fatal("kingbase 未找到")
	}
	if len(kb.SignatureTokens) == 0 {
		t.Fatal("kingbase signature_tokens 为空（无法作为 LLM 入参上下文）")
	}
	// 不含端口原文 / 不含患者字段
	for _, tok := range kb.SignatureTokens {
		if strings.Contains(tok, ":") {
			t.Fatalf("signature_tokens %q 含 ':'（疑似端口原文）", tok)
		}
		if strings.Contains(tok, "patient") || strings.Contains(tok, "患者") {
			t.Fatalf("signature_tokens %q 含患者可识别字段", tok)
		}
	}
}

func indexByBrand(bs []VendorSignature, brand string) (VendorSignature, bool) {
	for _, b := range bs {
		if b.Brand == brand {
			return b, true
		}
	}
	return VendorSignature{}, false
}
