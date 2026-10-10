package classify

import (
	"math"
	"strings"
	"testing"

	"xinchuang-db-guardian/internal/config"
)

// makeBrandMap 构造 5 品牌 brandMap fixture。
func makeBrandMap(t *testing.T) *config.BrandMap {
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
			Brand:           "openGauss",
			VersionRegex:    []string{`(?i)openGauss\s+\d+\.\d+\.\d+`},
			JDBCURLPattern:  []string{`jdbc:opengauss://[^:]+:[0-9]+/[^?]+`},
			SignatureTokens: []string{"opengauss"},
		},
		{
			Brand:           "IvorySQL",
			VersionRegex:    []string{`(?i)IvorySQL\s+\d+\.\d+`},
			JDBCURLPattern:  []string{`jdbc:ivorysql://[^:]+:[0-9]+/[^?]+`},
			SignatureTokens: []string{"ivorysql"},
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

func TestClassifyEmpty(t *testing.T) {
	bm := makeBrandMap(t)
	r := Classify("", "kingbase", bm)
	if r.Status != StatusUnknown {
		t.Errorf("空字符串期望 unknown，got %s", r.Status)
	}
	if r.Confidence != 0.0 {
		t.Errorf("空字符串期望 confidence=0，got %v", r.Confidence)
	}
}

func TestClassifyWhitespaceOnly(t *testing.T) {
	bm := makeBrandMap(t)
	r := Classify("   \t\n  ", "dm8", bm)
	if r.Status != StatusUnknown {
		t.Errorf("仅空白期望 unknown，got %s", r.Status)
	}
}

// 5 品牌 × 3 真实 version 字符串 = 15 case 断言 100% 正确。
func TestClassifier15Cases(t *testing.T) {
	bm := makeBrandMap(t)

	cases := []struct {
		vendor        string
		actual        string
		wantStatus    Status
		wantMatch     bool
		wantMinConf   float64
		mustNotHave   []string // mismatch tokens 不应出现的值
	}{
		// kingbase × 3
		{"kingbase", "KingbaseES V008R006C0010 on x86_64-pc-linux-gnu", StatusMatch, true, 0.9, nil},
		{"kingbase", "KingbaseES V008R006C10B0010 (PostgreSQL 13.6 compatible)", StatusMatch, true, 0.9, nil},
		{"kingbase", "KingbaseES V007R006C0030 release", StatusMatch, true, 0.9, nil},

		// dm8 × 3
		{"dm8", "DM Database Server V8.1.0", StatusMatch, true, 0.9, nil},
		{"dm8", "DM Database Server V8.1.2-Build(12345)", StatusMatch, true, 0.9, nil},
		{"dm8", "DM8 Database", StatusMatch, true, 0.7, nil},

		// openGauss × 3
		{"openGauss", "openGauss 5.0.0 build 12345", StatusMatch, true, 0.9, nil},
		{"openGauss", "openGauss 3.0.0", StatusMatch, true, 0.9, nil},
		{"openGauss", "openGauss 5.0.0 (compatible with PostgreSQL 14)", StatusMatch, true, 0.9, nil},

		// IvorySQL × 3
		{"IvorySQL", "IvorySQL 1.4 on x86_64", StatusMatch, true, 0.9, nil},
		{"IvorySQL", "IvorySQL 1.2 (based on PostgreSQL 13)", StatusMatch, true, 0.9, nil},
		{"IvorySQL", "IvorySQL 1.4 (瀚高)", StatusMatch, true, 0.9, nil},

		// pg-compat × 3
		{"pg-compat", "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1)", StatusMatch, true, 0.9, nil},
		{"pg-compat", "PostgreSQL 13.6", StatusMatch, true, 0.9, nil},
		{"pg-compat", "PostgreSQL 11.2", StatusMatch, true, 0.9, nil},
	}

	for i, tc := range cases {
		got := Classify(tc.actual, tc.vendor, bm)
		if got.Status != tc.wantStatus {
			t.Errorf("case %d [%s / %s]: status=%s, want %s", i, tc.vendor, tc.actual, got.Status, tc.wantStatus)
		}
		if tc.wantMatch && got.Confidence < tc.wantMinConf {
			t.Errorf("case %d [%s / %s]: confidence=%v < %v", i, tc.vendor, tc.actual, got.Confidence, tc.wantMinConf)
		}
		if tc.wantStatus == StatusMismatch {
			for _, tok := range tc.mustNotHave {
				for _, mt := range got.MismatchTokens {
					if mt == tok {
						t.Errorf("case %d: 不应包含 mismatch token %s", i, tok)
					}
				}
			}
		}
	}
}

// 典型混杂场景：PG banner 在 DM8 期望下识别 mismatch 而非误判匹配。
func TestClassifyPGBannerInDM8Expectation(t *testing.T) {
	bm := makeBrandMap(t)

	// PostgreSQL 14.10 (Debian) 在 dm8 期望下 → mismatch + confidence=1.0。
	r := Classify("PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1)", "dm8", bm)
	if r.Status != StatusMismatch {
		t.Errorf("PG banner 在 DM8 期望下应 mismatch，got %s", r.Status)
	}
	if r.Confidence < 0.99 {
		t.Errorf("PG banner in DM8 期望下 confidence 应 ≥0.99，got %v", r.Confidence)
	}
	hasPostgres := false
	hasDebian := false
	for _, tok := range r.MismatchTokens {
		if tok == "postgresql" {
			hasPostgres = true
		}
		if tok == "debian" {
			hasDebian = true
		}
	}
	if !hasPostgres {
		t.Errorf("MismatchTokens 应包含 postgresql，got %v", r.MismatchTokens)
	}
	if !hasDebian {
		t.Errorf("MismatchTokens 应包含 debian，got %v", r.MismatchTokens)
	}
}

// Kingbase 伪 Kingbase：vendor=kingbase 且 actual 含 PostgreSQL 但无 KingbaseES。
func TestClassifyFakeKingbase(t *testing.T) {
	bm := makeBrandMap(t)
	// 伪装：PostgreSQL 13.6 声称 kingbase。
	r := Classify("PostgreSQL 13.6 (Kingbase Marketing Wrapper)", "kingbase", bm)
	if r.Status != StatusMismatch {
		t.Errorf("PostgreSQL-only 在 kingbase 期望下应 mismatch，got %s", r.Status)
	}
}

// edge case：未注册 vendor → unknown（退化路径）。
func TestClassifyUnknownVendor(t *testing.T) {
	bm := makeBrandMap(t)
	r := Classify("Some Random DB", "made-up-vendor", bm)
	if r.Status != StatusUnknown {
		t.Errorf("未注册 vendor 应 unknown，got %s", r.Status)
	}
}

// edge case：normalize 处理生僻字 / 特殊字符不 panic。
func TestClassifyRareCharsNoPanic(t *testing.T) {
	bm := makeBrandMap(t)
	inputs := []string{
		"KingbaseES V008R006C0010 𰻝𰻞",
		"\x00\x01\x02",
		"DM Database V8 \n\r\ttab",
		strings.Repeat("a", 4096),
	}
	for _, in := range inputs {
		_ = Classify(in, "kingbase", bm)
		_ = Classify(in, "dm8", bm)
	}
}

// edge case：Kingbase 期望下，actual 是 KingbaseES + PostgreSQL 兼容模式（应 match）。
func TestClassifyKingbaseWithPGCompatible(t *testing.T) {
	bm := makeBrandMap(t)
	r := Classify("KingbaseES V008R006C10B0010 (PostgreSQL 13.6 compatible)", "kingbase", bm)
	if r.Status != StatusMatch {
		t.Errorf("KingbaseES + PG 兼容模式应 match，got %s", r.Status)
	}
}

// ----------------------------------------------------------------------------
// T19：confidence 衰减 + signature tokens + fuzz 不 panic
// ----------------------------------------------------------------------------

// TestComputeConfidenceDecayAlgorithm — T19 显式覆盖置信度衰减公式：
//   基础 1.0；prefix miss → -0.3；token 交集 < 50% → -0.2；confusion hit → +0.5（最高 1.0）。
func TestComputeConfidenceDecayAlgorithm(t *testing.T) {
	cases := []struct {
		prefixHit    bool
		tokenOverlap float64
		confusionHit bool
		want         float64
		desc         string
	}{
		{true, 1.0, false, 1.0, "prefix hit + 100% overlap + no confusion"},
		{true, 0.75, false, 1.0, "prefix hit + 75% overlap + no confusion"},
		{true, 0.5, false, 1.0, "prefix hit + 50% overlap + no confusion (boundary)"},
		{true, 0.49, false, 0.8, "prefix hit + 49% overlap → -0.2"},
		{true, 0.0, false, 0.8, "prefix hit + 0% overlap → -0.2"},
		{false, 1.0, false, 0.7, "prefix miss + 100% overlap → -0.3"},
		{false, 0.5, false, 0.7, "prefix miss + 50% overlap → -0.3"},
		{false, 0.49, false, 0.5, "prefix miss + 49% overlap → -0.3 -0.2"},
		{false, 0.0, false, 0.5, "prefix miss + 0% overlap → -0.3 -0.2"},
		{false, 0.0, true, 1.0, "confusion hit → -0.3 -0.2 +0.5 → capped 1.0"},
		{true, 1.0, true, 1.0, "confusion hit + full prefix → +0.5 capped"},
		{false, 1.0, true, 1.0, "confusion hit + full overlap → +0.5 capped"},
	}
	for i, tc := range cases {
		got := ComputeConfidence(tc.prefixHit, tc.tokenOverlap, tc.confusionHit)
		if math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("case %d [%s]: got %v, want %v", i, tc.desc, got, tc.want)
		}
	}
}

// TestComputeConfidenceClamped — 边界值保护：负值归零、超过 1.0 归 1.0。
func TestComputeConfidenceClamped(t *testing.T) {
	// 极端负：即使 tokenOverlap = -100 也不应输出负数。
	got1 := ComputeConfidence(false, -100.0, false)
	if math.Abs(got1-0.5) > 1e-9 {
		t.Errorf("extreme negative overlap: got %v, want 0.5", got1)
	}
	// 极端大：confusion hit + 极端 overlap 不应超过 1.0。
	got2 := ComputeConfidence(true, 100.0, true)
	if got2 != 1.0 {
		t.Errorf("extreme overlap: got %v, want 1.0 (capped)", got2)
	}
	// 0 边界
	if got := ComputeConfidence(true, 0.5, false); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("boundary 0.5 overlap: got %v, want 1.0", got)
	}
	if got := ComputeConfidence(true, 0.49999999, false); math.Abs(got-0.8) > 1e-9 {
		t.Errorf("just below 0.5 overlap: got %v, want 0.8", got)
	}
}

// TestBuildLLMContext_NoRawLeak — LLM prompt 严禁携带 actual 原字符串（避免端口原文泄漏）。
func TestBuildLLMContext_NoRawLeak(t *testing.T) {
	bm := makeBrandMap(t)
	secretRaw := "KingbaseES V008R006C0010 SECRET-PASSWORD-12345 ON-PORT-5432"
	ctx := BuildLLMContext(secretRaw, "kingbase", bm)
	prompt := ctx.RenderLLMPrompt()
	// 必须不出现 raw 中的 secret 子串。
	if strings.Contains(prompt, "SECRET-PASSWORD-12345") {
		t.Errorf("LLM prompt leaked raw port response text (SECRET-PASSWORD-12345):\n%s", prompt)
	}
	if strings.Contains(prompt, "ON-PORT-5432") {
		t.Errorf("LLM prompt leaked raw port response text (ON-PORT-5432):\n%s", prompt)
	}
	// 应该仍包含 vendor 与 tokens 上下文。
	if !strings.Contains(prompt, "kingbase") {
		t.Errorf("LLM prompt should contain vendor 'kingbase':\n%s", prompt)
	}
	if !strings.Contains(prompt, "kingbasees") {
		t.Errorf("LLM prompt should contain token 'kingbasees':\n%s", prompt)
	}
}

// TestBuildLLMContext_WithVersion — version 元数据正确入 prompt。
func TestBuildLLMContext_WithVersion(t *testing.T) {
	bm := makeBrandMap(t)
	ver := &VersionMeta{Brand: "kingbase", Major: 8, Minor: 6, Patch: 10}
	ctx := BuildLLMContextWithVersion("KingbaseES V008R006C0010", "kingbase", bm, ver)
	prompt := ctx.RenderLLMPrompt()
	if !strings.Contains(prompt, "版本元数据：kingbase 8.6.10") {
		t.Errorf("LLM prompt should contain version metadata 'kingbase 8.6.10':\n%s", prompt)
	}
	if ctx.Version == nil {
		t.Errorf("ctx.Version should be set")
	}
	if ctx.PrefixHit != true {
		t.Errorf("expected PrefixHit=true, got %v", ctx.PrefixHit)
	}
	if ctx.TokenOverlap < 0.99 {
		t.Errorf("expected TokenOverlap=1.0 (kingbasees matched), got %v", ctx.TokenOverlap)
	}
}

// TestBuildLLMContext_NoVersion — version 为 nil 时 prompt 不含版本元数据行。
func TestBuildLLMContext_NoVersion(t *testing.T) {
	bm := makeBrandMap(t)
	ctx := BuildLLMContext("KingbaseES V008R006C0010", "kingbase", bm)
	prompt := ctx.RenderLLMPrompt()
	if strings.Contains(prompt, "版本元数据") {
		t.Errorf("LLM prompt should not contain '版本元数据' when version is nil:\n%s", prompt)
	}
}

// TestBuildLLMContext_EmptyActual — actual 为空时 prompt 仍合法（token 列表空）。
func TestBuildLLMContext_EmptyActual(t *testing.T) {
	bm := makeBrandMap(t)
	ctx := BuildLLMContext("", "kingbase", bm)
	prompt := ctx.RenderLLMPrompt()
	if prompt == "" {
		t.Errorf("RenderLLMPrompt returned empty for empty actual")
	}
	if len(ctx.ActualTokens) != 0 {
		t.Errorf("expected empty ActualTokens, got %v", ctx.ActualTokens)
	}
	if ctx.PrefixHit {
		t.Errorf("empty actual should have PrefixHit=false")
	}
}

// TestClassifyEdgeCases_GBKUTF8 — T19 边缘 case：生僻字 / GBK-UTF8 混编 / 多行 / 10KB 长串 / 异常 Unicode 不 panic。
func TestClassifyEdgeCases_GBKUTF8(t *testing.T) {
	bm := makeBrandMap(t)
	inputs := []string{
		"KingbaseES V008R006C0010 中文汉字𰻝𰻞",
		"\x00\x01\x02\x03",                       // 控制字符
		"DM Database V8.1.0 mixed GBK UTF-8 字符", // GBK-UTF8 混编风格
		strings.Repeat("a", 10*1024),              // 10KB 长串
		strings.Repeat("𰻝𰻞", 5000),                  // 5K 个生僻字
		"\n\r\n\n  \t  KingbaseES V008R006C0010",  // 多行 + 空白前缀
		"KingbaseES V008R006C0010 \xef\xbf\xbd",  // 含 UTF-8 replacement char
		"DM8\x00\x00\x00\x00Database",            // NUL 字节混合
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d panicked: %v\ninput=%q", i, r, in)
				}
			}()
			_ = Classify(in, "kingbase", bm)
			_ = Classify(in, "dm8", bm)
			ctx := BuildLLMContext(in, "kingbase", bm)
			_ = ctx.RenderLLMPrompt()
			ctx2 := BuildLLMContextWithVersion(in, "dm8", bm, &VersionMeta{Brand: "dm8", Major: 8, Minor: 1, Patch: 0})
			_ = ctx2.RenderLLMPrompt()
		}()
	}
}

// TestClassifyEdgeCases_Oversized — 10KB / 100KB 字符串不 panic。
// 注意：使用包含正确 V###R###C### 模式的字符串（让 prefix regex 命中）以验证高置信度；
// 纯重复 "KingbaseES " 缺版本数字 → prefixHit=false + overlap=1.0 → confidence=0.7（符合 T19 算法）。
func TestClassifyEdgeCases_Oversized(t *testing.T) {
	bm := makeBrandMap(t)

	// Case 1：包含完整 V###R###C### 模式（prefix 命中 + overlap=1.0 → confidence=1.0）。
	for _, sz := range []int{10 * 1024, 100 * 1024} {
		chunk := "KingbaseES V008R006C0010 "
		in := strings.Repeat(chunk, sz/len(chunk))
		r := Classify(in, "kingbase", bm)
		if r.Status != StatusMatch {
			t.Errorf("oversized %d bytes (with version pattern): expected match, got %s", sz, r.Status)
		}
		if r.Confidence < 0.99 {
			t.Errorf("oversized %d bytes (with version pattern): expected confidence >=0.99, got %v", sz, r.Confidence)
		}
	}

	// Case 2：纯重复 "KingbaseES "（无版本号 → prefix miss + overlap=1.0 → confidence=0.7）。
	for _, sz := range []int{10 * 1024, 100 * 1024} {
		in := strings.Repeat("KingbaseES ", sz/11)
		r := Classify(in, "kingbase", bm)
		if r.Status != StatusMatch {
			t.Errorf("oversized %d bytes (plain): expected match, got %s", sz, r.Status)
		}
		// T19 算法：prefix miss → -0.3，token overlap ≥ 0.5 不扣 → 0.7
		if math.Abs(r.Confidence-0.7) > 1e-9 {
			t.Errorf("oversized %d bytes (plain): expected confidence=0.7 (T19 算法), got %v", sz, r.Confidence)
		}
	}
}

// TestClassifyConfidence_Across15Cases — 验证 15 case 的 confidence 全部在新算法下符合预期。
func TestClassifyConfidence_Across15Cases(t *testing.T) {
	bm := makeBrandMap(t)

	// 每个 case 都应给出 confidence >= 0.7（与原始测试 wantMinConf 兼容）
	cases := []struct {
		vendor string
		actual string
	}{
		{"kingbase", "KingbaseES V008R006C0010 on x86_64-pc-linux-gnu"},
		{"kingbase", "KingbaseES V008R006C10B0010 (PostgreSQL 13.6 compatible)"},
		{"kingbase", "KingbaseES V007R006C0030 release"},
		{"dm8", "DM Database Server V8.1.0"},
		{"dm8", "DM Database Server V8.1.2-Build(12345)"},
		{"dm8", "DM8 Database"},
		{"openGauss", "openGauss 5.0.0 build 12345"},
		{"openGauss", "openGauss 3.0.0"},
		{"openGauss", "openGauss 5.0.0 (compatible with PostgreSQL 14)"},
		{"IvorySQL", "IvorySQL 1.4 on x86_64"},
		{"IvorySQL", "IvorySQL 1.2 (based on PostgreSQL 13)"},
		{"IvorySQL", "IvorySQL 1.4 (瀚高)"},
		{"pg-compat", "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1)"},
		{"pg-compat", "PostgreSQL 13.6"},
		{"pg-compat", "PostgreSQL 11.2"},
	}
	for i, tc := range cases {
		r := Classify(tc.actual, tc.vendor, bm)
		if r.Status != StatusMatch {
			t.Errorf("case %d [%s/%s]: expected match, got %s", i, tc.vendor, tc.actual, r.Status)
		}
		if r.Confidence < 0.7 {
			t.Errorf("case %d [%s/%s]: confidence %v < 0.7 (T19 算法下界)", i, tc.vendor, tc.actual, r.Confidence)
		}
	}
}
