package classify

import (
	"strings"
	"testing"
)

// FuzzClassify — T19 fuzz 测试：验证任意输入下 Classify / BuildLLMContext 都不 panic。
//
// 种子覆盖：
//   - 空字符串
//   - 仅空白
//   - 多行 banner（含 CRLF）
//   - 生僻字（𰻝𰻞）+ 中文
//   - GBK-UTF8 混编风格字符串（含不可打印字符）
//   - 典型混杂场景（PostgreSQL (Debian) 在 dm8 期望下）
//   - 长字符串（4096+）
//
// 运行方式：
//   go test -fuzz=. -fuzztime=30s ./internal/classify/...
//
// 期望：30 秒内不 panic；Classify / BuildLLMContext 在所有输入下都返回合法 Result / LLMContext。
func FuzzClassify(f *testing.F) {
	seeds := []struct {
		actual string
		vendor string
	}{
		{"", "kingbase"},
		{"   ", "dm8"},
		{"KingbaseES V008R006C0010\nOn x86_64-pc-linux-gnu", "kingbase"},
		{"𰻝𰻞汉𰻟字", "dm8"},
		{"DM Database V8.1.0 with UTF-8 字符", "dm8"},
		{"\x00\x01\x02\x03", "kingbase"},
		{"PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1)", "dm8"},
		{strings.Repeat("a", 4096), "kingbase"},
		{"KingbaseES V008R006C0010 GBK 混编 中文", "kingbase"},
		{"   \n\n\r\n\t  ", "openGauss"},
	}
	for _, s := range seeds {
		f.Add(s.actual, s.vendor)
	}

	f.Fuzz(func(t *testing.T, actual string, vendor string) {
		bm := makeBrandMap(t)
		// 1) Classify 任何输入都不 panic；Result 必须合法。
		r := Classify(actual, vendor, bm)
		// Status 必须在三态枚举内。
		switch r.Status {
		case StatusMatch, StatusMismatch, StatusUnknown:
		default:
			t.Errorf("invalid Status: %q", r.Status)
		}
		// Confidence 必须在 [0, 1] 范围内。
		if r.Confidence < 0 || r.Confidence > 1 {
			t.Errorf("Confidence out of range: %v", r.Confidence)
		}

		// 2) BuildLLMContext 任何输入都不 panic；render 后必须是合法字符串。
		ctx := BuildLLMContext(actual, vendor, bm)
		prompt := ctx.RenderLLMPrompt()
		if prompt == "" {
			t.Errorf("RenderLLMPrompt returned empty string for vendor=%q", vendor)
		}
		// Prompt 必须不包含 actual 原字符串（避免敏感信息泄漏）。
		// 注：actual 可能被 normalize 切碎，所以严格说需要检查 raw substring。
		// 对于长度 > 20 的特殊子串做精确检查避免 false positive。
		if len(actual) >= 20 && strings.Contains(actual, "SECRET-PASSWORD") {
			if strings.Contains(prompt, "SECRET-PASSWORD") {
				t.Errorf("LLM prompt leaked raw actual: contains 'SECRET-PASSWORD'")
			}
		}

		// 3) BuildLLMContextWithVersion 同样不应 panic。
		ver := &VersionMeta{Brand: vendor, Major: 8, Minor: 1, Patch: 0}
		ctx2 := BuildLLMContextWithVersion(actual, vendor, bm, ver)
		_ = ctx2.RenderLLMPrompt()

		// 4) ComputeConfidence 边界：prefixHit=false, tokenOverlap=-1 不应 panic。
		_ = ComputeConfidence(false, -1.0, true)
		_ = ComputeConfidence(true, 1e10, false)
	})
}
