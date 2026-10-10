package version

import (
	"strings"
	"testing"
)

// TestParse_15Cases_AllBrands exercises the 15-case matrix demanded by T6
// ("5 品牌 × 3 真实 version 字符串 = 15 case 断言正确率 100%") in a single
// table-driven test so a regression in any brand / triple is one t.Run row.
func TestParse_15Cases_AllBrands(t *testing.T) {
	cases := []struct {
		name, raw, brandHint string
		wantMajor            int
		wantMinor            int
		wantPatch            int
		wantBrand            string
	}{
		// —— Kingbase (3) ——
		{"kb-v008r006c0010", "KingbaseES V008R006C0010 on x86_64-pc-linux-gnu", "kingbase", 8, 6, 10, "kingbase"},
		{"kb-v008r006c0020", "KingbaseES V008R006C0020 build debug", "kingbase", 8, 6, 20, "kingbase"},
		{"kb-v009r001c0001", "KingbaseES V009R001C0001 (release)", "kingbase", 9, 1, 1, "kingbase"},

		// —— DM (3) ——
		{"dm-v8.1.0", "DM Database Server V8.1.0.0", "dm8", 8, 1, 0, "dm8"},
		{"dm-v8.1.2", "DM Database Server V8.1.2 build 2453", "dm8", 8, 1, 2, "dm8"},
		{"dm-v8.2.0", "DM Database Server V8.2.0 build 3320 (64bit)", "dm8", 8, 2, 0, "dm8"},

		// —— openGauss (3) ——
		{"og-5.0.0", "openGauss 5.0.0", "opengauss", 5, 0, 0, "opengauss"},
		{"og-3.0.0", "openGauss-3.0.0 (build ...)", "opengauss", 3, 0, 0, "opengauss"},
		{"og-5.0.1", "openGauss 5.0.1 build ...", "opengauss", 5, 0, 1, "opengauss"},

		// —— IvorySQL (3) ——
		{"is-1.4", "IvorySQL 1.4 (on ...)", "ivorysql", 1, 4, 0, "ivorysql"},
		{"is-1.2.3", "IvorySQL 1.2.3 (compatible with PostgreSQL 13)", "ivorysql", 1, 2, 3, "ivorysql"},
		{"is-1.5", "IvorySQL 1.5", "ivorysql", 1, 5, 0, "ivorysql"},

		// —— pg-compat (3) ——
		{"pg-14.10-debian", "PostgreSQL 14.10 (Debian 14.10-1.pgdg110+1) on x86_64", "pg-compat", 14, 10, 0, "pg-compat"},
		{"pg-13.6", "PostgreSQL 13.6 on x86_64-pc-linux-gnu", "pg-compat", 13, 6, 0, "pg-compat"},
		{"pg-11.2", "PostgreSQL 11.2", "pg-compat", 11, 2, 0, "pg-compat"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.raw, tc.brandHint)
			if got.Brand != tc.wantBrand {
				t.Errorf("Brand = %q, want %q", got.Brand, tc.wantBrand)
			}
			if !got.ParsedOK {
				t.Fatalf("ParsedOK = false, want true (raw=%q hint=%q)", tc.raw, tc.brandHint)
			}
			if got.Major != tc.wantMajor || got.Minor != tc.wantMinor || got.Patch != tc.wantPatch {
				t.Errorf("triple = (%d, %d, %d), want (%d, %d, %d)",
					got.Major, got.Minor, got.Patch, tc.wantMajor, tc.wantMinor, tc.wantPatch)
			}
			if got.Raw != tc.raw {
				t.Errorf("Raw = %q, want %q (must round-trip raw input)", got.Raw, tc.raw)
			}
		})
	}
}

// TestParse_EdgeCases_NoPanic checks Parse never panics on degenerate input.
// Per T6: "空 / 仅空白 / 多行混合 / 异常字符入参不 panic".
func TestParse_EdgeCases_NoPanic(t *testing.T) {
	cases := []struct {
		name, raw, hint string
	}{
		{"empty-string", "", ""},
		{"empty-with-valid-hint", "", "kingbase"},
		{"empty-with-unknown-hint", "", "unknown"},
		{"whitespace-only-spaces", "   ", ""},
		{"whitespace-only-tabs", "\t\t", ""},
		{"whitespace-only-newlines", "\n\n\r\n", ""},
		{"only-punctuation", "...:::---", ""},
		{"only-cjk", "数据库服务", "dm8"},
		{"unicode-rare-cjk", "𰻝𰻞𰻝𰻞", ""},
		{"gbk-utf8-mixed-1", "DM数据库 8.1.0", "dm8"},
		{"gbk-utf8-mixed-2", "Kingbase��ES V008R006C0010", "kingbase"},
		{"very-long-string", strings.Repeat("PostgreSQL ", 1000), "pg-compat"},
		{"super-long-number", strings.Repeat("9", 100), ""},
		{"only-v-no-num", "V.", ""},
		{"only-dots", "1.2.3.4.5.6", ""},
		{"mixed-crlf", "KingbaseES V008R006C0010\r\n\r\ncompiled by ...\r\n", "kingbase"},
		{"nul-bytes", "PostgreSQL 14.10\x00\x00on x86", "pg-compat"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse panicked on %q (hint=%q): %v", tc.raw, tc.hint, r)
				}
			}()
			got := Parse(tc.raw, tc.hint)
			_ = got.Brand
			_ = got.ParsedOK
		})
	}
}

// TestParse_EmptyRaw_ReturnsBrandFromHint verifies that an empty raw still
// honors a valid brandHint (T7 will then see "kind=ok but ParsedOK=false" and
// route through fallback).
func TestParse_EmptyRaw_ReturnsBrandFromHint(t *testing.T) {
	got := Parse("", "kingbase")
	if got.Brand != "kingbase" {
		t.Errorf("Brand = %q, want %q (hint should win on empty raw)", got.Brand, "kingbase")
	}
	if got.ParsedOK {
		t.Error("ParsedOK must be false on empty raw regardless of hint")
	}
	if got.Raw != "" {
		t.Errorf("Raw = %q, want empty", got.Raw)
	}
	if len(got.SignatureTokens) != 0 {
		t.Errorf("SignatureTokens on empty raw = %v, want nil/empty", got.SignatureTokens)
	}
}

// TestParse_WhitespaceOnly_BrandUnknown keeps "no signal from raw" honest —
// neither hint nor raw may fabricate a brand.
func TestParse_WhitespaceOnly_BrandUnknown(t *testing.T) {
	got := Parse("   \t\n  ", "")
	if got.Brand != "unknown" {
		t.Errorf("Brand = %q, want unknown (whitespace-only raw with no hint)", got.Brand)
	}
	if got.ParsedOK {
		t.Error("ParsedOK must be false on whitespace-only raw")
	}
}

// TestParse_MultiLine_PicksFirstNonEmpty covers banners that carry trailing
// build notes / copyright lines.
func TestParse_MultiLine_PicksFirstNonEmpty(t *testing.T) {
	cases := []struct {
		name, raw, hint string
		want            string
	}{
		{
			"pg-trailing-notes",
			"\nPostgreSQL 14.10 (Debian 14.10-1)\ncompiled by ...\n",
			"pg-compat",
			"14",
		},
		{
			"kb-with-blank-lead",
			"\n\nKingbaseES V008R006C0010 on x86_64\n",
			"kingbase",
			"8",
		},
		{
			"dm-trailing-build",
			"DM Database Server V8.1.0.0\nBUILD: ...\nDISTRIB: ...",
			"dm8",
			"8",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.raw, tc.hint)
			if !got.ParsedOK {
				t.Fatalf("ParsedOK=false for multi-line %q", tc.name)
			}
			majorStr := intToString(got.Major)
			if majorStr != tc.want {
				t.Errorf("Major = %q, want %q", majorStr, tc.want)
			}
			if got.Raw != tc.raw {
				t.Errorf("Raw not preserved")
			}
		})
	}
}

// TestParse_NoHint_InferFromTokens verifies brand inference when T4 hands us
// no brand (defensive: raw tokens carry enough signal).
func TestParse_NoHint_InferFromTokens(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"kingbase", "KingbaseES V008R006C0010 ...", "kingbase"},
		{"dm", "DM Database Server V8.1.0", "dm8"},
		{"opengauss", "openGauss 5.0.0", "opengauss"},
		{"ivorysql", "IvorySQL 1.4", "ivorysql"},
		{"pg", "PostgreSQL 14.10 (Debian ...)", "pg-compat"},
		{"unknown", "l33tserver v9000 build ...", "unknown"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.raw, "")
			if got.Brand != tc.want {
				t.Errorf("Brand = %q, want %q (inferred)", got.Brand, tc.want)
			}
		})
	}
}

// TestParse_BrandHintOverridesRawWhenConflicting ensures the hint (from T4
// port probe) is authoritative — when the raw banner is spoofed or
// contradiction, we preserve the hint so T7 can detect the mismatch.
func TestParse_BrandHintOverridesRawWhenConflicting(t *testing.T) {
	got := Parse("PostgreSQL 14.10 (Debian)", "dm8")
	if got.Brand != "dm8" {
		t.Errorf("Brand = %q, want %q (hint takes precedence)", got.Brand, "dm8")
	}
	if !got.ParsedOK {
		t.Error("ParsedOK should still pick up 14.10 from spoofed PG banner")
	}
}

// TestParse_SignatureTokens_NonAlphanumeric verifies tokenization shape —
// alphanumerics merge, all other runes split. Used as T22 LLM prompt input.
func TestParse_SignatureTokens_NonAlphanumeric(t *testing.T) {
	cases := []struct {
		name, raw, hint string
		wantSubstrs     []string
	}{
		{"dm", "DM Database Server V8.1.0", "dm8",
			[]string{"DM", "Database", "Server"}},
		{"pg", "PostgreSQL 14.10 (Debian ...)", "pg-compat",
			[]string{"PostgreSQL", "Debian"}},
		{"kb", "KingbaseES V008R006C0010 on x86_64", "kingbase",
			[]string{"KingbaseES", "x86", "64"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.raw, tc.hint)
			if len(got.SignatureTokens) == 0 {
				t.Fatalf("SignatureTokens empty for %q", tc.raw)
			}
			joined := strings.Join(got.SignatureTokens, ",")
			for _, want := range tc.wantSubstrs {
				if !strings.Contains(joined, want) {
					t.Errorf("SignatureTokens %v missing substring %q (raw=%q)",
						got.SignatureTokens, want, tc.raw)
				}
			}
		})
	}
}

// TestParse_KingbaseRegexTakesPrecedenceOverGeneric guards against the
// "kingbase V008R006C0010 parse as 8/0/0" regression the brand-specific
// matcher exists to prevent.
func TestParse_KingbaseRegexTakesPrecedenceOverGeneric(t *testing.T) {
	got := Parse("KingbaseES V008R006C0010 ...", "kingbase")
	if !got.ParsedOK {
		t.Fatal("ParsedOK must be true for KB banner")
	}
	if got.Major != 8 || got.Minor != 6 || got.Patch != 10 {
		t.Errorf("KingbaseES parse = (%d, %d, %d), want (8, 6, 10)", got.Major, got.Minor, got.Patch)
	}
	// Generic versionRegex would have parsed "V008R006C0010" as (8, 0, 0)
	// (only the "V008" portion matches the dotted pattern).  The test fails
	// if Minor falls back to 0 because the generic regex silently won.
}

// TestParse_ParsedFalseImpliesZeroTriple makes the contract explicit so
// callers can safely check ParsedOK without surprise non-zero values.
func TestParse_ParsedFalseImpliesZeroTriple(t *testing.T) {
	cases := []string{"", "   ", "no numbers here", "...::::", "𰻝𰻞𰻝"}
	for _, raw := range cases {
		got := Parse(raw, "")
		if !got.ParsedOK && (got.Major != 0 || got.Minor != 0 || got.Patch != 0) {
			t.Errorf("Parse(%q) ParsedOK=false but triple=(%d,%d,%d) — callers must not read non-zero",
				raw, got.Major, got.Minor, got.Patch)
		}
	}
}

// TestParse_RawPreserved makes sure raw is preserved verbatim for audit
// rows in T9 / T11 (Round-trip integrity).
func TestParse_RawPreserved(t *testing.T) {
	inputs := []string{
		"",
		"a",
		strings.Repeat("x", 4096),
		"\n\nPostgreSQL 14.10\n\n",
		"DM Database Server V8.1.0\x00\x00",
	}
	for _, in := range inputs {
		got := Parse(in, "")
		if got.Raw != in {
			t.Errorf("Raw round-trip failed: got %q, want %q", got.Raw, in)
		}
	}
}

// TestExtractTokens_Shape locks the tokenization rules so a future refactor
// cannot silently change what T22 passes to the LLM.
func TestExtractTokens_Shape(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"foo", []string{"foo"}},
		{"foo bar", []string{"foo", "bar"}},
		{"foo,bar", []string{"foo", "bar"}},
		{"foo123", []string{"foo123"}},
		{"123foo", []string{"123foo"}},
		{"123.456", []string{"123", "456"}},
		{"v8.1.0", []string{"v8", "1", "0"}},
		{"DM数据库", []string{"DM"}},
		{"  leading", []string{"leading"}},
		{"trailing  ", []string{"trailing"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			got := extractTokens(tc.in)
			// Compare contents ignoring nil-vs-empty.
			if len(got) != len(tc.want) {
				t.Fatalf("extractTokens(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("extractTokens(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestCanonicalizeBrand covers the full brand-hint normalization matrix so
// T4 → T6 contract is reproducible across case / spelling variants.
func TestCanonicalizeBrand(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "unknown"},
		{"unknown", "unknown"},
		{"Kingbase", "kingbase"},
		{"KINGBASE", "kingbase"},
		{"kingbaseES", "kingbase"},
		{"Kb", "kingbase"},
		{"dm8", "dm8"},
		{"DM", "dm8"},
		{"DAMENG", "dm8"},
		{"openGauss", "opengauss"},
		// "opengauss-3.0.0" 是 brandHint 被版本串污染 — T4 只输出 canonical brand
		// ("opengauss") 而不掺杂版本。T6 不做宽容解析；T7 会看到 Brand=unknown
		// 并把行归类走 trial 分支。
		{"opengauss-3.0.0", ""},
		{"GaussDB", "opengauss"},
		{"IvorySQL", "ivorysql"},
		{"HG", "ivorysql"},
		{"highgo", "ivorysql"},
		{"pg-compat", "pg-compat"},
		{"PostgreSQL", "pg-compat"},
		{"postgres", "pg-compat"},
		{"junk", ""},
		{"oracle-but-listed-as-junk", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			got := canonicalizeBrand(tc.in)
			if got != tc.want {
				t.Errorf("canonicalizeBrand(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// FuzzParse is the optional 30-second fuzz gate called out in T6 step 6 —
// "testing.F + go test -fuzz 检验 panic-free (30s timeout)". It runs as a
// normal sub-test against the seed corpus; invoking `go test -fuzz Parse`
// extends the seed search indefinitely until -fuzztime expires.
func FuzzParse(f *testing.F) {
	seeds := []struct{ raw, hint string }{
		{"DM Database Server V8.1.0", "dm8"},
		{"KingbaseES V008R006C0010", "kingbase"},
		{"", ""},
		{"PostgreSQL 14.10 (Debian)", "pg-compat"},
		{"\n\nno numbers here\n\n", ""},
		{"𰻝𰻞𰻝 123", ""},
		{"V.", "v"},
		{"DM数据库 V8.1.0 中文", "dm8"},
		{"l33t", "kb"},
	}
	for _, s := range seeds {
		f.Add(s.raw, s.hint)
	}
	f.Fuzz(func(t *testing.T, raw, hint string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Parse panicked on raw=%q hint=%q: %v", raw, hint, r)
			}
		}()
		got := Parse(raw, hint)
		// Hard invariants — a regex / string refactor must not break these.
		if got.Raw != raw {
			t.Errorf("Raw round-trip: got %q, want %q", got.Raw, raw)
		}
		// Brand must be one of the canonical set OR "unknown".
		switch got.Brand {
		case "kingbase", "dm8", "opengauss", "ivorysql", "pg-compat", "unknown":
			// OK
		default:
			t.Errorf("Brand %q outside canonical set", got.Brand)
		}
		// Brand=unknown + ParsedOK=true 仍是合法组合：
		// 比如 raw="𰻝𰻞𰻝 123" 没有品牌 token，但数字三元组可解析。
		// 该状态是 T7 / T22 的「vendor 含糊」信号，verdict=trial + need_human_review，
		// 不视为异常 — 仅在 raw 完全没有数字信息时降级为 ParsedOK=false。
		_ = got.ParsedOK
	})
}

// intToString is a tiny helper that avoids importing strconv just for one
// assertion path; doubles as a check that atoiSafe produces decimal output
// trivially representable.
func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
