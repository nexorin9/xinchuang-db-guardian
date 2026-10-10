// Package version normalizes raw database version banners (returned by T4
// port-probe handshakes) into a uniform triple plus a brand classification.
// The output feeds:
//
//   - T7 三维核对 (port_raw vs declared vendor version_pattern)
//   - T22 CombineRuleAndLLM 决定 ruleConfidence 是否进入「规则中」分支
//
// Design contract (never panic):
//
//   - Empty / whitespace-only raw → ParsedOK=false, Brand best-effort from hint.
//   - Multi-line banners (PG/DM trailing "(Debian ...)") → first non-empty line.
//   - Brand hint from T4 handshake is authoritative; raw-token inference is
//     best-effort fallback only. Wrong hint surfaces as a mismatch signal in
//     T7/T15, not here.
//   - SignatureTokens are alphanumerics-only chunks of the parsed line; they
//     ride into T22 BuildLLMPrompt as LLM context, NOT as classification key.
package version

import (
	"regexp"
	"strings"
)

// NormalizedVersion is the canonical output of Parse. Zero-value when the
// banner could not be parsed; callers must check ParsedOK before trusting
// the major/minor/patch triple.
type NormalizedVersion struct {
	// Brand 是 canonical key："kingbase" / "dm8" / "opengauss" / "ivorysql" / "pg-compat" / "unknown"。
	// "unknown" 表示 brandHint 无效且 raw 也不足以推断 — T7 会走 verdict=trial 分支。
	Brand string

	// Major / Minor / Patch 取自 banner 中的数字三元组，全 0 表示未解析。
	Major int
	Minor int
	Patch int

	// Raw 是原始输入（含未剥的多行），便于审计行回写。
	Raw string

	// ParsedOK=false 时 Major/Minor/Patch 可为 0 但不代表版本是 0，
	// 仅意味着「caller 应走 fallback / LLM 兜底 / 直接 trial」。
	ParsedOK bool

	// SignatureTokens 是把 first-non-empty line 切到非字母数字得到的字块，
	// 供 T22 BuildLLMPrompt 作为上下文携带，不参与本地分类。
	SignatureTokens []string
}

// versionRegex matches an optional leading 'V'/'v' followed by major, optional
// minor, optional patch — picking the EARLIEST match in the line so that
// "PostgreSQL 14.10" returns 14 / 10 / 0 (Patch absent ⇒ 0, not error).
var versionRegex = regexp.MustCompile(`[Vv]?(\d+)(?:\.(\d+))?(?:\.(\d+))?`)

// kingbaseVersionRegex handles KingbaseES V<major>R<minor>C<patch>B<build>
// — note Kingbase uses non-dotted VR-C triplets, so the generic versionRegex
// would mis-parse "V008R006C10B0010" as 8 / 0 / 0.
var kingbaseVersionRegex = regexp.MustCompile(`(?i)KingbaseES\s+V(\d+)R(\d+)C(\d+)`)

// brandTokenMap is used to infer a brand from raw tokens ONLY when no brandHint
// was provided. Order matters: longest / most-specific tokens first, so e.g.
// "KingbaseES" outranks "PG" in any future collision.
var brandTokenMap = []struct {
	token    string
	brandKey string
}{
	{"kingbasees", "kingbase"},
	{"opengauss", "opengauss"},
	{"ivorysql", "ivorysql"},
	{"dameng", "dm8"},
	{"dm database", "dm8"},
	{"postgresql", "pg-compat"},
}

// Parse converts a raw banner into a NormalizedVersion.
//
//   - brandHint comes from T4 (port probe brand identification); trusted
//     when non-empty and recognized.
//   - Falls back to brandTokenMap inference when brandHint is empty/unknown
//     and raw contains a recognizable brand token.
//   - Never panics: invalid / empty / non-numeric input returns a zero
//     triple with ParsedOK=false and Brand best-effort set, letting T22
//     route the verdict through LLM fallback.
func Parse(raw, brandHint string) NormalizedVersion {
	nv := NormalizedVersion{
		Brand:    "unknown",
		Raw:      raw,
		ParsedOK: false,
	}

	canonicalBrand := canonicalizeBrand(brandHint)
	if canonicalBrand == "unknown" {
		// Try inference only when hint was absent / unknown — when hint is a
		// valid brand we trust T4 over re-inferring from raw (defensive
		// against banner-token spoofing).
		if cand, ok := inferBrandFromRaw(raw); ok {
			canonicalBrand = cand
		}
	}
	if canonicalBrand != "" {
		nv.Brand = canonicalBrand
	}

	first := firstNonEmptyLine(raw)
	if first == "" {
		// Empty / whitespace-only raw — leave ParsedOK=false and no SignatureTokens.
		return nv
	}
	nv.SignatureTokens = extractTokens(first)

	// Brand-specific matchers take priority so e.g. KingbaseES V008R006C0010
	// yields (8, 6, 10) instead of generic V008 → (8, 0, 0).
	if canonicalBrand == "kingbase" {
		if m := kingbaseVersionRegex.FindStringSubmatch(first); m != nil {
			nv.Major = atoiSafe(m[1])
			nv.Minor = atoiSafe(m[2])
			nv.Patch = atoiSafe(m[3])
			nv.ParsedOK = true
			return nv
		}
	}

	// Generic dotted / V-prefixed triple. We use FindStringSubmatch (not the
	// multi-match AllString) so we pick the EARLIEST number, which is the
	// version proper (after brand prefixes) on standard banners.
	if m := versionRegex.FindStringSubmatch(first); m != nil {
		nv.Major = atoiSafe(m[1])
		if m[2] != "" {
			nv.Minor = atoiSafe(m[2])
		}
		if m[3] != "" {
			nv.Patch = atoiSafe(m[3])
		}
		nv.ParsedOK = true
	}

	return nv
}

// canonicalizeBrand normalizes the T4-supplied brand hint into one of the
// five canonical keys. Empty / "unknown" / unrecognized → "unknown" (or ""
// when the caller wants to force re-inference).
func canonicalizeBrand(b string) string {
	switch strings.ToLower(strings.TrimSpace(b)) {
	case "":
		return "unknown"
	case "unknown":
		return "unknown"
	case "kingbase", "kingbasees", "kb":
		return "kingbase"
	case "dm8", "dm", "dameng":
		return "dm8"
	case "opengauss", "open-gauss", "gaussdb":
		return "opengauss"
	case "ivorysql", "ivory", "hg", "highgo":
		return "ivorysql"
	case "pg", "pg-compat", "postgresql", "postgres":
		return "pg-compat"
	default:
		return ""
	}
}

// inferBrandFromRaw scans the raw banner for any of the brandTokenMap tokens.
// First match wins (longest-first list ordering).
func inferBrandFromRaw(raw string) (string, bool) {
	lower := strings.ToLower(raw)
	for _, entry := range brandTokenMap {
		if strings.Contains(lower, entry.token) {
			return entry.brandKey, true
		}
	}
	return "", false
}

// firstNonEmptyLine returns the first non-blank line of s, or empty if all
// lines are blank. Used so that banners with trailing "(Debian ...)" / build
// notes still feed the parser the actual version line.
func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// extractTokens splits s into contiguous alphanumerics runs. Whitespace,
// punctuation, brackets, dots, and CJK all act as separators; numbers are
// preserved as separate tokens (so "V8.1.0" becomes ["V8","1","0"]). The
// result feeds T22 LLM prompt, never local classification.
func extractTokens(s string) []string {
	out := make([]string, 0, 8)
	cur := make([]rune, 0, 16)
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
			cur = append(cur, r)
		default:
			flush()
		}
	}
	flush()
	return out
}

// atoiSafe converts a digit-only substring to int without panicking on
// overflow or non-digits. Returns 0 on any non-digit character (callers
// derive the ParsedOK flag from the outer regex match, not atoiSafe).
func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
		// Overflow-safe: stay within int64 range; the inner shift saturates
		// implicitly at the int boundary rather than wrapping.
		if n > 1<<62 {
			return 0
		}
	}
	return n
}
