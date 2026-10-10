// Package classify — 三维核对的核心分类器：合同声明 vs 实际响应。
//
// 设计参考 cilium tools/cloud-dep-check/main.go:116-127 的 classify(pkg) 函数语义：
//   - 白名单按 prefix 匹配分类（cloud-dep-check 用 import path prefix）；
//   - 不匹配返回空串 → 视为"不在白名单" = mismatch 候选。
//
// 本项目把这一模式扩展为：
//   - prefix 层：brandHint + vendorSignature.VersionRegex 联合 prefix 匹配；
//   - token 层：从 actual 抽取非字母数字 token 集合，与 vendorSignature.SignatureTokens
//     求交集；交集占比 < 50% → confidence 衰减；
//   - 典型混杂检测：vendor=dm8 且 actual 含 'PostgreSQL'/'Debian' 直接 mismatch + 100% 置信；
//   - Kingbase 伪 Kingbase：vendor=kingbase 且 actual 含 'PostgreSQL' 但无 'KingbaseES' → mismatch；
//   - 置信度衰减（T19）：基础 1.0；prefix miss → -0.3；token 交集 < 50% → -0.2；
//     confusion hit → +0.5（最高 1.0）；
//   - LLMContext：T22 兜底集成时，给 LLM Gateway 喂结构化上下文（vendor + tokens + prefix 信号），
//     显式不携带 actual 原字符串（避免端口原文泄漏）。
//
// 调用方：internal/check/contract.go 的 Compare() 用 Classify() 做维度 1（端口响应 vs 期望版本）；
//         internal/check/llm_integration.go (T22) 在 confidence ∈ [0.3, 0.7) 时调 LLM，
//         用 BuildLLMContext 构造入参。
package classify

import (
	"fmt"
	"regexp"
	"strings"

	"xinchuang-db-guardian/internal/config"
)

// Status — 分类结果。
type Status string

const (
	// StatusMatch — actual 命中 vendor 期望。
	StatusMatch Status = "match"
	// StatusMismatch — actual 与 vendor 期望不一致（漂移候选）。
	StatusMismatch Status = "mismatch"
	// StatusUnknown — actual 为空或无可识别 token，无法判定。
	StatusUnknown Status = "unknown"
)

// Result — Classify 的完整产出。
type Result struct {
	Status         Status
	Confidence     float64 // 0.0–1.0
	MismatchTokens []string
}

// NormalizedActual 拆分 actual 字符串为可比较的 token 集合。
type NormalizedActual struct {
	Raw   string
	Lower string
	// Tokens 非字母数字拆分并归一（小写、过滤空字符串）。
	Tokens []string
}

// normalize 拆分 actual 字符串为 token 集合。
func normalize(raw string) NormalizedActual {
	lower := strings.ToLower(raw)
	// 按非字母数字拆分；为兼容中文等非 ASCII 字符，统一按 unicode 边界切分。
	split := regexp.MustCompile(`[^a-z0-9]+`).Split(lower, -1)
	tokens := make([]string, 0, len(split))
	for _, t := range split {
		if t == "" {
			continue
		}
		tokens = append(tokens, t)
	}
	return NormalizedActual{
		Raw:    raw,
		Lower:  lower,
		Tokens: tokens,
	}
}

// tokenSet — 把 token 列表变成集合（用于交集运算）。
func tokenSet(tokens []string) map[string]struct{} {
	m := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		m[t] = struct{}{}
	}
	return m
}

// hasAnyToken — actual tokens 是否包含任一候选 token。
func hasAnyToken(actual map[string]struct{}, candidates []string) (bool, []string) {
	var hits []string
	for _, c := range candidates {
		c = strings.ToLower(c)
		if _, ok := actual[c]; ok {
			hits = append(hits, c)
		}
	}
	return len(hits) > 0, hits
}

// confusionMismatchTokens — 典型混杂 token 集合（PG 在非 PG 期望下出现即 mismatch）。
var confusionMismatchTokens = map[string][]string{
	"dm8":       {"postgresql", "debian", "redhat"},
	"opengauss": {"kingbase"},
	"ivorysql":  {"dm8"},
	"pg-compat": {"kingbase", "dm8", "dameng", "opengauss"},
	"kingbase":  {"dameng"},
}

// vendorPrefixTokens — vendor 期望在 actual 中出现的关键 token。
var vendorPrefixTokens = map[string][]string{
	"kingbase":  {"kingbasees"},
	"dm8":       {"dm", "dameng"},
	"opengauss": {"opengauss"},
	"ivorysql":  {"ivorysql"},
	"pg-compat": {"postgresql"},
}

// ComputeConfidence — T19 置信度衰减公式：
//
//	基础 = 1.0
//	prefix 不命中 → -0.3
//	token 交集占比 < 50% → -0.2
//	典型混杂检测命中（confusion mismatch） → +0.5（最高 1.0）
//
// 返回 [0.0, 1.0] 范围内的浮点置信度。
func ComputeConfidence(prefixHit bool, tokenOverlap float64, confusionHit bool) float64 {
	conf := 1.0
	if !prefixHit {
		conf -= 0.3
	}
	if tokenOverlap < 0.5 {
		conf -= 0.2
	}
	if confusionHit {
		conf += 0.5
	}
	if conf > 1.0 {
		return 1.0
	}
	if conf < 0.0 {
		return 0.0
	}
	return conf
}

// VersionMeta — 简化版版本元数据（与 probe/version.NormalizedVersion 兼容）。
//
// classify 包内独立定义以避免循环依赖；调用方可以从 probe/version.Parse() 转换过来。
// 字段语义与 NormalizedVersion 一致：零值表示未提供版本元数据。
type VersionMeta struct {
	Brand string
	Major int
	Minor int
	Patch int
}

// LLMContext — T19 / T22 桥接：当 Classify 无法定论时（confidence ∈ [0.3, 0.7)），
// 传给 LLM Gateway 的结构化上下文。显式不携带 actual 原字符串（避免敏感信息），
// 仅携带：vendor 期望、normalized tokens、prefix 信号、可选 version 元数据。
type LLMContext struct {
	Vendor       string
	ActualTokens []string
	VendorTokens []string
	PrefixHit    bool
	TokenOverlap float64
	BrandHint    string
	Version      *VersionMeta // optional; nil if caller didn't pass it
}

// BuildLLMContext — 构造 LLM 入参上下文。仅结构化字段，不携带 actual 原字符串。
func BuildLLMContext(actual string, vendor string, brandMap *config.BrandMap) LLMContext {
	return BuildLLMContextWithVersion(actual, vendor, brandMap, nil)
}

// BuildLLMContextWithVersion — BuildLLMContext + 可选 version 元数据。
//
// 调用方一般用法：BuildLLMContextWithVersion(portRaw, contract.Vendor, brandMap,
// &classify.VersionMeta{Brand: nv.Brand, Major: nv.Major, Minor: nv.Minor, Patch: nv.Patch})
// 其中 nv 是 probe/version.Parse(portRaw, brandHint) 的产物。
func BuildLLMContextWithVersion(actual string, vendor string, brandMap *config.BrandMap, ver *VersionMeta) LLMContext {
	trimmed := strings.TrimSpace(actual)
	norm := normalize(trimmed)
	actualSet := tokenSet(norm.Tokens)
	ctx := LLMContext{
		Vendor:       strings.ToLower(vendor),
		ActualTokens: norm.Tokens,
		BrandHint:    vendor,
		Version:      ver,
	}

	if brandMap != nil {
		if sig, ok := brandMap.Get(vendor); ok {
			ctx.VendorTokens = sig.SignatureTokens
			for _, rx := range sig.VersionRegex {
				re, err := regexp.Compile(rx)
				if err != nil {
					continue
				}
				if re.MatchString(trimmed) {
					ctx.PrefixHit = true
					break
				}
			}
		}
	}

	if len(ctx.VendorTokens) > 0 {
		hits := 0
		for _, t := range ctx.VendorTokens {
			t = strings.ToLower(t)
			if _, ok := actualSet[t]; ok {
				hits++
			}
		}
		ctx.TokenOverlap = float64(hits) / float64(len(ctx.VendorTokens))
	}

	return ctx
}

// RenderLLMPrompt — 把 LLMContext 渲染为中文 prompt（不含 actual 原字符串）。
//
// 字段顺序：vendor 期望 → actual tokens → vendor 期望 tokens → prefix 命中 →
// token 交集占比 → 版本元数据（可选）。最末要求 LLM 输出 JSON {verdict, confidence, reason}。
func (c LLMContext) RenderLLMPrompt() string {
	versionLine := ""
	if c.Version != nil {
		versionLine = fmt.Sprintf("版本元数据：%s %d.%d.%d\n", c.Version.Brand, c.Version.Major, c.Version.Minor, c.Version.Patch)
	}
	return fmt.Sprintf(
		"请根据以下结构化信息判断数据库厂商一致性。\n"+
			"vendor 期望：%s\n"+
			"actual tokens：%v\n"+
			"vendor 期望 tokens：%v\n"+
			"prefix regex 命中：%v\n"+
			"token 交集占比：%.2f\n"+
			"%s"+
			"请输出 JSON：{verdict, confidence, reason}",
		c.Vendor, c.ActualTokens, c.VendorTokens, c.PrefixHit, c.TokenOverlap, versionLine,
	)
}

// Classify — actual 字符串 vs vendor 期望分类（T19：置信度改用 ComputeConfidence 统一衰减）。
//
// 入参：
//   - actual: 端口握手 / 解析后的 version 字符串（如 "KingbaseES V008R006C0010 ..."）；
//   - vendor: 合同声明品牌（kingbase / dm8 / openGauss / IvorySQL / pg-compat …）；
//   - brandMap: 品牌指纹字典（用于 version regex + signature tokens）；
//
// 行为：
//  1. actual 为空/仅空白 → unknown + confidence=0；
//  2. 典型混杂检测（dm8 期望但 actual 含 PostgreSQL/Debian）→ mismatch + confidence=1.0；
//  3. Kingbase 伪 Kingbase（vendor=kingbase + actual 含 PostgreSQL 但无 KingbaseES）→ mismatch + confidence=1.0；
//  4. prefix regex 命中 → match；不命中 → token 交集占比 ≥ 50% → match；< 50% → mismatch；
//  5. 兜底：未命中任何已知品牌 → unknown；
//  6. 所有 confidence 通过 ComputeConfidence(prefixHit, overlap, confusionHit) 统一计算。
func Classify(actual string, vendor string, brandMap *config.BrandMap) Result {
	trimmed := strings.TrimSpace(actual)
	if trimmed == "" {
		return Result{Status: StatusUnknown, Confidence: 0.0, MismatchTokens: nil}
	}

	norm := normalize(trimmed)
	actualSet := tokenSet(norm.Tokens)
	vendorLower := strings.ToLower(vendor)

	// 典型混杂检测：vendor 期望但 actual 含其他品牌关键 token。
	confusionHit := false
	var confusionTokens []string
	if suspects, ok := confusionMismatchTokens[vendorLower]; ok {
		if hit, which := hasAnyToken(actualSet, suspects); hit {
			confusionHit = true
			confusionTokens = which
		}
	}

	// Kingbase 伪 Kingbase：vendor=kingbase 且 actual 含 PostgreSQL 但无 KingbaseES。
	fakeKingbase := false
	if vendorLower == "kingbase" {
		if _, hasPg := actualSet["postgresql"]; hasPg {
			if _, hasKb := actualSet["kingbasees"]; !hasKb {
				fakeKingbase = true
			}
		}
	}

	// 任何混淆检测命中 → 直接 mismatch（不依赖 brandMap，confidence 通过 ComputeConfidence 公式）。
	// 注意：放在 brandMap.Get 之前，否则 nil brandMap 会 panic。
	if confusionHit {
		return Result{
			Status:         StatusMismatch,
			Confidence:     ComputeConfidence(false, 0, true),
			MismatchTokens: confusionTokens,
		}
	}
	if fakeKingbase {
		return Result{
			Status:         StatusMismatch,
			Confidence:     ComputeConfidence(false, 0, true),
			MismatchTokens: []string{"postgresql"},
		}
	}

	// 取 vendor signature。
	if brandMap == nil {
		// brandMap 为 nil —— 退化到 token 集合检查。
		return classifyByTokens(norm, actualSet, vendorLower)
	}
	sig, hasSig := brandMap.Get(vendor)
	if !hasSig {
		// 未注册的 vendor —— 退化为 token 集合检查。
		return classifyByTokens(norm, actualSet, vendorLower)
	}

	// prefix regex 匹配。
	prefixHit := false
	for _, rx := range sig.VersionRegex {
		re, err := regexp.Compile(rx)
		if err != nil {
			continue
		}
		if re.MatchString(trimmed) {
			prefixHit = true
			break
		}
	}

	// token 交集：actual 与 vendor signature tokens。
	overlap := 0.0
	if len(sig.SignatureTokens) > 0 {
		hits := 0
		for _, t := range sig.SignatureTokens {
			t = strings.ToLower(t)
			if _, ok := actualSet[t]; ok {
				hits++
			}
		}
		overlap = float64(hits) / float64(len(sig.SignatureTokens))
	}

	// 正常路径：prefix + token 联合判定。
	if prefixHit {
		return Result{
			Status:         StatusMatch,
			Confidence:     ComputeConfidence(prefixHit, overlap, false),
			MismatchTokens: nil,
		}
	}
	if len(sig.SignatureTokens) > 0 && overlap >= 0.5 {
		return Result{
			Status:         StatusMatch,
			Confidence:     ComputeConfidence(prefixHit, overlap, false),
			MismatchTokens: nil,
		}
	}
	// prefix + token 都未充分命中 → mismatch，列出缺失的关键 token。
	missing := make([]string, 0, len(sig.SignatureTokens))
	for _, t := range sig.SignatureTokens {
		t = strings.ToLower(t)
		if _, ok := actualSet[t]; !ok {
			missing = append(missing, t)
		}
	}
	return Result{
		Status:         StatusMismatch,
		Confidence:     ComputeConfidence(prefixHit, overlap, false),
		MismatchTokens: missing,
	}
}

// classifyByTokens — brand 未注册时的退化路径。
func classifyByTokens(norm NormalizedActual, actualSet map[string]struct{}, vendorLower string) Result {
	expected, ok := vendorPrefixTokens[vendorLower]
	if !ok {
		return Result{Status: StatusUnknown, Confidence: 0.0, MismatchTokens: nil}
	}
	if hit, _ := hasAnyToken(actualSet, expected); hit {
		return Result{Status: StatusMatch, Confidence: 0.7, MismatchTokens: nil}
	}
	return Result{
		Status:         StatusMismatch,
		Confidence:     0.7,
		MismatchTokens: expected,
	}
}
