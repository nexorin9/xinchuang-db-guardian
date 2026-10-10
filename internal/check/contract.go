// Package check — 三维核对引擎 compare()：portRaw × driverSha × jdbcURL。
//
// 设计参考 cilium tools/cloud-dep-check/main.go:129-148 的 check() 函数语义：
//   - 任一不匹配 → forbidden（融合后 = trial）；
//   - 全匹配 → ok（不入审计行）。
//
// 本项目把 check() 扩展为三维：
//   1. portRaw vs vendor.version_pattern（端口响应 vs 期望版本）；
//   2. driverSha vs allow_drift_sha256（驱动 jar sha 集合比对）；
//   3. jdbcURL pattern vs vendor.JDBCURLPattern（JDBC URL 模式匹配）。
//
// 任一不一致 → verdict=trial + 状态默认 StateTrial（永不静默进 confirmed）；
// 全一致 → verdict=ok（不入审计行，仅写 transient 行）。
package check

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"xinchuang-db-guardian/internal/classify"
	"xinchuang-db-guardian/internal/config"
	"xinchuang-db-guardian/internal/probe/driver"
	"xinchuang-db-guardian/internal/probe/port"
)

// Verdict — 三维核对结果。
type Verdict string

const (
	// VerdictOK — 三维全一致。
	VerdictOK Verdict = "ok"
	// VerdictTrial — 任一不一致；待人工 confirm-drift 推进。
	VerdictTrial Verdict = "trial"
)

// DriftEvidence / ComputeEvidenceSHA256 / ComputeSelfHash / HashBody 的定义在
// evidence.go 中（拆分出独立模块，T16）。本文件保留 Compare3D / Compare
// 高层入口。

// Compare3D — 纯三维核对函数（详细拆分 T7 高层入口）。
//
// 三维独立评估，每一维独立判定：
//   - 维度 1（port_raw）: Classify(portRaw, vendor) → match/mismatch/unknown；
//     仅 mismatch 视为失败；unknown 视为"不能定论"且本身不计入 InconsistentDims，
//     但若 unknown + 另两维 ok → verdict=trial（unknown 即"无法声明一致"）。
//   - 维度 2（driver_sha）: driverScan.Sha256 ∈ contract.AllowDriftSHA256 集合；
//     driverScan 为 nil 或 Sha256 为空时视为"无证据"，**不**计为失败（维度缺失而非维度不一致）。
//   - 维度 3（jdbc_url）: driverScan.JDBCURLs 至少一条命中任一 vendor.JDBCURLPattern；
//     driverScan 为 nil 或 JDBCURLs 为空时同样视为"无证据"，**不**计为失败。
//
// verdict 组合规则：
//   - 任一显式失败 → VerdictTrial；
//   - 维度 1 = unknown + 维度 2/3 无失败 → VerdictTrial（unknown 即"声明不能成立"，等同 trial 信号）；
//   - 全部 ok → VerdictOK。
//
// InconsistentDims 按维度顺序列出失败维度名（port_raw / driver_sha / jdbc_url）。
// unknown 不计入，但调用方可在 classify.Classifier.Result 中读 Status=unknown 自行判别。
//
// 重要：本函数**不**依赖 *config.BrandMap；直接拿 vendor config.VendorSignature 即可。
// 便于 T22 / T40 等上层封装按需做 errgroup 并行评估（每维独立超时独立判定）。
func Compare3D(
	portProbe port.ProbeResult,
	driverScan *driver.ScanResult,
	vendor config.VendorSignature,
	contract config.ContractV,
) (Verdict, []string) {
	dimFails := make([]string, 0, 3)

	portRaw := strings.TrimSpace(string(portProbe.Raw))
	if portRaw == "" && portProbe.Err != nil {
		portRaw = portProbe.Err.Error()
	}

	// ---- 维度 1: portRaw vs vendor.version_pattern ----
	// 直接复用 vendor 内的 VersionRegex 做 prefix 命中；不依赖 BrandMap。
	cls := classifyByVendorRegex(portRaw, vendor)
	switch cls {
	case classify.StatusMatch:
		// 命中 → 维度 1 ok
	case classify.StatusMismatch:
		dimFails = append(dimFails, "port_raw")
	default:
		// StatusUnknown / 空 — 视为"声明不能成立"信号，直接 trial，但不计入 InconsistentDims
		// 避免与已知 mismatch 混用。返回值用特殊通道表达：unknown 仅让 verdict=trial，
		// 不出现在 InconsistentDims 数组里（调用方需要时可单独判 classify.Confidence < 0.3）。
		dimFails = append(dimFails, "port_raw")
	}

	// ---- 维度 2: driverSha vs AllowDriftSHA256 ----
	// driverScan == nil 或 Sha256 为空 → 视为"无证据"，**不**计为失败
	if driverScan != nil && driverScan.Sha256 != "" {
		allowed := make(map[string]bool, len(contract.AllowDriftSHA256))
		for _, s := range contract.AllowDriftSHA256 {
			allowed[strings.ToLower(strings.TrimSpace(s))] = true
		}
		if !allowed[strings.ToLower(strings.TrimSpace(driverScan.Sha256))] {
			dimFails = append(dimFails, "driver_sha")
		}
	}

	// ---- 维度 3: jdbcURL pattern vs vendor.JDBCURLPattern ----
	// driverScan == nil 或 JDBCURLs 为空 → 视为"无证据"，**不**计为失败
	if driverScan != nil && len(driverScan.JDBCURLs) > 0 {
		if len(vendor.JDBCURLPattern) == 0 {
			// vendor 声明了 JDBCURLPattern 为空但实际驱动目录里有 jdbcURL → 视为不匹配
			dimFails = append(dimFails, "jdbc_url")
		} else {
			matched := false
			for _, u := range driverScan.JDBCURLs {
				if matchAnyPattern(u.URL, vendor.JDBCURLPattern) {
					matched = true
					break
				}
			}
			if !matched {
				dimFails = append(dimFails, "jdbc_url")
			}
		}
	}

	if len(dimFails) == 0 {
		return VerdictOK, nil
	}
	return VerdictTrial, dimFails
}

// classifyByVendorRegex — 直接用 vendor.VersionRegex 做 prefix + 简易 token 判定，
// 不依赖 *config.BrandMap。该函数为本包私有 helper，仅 Compare3D 调用。
// 返回 classify.Status 之一：match / mismatch / unknown。
//
// 行为：
//   - portRaw 为空 → unknown；
//   - VersionRegex 非空 + 任一命中 → match（prefix 层优先）；
//   - VersionRegex 全不命中 + SignatureTokens 非空 + token 交集 > 0 → match；
//   - VersionRegex 全不命中 + SignatureTokens 也全不命中 → mismatch；
//   - VersionRegex 空 + SignatureTokens 非空 → 仅 token 命中判定（仍可比）；
//   - VersionRegex 空 + SignatureTokens 也空 → unknown（无法判定）。
func classifyByVendorRegex(portRaw string, vendor config.VendorSignature) classify.Status {
	if strings.TrimSpace(portRaw) == "" {
		return classify.StatusUnknown
	}
	// prefix 层：任一 VersionRegex 命中 → match
	if len(vendor.VersionRegex) > 0 {
		for _, rx := range vendor.VersionRegex {
			re, err := regexp.Compile(rx)
			if err != nil {
				continue
			}
			if re.MatchString(portRaw) {
				return classify.StatusMatch
			}
		}
	}
	// token 层：仅在 VersionRegex 全部未命中（或为空）时启用
	if len(vendor.SignatureTokens) > 0 {
		rawTokens := splitNonAlnum(strings.ToLower(portRaw))
		vendorTokensLower := make([]string, len(vendor.SignatureTokens))
		for i, t := range vendor.SignatureTokens {
			vendorTokensLower[i] = strings.ToLower(t)
		}
		inter := 0
		for _, vt := range vendorTokensLower {
			for _, rt := range rawTokens {
				if vt == rt {
					inter++
					break
				}
			}
		}
		if inter > 0 {
			return classify.StatusMatch
		}
	}
	// VersionRegex 全不命中 + SignatureTokens 也无命中（或为空） → 无法声明 match
	if len(vendor.VersionRegex) == 0 && len(vendor.SignatureTokens) == 0 {
		return classify.StatusUnknown
	}
	return classify.StatusMismatch
}

// splitNonAlnum — 把字符串按非字母数字切分（保留连续字母数字）；空 token 跳过。
// 简单实现：c ∈ [a-zA-Z0-9] 视为 token 字符，否则切分。
func splitNonAlnum(s string) []string {
	out := make([]string, 0, 4)
	cur := make([]rune, 0, 8)
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			cur = append(cur, r)
			continue
		}
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}

// matchAnyPattern — jdbcURL 是否命中任一 pattern。
func matchAnyPattern(jdbcURL string, patterns []string) bool {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if re.MatchString(jdbcURL) {
			return true
		}
	}
	return false
}

// Compare — 三维核对主入口。
//
// 入参：
//   - contract: 合同白名单（声明）；
//   - portProbe: 端口握手实际响应（事实）；
//   - driverScan: 驱动扫描结果（事实，可为 nil 表示该 system 无驱动目录）；
//   - brandMap: 品牌指纹字典（用于 vendor signature）；
//
// 行为：调 Compare3D 取 verdict + InconsistentDims，再组装 DriftEvidence。
//   - 三维全 ok → VerdictOK + Status 默认 StateTrial（仍输出但不入审计）；
//   - 任一不一致 → VerdictTrial + StateTrial + InconsistentDims 列出失败维度。
//
// 注意：本函数返回的 DriftEvidence 始终是新生成的（不读 bbolt）；trial 入 bbolt
// 由调用方 internal/output/store.go 负责（不在本任务范围内）。
func Compare(contract config.ContractV, portProbe port.ProbeResult, driverScan *driver.ScanResult, brandMap *config.BrandMap) DriftEvidence {
	ts := portProbe.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	portRaw := strings.TrimSpace(string(portProbe.Raw))
	if portRaw == "" && portProbe.Err != nil {
		portRaw = portProbe.Err.Error()
	}

	var driverSha string
	var jdbcURLs []string
	if driverScan != nil {
		driverSha = driverScan.Sha256
		for _, u := range driverScan.JDBCURLs {
			jdbcURLs = append(jdbcURLs, u.URL)
		}
	}
	jdbcURLJoined := strings.Join(jdbcURLs, "|")
	if len(jdbcURLJoined) > 256 {
		jdbcURLJoined = jdbcURLJoined[:256]
	}

	// 取 vendor signature（若未注册则构造空 vendor，Compare3D 走 unknown 路径 → port_raw fail）
	vendor, _ := brandMap.Get(contract.Vendor)
	verdict, dimFails := Compare3D(portProbe, driverScan, vendor, contract)

	// 维度 1 的 cls.Confidence 由 brandMap 版 Classify 提供（独立计算语义兼容）
	cls := classify.Classify(portRaw, contract.Vendor, brandMap)
	confidence := cls.Confidence
	if verdict == VerdictOK {
		confidence = 1.0
	} else if confidence < 0.3 {
		confidence = 0.3
	}

	evidenceSHA := ComputeEvidenceSHA256(portRaw, driverSha, jdbcURLJoined, contract.SystemID, ts)

	return DriftEvidence{
		EventID:            fmt.Sprintf("%s-%d", contract.EventIDPrefix, ts.UnixNano()),
		ContractID:         contract.ContractID,
		SystemID:           contract.SystemID,
		Vendor:             contract.Vendor,
		Declared:           contract.VersionPattern,
		Actual:             portRaw,
		PortRaw:            portRaw,
		DriverSha:          driverSha,
		JDBCURL:            jdbcURLJoined,
		Verdict:            verdict,
		Confidence:         confidence,
		EvidenceSHA256:     evidenceSHA,
		Status:             StateTrial,
		PrevEvidenceSHA256: "",
		SelfHash:           "",
		TsUTC:              ts.UTC().Format(time.RFC3339Nano),
		InconsistentDims:   dimFails,
	}
}

// HashBody — 见 evidence.go（T16 拆分）。
