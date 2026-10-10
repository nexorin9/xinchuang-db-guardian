package check

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ----------------------------------------------------------------------------
// DriftEvidence 数据结构 — 一次漂移命中的完整事实包。
//
// 字段语义与 spec.md §3.3 审计行 + spec.md §4 验收故事一一对应。每条
// DriftEvidence 在 Compare() 返回后被 caller 写入 audit.jsonl，并在
// confirm-drift / re-verified 时由 State 字段推进状态机。
//
// JSON tag 是审计行 schema 的权威来源；任何字段改名或新增都须更新
// docs/concepts/ 与 README 输出样例。
// ----------------------------------------------------------------------------

// DriftEvidence — 一次漂移命中的完整事实包。
type DriftEvidence struct {
	EventID            string  `json:"event_id"`
	ContractID         string  `json:"contract_id"`
	SystemID           string  `json:"system_id"`
	Vendor             string  `json:"vendor"`
	Declared           string  `json:"declared"`
	Actual             string  `json:"actual"`
	PortRaw            string  `json:"port_raw"`
	DriverSha          string  `json:"driver_sha"`
	JDBCURL            string  `json:"jdbc_url"`
	Verdict            Verdict `json:"verdict"`
	Confidence         float64 `json:"confidence"`
	EvidenceSHA256     string  `json:"evidence_sha256"`
	Status             State   `json:"status"`
	PrevEvidenceSHA256 string  `json:"prev_evidence_sha256"`
	SelfHash           string  `json:"self_hash"`
	TsUTC              string  `json:"ts_utc"`
	InconsistentDims   []string `json:"inconsistent_dimensions,omitempty"`
	LLMVerdict         string  `json:"llm_verdict,omitempty"`
	LLMConfidence      float64 `json:"llm_confidence,omitempty"`
	LLMReasonZH        string  `json:"llm_reason_zh,omitempty"`
}

// ----------------------------------------------------------------------------
// ComputeEvidenceSHA256 — 三维签名：portRaw × driverSha × jdbcURL × systemID × ts。
//
// 公式（spec.md §3.2）：
//   sha256( portRaw || \x00 || driverSha || \x00 || jdbcURL || \x00 ||
//           systemID || \x00 || tsRFC3339Nano )
//
// \x00 分隔符避免 "ab"+"cd" 与 "a"+"bcd" 产生相同 hash。ts 升入输入确保
// 每次 Compare 的证据指纹都不同，从而 trail 不会在 5min 去重窗口里被自
// 动吞掉。
//
// 确定性：相同输入（含相同 ts）必须返回相同 hex；不同输入（含不同 ts）
// 必须返回不同 hex（collision 概率 ~ 2^-256，可忽略）。
// ----------------------------------------------------------------------------

// ComputeEvidenceSHA256 — evidence_sha256 = sha256(portRaw || \x00 || driverSha || \x00 || jdbcURL || \x00 || systemID || \x00 || ts).
func ComputeEvidenceSHA256(portRaw, driverSha, jdbcURL, systemID string, ts time.Time) string {
	h := sha256.New()
	h.Write([]byte(portRaw))
	h.Write([]byte{0x00})
	h.Write([]byte(driverSha))
	h.Write([]byte{0x00})
	h.Write([]byte(jdbcURL))
	h.Write([]byte{0x00})
	h.Write([]byte(systemID))
	h.Write([]byte{0x00})
	h.Write([]byte(ts.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}

// ----------------------------------------------------------------------------
// ComputeSelfHash — append-only sha256 链的链节 hash。
//
// 公式：sha256( prevEvidenceSHA256 || body )
//
// - prevEvidenceSHA256：上一条 DriftEvidence 的 SelfHash；链头为空串 ""。
// - body：除 self_hash 与 prev_evidence_sha256 字段外的其余字段拼接字节，
//   取自 HashBody(evidence)。body 在 append 时计算并随 row 持久化。
//
// 链式校验（VerifyChain）逐行核验：
//   1. row.SelfHash == ComputeSelfHash(row.PrevEvidenceSHA256, body)；
//   2. row.PrevEvidenceSHA256 == 上一个 row.SelfHash（首行 prev="" 放行）。
// 任一不匹配 → BadLineError{Reason: self_hash_mismatch | chain_break}。
// ----------------------------------------------------------------------------

// ComputeSelfHash — self_hash = sha256(prevEvidenceSHA256 || body)。
func ComputeSelfHash(prevEvidenceSHA256 string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(prevEvidenceSHA256))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// HashBody — 用于 SelfHash 计算的 body 拼接：除 self_hash 与
// prev_evidence_sha256 之外的全部字段按固定顺序拼接成字符串字节。
//
// 顺序对 hash 完全敏感；改动 HashBody 顺序必须改 evidence_sha 实现一致。
//
// 字段拼接用 `|` 分隔（业务字段内不出现 `|`，因为 system_id / vendor
// / event_id / declared 由 yaml schema 校验 + action / operator 由 CLI
// flag 解析，不允许包含 `|`）。
func HashBody(evidence DriftEvidence) []byte {
	var b strings.Builder
	b.WriteString(evidence.EventID)
	b.WriteString("|")
	b.WriteString(evidence.ContractID)
	b.WriteString("|")
	b.WriteString(evidence.SystemID)
	b.WriteString("|")
	b.WriteString(evidence.Vendor)
	b.WriteString("|")
	b.WriteString(evidence.Declared)
	b.WriteString("|")
	b.WriteString(evidence.Actual)
	b.WriteString("|")
	b.WriteString(evidence.PortRaw)
	b.WriteString("|")
	b.WriteString(evidence.DriverSha)
	b.WriteString("|")
	b.WriteString(evidence.JDBCURL)
	b.WriteString("|")
	b.WriteString(string(evidence.Verdict))
	b.WriteString("|")
	fmt.Fprintf(&b, "%.6f", evidence.Confidence)
	b.WriteString("|")
	b.WriteString(evidence.EvidenceSHA256)
	b.WriteString("|")
	b.WriteString(string(evidence.Status))
	b.WriteString("|")
	b.WriteString(evidence.TsUTC)
	return []byte(b.String())
}
