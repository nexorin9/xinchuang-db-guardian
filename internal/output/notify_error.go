// Package output — 出站失败归类（kind=notify_error 审计行 + 重试预算）。
//
// 本文件是 wecom.go / smtp.go 的**分类层**：
//   - 持有 NotifyErrorKind 枚举（wecom_4xx / wecom_5xx / wecom_timeout / wecom_malformed
//     / smtp_auth / smtp_5xx / smtp_timeout / smtp_malformed / llm_unavailable）；
//   - 提供 NotifyErrorEvent 结构（一次性出站失败的元数据包）；
//   - 提供 ClassifyHTTP / ClassifySMTP / ClassifyLLM 三个分类入口；
//   - 提供 ShouldRetry(kind) → RetryBudget 决定重试策略；
//   - 提供 AppendNotifyError(auditPath, event) 写 kind=notify_error 审计行。
//
// 与其它文件的关系：
//   - wecom.go / smtp.go 仅做协议细节（HTTP POST / SMTP 握手），分类委托给本文件；
//   - fallback_audit.go（LLM 兜底）写 kind=llm_fallback，**与本文件不同**（kind 字段值不同）；
//     llm_unavailable 仅作为**分类标识**用于跨模块沟通，不在本文件写审计行。
//
// 关键不变量（spec.md §4 验收 + 安全合规边界）：
//  1. **永不自动推进 trial**：出站失败仅追加 1 行 JSONL（kind=notify_error），**不**
//     写 TrialStore，**不**调 PromoteTrial，**不**调 confirm-drift。
//  2. **不含患者可识别字段**：audit 行的 declared / actual 仅承载 vendor / version
//     字符串（不含患者 / 姓名 / 身份证 / 病案号 / 住院号 / 处方号）；
//     LLM 不可达场景由 caller 保证敏感字段已在 ctx 中预脱敏。
//  3. **kind 标签独立**：本文件写 kind=notify_error（区别于 drift / drift_confirmed /
//     drift_remedied / drift_re_verified / llm_fallback / probe_error / scan_error /
//     audit_anchor），便于 export-evidence 按 kind 过滤装订。
//  4. **append-only 链**：调 AppendJSONL，自动维护 self_hash 与 prev_evidence_sha256 链；
//     与 drift / llm_fallback 行共用同一条 sha256 链（不另起一条链）。
//
// 失败语义：审计行写入失败向上抛 error，**不**静默吞错；caller 收到 error 后应
// slog.Error 记录 reason，由信息科后续补录或重跑确认。
package output

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// NotifyErrorKind — 出站失败分类标签。
//
// 与 spec.md §4 / plan.md §3.2 验收一致：9 个枚举常量覆盖 wecom / SMTP / LLM
// 全部出站失败类型。
type NotifyErrorKind string

const (
	// 企微 webhook 出站失败。
	NotifyErrorKindWecom4xx       NotifyErrorKind = "wecom_4xx"       // HTTP 4xx：不重试
	NotifyErrorKindWecom5xx       NotifyErrorKind = "wecom_5xx"       // HTTP 5xx：重试 1 次
	NotifyErrorKindWecomTimeout   NotifyErrorKind = "wecom_timeout"   // 网络超时：重试 1 次
	NotifyErrorKindWecomMalformed NotifyErrorKind = "wecom_malformed" // 协议 / 序列化错：不重试

	// SMTP 出站失败。
	NotifyErrorKindSMTPAuth      NotifyErrorKind = "smtp_auth"      // 认证 / AUTH 失败：不重试
	NotifyErrorKindSMTP5xx       NotifyErrorKind = "smtp_5xx"       // SMTP 5xx：重试 1 次
	NotifyErrorKindSMTPTimeout   NotifyErrorKind = "smtp_timeout"   // 拨号 / 网络超时：重试 1 次
	NotifyErrorKindSMTPMalformed NotifyErrorKind = "smtp_malformed" // 协议 / 解析错：不重试

	// LLM 出站失败。
	NotifyErrorKindLLMUnavailable NotifyErrorKind = "llm_unavailable" // 不可达 / 5xx / 超时 / schema 不合法：不重试，且 trial 不静默推进
)

// Channel — 出站通道标识，与 NotifyErrorKind 一对一映射。
type Channel string

const (
	ChannelWecom Channel = "wecom"
	ChannelSMTP  Channel = "smtp"
	ChannelLLM   Channel = "llm"
)

// RetryBudget — 每种 NotifyErrorKind 对应的重试策略。
//
// 返回 RetryBudget{MaxAttempts int / Description string}：
//   - MaxAttempts = 1 表示不重试（仅原 attempt 一次）；
//   - MaxAttempts = 2 表示原 attempt + 1 次重试（默认 wecom / smtp）；
//   - MaxAttempts = 3 表示原 attempt + 2 次重试（保留扩展）。
//
// 该表与 wecom.go / smtp.go 的 MaxRetries 字段保持等价；本文件为 canonical 真源。
type RetryBudget struct {
	MaxAttempts int
	Description string
}

// RetryBudgetFor — 给定 NotifyErrorKind 返回重试预算；未知 kind 返回 MaxAttempts=1（不重试）。
func RetryBudgetFor(kind NotifyErrorKind) RetryBudget {
	switch kind {
	case NotifyErrorKindWecom5xx, NotifyErrorKindWecomTimeout:
		return RetryBudget{MaxAttempts: 2, Description: "wecom 5xx or timeout: 1 retry"}
	case NotifyErrorKindSMTP5xx, NotifyErrorKindSMTPTimeout:
		return RetryBudget{MaxAttempts: 2, Description: "smtp 5xx or timeout: 1 retry"}
	case NotifyErrorKindWecom4xx, NotifyErrorKindWecomMalformed:
		return RetryBudget{MaxAttempts: 1, Description: "wecom 4xx or malformed: no retry"}
	case NotifyErrorKindSMTPAuth, NotifyErrorKindSMTPMalformed:
		return RetryBudget{MaxAttempts: 1, Description: "smtp auth or malformed: no retry"}
	case NotifyErrorKindLLMUnavailable:
		return RetryBudget{MaxAttempts: 1, Description: "llm unavailable: no retry (rule verdict fallback)"}
	default:
		return RetryBudget{MaxAttempts: 1, Description: fmt.Sprintf("unknown kind %q: default no retry", kind)}
	}
}

// ShouldRetry — 便捷查询：当前 kind 是否允许重试。
func ShouldRetry(kind NotifyErrorKind) bool {
	return RetryBudgetFor(kind).MaxAttempts > 1
}

// NotifyErrorEvent — 一次出站失败事件的完整元数据包。
//
// 本结构是 wecom.go / smtp.go 的失败回调的入参，也是 AppendNotifyError 的入参。
// 与 audit.AuditRow 不同：本结构**额外**承载 Channel / HTTPStatus / RetryCount
// 等出站侧元数据；AppendNotifyError 把它映射成一行 kind=notify_error 的 JSONL。
type NotifyErrorEvent struct {
	// Kind 是分类标签（必填）。
	Kind NotifyErrorKind
	// Channel 是出站通道：wecom / smtp / llm（必填）。
	Channel Channel
	// SystemID / Vendor / EvidenceSHA256 是事件溯源字段，可空（出站失败未必能拿到完整上下文）。
	SystemID       string
	Vendor         string
	EvidenceSHA256 string
	// HTTPStatus 仅 wecom / 部分 smtp 路径有意义；LLM 不可达时填 0。
	HTTPStatus int
	// RetryCount 是实际重试次数（0 = 首次即失败；1 = 第一次重试后失败；…）。
	RetryCount int
	// Err 是底层错误消息（写入审计行 Action 字段或 detail）。
	Err string
	// Timestamp 是事件发生时间；为空时由 AppendNotifyError 填本机 UTC。
	Timestamp time.Time
	// EventID / ContractID 用于审计链溯源（与 DriftEvent.EventID 对齐）。
	EventID    string
	ContractID string
	// Action / Operator 标识审计写入侧（默认 "auto_notify_error" / "auto_notify"）。
	Action   string
	Operator string
}

// ClassifyHTTP — 企微 HTTP 出站失败的分类入口。
//
// 入参：
//   - status: HTTP 响应码（0 表示无响应，仅有 err）；
//   - err:   底层网络错误（可空）；
//
// 返回：
//   - kind: NotifyErrorKind 标签；
//   - retryable: 是否允许重试（由 RetryBudgetFor 推导）。
//
// 分类规则：
//   - err 是 timeout / network → wecom_timeout（重试 1 次）；
//   - status ∈ [400, 500) → wecom_4xx（不重试）；
//   - status ∈ [500, 600) → wecom_5xx（重试 1 次）；
//   - 其它（malformed body / 不可识别 status）→ wecom_malformed（不重试）。
func ClassifyHTTP(status int, err error) (kind NotifyErrorKind, retryable bool) {
	if err != nil {
		if isNotifyTimeoutErr(err) || isNotifyNetErr(err) {
			return NotifyErrorKindWecomTimeout, ShouldRetry(NotifyErrorKindWecomTimeout)
		}
		// 序列化 / 解码错 → malformed
		return NotifyErrorKindWecomMalformed, ShouldRetry(NotifyErrorKindWecomMalformed)
	}
	switch {
	case status >= 400 && status < 500:
		return NotifyErrorKindWecom4xx, ShouldRetry(NotifyErrorKindWecom4xx)
	case status >= 500 && status < 600:
		return NotifyErrorKindWecom5xx, ShouldRetry(NotifyErrorKindWecom5xx)
	default:
		// 0 / 3xx / 不可识别 → 保守 4xx
		return NotifyErrorKindWecom4xx, ShouldRetry(NotifyErrorKindWecom4xx)
	}
}

// ClassifySMTP — SMTP 出站失败的分类入口。
//
// 入参：
//   - smtpCode: SMTP 协议响应 3 位 code（0 表示无 SMTP code，仅有 err）；
//   - err:      底层错误（可空）；
//
// 返回：
//   - kind: NotifyErrorKind 标签；
//   - retryable: 是否允许重试。
//
// 分类规则：
//   - err 是 timeout → smtp_timeout（重试 1 次）；
//   - smtpCode == 535（auth failed 协议标准码）→ smtp_auth（不重试）；
//   - smtpCode ∈ [400, 500) → smtp_auth（不重试）；
//   - smtpCode ∈ [500, 600) 但非 535 → smtp_5xx（重试 1 次）；
//   - err 是 net.OpError 等拨号错 → smtp_5xx（重试 1 次）；
//   - 其它（handshake 失败 / DATA 解析错）→ smtp_malformed（不重试）。
func ClassifySMTP(smtpCode int, err error) (kind NotifyErrorKind, retryable bool) {
	if err != nil && isNotifyTimeoutErr(err) {
		return NotifyErrorKindSMTPTimeout, ShouldRetry(NotifyErrorKindSMTPTimeout)
	}
	// 535 是 SMTP 标准的「Authentication credentials invalid」码；语义属于
	// auth 类（不重试），不是普通的 5xx（重试）。SMTP code 范围 530-539
	// 都属于 auth 系列；本函数以 535 为代表做特例判断。
	if smtpCode == 535 {
		return NotifyErrorKindSMTPAuth, ShouldRetry(NotifyErrorKindSMTPAuth)
	}
	if smtpCode >= 500 {
		return NotifyErrorKindSMTP5xx, ShouldRetry(NotifyErrorKindSMTP5xx)
	}
	if smtpCode >= 400 {
		return NotifyErrorKindSMTPAuth, ShouldRetry(NotifyErrorKindSMTPAuth)
	}
	if err != nil {
		// 拨号 / network 错（不是 timeout）
		if isNotifyNetErr(err) {
			return NotifyErrorKindSMTP5xx, ShouldRetry(NotifyErrorKindSMTP5xx)
		}
		// 协议 / 解析错
		return NotifyErrorKindSMTPMalformed, ShouldRetry(NotifyErrorKindSMTPMalformed)
	}
	return NotifyErrorKindSMTPMalformed, ShouldRetry(NotifyErrorKindSMTPMalformed)
}

// ClassifyLLM — LLM 出站失败的分类入口。
//
// LLM 不可达 / 5xx / 超时 / schema 不合法 → 一律 NotifyErrorKindLLMUnavailable；
// 不重试（rule verdict fallback 即可，trial 不静默推进）。
func ClassifyLLM(status int, err error) (kind NotifyErrorKind, retryable bool) {
	return NotifyErrorKindLLMUnavailable, ShouldRetry(NotifyErrorKindLLMUnavailable)
}

// AppendNotifyError — 把一次出站失败事件写入 JSONL 审计链。
//
// 关键不变量：
//  1. **永不自动推进 trial** — 仅追加 1 行 JSONL，**不**写 TrialStore。
//  2. **kind 标签固定** — 写 kind=notify_error（区别于 llm_fallback）。
//  3. **完整出站元数据** — Channel / HTTPStatus / RetryCount / ErrorKind 全部落审计行。
//  4. **append-only 链** — 调 AppendJSONL，自动维护 self_hash 与 prev_evidence_sha256 链。
//
// 失败语义：JSONL 写入失败向上抛 error，**不**静默吞错。
func AppendNotifyError(auditPath string, ev NotifyErrorEvent) (AuditRow, error) {
	if auditPath == "" {
		return AuditRow{}, errors.New("output: AppendNotifyError auditPath empty")
	}
	if ev.Kind == "" {
		return AuditRow{}, errors.New("output: AppendNotifyError Kind empty")
	}
	if ev.Channel == "" {
		return AuditRow{}, errors.New("output: AppendNotifyError Channel empty")
	}

	tsUTC := ""
	if !ev.Timestamp.IsZero() {
		tsUTC = ev.Timestamp.UTC().Format(time.RFC3339Nano)
	} else {
		tsUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}

	action := ev.Action
	if action == "" {
		action = "auto_notify_error"
	}
	operator := ev.Operator
	if operator == "" {
		operator = "auto_notify"
	}

	// Verdict 字段填 kind 字符串（审计行 verdict 字段不含 ok/trial，因为本行
	// 不是 drift verdict，是出站失败事件）；export-evidence 按 kind 过滤，
	// notify_error 行不进 drift_events.csv。
	row := AuditRow{
		TsUTC:          tsUTC,
		EventID:        ev.EventID,
		ContractID:     ev.ContractID,
		SystemID:       ev.SystemID,
		Vendor:         ev.Vendor,
		EvidenceSHA256: ev.EvidenceSHA256,
		Verdict:        string(ev.Kind),
		Action:         action,
		Operator:       operator,
		Kind:           "notify_error",
	}

	// 把出站侧元数据塞到 Actual 字段（JSONL 字段对齐 spec.md §3.3 表）。
	row.Actual = renderNotifyDetail(ev)

	if written, err := AppendJSONL(auditPath, row); err != nil {
		return AuditRow{}, fmt.Errorf("output: AppendNotifyError AppendJSONL: %w", err)
	} else if written != 1 {
		return AuditRow{}, fmt.Errorf("output: AppendNotifyError wrote %d rows, expected 1", written)
	}
	return row, nil
}

// renderNotifyDetail — 把出站侧元数据渲染成可读 detail 字符串。
//
// 写入 audit.jsonl 的 Actual 字段；不含患者可识别信息（仅含 system_id /
// vendor / kind / http / retry / 错误摘要）。
func renderNotifyDetail(ev NotifyErrorEvent) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("notify_kind=%s channel=%s", ev.Kind, ev.Channel))
	if ev.HTTPStatus != 0 {
		b.WriteString(fmt.Sprintf(" http_status=%d", ev.HTTPStatus))
	}
	if ev.RetryCount > 0 {
		b.WriteString(fmt.Sprintf(" retry_count=%d", ev.RetryCount))
	}
	if ev.Err != "" {
		// 截断避免过长污染审计行
		errStr := ev.Err
		if len(errStr) > 200 {
			errStr = errStr[:200] + "..."
		}
		b.WriteString(fmt.Sprintf(" err=%q", errStr))
	}
	return b.String()
}

// isNotifyTimeoutErr / isNotifyNetErr — 出站层 timeout / network 错误的启发式判断。
//
// 这些 helper 仅在出站层（本文件 + wecom.go / smtp.go）使用，不导出。
func isNotifyTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	type t interface{ Timeout() bool }
	if te, ok := err.(t); ok && te.Timeout() {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	return false
}

func isNotifyNetErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "broken pipe")
}
