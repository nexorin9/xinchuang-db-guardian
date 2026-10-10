// Package output — 企微 webhook 出站（markdown 卡片）。
//
// 设计要点（spec.md §3.2 / §3.3 / §4）：
//   - POST application/json 到 WECHAT_WEBHOOK_URL；
//   - 卡片模板含 system_id / vendor / declared / actual / verdict / evidence_sha / ts_utc；
//   - 严禁出现患者可识别字段（system_id 在合同校验期已规范化为系统标识，不含患者 ID）；
//   - 4xx 不重试（参数错/权限错）；5xx / timeout 重试 1 次（200ms 退避）；
//   - 出站失败 → 调 NotifyAuditHook(kind=notify_error, …) 让审计行写入侧落盘，
//     本函数不直接写 JSONL（T11 接管）；凭据缺失 / 5xx / 超时均归 NotifyErrorKind*。
package output

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// NotifyErrorKind 与 Channel 常量已迁至 notify_error.go（本文件仅复用其类型）。

// NotifyAuditRow — 出站失败审计元数据；本包不直接写 JSONL，
// 由调用方（cmd daemon）注入 NotifyAuditHook 接入审计链（T11）。
type NotifyAuditRow struct {
	Kind           NotifyErrorKind
	Channel        string // "wecom" | "smtp"
	SystemID       string
	Vendor         string
	EvidenceSHA256 string
	HTTPStatus     int
	Err            string
	RetryCount     int
	Timestamp      time.Time
}

// NotifyAuditHook — 出站失败回调签名；测试用 in-memory recorder，生产用 audit appender。
type NotifyAuditHook func(NotifyAuditRow)

// wecomPayload — 企微 webhook POST 协议。
type wecomPayload struct {
	MsgType  string `json:"msgtype"`
	Markdown struct {
		Content string `json:"content"`
	} `json:"markdown"`
}

// WecomCard — 企微 markdown 卡片字段。
type WecomCard struct {
	SystemID       string
	Vendor         string
	Declared       string
	Actual         string
	Verdict        string
	EvidenceSHA256 string
	TsUTC          string
}

// RenderWecomCard — 模板渲染（独立函数方便测试与复用）。
//
// 严禁出现患者可识别字段：system_id 仅作系统级标识（来自 contracts.yaml）；
// evidence_sha256 是 sha256 三维签名，不含业务数据。
func RenderWecomCard(c WecomCard) string {
	var b strings.Builder
	b.WriteString("**信创合规漂移命中**\n")
	b.WriteString(fmt.Sprintf("- system_id: `%s`\n", c.SystemID))
	b.WriteString(fmt.Sprintf("- 厂商: %s\n", c.Vendor))
	b.WriteString(fmt.Sprintf("- 申报: %s\n", c.Declared))
	b.WriteString(fmt.Sprintf("- 实际: %s\n", c.Actual))
	b.WriteString(fmt.Sprintf("- verdict: `%s`\n", c.Verdict))
	b.WriteString(fmt.Sprintf("- evidence_sha: `%s`\n", c.EvidenceSHA256))
	b.WriteString(fmt.Sprintf("- 时间: %s", c.TsUTC))
	return b.String()
}

// WecomSender — 单实例发送器；带超时 + 1 次重试（仅 5xx / timeout 重试）。
type WecomSender struct {
	HTTPClient    *http.Client
	Timeout       time.Duration
	MaxRetries    int           // 额外重试次数；默认 1 表示总尝试 2 次
	RetryBackoff  time.Duration // 重试退避；默认 200ms
	NotifyHook    NotifyAuditHook
	Now           func() time.Time // 可注入（测试）
}

// NewWecomSender — 默认配置：5s timeout + 1 次重试 + 200ms 退避。
func NewWecomSender() *WecomSender {
	return &WecomSender{
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
		Timeout:      5 * time.Second,
		MaxRetries:   1,
		RetryBackoff: 200 * time.Millisecond,
		Now:          func() time.Time { return time.Now().UTC() },
	}
}

// SetNotifyHook — 注入失败回调。
func (s *WecomSender) SetNotifyHook(h NotifyAuditHook) { s.NotifyHook = h }

// SendWecom — POST WECHAT_WEBHOOK_URL 并按策略重试 / 调 Hook。
//
// 返回值：
//   - nil：200 / 204 成功；
//   - 非 nil：最后一次失败的 *SendError，含 HTTPStatus / ErrorKind / RetryCount / Err。
//
// 行为：
//   - webhookURL 空 → 直接失败 NotifyErrorKindWecom4xx；
//   - 4xx → 不重试 → 失败 NotifyErrorKindWecom4xx；
//   - 5xx → 重试 1 次 → 失败 NotifyErrorKindWecom5xx；
//   - timeout / network → 重试 1 次 → 失败 NotifyErrorKindWecomTimeout；
//   - 任何失败路径调 NotifyHook(kind=notify_error, …)。
func (s *WecomSender) SendWecom(ctx context.Context, webhookURL string, card WecomCard) error {
	if webhookURL == "" {
		return s.fail(ctx, NotifyAuditRow{
			Kind:    NotifyErrorKindWecom4xx,
			Channel: "wecom",
			SystemID: card.SystemID, Vendor: card.Vendor, EvidenceSHA256: card.EvidenceSHA256,
			Err: "missing webhook url",
		})
	}

	content := RenderWecomCard(card)
	body := wecomPayload{MsgType: "markdown"}
	body.Markdown.Content = content
	payload, err := json.Marshal(body)
	if err != nil {
		return s.fail(ctx, NotifyAuditRow{
			Kind:    NotifyErrorKindWecomMalformed,
			Channel: "wecom",
			SystemID: card.SystemID, Vendor: card.Vendor, EvidenceSHA256: card.EvidenceSHA256,
			Err: "marshal payload: " + err.Error(),
		})
	}

	maxAttempts := s.MaxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	var lastStatus int
	var lastKind NotifyErrorKind

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return s.fail(ctx, NotifyAuditRow{
					Kind:    NotifyErrorKindWecomTimeout,
					Channel: "wecom",
					SystemID: card.SystemID, Vendor: card.Vendor, EvidenceSHA256: card.EvidenceSHA256,
					HTTPStatus: lastStatus, Err: ctx.Err().Error(),
					RetryCount: attempt,
				})
			case <-time.After(s.RetryBackoff):
			}
		}

		status, err := s.doPost(ctx, webhookURL, payload)
		lastErr = err
		lastStatus = status

		if err == nil && status >= 200 && status < 300 {
			return nil
		}

		// 分类
		switch {
		case err != nil && (isTimeout(err) || isNetErr(err)):
			lastKind = NotifyErrorKindWecomTimeout
			// 重试
			continue
		case status >= 400 && status < 500:
			// 4xx 不重试
			return s.fail(ctx, NotifyAuditRow{
				Kind:    NotifyErrorKindWecom4xx,
				Channel: "wecom",
				SystemID: card.SystemID, Vendor: card.Vendor, EvidenceSHA256: card.EvidenceSHA256,
				HTTPStatus: status,
				Err:        http.StatusText(status),
				RetryCount: attempt,
			})
		case status >= 500:
			lastKind = NotifyErrorKindWecom5xx
			// 重试
			continue
		default:
			// 不可识别错误（含 3xx）→ 视为 4xx 失败
			return s.fail(ctx, NotifyAuditRow{
				Kind:    NotifyErrorKindWecom4xx,
				Channel: "wecom",
				SystemID: card.SystemID, Vendor: card.Vendor, EvidenceSHA256: card.EvidenceSHA256,
				HTTPStatus: status,
				Err:        fmt.Sprintf("unexpected status %d", status),
				RetryCount: attempt,
			})
		}
	}

	// 重试耗尽
	errMsg := "retries exhausted"
	if lastErr != nil {
		errMsg = lastErr.Error()
	}
	return s.fail(ctx, NotifyAuditRow{
		Kind:    lastKind,
		Channel: "wecom",
		SystemID: card.SystemID, Vendor: card.Vendor, EvidenceSHA256: card.EvidenceSHA256,
		HTTPStatus: lastStatus, Err: errMsg,
		RetryCount: s.MaxRetries,
	})
}

// doPost — 单次 HTTP POST；返回 status 与底层 err。
func (s *WecomSender) doPost(ctx context.Context, url string, payload []byte) (int, error) {
	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: s.Timeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	return resp.StatusCode, nil
}

// fail — 调 Hook 并返回 *SendError；Hook 为 nil 时只返回 error（测试场景）。
func (s *WecomSender) fail(ctx context.Context, row NotifyAuditRow) error {
	if row.Timestamp.IsZero() {
		row.Timestamp = s.now()
	}
	if s.NotifyHook != nil {
		s.NotifyHook(row)
	}
	errMsg := row.Err
	if errMsg == "" {
		errMsg = string(row.Kind)
	}
	return &SendError{
		Channel:    row.Channel,
		Kind:       row.Kind,
		HTTPStatus: row.HTTPStatus,
		RetryCount: row.RetryCount,
		Err:        errMsg,
	}
}

// now — 可注入时间。
func (s *WecomSender) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// SendError — 出站失败的统一错误包装；caller 可用 errors.As 拆解。
type SendError struct {
	Channel    string
	Kind       NotifyErrorKind
	HTTPStatus int
	RetryCount int
	Err        string
}

func (e *SendError) Error() string {
	if e.HTTPStatus != 0 {
		return fmt.Sprintf("%s send failed [%s, http=%d, retries=%d]: %s",
			e.Channel, e.Kind, e.HTTPStatus, e.RetryCount, e.Err)
	}
	return fmt.Sprintf("%s send failed [%s, retries=%d]: %s",
		e.Channel, e.Kind, e.RetryCount, e.Err)
}

// isTimeout / isNetErr — 启发式判断错误类别。
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	type t interface{ Timeout() bool }
	if te, ok := err.(t); ok && te.Timeout() {
		return true
	}
	return false
}

func isNetErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "EOF")
}
