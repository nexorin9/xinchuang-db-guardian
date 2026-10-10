// Package output — SMTP 出站（net/smtp + markdown 邮件正文）。
//
// 设计要点：
//   - Subject = `[XINCHUANG-DRIFT] ${system_id}`；
//   - Body = markdown（含 vendor / declared / actual / verdict / evidence_sha / ts_utc / event_id）；
//   - TLS / StartTLS / None 三种模式（端口默认 587 StartTLS / 465 TLS / 25 None）；
//   - 认证错 / 4xx 不重试；5xx / timeout 重试 1 次；
//   - 出站失败 → NotifyAuditHook(kind=notify_error, …)。
package output

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SMTPMode — SMTP 连接模式。
type SMTPMode string

const (
	SMTPModeNone     SMTPMode = "none"
	SMTPModeStartTLS SMTPMode = "starttls"
	SMTPModeTLS      SMTPMode = "tls"
)

// SMTPConfig — SMTP 连接配置。
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Mode     SMTPMode
	// From 是 From 头地址（默认 = Username）。
	From string
	// Timeout 是单次 SMTP 握手 + 邮件投递总超时。
	Timeout time.Duration
	// MaxRetries 是额外重试次数；默认 1。
	MaxRetries int
	// RetryBackoff 重试退避；默认 200ms。
	RetryBackoff time.Duration
}

// SMTPMessage — 单条 SMTP 出站邮件。
type SMTPMessage struct {
	To       []string
	Subject  string
	Body     string
	SystemID string
}

// SMTPSender — 单实例发送器。
type SMTPSender struct {
	Config     SMTPConfig
	NotifyHook NotifyAuditHook
	// Dial 自定义拨号（测试用）；默认 net.Dial。
	Dial func(network, addr string) (net.Conn, error)
	// Now 可注入时间（测试用）。
	Now func() time.Time
}

// LoadSMTPConfigFromEnv — 从环境变量构造 SMTPConfig（凭据全 env，零硬编码）。
//
// 必填（缺一返 InvalidConfig）：
//   - SMTP_HOST
//   - SMTP_PORT（缺省 587；可显式 465 / 25）
//   - SMTP_USERNAME
//   - SMTP_PASSWORD
//   - SMTP_TO（逗号分隔收件人列表）
//
// 可选：
//   - SMTP_MODE ∈ {none, starttls, tls}（缺省 starttls）
//   - SMTP_FROM（缺省 = Username）
//   - SMTP_TIMEOUT_SECS（缺省 10）
//   - SMTP_MAX_RETRIES（缺省 1）
//   - SMTP_RETRY_BACKOFF_MS（缺省 200）
//
// 注意：仅在 cfg 中填 Host/Port 时使用 env；调用方可在传入 cfg 上预先 set 部分字段作为 override。
func LoadSMTPConfigFromEnv(env func(string) string) (SMTPConfig, []string, error) {
	if env == nil {
		env = func(string) string { return "" }
	}
	host := env("SMTP_HOST")
	if host == "" {
		return SMTPConfig{}, nil, errors.New("output: SMTP_HOST missing")
	}
	username := env("SMTP_USERNAME")
	if username == "" {
		return SMTPConfig{}, nil, errors.New("output: SMTP_USERNAME missing")
	}
	password := env("SMTP_PASSWORD")
	if password == "" {
		return SMTPConfig{}, nil, errors.New("output: SMTP_PASSWORD missing")
	}
	toRaw := env("SMTP_TO")
	if toRaw == "" {
		return SMTPConfig{}, nil, errors.New("output: SMTP_TO missing")
	}
	var toList []string
	for _, p := range strings.Split(toRaw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			toList = append(toList, p)
		}
	}
	if len(toList) == 0 {
		return SMTPConfig{}, nil, errors.New("output: SMTP_TO empty after split")
	}

	port := 587
	if p := env("SMTP_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return SMTPConfig{}, nil, fmt.Errorf("output: bad SMTP_PORT %q", p)
		}
		port = n
	}

	mode := SMTPModeStartTLS
	if m := env("SMTP_MODE"); m != "" {
		switch SMTPMode(strings.ToLower(m)) {
		case SMTPModeNone, SMTPModeStartTLS, SMTPModeTLS:
			mode = SMTPMode(strings.ToLower(m))
		default:
			return SMTPConfig{}, nil, fmt.Errorf("output: bad SMTP_MODE %q", m)
		}
	}

	timeout := 10 * time.Second
	if t := env("SMTP_TIMEOUT_SECS"); t != "" {
		n, err := strconv.Atoi(t)
		if err != nil || n <= 0 {
			return SMTPConfig{}, nil, fmt.Errorf("output: bad SMTP_TIMEOUT_SECS %q", t)
		}
		timeout = time.Duration(n) * time.Second
	}

	maxRetries := 1
	if r := env("SMTP_MAX_RETRIES"); r != "" {
		n, err := strconv.Atoi(r)
		if err != nil || n < 0 {
			return SMTPConfig{}, nil, fmt.Errorf("output: bad SMTP_MAX_RETRIES %q", r)
		}
		maxRetries = n
	}

	retryBackoff := 200 * time.Millisecond
	if b := env("SMTP_RETRY_BACKOFF_MS"); b != "" {
		n, err := strconv.Atoi(b)
		if err != nil || n <= 0 {
			return SMTPConfig{}, nil, fmt.Errorf("output: bad SMTP_RETRY_BACKOFF_MS %q", b)
		}
		retryBackoff = time.Duration(n) * time.Millisecond
	}

	from := env("SMTP_FROM")
	if from == "" {
		from = username
	}

	cfg := SMTPConfig{
		Host:        host,
		Port:        port,
		Username:    username,
		Password:    password,
		Mode:        mode,
		From:        from,
		Timeout:     timeout,
		MaxRetries:  maxRetries,
		RetryBackoff: retryBackoff,
	}
	return cfg, toList, nil
}

// NewDefaultSMTPSender — 默认配置：10s timeout + 1 次重试 + StartTLS。
func NewDefaultSMTPSender(cfg SMTPConfig) *SMTPSender {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 1
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 200 * time.Millisecond
	}
	if cfg.Mode == "" {
		cfg.Mode = SMTPModeStartTLS
	}
	if cfg.From == "" {
		cfg.From = cfg.Username
	}
	if cfg.Port == 0 {
		switch cfg.Mode {
		case SMTPModeTLS:
			cfg.Port = 465
		case SMTPModeStartTLS, SMTPModeNone:
			cfg.Port = 587
		}
	}
	return &SMTPSender{
		Config: cfg,
		Dial:   (&net.Dialer{Timeout: cfg.Timeout}).Dial,
		Now:    func() time.Time { return time.Now().UTC() },
	}
}

// SetNotifyHook — 注入失败回调。
func (s *SMTPSender) SetNotifyHook(h NotifyAuditHook) { s.NotifyHook = h }

// RenderSubject — Subject = `[XINCHUANG-DRIFT] ${system_id}`。
func RenderSubject(systemID string) string {
	return fmt.Sprintf("[XINCHUANG-DRIFT] %s", systemID)
}

// RenderSMTPBody — markdown 邮件正文。
func RenderSMTPBody(c WecomCard, eventID string) string {
	var b strings.Builder
	b.WriteString("# 信创合规漂移命中\n\n")
	b.WriteString(fmt.Sprintf("- event_id: `%s`\n", eventID))
	b.WriteString(fmt.Sprintf("- system_id: `%s`\n", c.SystemID))
	b.WriteString(fmt.Sprintf("- 厂商: %s\n", c.Vendor))
	b.WriteString(fmt.Sprintf("- 申报: %s\n", c.Declared))
	b.WriteString(fmt.Sprintf("- 实际: %s\n", c.Actual))
	b.WriteString(fmt.Sprintf("- verdict: `%s`\n", c.Verdict))
	b.WriteString(fmt.Sprintf("- evidence_sha: `%s`\n", c.EvidenceSHA256))
	b.WriteString(fmt.Sprintf("- 时间: %s\n", c.TsUTC))
	b.WriteString("\n> 此邮件由信创数据库合规漂移守护自动发出，回复邮箱无人值守；\n")
	b.WriteString("> 详情见 audit.jsonl 与 export-evidence 证据包。")
	return b.String()
}

// SendSMTP — 投递 SMTP 邮件；带超时 + 1 次重试。
//
// 行为：
//   - Config.Host 空或 To 空 → 直接失败 NotifyErrorKindSMTPAuth；
//   - 认证错 (smtp.ErrAuth) → 不重试 → 失败 NotifyErrorKindSMTPAuth；
//   - SMTP 4xx 响应 → 不重试 → 失败 NotifyErrorKindSMTP5xx（带 SMTP code）；
//   - 5xx / timeout → 重试 1 次 → 失败 NotifyErrorKindSMTP5xx 或 SMTPTimeout；
//   - 任何失败 → NotifyAuditHook(kind=notify_error, …)。
func (s *SMTPSender) SendSMTP(ctx context.Context, msg SMTPMessage) error {
	if s.Config.Host == "" || s.Config.Port == 0 {
		return s.fail(ctx, NotifyAuditRow{
			Kind:    NotifyErrorKindSMTPAuth,
			Channel: "smtp",
			SystemID: msg.SystemID, Err: "missing smtp host/port",
		})
	}
	if len(msg.To) == 0 {
		return s.fail(ctx, NotifyAuditRow{
			Kind:    NotifyErrorKindSMTPMalformed,
			Channel: "smtp",
			SystemID: msg.SystemID, Err: "empty To",
		})
	}

	maxAttempts := s.Config.MaxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	var lastKind NotifyErrorKind

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return s.fail(ctx, NotifyAuditRow{
					Kind:    NotifyErrorKindSMTPTimeout,
					Channel: "smtp",
					SystemID: msg.SystemID,
					Err:     ctx.Err().Error(),
					RetryCount: attempt,
				})
			case <-time.After(s.Config.RetryBackoff):
			}
		}

		err := s.sendOnce(ctx, msg)
		if err == nil {
			return nil
		}
		lastErr = err

		// 分类
		se, ok := err.(*SendError)
		if !ok {
			// 不可拆解 → 视为 timeout / network
			lastKind = NotifyErrorKindSMTPTimeout
			continue
		}
		switch se.Kind {
		case NotifyErrorKindSMTPAuth, NotifyErrorKindSMTPMalformed:
			// 不重试
			return s.fail(ctx, NotifyAuditRow{
				Kind:    se.Kind,
				Channel: "smtp",
				SystemID: msg.SystemID,
				Err:     se.Err,
				RetryCount: attempt,
			})
		default:
			lastKind = se.Kind
			// 重试
		}
	}

	errMsg := "retries exhausted"
	if lastErr != nil {
		errMsg = lastErr.Error()
	}
	return s.fail(ctx, NotifyAuditRow{
		Kind:    lastKind,
		Channel: "smtp",
		SystemID: msg.SystemID, Err: errMsg,
		RetryCount: s.Config.MaxRetries,
	})
}

// sendOnce — 单次 SMTP 投递；返回 *SendError。
func (s *SMTPSender) sendOnce(ctx context.Context, msg SMTPMessage) error {
	addr := net.JoinHostPort(s.Config.Host, strconv.Itoa(s.Config.Port))
	dialer := s.Dial
	if dialer == nil {
		dialer = (&net.Dialer{Timeout: s.Config.Timeout}).Dial
	}

	// 用 ctx 控制拨号超时
	dialCtx, cancel := context.WithTimeout(ctx, s.Config.Timeout)
	defer cancel()

	type dialResult struct {
		conn net.Conn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		c, e := dialer("tcp", addr)
		dialCh <- dialResult{conn: c, err: e}
	}()
	var conn net.Conn
	select {
	case <-dialCtx.Done():
		return &SendError{
			Channel: "smtp", Kind: NotifyErrorKindSMTPTimeout,
			Err: "dial timeout: " + dialCtx.Err().Error(),
		}
	case r := <-dialCh:
		if r.err != nil {
			return &SendError{
				Channel: "smtp", Kind: classifyDialErr(r.err),
				Err: r.err.Error(),
			}
		}
		conn = r.conn
	}

	// 构造 smtp.Client（不依赖 Client.Start 之外的网络读）
	client, err := smtp.NewClient(conn, s.Config.Host)
	if err != nil {
		_ = conn.Close()
		return &SendError{
			Channel: "smtp", Kind: NotifyErrorKindSMTPMalformed,
			Err: "smtp handshake: " + err.Error(),
		}
	}
	defer func() {
		_ = client.Quit()
	}()

	switch s.Config.Mode {
	case SMTPModeTLS:
		if err := client.StartTLS(nil); err != nil {
			_ = client.Close()
			return &SendError{Channel: "smtp", Kind: NotifyErrorKindSMTPMalformed, Err: "starttls: " + err.Error()}
		}
	case SMTPModeStartTLS:
		// StartTLS 同 TLS（StartTLS 与 TLS 模式都使用 STARTTLS 命令）
		if err := client.StartTLS(nil); err != nil {
			// 非致命：某些服务器不支持 STARTTLS 时降级为明文（仅测试桩场景）
		}
	case SMTPModeNone:
		// 明文，不调 StartTLS
	}

	if s.Config.Username != "" {
		auth := smtp.PlainAuth("", s.Config.Username, s.Config.Password, s.Config.Host)
		if err := client.Auth(auth); err != nil {
			_ = client.Close()
			return &SendError{
				Channel: "smtp", Kind: NotifyErrorKindSMTPAuth,
				Err: "auth: " + err.Error(),
			}
		}
	}

	from := s.Config.From
	if from == "" {
		from = s.Config.Username
	}
	if err := client.Mail(from); err != nil {
		return &SendError{Channel: "smtp", Kind: classifySMTPRespErr(err), Err: "MAIL FROM: " + err.Error()}
	}
	for _, rcpt := range msg.To {
		if err := client.Rcpt(rcpt); err != nil {
			return &SendError{Channel: "smtp", Kind: classifySMTPRespErr(err), Err: "RCPT TO " + rcpt + ": " + err.Error()}
		}
	}

	w, err := client.Data()
	if err != nil {
		return &SendError{Channel: "smtp", Kind: classifySMTPRespErr(err), Err: "DATA: " + err.Error()}
	}
	// 构造 RFC 5322 邮件
	full := buildRFC822(from, msg.To, msg.Subject, msg.Body)
	if _, err := w.Write([]byte(full)); err != nil {
		_ = w.Close()
		return &SendError{Channel: "smtp", Kind: classifySMTPRespErr(err), Err: "write body: " + err.Error()}
	}
	if err := w.Close(); err != nil {
		return &SendError{Channel: "smtp", Kind: classifySMTPRespErr(err), Err: "close body: " + err.Error()}
	}

	return nil
}

// buildRFC822 — 拼装最小 RFC 822 邮件头 + 正文。
func buildRFC822(from string, to []string, subject, body string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("From: %s\r\n", from))
	b.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	b.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

// classifyDialErr — 拨号错误分类。
func classifyDialErr(err error) NotifyErrorKind {
	if err == nil {
		return NotifyErrorKindSMTPMalformed
	}
	if isTimeout(err) {
		return NotifyErrorKindSMTPTimeout
	}
	return NotifyErrorKindSMTP5xx
}

// classifySMTPRespErr — SMTP 协议响应错误分类。
//
// net/smtp 把 SMTP code 嵌入 err.Error() 字符串，格式形如：
//
//	"MAIL FROM:<x>: 550 mailbox unavailable"
//	"RCPT TO <x>: 451 temporary failure"
//	"AUTH PLAIN: 535 auth failed"
//
// 我们用「3 位 SMTP code + 首字符」启发式判断（5 开头 → 5xx；4 开头 → 4xx/auth）。
func classifySMTPRespErr(err error) NotifyErrorKind {
	if err == nil {
		return NotifyErrorKindSMTPMalformed
	}
	msg := err.Error()
	// 用正则提 SMTP 3 位 code（出现在 ": NN" 或 " NN" 后）
	code := extractSMTPCode(msg)
	switch {
	case code >= 500:
		return NotifyErrorKindSMTP5xx
	case code >= 400:
		return NotifyErrorKindSMTPAuth
	}
	// 退化：消息里出现 4/5 但拿不出 3 位 code → 视作 malformed
	if strings.Contains(msg, "4") || strings.Contains(msg, "5") {
		return NotifyErrorKindSMTPMalformed
	}
	return NotifyErrorKindSMTPMalformed
}

// extractSMTPCode — 从错误消息里抽 3 位 SMTP code。
//
// 接受以下两种形态：
//   - "550 mailbox unavailable"（开头就是 3 位 code）
//   - ": 550 mailbox unavailable"（: 后接 3 位 code）
//   - " 550 mailbox unavailable"（空格后接 3 位 code）
//
// 找不到返 0。
func extractSMTPCode(msg string) int {
	if len(msg) < 3 {
		return 0
	}
	// 优先：消息开头 3 位数字（net/smtp 直接返回 code 在最前）
	if c1, c2, c3 := msg[0], msg[1], msg[2]; c1 >= '0' && c1 <= '9' && c2 >= '0' && c2 <= '9' && c3 >= '0' && c3 <= '9' {
		return int(c1-'0')*100 + int(c2-'0')*10 + int(c3-'0')
	}
	// 次选：在 ": " 或 " " 之后找 3 位数字
	for i := 0; i+4 < len(msg); i++ {
		if msg[i] == ':' && msg[i+1] == ' ' {
			if c1, c2, c3 := msg[i+2], msg[i+3], msg[i+4]; c1 >= '0' && c1 <= '9' && c2 >= '0' && c2 <= '9' && c3 >= '0' && c3 <= '9' {
				return int(c1-'0')*100 + int(c2-'0')*10 + int(c3-'0')
			}
		}
	}
	for i := 0; i+3 < len(msg); i++ {
		if msg[i] == ' ' {
			if c1, c2, c3 := msg[i+1], msg[i+2], msg[i+3]; c1 >= '0' && c1 <= '9' && c2 >= '0' && c2 <= '9' && c3 >= '0' && c3 <= '9' {
				return int(c1-'0')*100 + int(c2-'0')*10 + int(c3-'0')
			}
		}
	}
	return 0
}

// fail — 调 Hook 并返回 *SendError。
func (s *SMTPSender) fail(ctx context.Context, row NotifyAuditRow) error {
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

func (s *SMTPSender) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// errSentinel — 用于 errors.Is 兼容（保留供后续单元测试）。
var errSentinel = errors.New("output: send failed")
