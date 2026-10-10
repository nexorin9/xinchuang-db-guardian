package output

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// smtpMock — 极简 SMTP 服务器桩（用于测试）。
//
// 行为：
//   - 收到 CONNECT → 220 banner；
//   - 收到 EHLO → 250 OK；
//   - 收到 AUTH PLAIN/LOGIN → 235 OK（可配失败）；
//   - 收到 MAIL FROM / RCPT TO → 250 OK；
//   - 收到 DATA → 354 → 等待 CRLF.CRLF → 250 OK；
//   - 收到 QUIT → 221 bye。
//
// 通过 fakeServer.noReplyMode 控制首读延迟（模拟 timeout）；
// 通过 fakeServer.codeOverride 控制 SMTP code 替换（模拟 5xx / 4xx）。
type smtpMock struct {
	listener       net.Listener
	wg             sync.WaitGroup
	conversations  []string
	codeMap        map[string]string // SMTP command prefix → reply code
	rejectCommands map[string]bool   // SMTP command prefix → 一律拒
	holdOnDATA     time.Duration
	mu             sync.Mutex
	stopOnce       sync.Once
}

func newSMTPMock(t *testing.T, opts ...func(*smtpMock)) *smtpMock {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("smtp mock listen: %v", err)
	}
	m := &smtpMock{
		listener:       ln,
		codeMap:        map[string]string{},
		rejectCommands: map[string]bool{},
	}
	for _, opt := range opts {
		opt(m)
	}
	m.wg.Add(1)
	go m.acceptLoop()
	return m
}

func (m *smtpMock) acceptLoop() {
	defer m.wg.Done()
	for {
		c, err := m.listener.Accept()
		if err != nil {
			return
		}
		m.wg.Add(1)
		go m.handle(c)
	}
}

func (m *smtpMock) handle(c net.Conn) {
	defer m.wg.Done()
	defer c.Close()
	r := bufio.NewReader(c)
	w := bufio.NewWriter(c)
	defer w.Flush()

	// 220 banner
	fmt.Fprintf(w, "220 smtp.mock ready\r\n")
	w.Flush()

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		m.record(line)

		cmd := strings.ToUpper(strings.Fields(line)[0])

		// 校验 codeMap 强制替换
		if code, ok := m.codeMap[cmd]; ok && code != "" {
			fmt.Fprintf(w, "%s forced\r\n", code)
			w.Flush()
			if strings.HasPrefix(code, "4") || strings.HasPrefix(code, "5") {
				// 拒后等 QUIT 或继续
				continue
			}
		}

		switch cmd {
		case "EHLO", "HELO":
			fmt.Fprintf(w, "250-smtp.mock\r\n250 SIZE 10240000\r\n")
		case "AUTH":
			if m.rejectCommands["AUTH"] {
				fmt.Fprintf(w, "535 auth rejected\r\n")
			} else {
				fmt.Fprintf(w, "235 auth ok\r\n")
			}
		case "MAIL":
			fmt.Fprintf(w, "250 sender ok\r\n")
		case "RCPT":
			fmt.Fprintf(w, "250 recipient ok\r\n")
		case "DATA":
			fmt.Fprintf(w, "354 go ahead\r\n")
			w.Flush()
			if m.holdOnDATA > 0 {
				time.Sleep(m.holdOnDATA)
			}
			// 读 DATA 体直到 \r\n.\r\n
			var body strings.Builder
			for {
				dl, derr := r.ReadString('\n')
				if derr != nil {
					return
				}
				dl = strings.TrimRight(dl, "\r\n")
				if dl == "." {
					break
				}
				body.WriteString(dl)
				body.WriteString("\n")
				m.record("DATA_BODY: " + dl)
			}
			fmt.Fprintf(w, "250 message accepted\r\n")
		case "QUIT":
			fmt.Fprintf(w, "221 bye\r\n")
			return
		case "RSET", "NOOP":
			fmt.Fprintf(w, "250 ok\r\n")
		case "STARTTLS":
			// 测试桩里我们不实现 TLS，回 454 让客户端继续明文（无成本）
			fmt.Fprintf(w, "454 TLS not available\r\n")
		default:
			fmt.Fprintf(w, "500 unrecognized\r\n")
		}
		w.Flush()
	}
}

func (m *smtpMock) record(line string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conversations = append(m.conversations, line)
}

func (m *smtpMock) conversationsCopy() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.conversations))
	copy(out, m.conversations)
	return out
}

func (m *smtpMock) addr() string {
	return m.listener.Addr().String()
}

func (m *smtpMock) close() {
	m.stopOnce.Do(func() {
		_ = m.listener.Close()
	})
}

// 拆分 addr 为 host / port。
func splitHostPort(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// smtpTestCfg — 默认测试 SMTP 配置。
func smtpTestCfg(addr string) SMTPConfig {
	host, port := splitHostPort(addr)
	return SMTPConfig{
		Host:     host,
		Port:     port,
		Username: "smoke",
		Password: "smoke-pwd",
		Mode:     SMTPModeNone, // 测试桩不实现 TLS
		Timeout:  2 * time.Second,
	}
}

func TestSMTPSender_SendSuccess(t *testing.T) {
	m := newSMTPMock(t)
	defer m.close()

	rec := &recorder{}
	s := NewDefaultSMTPSender(smtpTestCfg(m.addr()))
	s.SetNotifyHook(rec.Hook())

	card := sampleCard
	body := RenderSMTPBody(card, "evt-001")
	msg := SMTPMessage{
		To:      []string{"ops@hospital.local"},
		Subject: RenderSubject(card.SystemID),
		Body:    body,
		SystemID: card.SystemID,
	}
	if err := s.SendSMTP(context.Background(), msg); err != nil {
		t.Fatalf("SendSMTP failed: %v", err)
	}
	if n := atomic.LoadInt32(&rec.n); n != 0 {
		t.Errorf("Hook should not fire on success; got %d", n)
	}

	// 验证 SMTP 会话
	conv := strings.Join(m.conversationsCopy(), "\n")
	for _, kw := range []string{"EHLO", "AUTH PLAIN", "MAIL FROM", "RCPT TO", "DATA", "QUIT"} {
		if !strings.Contains(conv, kw) {
			t.Errorf("SMTP conversation missing %q", kw)
		}
	}
	// 验证 Subject / Body（DATA_BODY 行包含邮件正文）
	if !strings.Contains(conv, "[XINCHUANG-DRIFT] lis-pacs-1") {
		t.Errorf("Subject not in conversation: %s", conv)
	}
	if !strings.Contains(conv, "DATA_BODY: Subject: [XINCHUANG-DRIFT] lis-pacs-1") {
		t.Errorf("Subject line not in DATA body: %s", conv)
	}
	if !strings.Contains(conv, "DATA_BODY: - event_id: `evt-001`") {
		t.Errorf("Body field evt-001 missing: %s", conv)
	}
	if !strings.Contains(conv, card.EvidenceSHA256) {
		t.Errorf("Body evidence_sha missing: %s", conv)
	}
}

func TestSMTPSender_AuthRejected(t *testing.T) {
	m := newSMTPMock(t, func(mm *smtpMock) {
		mm.rejectCommands["AUTH"] = true
	})
	defer m.close()

	rec := &recorder{}
	s := NewDefaultSMTPSender(smtpTestCfg(m.addr()))
	s.SetNotifyHook(rec.Hook())

	msg := SMTPMessage{
		To: []string{"ops@hospital.local"}, Subject: "x", Body: "y", SystemID: "lis-pacs-1",
	}
	err := s.SendSMTP(context.Background(), msg)
	if err == nil {
		t.Fatalf("expected auth failure")
	}
	se, ok := err.(*SendError)
	if !ok {
		t.Fatalf("expected *SendError, got %T", err)
	}
	if se.Kind != NotifyErrorKindSMTPAuth {
		t.Errorf("expected kind=smtp_auth, got %s", se.Kind)
	}
	if se.Channel != "smtp" {
		t.Errorf("expected channel=smtp, got %s", se.Channel)
	}
	if se.RetryCount != 0 {
		t.Errorf("auth failure should not retry; got RetryCount=%d", se.RetryCount)
	}
	rows := rec.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 hook call, got %d", len(rows))
	}
	if rows[0].Kind != NotifyErrorKindSMTPAuth {
		t.Errorf("hook kind mismatch: %s", rows[0].Kind)
	}
}

func TestSMTPSender_MissingHost(t *testing.T) {
	rec := &recorder{}
	cfg := SMTPConfig{Mode: SMTPModeNone}
	s := NewDefaultSMTPSender(cfg)
	s.SetNotifyHook(rec.Hook())

	msg := SMTPMessage{To: []string{"a@b"}, Subject: "x", Body: "y", SystemID: "lis-pacs-1"}
	err := s.SendSMTP(context.Background(), msg)
	if err == nil {
		t.Fatalf("expected missing host error")
	}
	se := err.(*SendError)
	if se.Kind != NotifyErrorKindSMTPAuth {
		t.Errorf("expected kind=smtp_auth on missing host, got %s", se.Kind)
	}
}

func TestSMTPSender_EmptyTo(t *testing.T) {
	m := newSMTPMock(t)
	defer m.close()

	rec := &recorder{}
	s := NewDefaultSMTPSender(smtpTestCfg(m.addr()))
	s.SetNotifyHook(rec.Hook())

	msg := SMTPMessage{Subject: "x", Body: "y", SystemID: "lis-pacs-1"}
	err := s.SendSMTP(context.Background(), msg)
	if err == nil {
		t.Fatalf("expected empty To error")
	}
	se := err.(*SendError)
	if se.Kind != NotifyErrorKindSMTPMalformed {
		t.Errorf("expected kind=smtp_malformed on empty To, got %s", se.Kind)
	}
}

func TestSMTPSender_DialTimeout(t *testing.T) {
	// 用一个 1ms 超时的拨号器对不可达地址拨号 → 立即超时
	rec := &recorder{}
	cfg := SMTPConfig{
		Host: "192.0.2.1", Port: 25, Mode: SMTPModeNone,
		Timeout: 1 * time.Millisecond, MaxRetries: 0,
	}
	s := NewDefaultSMTPSender(cfg)
	s.SetNotifyHook(rec.Hook())
	// 自定义一个直接返回 timeout 的 Dial（避免真实网络抖动）
	s.Dial = func(network, addr string) (net.Conn, error) {
		return nil, &timeoutErr{}
	}

	msg := SMTPMessage{To: []string{"a@b"}, Subject: "x", Body: "y", SystemID: "lis-pacs-1"}
	err := s.SendSMTP(context.Background(), msg)
	if err == nil {
		t.Fatalf("expected dial timeout")
	}
	se, ok := err.(*SendError)
	if !ok {
		t.Fatalf("expected *SendError, got %T: %v", err, err)
	}
	if se.Kind != NotifyErrorKindSMTPTimeout {
		t.Errorf("expected kind=smtp_timeout, got %s", se.Kind)
	}
	rows := rec.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 hook call, got %d", len(rows))
	}
	if rows[0].Kind != NotifyErrorKindSMTPTimeout {
		t.Errorf("hook kind mismatch: %s", rows[0].Kind)
	}
}

// timeoutErr — 模拟 net.Error.Timeout() == true 的错误。
type timeoutErr struct{}

func (e *timeoutErr) Error() string   { return "i/o timeout" }
func (e *timeoutErr) Timeout() bool   { return true }
func (e *timeoutErr) Temporary() bool { return true }

func TestSMTPSender_5xxRetriesThenSuccess(t *testing.T) {
	var rcptCount int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				w := bufio.NewWriter(conn)
				fmt.Fprintf(w, "220 smtp.mock ready\r\n")
				w.Flush()
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.ToUpper(strings.Fields(line)[0])
					switch cmd {
					case "EHLO", "HELO":
						fmt.Fprintf(w, "250 ok\r\n")
					case "AUTH":
						fmt.Fprintf(w, "235 ok\r\n")
					case "MAIL":
						fmt.Fprintf(w, "250 ok\r\n")
					case "RCPT":
						n := atomic.AddInt32(&rcptCount, 1)
						if n <= 2 {
							fmt.Fprintf(w, "550 mailbox unavailable\r\n")
						} else {
							fmt.Fprintf(w, "250 ok\r\n")
						}
					case "DATA":
						fmt.Fprintf(w, "354 go ahead\r\n")
						w.Flush()
						for {
							dl, derr := r.ReadString('\n')
							if derr != nil {
								return
							}
							dl = strings.TrimRight(dl, "\r\n")
							if dl == "." {
								break
							}
						}
						fmt.Fprintf(w, "250 accepted\r\n")
					case "QUIT":
						fmt.Fprintf(w, "221 bye\r\n")
						return
					default:
						fmt.Fprintf(w, "500 unrecognized\r\n")
					}
					w.Flush()
				}
			}(c)
		}
	}()

	rec := &recorder{}
	host, port := splitHostPort(ln.Addr().String())
	cfg := SMTPConfig{
		Host: host, Port: port, Username: "u", Password: "p",
		Mode: SMTPModeNone, Timeout: 1 * time.Second,
		MaxRetries: 2, RetryBackoff: 5 * time.Millisecond,
	}
	s := NewDefaultSMTPSender(cfg)
	s.SetNotifyHook(rec.Hook())

	msg := SMTPMessage{To: []string{"ops@hospital.local"}, Subject: "x", Body: "y", SystemID: "lis-pacs-1"}
	err = s.SendSMTP(context.Background(), msg)
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	if n := atomic.LoadInt32(&rcptCount); n != 3 {
		t.Errorf("expected 3 RCPT attempts, got %d", n)
	}
}

func TestRenderSubject_Format(t *testing.T) {
	got := RenderSubject("his-core")
	want := "[XINCHUANG-DRIFT] his-core"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRenderSMTPBody_NoPatientFields(t *testing.T) {
	card := sampleCard
	rendered := RenderSMTPBody(card, "evt-001")
	banned := []string{"患者", "姓名", "身份证", "病案号", "住院号", "处方号", "patient", "patient_id"}
	for _, kw := range banned {
		if strings.Contains(rendered, kw) {
			t.Errorf("body should not contain %q; got: %s", kw, rendered)
		}
	}
	for _, kw := range []string{
		"evt-001", card.SystemID, card.Vendor,
		card.Declared, card.Actual, card.Verdict, card.EvidenceSHA256, card.TsUTC,
	} {
		if !strings.Contains(rendered, kw) {
			t.Errorf("body missing %q; got: %s", kw, rendered)
		}
	}
}

func TestNewDefaultSMTPSender_DefaultsApplied(t *testing.T) {
	cfg := SMTPConfig{Host: "smtp.example.com", Username: "u"}
	s := NewDefaultSMTPSender(cfg)
	if s.Config.Port != 587 {
		t.Errorf("default StartTLS port should be 587, got %d", s.Config.Port)
	}
	if s.Config.Mode != SMTPModeStartTLS {
		t.Errorf("default mode should be starttls, got %s", s.Config.Mode)
	}
	if s.Config.From != "u" {
		t.Errorf("From should default to Username, got %s", s.Config.From)
	}
	if s.Config.Timeout != 10*time.Second {
		t.Errorf("Timeout default should be 10s, got %s", s.Config.Timeout)
	}
	if s.Config.MaxRetries != 1 {
		t.Errorf("MaxRetries default should be 1, got %d", s.Config.MaxRetries)
	}

	cfgTLS := SMTPConfig{Host: "smtp.example.com", Mode: SMTPModeTLS}
	sTLS := NewDefaultSMTPSender(cfgTLS)
	if sTLS.Config.Port != 465 {
		t.Errorf("default TLS port should be 465, got %d", sTLS.Config.Port)
	}

	cfgNone := SMTPConfig{Host: "smtp.example.com", Mode: SMTPModeNone}
	sNone := NewDefaultSMTPSender(cfgNone)
	if sNone.Config.Port != 587 {
		t.Errorf("default None port should be 587, got %d", sNone.Config.Port)
	}
}

func TestSMTPSender_DialHandshakeError(t *testing.T) {
	// 用一个监听后立刻关连接的 listener；客户端 dial 成功但 server 立刻 reset。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// accept 后立刻关闭 — 客户端拿到一个已关闭的 conn
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
		accepted <- c
	}()

	rec := &recorder{}
	host, port := splitHostPort(ln.Addr().String())
	cfg := SMTPConfig{
		Host: host, Port: port, Mode: SMTPModeNone,
		Timeout: 500 * time.Millisecond, MaxRetries: 0,
	}
	s := NewDefaultSMTPSender(cfg)
	s.SetNotifyHook(rec.Hook())

	msg := SMTPMessage{To: []string{"ops@hospital.local"}, Subject: "x", Body: "y", SystemID: "lis-pacs-1"}
	err = s.SendSMTP(context.Background(), msg)
	if err == nil {
		t.Fatalf("expected handshake error")
	}
	se, ok := err.(*SendError)
	if !ok {
		t.Fatalf("expected *SendError, got %T: %v", err, err)
	}
	// 应该归类为 malformed 或 timeout
	if se.Kind != NotifyErrorKindSMTPMalformed && se.Kind != NotifyErrorKindSMTPTimeout {
		t.Errorf("expected kind=smtp_malformed or smtp_timeout, got %s", se.Kind)
	}
}

// TestSMTPSender_BodyContainsSystemID — 显式断言 Subject 与 Body 必含 system_id
// （T28 详细验收："验证 Subject 与 Body 含 system_id"）。
func TestSMTPSender_BodyContainsSystemID(t *testing.T) {
	m := newSMTPMock(t)
	defer m.close()

	rec := &recorder{}
	s := NewDefaultSMTPSender(smtpTestCfg(m.addr()))
	s.SetNotifyHook(rec.Hook())

	card := sampleCard
	msg := SMTPMessage{
		To:       []string{"ops@hospital.local"},
		Subject:  RenderSubject(card.SystemID),
		Body:     RenderSMTPBody(card, "evt-001"),
		SystemID: card.SystemID,
	}
	if err := s.SendSMTP(context.Background(), msg); err != nil {
		t.Fatalf("SendSMTP failed: %v", err)
	}

	conv := strings.Join(m.conversationsCopy(), "\n")
	// Subject 必含 system_id（[XINCHUANG-DRIFT] ${system_id}）
	if !strings.Contains(conv, "DATA_BODY: Subject: [XINCHUANG-DRIFT] lis-pacs-1") {
		t.Errorf("DATA body Subject missing system_id: %s", conv)
	}
	if !strings.Contains(conv, "[XINCHUANG-DRIFT] lis-pacs-1") {
		t.Errorf("SMTP conversation missing Subject+system_id: %s", conv)
	}
	// Body 必含 system_id（"system_id: `lis-pacs-1`"）
	if !strings.Contains(conv, "DATA_BODY: - system_id: `lis-pacs-1`") {
		t.Errorf("DATA body Body missing system_id: %s", conv)
	}
}

// TestSMTPSender_StartTLSSendsSTARTTLSCommand — TLS 路径覆盖：StartTLS 模式
// 必须向服务端发 STARTTLS 命令（T28 详细验收："TLS 路径覆盖"）。
//
// smtpMock 在 STARTTLS 命令时回 454 TLS not available — 我们的 StartTLS 模式
// 把这条命令的非致命错误吞掉继续投递，验证 STARTTLS 已被发出即可。
func TestSMTPSender_StartTLSSendsSTARTTLSCommand(t *testing.T) {
	m := newSMTPMock(t)
	defer m.close()

	rec := &recorder{}
	host, port := splitHostPort(m.addr())
	cfg := SMTPConfig{
		Host: host, Port: port, Username: "u", Password: "p",
		Mode: SMTPModeStartTLS, Timeout: 2 * time.Second,
	}
	s := NewDefaultSMTPSender(cfg)
	s.SetNotifyHook(rec.Hook())

	card := sampleCard
	msg := SMTPMessage{
		To:       []string{"ops@hospital.local"},
		Subject:  RenderSubject(card.SystemID),
		Body:     RenderSMTPBody(card, "evt-001"),
		SystemID: card.SystemID,
	}
	if err := s.SendSMTP(context.Background(), msg); err != nil {
		t.Fatalf("StartTLS send failed: %v", err)
	}
	conv := strings.Join(m.conversationsCopy(), "\n")
	if !strings.Contains(conv, "STARTTLS") {
		t.Errorf("StartTLS mode should issue STARTTLS command; conv=%s", conv)
	}
}

// TestSMTPSender_TLSModeReportsMalformedOnSTARTTLSFailure — TLS 模式（端口 465
// implicit TLS）的代码路径：客户端 StartTLS 失败时归类 smtp_malformed（验证
// 失败分类覆盖）。本测试用空 listener + 关闭连接来触发 StartTLS 失败路径。
func TestSMTPSender_TLSModeReportsMalformedOnSTARTTLSFailure(t *testing.T) {
	// listener accept 后立刻关闭，模拟 StartTLS 握手时连接被 reset
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// 写完 banner，收到 STARTTLS 后立刻关闭
		go func(conn net.Conn) {
			defer conn.Close()
			fmt.Fprintf(conn, "220 smtp.mock ready\r\n")
			br := bufio.NewReader(conn)
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimRight(line, "\r\n")
				cmd := strings.ToUpper(strings.Fields(line)[0])
				if cmd == "STARTTLS" {
					// 假装 STARTTLS 失败 — 关连接
					conn.Close()
					return
				}
				if cmd == "EHLO" || cmd == "HELO" {
					fmt.Fprintf(conn, "250-smtp.mock\r\n250 STARTTLS\r\n")
				} else {
					fmt.Fprintf(conn, "250 ok\r\n")
				}
			}
		}(c)
	}()

	rec := &recorder{}
	host, port := splitHostPort(ln.Addr().String())
	cfg := SMTPConfig{
		Host: host, Port: port, Username: "u", Password: "p",
		Mode: SMTPModeTLS, Timeout: 500 * time.Millisecond, MaxRetries: 0,
	}
	s := NewDefaultSMTPSender(cfg)
	s.SetNotifyHook(rec.Hook())

	msg := SMTPMessage{To: []string{"a@b"}, Subject: "x", Body: "y", SystemID: "lis-pacs-1"}
	err = s.SendSMTP(context.Background(), msg)
	if err == nil {
		t.Fatalf("expected StartTLS failure for SMTPModeTLS")
	}
	se := err.(*SendError)
	if se.Kind != NotifyErrorKindSMTPMalformed && se.Kind != NotifyErrorKindSMTP5xx {
		t.Errorf("expected smtp_malformed or smtp_5xx, got %s", se.Kind)
	}
}

// TestSMTPSender_4xxNoRetry — SMTP 4xx 响应（如 451 transient）应归类为
// smtp_auth（实现中 4xx 走 smtp_auth 路径）且不重试。
func TestSMTPSender_4xxNoRetry(t *testing.T) {
	var rcptCount int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				w := bufio.NewWriter(conn)
				fmt.Fprintf(w, "220 smtp.mock ready\r\n")
				w.Flush()
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.ToUpper(strings.Fields(line)[0])
					switch cmd {
					case "EHLO", "HELO":
						fmt.Fprintf(w, "250 ok\r\n")
					case "AUTH":
						fmt.Fprintf(w, "235 ok\r\n")
					case "MAIL":
						fmt.Fprintf(w, "250 ok\r\n")
					case "RCPT":
						atomic.AddInt32(&rcptCount, 1)
						// 4xx 响应 — 模拟临时拒收
						fmt.Fprintf(w, "451 temporary\r\n")
					case "DATA":
						fmt.Fprintf(w, "354 go\r\n")
						w.Flush()
					case "QUIT":
						fmt.Fprintf(w, "221 bye\r\n")
						return
					default:
						fmt.Fprintf(w, "500 unrecognized\r\n")
					}
					w.Flush()
				}
			}(c)
		}
	}()

	rec := &recorder{}
	host, port := splitHostPort(ln.Addr().String())
	cfg := SMTPConfig{
		Host: host, Port: port, Username: "u", Password: "p",
		Mode: SMTPModeNone, Timeout: 1 * time.Second,
		MaxRetries: 3, RetryBackoff: 5 * time.Millisecond,
	}
	s := NewDefaultSMTPSender(cfg)
	s.SetNotifyHook(rec.Hook())

	msg := SMTPMessage{To: []string{"ops@hospital.local"}, Subject: "x", Body: "y", SystemID: "lis-pacs-1"}
	err = s.SendSMTP(context.Background(), msg)
	if err == nil {
		t.Fatalf("expected 4xx failure")
	}
	se := err.(*SendError)
	// 4xx 走 smtp_auth（因为 classifySMTPRespErr 把 4xx 归 smtp_auth）
	if se.Kind != NotifyErrorKindSMTPAuth {
		t.Errorf("expected kind=smtp_auth for 4xx, got %s", se.Kind)
	}
	if se.RetryCount != 0 {
		t.Errorf("4xx should not retry; got RetryCount=%d", se.RetryCount)
	}
	if n := atomic.LoadInt32(&rcptCount); n != 1 {
		t.Errorf("expected exactly 1 RCPT attempt (no retry on 4xx), got %d", n)
	}
}

// TestLoadSMTPConfigFromEnv_OK — 全部 env 填齐时正确解析；To 拆为 2 个收件人。
func TestLoadSMTPConfigFromEnv_OK(t *testing.T) {
	env := func(k string) string {
		m := map[string]string{
			"SMTP_HOST":           "smtp.hospital.local",
			"SMTP_PORT":           "587",
			"SMTP_USERNAME":       "xinchuang-bot",
			"SMTP_PASSWORD":       "s3cr3t-from-env",
			"SMTP_TO":             "ops@hospital.local, infosec@hospital.local",
			"SMTP_MODE":           "starttls",
			"SMTP_TIMEOUT_SECS":   "20",
			"SMTP_MAX_RETRIES":    "2",
			"SMTP_RETRY_BACKOFF_MS": "500",
		}
		return m[k]
	}
	cfg, toList, err := LoadSMTPConfigFromEnv(env)
	if err != nil {
		t.Fatalf("LoadSMTPConfigFromEnv: %v", err)
	}
	if cfg.Host != "smtp.hospital.local" {
		t.Errorf("Host mismatch: %s", cfg.Host)
	}
	if cfg.Port != 587 {
		t.Errorf("Port mismatch: %d", cfg.Port)
	}
	if cfg.Username != "xinchuang-bot" {
		t.Errorf("Username mismatch: %s", cfg.Username)
	}
	if cfg.Password != "s3cr3t-from-env" {
		t.Errorf("Password mismatch: %s", cfg.Password)
	}
	if cfg.Mode != SMTPModeStartTLS {
		t.Errorf("Mode mismatch: %s", cfg.Mode)
	}
	if cfg.Timeout != 20*time.Second {
		t.Errorf("Timeout mismatch: %s", cfg.Timeout)
	}
	if cfg.MaxRetries != 2 {
		t.Errorf("MaxRetries mismatch: %d", cfg.MaxRetries)
	}
	if cfg.RetryBackoff != 500*time.Millisecond {
		t.Errorf("RetryBackoff mismatch: %s", cfg.RetryBackoff)
	}
	if cfg.From != "xinchuang-bot" {
		t.Errorf("From default to Username mismatch: %s", cfg.From)
	}
	if len(toList) != 2 || toList[0] != "ops@hospital.local" || toList[1] != "infosec@hospital.local" {
		t.Errorf("toList mismatch: %v", toList)
	}
}

// TestLoadSMTPConfigFromEnv_MissingPassword — SMTP_PASSWORD 缺失返回友好错误，
// 关键凭据位绝不静默回落到空串（零硬编码原则）。
func TestLoadSMTPConfigFromEnv_MissingPassword(t *testing.T) {
	env := func(k string) string {
		m := map[string]string{
			"SMTP_HOST":     "smtp.hospital.local",
			"SMTP_PORT":     "587",
			"SMTP_USERNAME": "xinchuang-bot",
			// SMTP_PASSWORD 缺失
			"SMTP_TO": "ops@hospital.local",
		}
		return m[k]
	}
	_, _, err := LoadSMTPConfigFromEnv(env)
	if err == nil {
		t.Fatalf("expected error when SMTP_PASSWORD missing")
	}
	if !strings.Contains(err.Error(), "SMTP_PASSWORD") {
		t.Errorf("error should mention SMTP_PASSWORD: %v", err)
	}
}

// TestLoadSMTPConfigFromEnv_BadMode — SMTP_MODE 非法值返回错误。
func TestLoadSMTPConfigFromEnv_BadMode(t *testing.T) {
	env := func(k string) string {
		m := map[string]string{
			"SMTP_HOST":     "smtp.hospital.local",
			"SMTP_USERNAME": "u",
			"SMTP_PASSWORD": "p",
			"SMTP_TO":       "ops@hospital.local",
			"SMTP_MODE":     "ssl-bad-mode",
		}
		return m[k]
	}
	_, _, err := LoadSMTPConfigFromEnv(env)
	if err == nil {
		t.Fatalf("expected error for bad SMTP_MODE")
	}
	if !strings.Contains(err.Error(), "SMTP_MODE") {
		t.Errorf("error should mention SMTP_MODE: %v", err)
	}
}

// TestLoadSMTPConfigFromEnv_BadPort — SMTP_PORT 非法值返回错误。
func TestLoadSMTPConfigFromEnv_BadPort(t *testing.T) {
	env := func(k string) string {
		m := map[string]string{
			"SMTP_HOST":     "smtp.hospital.local",
			"SMTP_PORT":     "not-a-number",
			"SMTP_USERNAME": "u",
			"SMTP_PASSWORD": "p",
			"SMTP_TO":       "ops@hospital.local",
		}
		return m[k]
	}
	_, _, err := LoadSMTPConfigFromEnv(env)
	if err == nil {
		t.Fatalf("expected error for bad SMTP_PORT")
	}
}

// TestNewDefaultSMTPSender_NilEnvLoaderDefensive — LoadSMTPConfigFromEnv 接受
// nil env loader 时不 panic，返回 SMTP_HOST missing 错误。
func TestLoadSMTPConfigFromEnv_NilEnvLoader(t *testing.T) {
	_, _, err := LoadSMTPConfigFromEnv(nil)
	if err == nil {
		t.Fatalf("expected error when env loader is nil")
	}
	if !strings.Contains(err.Error(), "SMTP_HOST") {
		t.Errorf("nil env loader should report SMTP_HOST missing: %v", err)
	}
}

// TestSMTPSender_EndToEndWithEnvConfig — 端到端：env → cfg → sender → smtpMock；
// 验证 Subject / Body 完整内容含 system_id。
func TestSMTPSender_EndToEndWithEnvConfig(t *testing.T) {
	m := newSMTPMock(t)
	defer m.close()

	host, port := splitHostPort(m.addr())
	env := func(k string) string {
		m := map[string]string{
			"SMTP_HOST":     host,
			"SMTP_PORT":     strconv.Itoa(port),
			"SMTP_USERNAME": "bot",
			"SMTP_PASSWORD": "p",
			"SMTP_TO":       "ops@hospital.local",
			"SMTP_MODE":     "none",
		}
		return m[k]
	}
	cfg, toList, err := LoadSMTPConfigFromEnv(env)
	if err != nil {
		t.Fatalf("env load: %v", err)
	}
	rec := &recorder{}
	s := NewDefaultSMTPSender(cfg)
	s.SetNotifyHook(rec.Hook())

	card := sampleCard
	msg := SMTPMessage{
		To:       toList,
		Subject:  RenderSubject(card.SystemID),
		Body:     RenderSMTPBody(card, "evt-e2e-001"),
		SystemID: card.SystemID,
	}
	if err := s.SendSMTP(context.Background(), msg); err != nil {
		t.Fatalf("SendSMTP failed: %v", err)
	}
	if n := atomic.LoadInt32(&rec.n); n != 0 {
		t.Errorf("Hook should not fire on success; got %d", n)
	}
	conv := strings.Join(m.conversationsCopy(), "\n")
	for _, kw := range []string{
		"DATA_BODY: Subject: [XINCHUANG-DRIFT] lis-pacs-1",
		"DATA_BODY: - system_id: `lis-pacs-1`",
		"DATA_BODY: - event_id: `evt-e2e-001`",
		card.EvidenceSHA256,
	} {
		if !strings.Contains(conv, kw) {
			t.Errorf("SMTP e2e missing %q; conv=%s", kw, conv)
		}
	}
}
