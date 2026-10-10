package output

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xinchuang-db-guardian/internal/llm"
)

// TestNotifyErrorKind_Constants — 9 个枚举常量值稳定（防漂移：spec.md §4 / plan.md §3.2）。
//
// 这些字符串值会被 export-evidence 按 kind 过滤、并被审计链 verify-chain 读出
// 做反序列化；任何变动都会破坏既有 audit.jsonl 行的可读性。
func TestNotifyErrorKind_Constants(t *testing.T) {
	cases := []struct {
		k    NotifyErrorKind
		want string
	}{
		{NotifyErrorKindWecom4xx, "wecom_4xx"},
		{NotifyErrorKindWecom5xx, "wecom_5xx"},
		{NotifyErrorKindWecomTimeout, "wecom_timeout"},
		{NotifyErrorKindWecomMalformed, "wecom_malformed"},
		{NotifyErrorKindSMTPAuth, "smtp_auth"},
		{NotifyErrorKindSMTP5xx, "smtp_5xx"},
		{NotifyErrorKindSMTPTimeout, "smtp_timeout"},
		{NotifyErrorKindSMTPMalformed, "smtp_malformed"},
		{NotifyErrorKindLLMUnavailable, "llm_unavailable"},
	}
	for _, tc := range cases {
		if string(tc.k) != tc.want {
			t.Errorf("NotifyErrorKind=%q want %q", string(tc.k), tc.want)
		}
	}
}

// TestChannel_Constants — Channel 三枚举稳定。
func TestChannel_Constants(t *testing.T) {
	if string(ChannelWecom) != "wecom" {
		t.Errorf("ChannelWecom=%q", ChannelWecom)
	}
	if string(ChannelSMTP) != "smtp" {
		t.Errorf("ChannelSMTP=%q", ChannelSMTP)
	}
	if string(ChannelLLM) != "llm" {
		t.Errorf("ChannelLLM=%q", ChannelLLM)
	}
}

// TestClassifyHTTP — 6 case 分类 100% 命中。
//
// Case 1：HTTP 400 → wecom_4xx，不重试
// Case 2：HTTP 500 → wecom_5xx，重试 1 次
// Case 3：context deadline exceeded → wecom_timeout，重试 1 次
// Case 4：HTTP 502 + 重试 2 次仍 fail → retry_count=2 计入预算
// Case 5：malformed body（json marshal 错） → wecom_malformed，不重试
// Case 6：HTTP 200 → 不应该走 ClassifyHTTP；保留 nil/无错路径（防御性）
func TestClassifyHTTP(t *testing.T) {
	type tc struct {
		name        string
		status      int
		err         error
		wantKind    NotifyErrorKind
		wantRetry   bool
		description string
	}
	cases := []tc{
		{"case1_http400_no_retry", 400, nil, NotifyErrorKindWecom4xx, false, "wecom_4xx: no retry"},
		{"case2_http500_retry", 500, nil, NotifyErrorKindWecom5xx, true, "wecom_5xx: 1 retry"},
		{"case3_context_deadline_retry", 0, context.DeadlineExceeded, NotifyErrorKindWecomTimeout, true, "wecom_timeout: 1 retry"},
		{"case4_http502_with_2_retries_exhausted", 502, nil, NotifyErrorKindWecom5xx, true, "wecom_5xx with retry_count=2 → budget exhausted"},
		{"case5_malformed_body_no_retry", 0, errMalformedJSON, NotifyErrorKindWecomMalformed, false, "wecom_malformed: no retry"},
		{"case6_http200_no_failure_path", 200, nil, NotifyErrorKindWecom4xx, false, "should not reach here in production (no failure); classified to wecom_4xx as defensive default"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, r := ClassifyHTTP(c.status, c.err)
			if k != c.wantKind {
				t.Errorf("kind=%q want %q (%s)", k, c.wantKind, c.description)
			}
			if r != c.wantRetry {
				t.Errorf("retryable=%v want %v (%s)", r, c.wantRetry, c.description)
			}
		})
	}
}

// errMalformedJSON — 模拟序列化错（用于 case 5）。
// 注意：错误消息不含 "EOF" / "connection" / "no such host" 等网络关键字，
// 以免被 isNotifyNetErr 误判为网络错。
var errMalformedJSON = errors.New("output: invalid json payload: unexpected token")

// TestClassifySMTP — SMTP 出站 6 case 分类 100% 命中。
//
// Case 1：smtp code 535 → smtp_auth，不重试
// Case 2：smtp code 550 → smtp_5xx，重试 1 次
// Case 3：smtp code 451 → smtp_auth（4xx 范围），不重试
// Case 4：net.OpError 拨号错 → smtp_5xx，重试 1 次
// Case 5：context deadline exceeded → smtp_timeout，重试 1 次
// Case 6：smtp handshake 失败（handshake error）→ smtp_malformed，不重试
func TestClassifySMTP(t *testing.T) {
	type tc struct {
		name        string
		smtpCode    int
		err         error
		wantKind    NotifyErrorKind
		wantRetry   bool
		description string
	}
	cases := []tc{
		{"case1_code535_auth_no_retry", 535, nil, NotifyErrorKindSMTPAuth, false, "smtp_auth: no retry"},
		{"case2_code550_5xx_retry", 550, nil, NotifyErrorKindSMTP5xx, true, "smtp_5xx: 1 retry"},
		{"case3_code451_4xx_no_retry", 451, nil, NotifyErrorKindSMTPAuth, false, "smtp_auth (451 is 4xx range)"},
		{"case4_dial_net_op_error_retry", 0, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, NotifyErrorKindSMTP5xx, true, "smtp_5xx: 1 retry"},
		{"case5_context_deadline_retry", 0, context.DeadlineExceeded, NotifyErrorKindSMTPTimeout, true, "smtp_timeout: 1 retry"},
		{"case6_handshake_malformed_no_retry", 0, errors.New("smtp handshake protocol violation: cannot parse greeting"), NotifyErrorKindSMTPMalformed, false, "smtp_malformed: no retry"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, r := ClassifySMTP(c.smtpCode, c.err)
			if k != c.wantKind {
				t.Errorf("kind=%q want %q (%s)", k, c.wantKind, c.description)
			}
			if r != c.wantRetry {
				t.Errorf("retryable=%v want %v (%s)", r, c.wantRetry, c.description)
			}
		})
	}
}

// TestClassifyLLM — LLM 出站 4 case 一律 NotifyErrorKindLLMUnavailable（不重试）。
func TestClassifyLLM(t *testing.T) {
	cases := []struct {
		name   string
		status int
		err    error
	}{
		{"case1_http_503", 503, nil},
		{"case2_context_deadline", 0, context.DeadlineExceeded},
		{"case3_http_400", 400, nil},
		{"case4_schema_violation", 200, errors.New("schema violation: missing required field verdict")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, r := ClassifyLLM(c.status, c.err)
			if k != NotifyErrorKindLLMUnavailable {
				t.Errorf("kind=%q want llm_unavailable", k)
			}
			if r {
				t.Errorf("retryable=true want false (LLM no retry)")
			}
		})
	}
}

// TestRetryBudgetFor — 9 个枚举的重试预算表 100% 命中。
func TestRetryBudgetFor(t *testing.T) {
	cases := []struct {
		kind         NotifyErrorKind
		wantAttempts int
		wantRetry    bool
	}{
		{NotifyErrorKindWecom4xx, 1, false},
		{NotifyErrorKindWecom5xx, 2, true},
		{NotifyErrorKindWecomTimeout, 2, true},
		{NotifyErrorKindWecomMalformed, 1, false},
		{NotifyErrorKindSMTPAuth, 1, false},
		{NotifyErrorKindSMTP5xx, 2, true},
		{NotifyErrorKindSMTPTimeout, 2, true},
		{NotifyErrorKindSMTPMalformed, 1, false},
		{NotifyErrorKindLLMUnavailable, 1, false},
	}
	for _, c := range cases {
		t.Run(string(c.kind), func(t *testing.T) {
			budget := RetryBudgetFor(c.kind)
			if budget.MaxAttempts != c.wantAttempts {
				t.Errorf("kind=%q MaxAttempts=%d want %d", c.kind, budget.MaxAttempts, c.wantAttempts)
			}
			if budget.Description == "" {
				t.Errorf("kind=%q Description empty", c.kind)
			}
			if got := ShouldRetry(c.kind); got != c.wantRetry {
				t.Errorf("kind=%q ShouldRetry=%v want %v", c.kind, got, c.wantRetry)
			}
		})
	}
	// 未知 kind 走兜底：MaxAttempts=1（不重试）。
	if b := RetryBudgetFor("made-up-kind"); b.MaxAttempts != 1 {
		t.Errorf("unknown kind budget.MaxAttempts=%d want 1", b.MaxAttempts)
	}
}

// TestAppendNotifyError_Basic — 基础 happy path：写一行 kind=notify_error 审计行。
func TestAppendNotifyError_Basic(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	ev := NotifyErrorEvent{
		Kind:           NotifyErrorKindWecom5xx,
		Channel:        ChannelWecom,
		SystemID:       "his-core",
		Vendor:         "kingbase",
		EvidenceSHA256: "21c9d66e586e4bc6faeeda70b2fa401d9537399e97afaf59c9c1e75ba381d1b2",
		HTTPStatus:     502,
		RetryCount:     1,
		Err:            "502 Bad Gateway",
		EventID:        "evt-001",
		ContractID:     "contract-his-core",
	}

	row, err := AppendNotifyError(auditPath, ev)
	if err != nil {
		t.Fatalf("AppendNotifyError: %v", err)
	}

	if row.Kind != "notify_error" {
		t.Errorf("row.Kind=%q want notify_error", row.Kind)
	}
	if row.Verdict != string(NotifyErrorKindWecom5xx) {
		t.Errorf("row.Verdict=%q want %q", row.Verdict, NotifyErrorKindWecom5xx)
	}
	if row.SystemID != "his-core" {
		t.Errorf("row.SystemID=%q", row.SystemID)
	}
	if !strings.Contains(row.Actual, "wecom_5xx") {
		t.Errorf("row.Actual missing kind: %q", row.Actual)
	}
	if !strings.Contains(row.Actual, "http_status=502") {
		t.Errorf("row.Actual missing http_status: %q", row.Actual)
	}
	if !strings.Contains(row.Actual, "retry_count=1") {
		t.Errorf("row.Actual missing retry_count: %q", row.Actual)
	}
	if row.TsUTC == "" {
		t.Errorf("row.TsUTC empty")
	}
	if row.Action != "auto_notify_error" {
		t.Errorf("row.Action=%q want auto_notify_error", row.Action)
	}
	if row.Operator != "auto_notify" {
		t.Errorf("row.Operator=%q want auto_notify", row.Operator)
	}

	// 验证文件可读 + 1 行 + JSON round-trip。
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := splitNotifyLines(string(data))
	if len(lines) != 1 {
		t.Fatalf("lines=%d want 1 (data=%q)", len(lines), data)
	}
	var got AuditRow
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Kind != "notify_error" {
		t.Errorf("got.Kind=%q", got.Kind)
	}
}

// TestAppendNotifyError_VerifyChain — 审计链 verify-chain 通过（含 drift 行混合）。
func TestAppendNotifyError_VerifyChain(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	// 先写 1 行 drift 做链头。
	if _, err := AppendJSONL(auditPath, AuditRow{
		TsUTC:          "2026-10-10T04:00:00.000000000Z",
		Kind:           "drift",
		EventID:        "evt-trial-001",
		ContractID:     "contract-his-core",
		SystemID:       "his-core",
		Vendor:         "kingbase",
		Verdict:        "trial",
		EvidenceSHA256: "11aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}); err != nil {
		t.Fatalf("seed drift: %v", err)
	}

	// 写 1 行 notify_error 做链尾。
	if _, err := AppendNotifyError(auditPath, NotifyErrorEvent{
		Kind:       NotifyErrorKindSMTPAuth,
		Channel:    ChannelSMTP,
		SystemID:   "lis-pacs-1",
		Vendor:     "kingbase",
		HTTPStatus: 0,
		Err:        "auth: 535 auth failed",
		EventID:    "evt-notify-001",
		ContractID: "contract-lis",
	}); err != nil {
		t.Fatalf("AppendNotifyError: %v", err)
	}

	if err := VerifyChain(auditPath); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// TestAppendNotifyError_DoesNotTouchTrialStore — notify_error 行**不**写 TrialStore。
func TestAppendNotifyError_DoesNotTouchTrialStore(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")
	storePath := filepath.Join(tmp, "trial.db")
	defer func() { _ = os.Remove(storePath) }()

	store, err := OpenTrialStore(storePath)
	if err != nil {
		t.Fatalf("OpenTrialStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	if _, err := AppendNotifyError(auditPath, NotifyErrorEvent{
		Kind:     NotifyErrorKindWecom5xx,
		Channel:  ChannelWecom,
		SystemID: "his-core",
		Vendor:   "kingbase",
		Err:      "502",
	}); err != nil {
		t.Fatalf("AppendNotifyError: %v", err)
	}

	head, err := store.GlobalChainHead()
	if err != nil {
		t.Fatalf("GlobalChainHead: %v", err)
	}
	if head != "" {
		t.Fatalf("trial_state touched (chain head=%q); notify_error must not advance trial", head)
	}
}

// TestAppendNotifyError_NoPatientFields — 审计行的 declared / actual 不含患者可识别字段。
func TestAppendNotifyError_NoPatientFields(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	row, err := AppendNotifyError(auditPath, NotifyErrorEvent{
		Kind:       NotifyErrorKindSMTPTimeout,
		Channel:    ChannelSMTP,
		SystemID:   "his-core",
		Vendor:     "kingbase",
		HTTPStatus: 0,
		Err:        "dial timeout: context deadline exceeded",
	})
	if err != nil {
		t.Fatalf("AppendNotifyError: %v", err)
	}

	forbidden := []string{"patient", "患者", "姓名", "身份证", "病案号", "住院号", "处方号"}
	for _, term := range forbidden {
		if strings.Contains(row.Declared, term) {
			t.Errorf("Declared 含 %q: %q", term, row.Declared)
		}
		if strings.Contains(row.Actual, term) {
			t.Errorf("Actual 含 %q: %q", term, row.Actual)
		}
	}
}

// TestAppendNotifyError_Validation — 入参校验失败（empty path / empty kind / empty channel）。
func TestAppendNotifyError_Validation(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	cases := []struct {
		name    string
		path    string
		ev      NotifyErrorEvent
		wantErr string
	}{
		{
			name:    "empty_path",
			path:    "",
			ev:      NotifyErrorEvent{Kind: NotifyErrorKindWecom4xx, Channel: ChannelWecom},
			wantErr: "auditPath",
		},
		{
			name:    "empty_kind",
			path:    auditPath,
			ev:      NotifyErrorEvent{Channel: ChannelWecom},
			wantErr: "Kind",
		},
		{
			name:    "empty_channel",
			path:    auditPath,
			ev:      NotifyErrorEvent{Kind: NotifyErrorKindWecom4xx},
			wantErr: "Channel",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := AppendNotifyError(c.path, c.ev)
			if err == nil {
				t.Fatalf("expected error containing %q", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err=%q want substring %q", err.Error(), c.wantErr)
			}
		})
	}
}

// TestAppendNotifyError_TimestampAutoFill — Timestamp 为空时自动填本机 UTC。
func TestAppendNotifyError_TimestampAutoFill(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	before := time.Now().UTC().Format(time.RFC3339Nano)
	row, err := AppendNotifyError(auditPath, NotifyErrorEvent{
		Kind:     NotifyErrorKindWecom4xx,
		Channel:  ChannelWecom,
		SystemID: "his-core",
		Err:      "400 bad request",
	})
	after := time.Now().UTC().Format(time.RFC3339Nano)
	if err != nil {
		t.Fatalf("AppendNotifyError: %v", err)
	}
	if row.TsUTC < before || row.TsUTC > after {
		t.Errorf("TsUTC=%q not in [%q, %q]", row.TsUTC, before, after)
	}
}

// TestAppendNotifyError_CustomTimestamp — 自定义 Timestamp 时按指定时间格式化。
func TestAppendNotifyError_CustomTimestamp(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	custom := time.Date(2026, 10, 10, 5, 0, 0, 123456789, time.UTC)
	row, err := AppendNotifyError(auditPath, NotifyErrorEvent{
		Kind:      NotifyErrorKindWecom5xx,
		Channel:   ChannelWecom,
		SystemID:  "his-core",
		Err:       "502",
		Timestamp: custom,
	})
	if err != nil {
		t.Fatalf("AppendNotifyError: %v", err)
	}
	if !strings.HasPrefix(row.TsUTC, "2026-10-10T05:00:00") {
		t.Errorf("TsUTC=%q want prefix 2026-10-10T05:00:00", row.TsUTC)
	}
}

// TestAppendNotifyError_CustomActionOperator — 自定义 Action / Operator 时保留。
func TestAppendNotifyError_CustomActionOperator(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	row, err := AppendNotifyError(auditPath, NotifyErrorEvent{
		Kind:     NotifyErrorKindWecom5xx,
		Channel:  ChannelWecom,
		SystemID: "his-core",
		Err:      "502",
		Action:   "manual_notify",
		Operator: "zhang.zhuren",
	})
	if err != nil {
		t.Fatalf("AppendNotifyError: %v", err)
	}
	if row.Action != "manual_notify" {
		t.Errorf("Action=%q want manual_notify", row.Action)
	}
	if row.Operator != "zhang.zhuren" {
		t.Errorf("Operator=%q want zhang.zhuren", row.Operator)
	}
}

// TestRenderNotifyDetail_ErrTruncation — err 超过 200 字符时被截断（保护审计行体积）。
func TestRenderNotifyDetail_ErrTruncation(t *testing.T) {
	longErr := strings.Repeat("x", 500)
	ev := NotifyErrorEvent{
		Kind:    NotifyErrorKindWecom5xx,
		Channel: ChannelWecom,
		Err:     longErr,
	}
	got := renderNotifyDetail(ev)
	if !strings.Contains(got, "...") {
		t.Errorf("renderNotifyDetail missing truncation marker; got: %q", got)
	}
	if strings.Count(got, "x") > 210 {
		t.Errorf("renderNotifyDetail err not truncated; x count=%d", strings.Count(got, "x"))
	}
}

// TestAppendNotifyError_RoundTripWithRealHTTP5xx — 端到端：httptest 桩返回 502，
// WecomSender.SendWecom 走 fallback 路径 → 触发 AppendNotifyError（kind=notify_error）。
//
// 关键不变量：本测试不依赖外部告警通道，所有"出站"都走 httptest 桩；审计行
// 不会被静默推进，仅追加 1 行 JSONL。
func TestAppendNotifyError_RoundTripWithRealHTTP5xx(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	var posts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("bad gateway"))
	}))
	defer srv.Close()

	sender := NewWecomSender()
	// 手动注入 NotifyHook 走 AppendNotifyError。
	sender.SetNotifyHook(func(row NotifyAuditRow) {
		_, err := AppendNotifyError(auditPath, NotifyErrorEvent{
			Kind:           row.Kind,
			Channel:        ChannelWecom,
			SystemID:       row.SystemID,
			Vendor:         row.Vendor,
			EvidenceSHA256: row.EvidenceSHA256,
			HTTPStatus:     row.HTTPStatus,
			RetryCount:     row.RetryCount,
			Err:            row.Err,
			Timestamp:      row.Timestamp,
		})
		if err != nil {
			t.Errorf("AppendNotifyError: %v", err)
		}
	})

	_ = sender.SendWecom(context.Background(), srv.URL, WecomCard{
		SystemID:       "his-core",
		Vendor:         "kingbase",
		Declared:       "KingbaseES V008R006C",
		Actual:         "PostgreSQL 14.10 (Debian)",
		Verdict:        "trial",
		EvidenceSHA256: "21c9d66e586e4bc6faeeda70b2fa401d9537399e97afaf59c9c1e75ba381d1b2",
		TsUTC:          "2026-10-10T05:00:00Z",
	})

	// 重试 1 次 → 共 2 次 POST。
	if got := atomic.LoadInt32(&posts); got != 2 {
		t.Errorf("posts=%d want 2 (1 retry)", got)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := splitNotifyLines(string(data))
	if len(lines) != 1 {
		t.Fatalf("lines=%d want 1 (data=%q)", len(lines), data)
	}
	var got AuditRow
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Kind != "notify_error" {
		t.Errorf("got.Kind=%q want notify_error", got.Kind)
	}
	if got.Verdict != string(NotifyErrorKindWecom5xx) {
		t.Errorf("got.Verdict=%q want wecom_5xx", got.Verdict)
	}
}

// TestIsNotifyTimeoutErr — timeout 错误识别（含 context.DeadlineExceeded / context.Canceled）。
func TestIsNotifyTimeoutErr(t *testing.T) {
	if !isNotifyTimeoutErr(context.DeadlineExceeded) {
		t.Error("context.DeadlineExceeded should be timeout")
	}
	if !isNotifyTimeoutErr(context.Canceled) {
		t.Error("context.Canceled should be timeout")
	}
	// net.OpError + Timeout() = true。
	if !isNotifyTimeoutErr(&net.OpError{Op: "dial", Net: "tcp", Err: timeoutErrSentinel{}}) {
		t.Error("net.OpError with Timeout()=true should be timeout")
	}
	if isNotifyTimeoutErr(errors.New("some other err")) {
		t.Error("non-timeout err should not be classified as timeout")
	}
	if isNotifyTimeoutErr(nil) {
		t.Error("nil err should not be timeout")
	}
}

// timeoutErrSentinel — 实现 Timeout() bool 的 sentinel error。
type timeoutErrSentinel struct{}

func (timeoutErrSentinel) Error() string { return "i/o timeout" }
func (timeoutErrSentinel) Timeout() bool  { return true }

// TestIsNotifyNetErr — 网络错误识别（net.OpError / connection refused / EOF 等）。
func TestIsNotifyNetErr(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, true},
		{errors.New("dial tcp: lookup smtp.example: no such host"), true},
		{errors.New("connection refused"), true},
		{errors.New("connection reset by peer"), true},
		{errors.New("no such host"), true},
		{errors.New("unexpected EOF"), true},
		{errors.New("broken pipe"), true},
		{errors.New("invalid argument"), false},
		{nil, false},
	}
	for _, c := range cases {
		got := isNotifyNetErr(c.err)
		if got != c.want {
			t.Errorf("err=%v want=%v got=%v", c.err, c.want, got)
		}
	}
}

// TestClassifyHTTP_StabilityAcrossStatusCodes — HTTP 状态码边界值 [400, 500) → wecom_4xx；[500, 600) → wecom_5xx。
func TestClassifyHTTP_StabilityAcrossStatusCodes(t *testing.T) {
	for status := 400; status < 500; status++ {
		k, _ := ClassifyHTTP(status, nil)
		if k != NotifyErrorKindWecom4xx {
			t.Errorf("status=%d kind=%q want wecom_4xx", status, k)
		}
	}
	for status := 500; status < 600; status++ {
		k, _ := ClassifyHTTP(status, nil)
		if k != NotifyErrorKindWecom5xx {
			t.Errorf("status=%d kind=%q want wecom_5xx", status, k)
		}
	}
}

// TestClassifySMTP_StabilityAcrossSMTPCodes — SMTP code 边界值 [400, 500) → smtp_auth；
// [500, 600) 但非 535 → smtp_5xx；535 → smtp_auth（auth 系列）。
func TestClassifySMTP_StabilityAcrossSMTPCodes(t *testing.T) {
	for code := 400; code < 500; code++ {
		k, _ := ClassifySMTP(code, nil)
		if k != NotifyErrorKindSMTPAuth {
			t.Errorf("smtp_code=%d kind=%q want smtp_auth", code, k)
		}
	}
	for code := 500; code < 600; code++ {
		if code == 535 {
			// 535 特例：auth 系列 → smtp_auth（不重试）。
			k, _ := ClassifySMTP(code, nil)
			if k != NotifyErrorKindSMTPAuth {
				t.Errorf("smtp_code=535 kind=%q want smtp_auth (auth series)", k)
			}
			continue
		}
		k, _ := ClassifySMTP(code, nil)
		if k != NotifyErrorKindSMTP5xx {
			t.Errorf("smtp_code=%d kind=%q want smtp_5xx", code, k)
		}
	}
}

// TestAppendNotifyError_DoesNotAdvanceTrial — 关键不变量：notify_error 行
// 永不推进 trial → confirmed/remedied/re_verified（必须由人工 confirm-drift）。
func TestAppendNotifyError_DoesNotAdvanceTrial(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")
	storePath := filepath.Join(tmp, "trial.db")
	defer func() { _ = os.Remove(storePath) }()

	store, err := OpenTrialStore(storePath)
	if err != nil {
		t.Fatalf("OpenTrialStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	if _, err := AppendNotifyError(auditPath, NotifyErrorEvent{
		Kind:     NotifyErrorKindWecom5xx,
		Channel:  ChannelWecom,
		SystemID: "his-core",
		Vendor:   "kingbase",
		Err:      "502",
	}); err != nil {
		t.Fatalf("AppendNotifyError: %v", err)
	}

	// 调 PromoteTrial 期望 ErrTrialNotFound（trial_state 没被新事件污染）。
	// 用 string("confirmed") 而不是 StateConfirmed（State 在 check 包，不在本测试）。
	_, err = store.PromoteTrial("evt-does-not-exist", "confirmed", "test-op")
	if !errors.Is(err, ErrTrialNotFound) {
		t.Errorf("PromoteTrial err=%v want ErrTrialNotFound", err)
	}
}

// TestAppendNotifyError_SixCasesIntegration — 6 case 端到端集成（写文件 + 验内容）。
func TestAppendNotifyError_SixCasesIntegration(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	cases := []NotifyErrorEvent{
		{Kind: NotifyErrorKindWecom4xx, Channel: ChannelWecom, SystemID: "his-core", Vendor: "kingbase", HTTPStatus: 400, RetryCount: 0, Err: "missing webhook url"},
		{Kind: NotifyErrorKindWecom5xx, Channel: ChannelWecom, SystemID: "his-core", Vendor: "kingbase", HTTPStatus: 502, RetryCount: 1, Err: "502 Bad Gateway"},
		{Kind: NotifyErrorKindWecomTimeout, Channel: ChannelWecom, SystemID: "his-core", Vendor: "kingbase", HTTPStatus: 0, RetryCount: 1, Err: "context deadline exceeded"},
		{Kind: NotifyErrorKindSMTPAuth, Channel: ChannelSMTP, SystemID: "lis-pacs-1", Vendor: "kingbase", HTTPStatus: 0, RetryCount: 0, Err: "auth: 535 auth failed"},
		{Kind: NotifyErrorKindSMTP5xx, Channel: ChannelSMTP, SystemID: "lis-pacs-1", Vendor: "kingbase", HTTPStatus: 0, RetryCount: 1, Err: "550 mailbox unavailable"},
		{Kind: NotifyErrorKindSMTPTimeout, Channel: ChannelSMTP, SystemID: "lis-pacs-1", Vendor: "kingbase", HTTPStatus: 0, RetryCount: 1, Err: "dial timeout"},
	}
	for i, ev := range cases {
		if _, err := AppendNotifyError(auditPath, ev); err != nil {
			t.Fatalf("case %d AppendNotifyError: %v", i, err)
		}
	}

	// 验文件：6 行 notify_error + VerifyChain OK + 每行 kind 正确。
	rows, err := LoadChain(auditPath)
	if err != nil {
		t.Fatalf("LoadChain: %v", err)
	}
	if len(rows) != 6 {
		t.Errorf("rows=%d want 6", len(rows))
	}
	for i, row := range rows {
		if row.Kind != "notify_error" {
			t.Errorf("row[%d].Kind=%q want notify_error", i, row.Kind)
		}
		if row.Verdict != string(cases[i].Kind) {
			t.Errorf("row[%d].Verdict=%q want %q", i, row.Verdict, cases[i].Kind)
		}
	}
	if err := VerifyChain(auditPath); err != nil {
		t.Errorf("VerifyChain: %v", err)
	}
}

// TestAppendNotifyError_LLMAvailableRoundTrip — LLM 不可达走 AppendFallbackAudit（kind=llm_fallback），
// **不**走 AppendNotifyError。本测试断言 notify_error.go 不被 LLM fallback 路径调用。
func TestAppendNotifyError_LLMAvailableRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	// 模拟 LLM fallback（应写 llm_fallback，**不**写 notify_error）。
	meta := llm.FallbackMetadata{
		TsUTC:      "2026-10-10T05:00:00.000000000Z",
		LLMModel:   "gpt-4o-mini-test",
		LatencyMs:  1500,
		HTTPStatus: 503,
		ErrorKind:  "http_5xx",
	}
	ctx := llm.FallbackDriftContext{
		EventID:        "evt-llm-001",
		ContractID:     "contract-his-core",
		SystemID:       "his-core",
		Vendor:         "kingbase",
		Declared:       "KingbaseES V008R006C",
		Actual:         "PostgreSQL 14.10 (Debian)",
		EvidenceSHA256: "21c9d66e586e4bc6faeeda70b2fa401d9537399e97afaf59c9c1e75ba381d1b2",
		RuleVerdict:    "trial",
	}
	if _, err := AppendFallbackAudit(auditPath, meta, ctx); err != nil {
		t.Fatalf("AppendFallbackAudit: %v", err)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := splitNotifyLines(string(data))
	if len(lines) != 1 {
		t.Fatalf("lines=%d want 1", len(lines))
	}
	if !strings.Contains(lines[0], `"kind":"llm_fallback"`) {
		t.Errorf("expected kind=llm_fallback, got: %s", lines[0])
	}
	if strings.Contains(lines[0], `"kind":"notify_error"`) {
		t.Errorf("notify_error should not appear for LLM fallback path: %s", lines[0])
	}
}

// splitNotifyLines — 简易按 '\n' 切（保留空行做 tolerant count）。
func splitNotifyLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}
