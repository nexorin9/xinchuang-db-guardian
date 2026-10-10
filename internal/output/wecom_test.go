package output

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recorder — 线程安全的 NotifyAuditHook 行收集器。
type recorder struct {
	mu   sync.Mutex
	rows []NotifyAuditRow
	n    int32
}

func (r *recorder) Hook() NotifyAuditHook {
	return func(row NotifyAuditRow) {
		atomic.AddInt32(&r.n, 1)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.rows = append(r.rows, row)
	}
}

func (r *recorder) Rows() []NotifyAuditRow {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]NotifyAuditRow, len(r.rows))
	copy(out, r.rows)
	return out
}

// sampleCard — 典型卡片 fixture。
var sampleCard = WecomCard{
	SystemID:       "lis-pacs-1",
	Vendor:         "kingbase",
	Declared:       "KingbaseES V008R006C10",
	Actual:         "PostgreSQL 14.10 (Debian)",
	Verdict:        "trial",
	EvidenceSHA256: "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
	TsUTC:          "2026-10-10T05:00:00Z",
}

func TestWecomSender_SendSuccess(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}
		body, _ := io.ReadAll(r.Body)
		var p wecomPayload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Errorf("payload unmarshal: %v", err)
		}
		if p.MsgType != "markdown" {
			t.Errorf("expected msgtype=markdown, got %s", p.MsgType)
		}
		// 必含字段
		for _, kw := range []string{
			"lis-pacs-1", "kingbase", sampleCard.EvidenceSHA256,
			"trial", "KingbaseES V008R006C10", "PostgreSQL 14.10",
			"2026-10-10T05:00:00Z",
		} {
			if !strings.Contains(p.Markdown.Content, kw) {
				t.Errorf("content missing %q: %s", kw, p.Markdown.Content)
			}
		}
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()

	rec := &recorder{}
	s := NewWecomSender()
	s.SetNotifyHook(rec.Hook())

	if err := s.SendWecom(context.Background(), srv.URL, sampleCard); err != nil {
		t.Fatalf("SendWecom failed: %v", err)
	}
	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected 1 POST, got %d", received)
	}
	if n := atomic.LoadInt32(&rec.n); n != 0 {
		t.Errorf("Hook should not fire on success; got %d", n)
	}
}

func TestWecomSender_4xxNoRetry(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	rec := &recorder{}
	s := NewWecomSender()
	s.SetNotifyHook(rec.Hook())

	err := s.SendWecom(context.Background(), srv.URL, sampleCard)
	if err == nil {
		t.Fatalf("expected error on 4xx")
	}
	if atomic.LoadInt32(&attempts) != 1 {
		t.Errorf("4xx should not retry; got %d attempts", attempts)
	}
	rows := rec.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 hook call, got %d", len(rows))
	}
	if rows[0].Kind != NotifyErrorKindWecom4xx {
		t.Errorf("expected kind=wecom_4xx, got %s", rows[0].Kind)
	}
	if rows[0].HTTPStatus != 400 {
		t.Errorf("expected HTTPStatus=400, got %d", rows[0].HTTPStatus)
	}
	if rows[0].Channel != "wecom" {
		t.Errorf("expected channel=wecom, got %s", rows[0].Channel)
	}
	if rows[0].SystemID != sampleCard.SystemID {
		t.Errorf("expected SystemID=%s, got %s", sampleCard.SystemID, rows[0].SystemID)
	}
	if rows[0].EvidenceSHA256 != sampleCard.EvidenceSHA256 {
		t.Errorf("expected EvidenceSHA256=%s, got %s", sampleCard.EvidenceSHA256, rows[0].EvidenceSHA256)
	}
}

func TestWecomSender_5xxRetriesThenSuccess(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rec := &recorder{}
	s := NewWecomSender()
	s.SetNotifyHook(rec.Hook())
	s.MaxRetries = 2 // 总共 3 次尝试 (1 首次 + 2 重试)
	s.RetryBackoff = 5 * time.Millisecond

	err := s.SendWecom(context.Background(), srv.URL, sampleCard)
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("expected 3 attempts (2 fails + 1 ok), got %d", attempts)
	}
	if n := atomic.LoadInt32(&rec.n); n != 0 {
		t.Errorf("Hook should not fire on eventual success; got %d", n)
	}
}

func TestWecomSender_5xxExhaustRetries(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rec := &recorder{}
	s := NewWecomSender()
	s.SetNotifyHook(rec.Hook())
	s.RetryBackoff = 5 * time.Millisecond

	err := s.SendWecom(context.Background(), srv.URL, sampleCard)
	if err == nil {
		t.Fatalf("expected error after retries exhausted")
	}
	// 默认 1 次重试 + 1 次首次 = 2 次
	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
	rows := rec.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 hook call, got %d", len(rows))
	}
	if rows[0].Kind != NotifyErrorKindWecom5xx {
		t.Errorf("expected kind=wecom_5xx, got %s", rows[0].Kind)
	}
	if rows[0].RetryCount != 1 {
		t.Errorf("expected RetryCount=1, got %d", rows[0].RetryCount)
	}
}

func TestWecomSender_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rec := &recorder{}
	s := NewWecomSender()
	s.SetNotifyHook(rec.Hook())
	s.HTTPClient = &http.Client{Timeout: 50 * time.Millisecond}
	s.RetryBackoff = 5 * time.Millisecond

	err := s.SendWecom(context.Background(), srv.URL, sampleCard)
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	rows := rec.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 hook call, got %d", len(rows))
	}
	if rows[0].Kind != NotifyErrorKindWecomTimeout {
		t.Errorf("expected kind=wecom_timeout, got %s", rows[0].Kind)
	}
}

func TestWecomSender_MissingURL(t *testing.T) {
	rec := &recorder{}
	s := NewWecomSender()
	s.SetNotifyHook(rec.Hook())

	err := s.SendWecom(context.Background(), "", sampleCard)
	if err == nil {
		t.Fatalf("expected error on missing URL")
	}
	rows := rec.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 hook call, got %d", len(rows))
	}
	if rows[0].Kind != NotifyErrorKindWecom4xx {
		t.Errorf("expected kind=wecom_4xx, got %s", rows[0].Kind)
	}
	if rows[0].Err != "missing webhook url" {
		t.Errorf("expected err msg 'missing webhook url', got %q", rows[0].Err)
	}
}

func TestWecomSender_NoHookAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	s := NewWecomSender()
	// 不设 Hook — 应当不 panic
	err := s.SendWecom(context.Background(), srv.URL, sampleCard)
	if err == nil {
		t.Fatalf("expected error")
	}
	se, ok := err.(*SendError)
	if !ok {
		t.Fatalf("expected *SendError, got %T", err)
	}
	if se.Kind != NotifyErrorKindWecom4xx {
		t.Errorf("expected kind=wecom_4xx, got %s", se.Kind)
	}
}

func TestWecomSender_ContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rec := &recorder{}
	s := NewWecomSender()
	s.SetNotifyHook(rec.Hook())
	s.RetryBackoff = 5 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := s.SendWecom(ctx, srv.URL, sampleCard)
	if err == nil {
		t.Fatalf("expected context cancel error")
	}
	rows := rec.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 hook call, got %d", len(rows))
	}
	if rows[0].Kind != NotifyErrorKindWecomTimeout {
		t.Errorf("expected kind=wecom_timeout on ctx cancel, got %s", rows[0].Kind)
	}
}

func TestWecomSender_Concurrent(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rec := &recorder{}
	s := NewWecomSender()
	s.SetNotifyHook(rec.Hook())

	const N = 10
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.SendWecom(context.Background(), srv.URL, sampleCard)
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&attempts); got != N {
		t.Errorf("expected %d POSTs, got %d", N, got)
	}
	if n := atomic.LoadInt32(&rec.n); n != 0 {
		t.Errorf("Hook should not fire on concurrent success; got %d", n)
	}
}

func TestRenderWecomCard_NoPatientFields(t *testing.T) {
	rendered := RenderWecomCard(sampleCard)
	// 不允许出现患者可识别字段
	banned := []string{"患者", "姓名", "身份证", "病案号", "住院号", "处方号", "patient", "patient_id"}
	for _, kw := range banned {
		if strings.Contains(rendered, kw) {
			t.Errorf("card should not contain %q; got: %s", kw, rendered)
		}
	}
	// 必含字段
	for _, kw := range []string{
		"lis-pacs-1", "kingbase", "KingbaseES V008R006C10",
		"PostgreSQL 14.10", "trial", sampleCard.EvidenceSHA256, "2026-10-10T05:00:00Z",
	} {
		if !strings.Contains(rendered, kw) {
			t.Errorf("card missing %q; got: %s", kw, rendered)
		}
	}
}

func TestSendError_Error(t *testing.T) {
	se := &SendError{
		Channel: "wecom", Kind: NotifyErrorKindWecom5xx,
		HTTPStatus: 500, RetryCount: 1, Err: "boom",
	}
	s := se.Error()
	for _, kw := range []string{"wecom", "wecom_5xx", "http=500", "boom"} {
		if !strings.Contains(s, kw) {
			t.Errorf("SendError.Error() missing %q: %s", kw, s)
		}
	}

	// 无 HTTPStatus 的格式
	se2 := &SendError{Channel: "smtp", Kind: NotifyErrorKindSMTPAuth, RetryCount: 0, Err: "x"}
	s2 := se2.Error()
	if !strings.Contains(s2, "smtp") || !strings.Contains(s2, "smtp_auth") || !strings.Contains(s2, "x") {
		t.Errorf("SendError.Error() (no status) unexpected: %s", s2)
	}
}
