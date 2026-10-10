package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestLogger — 测试用 silent logger（写到 io.Discard）。
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// validResponseBody — 标准 OpenAI 兼容响应。
//
// choices[0].message.content 是 JSON **字符串**（OpenAI API 规范）：
// 在 response_format=json_object 模式下，LLM 把 verdict 对象**字符串化**后放进 content。
// 这里 we take the raw verdict JSON object string and json-escape it so it sits as
// a proper JSON string literal inside the response body.
func validResponseBody(verdictObjJSON string) string {
	escaped, _ := json.Marshal(verdictObjJSON) // 把 verdictObjJSON 编码成合法 JSON 字符串字面量（含转义引号）
	return `{
  "id": "chatcmpl-test-001",
  "object": "chat.completion",
  "created": 1735689600,
  "model": "gpt-4o-mini-test",
  "system_fingerprint": "fp_test",
  "choices": [
    {
      "index": 0,
      "message": {"role": "assistant", "content": ` + string(escaped) + `},
      "finish_reason": "stop"
    }
  ],
  "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
}`
}

// validVerdictJSON — 一个合法 verdict JSON。
func validVerdictJSON(verdict string, confidence float64, reason string) string {
	return `{"verdict":"` + verdict + `","confidence":` + f64str(confidence) +
		`,"reason":"` + reason + `"}`
}

func f64str(v float64) string {
	// 用足够精度的小数字面，避免 %g 引入指数计数法。
	if v == 0 {
		return "0"
	}
	if v == 1 {
		return "1"
	}
	// 小数用 %.4f，剥离末尾 0。
	s := strings.TrimRight(strings.TrimRight(sprintf("%v", v), "0"), ".")
	if s == "" {
		return "0"
	}
	return s
}

// sprintf — 不直接 fmt.Sprintf 防止格式化字符串注入；只用于小数字面。
func sprintf(format string, args ...interface{}) string {
	switch format {
	case "%v":
		s, _ := args[0].(interface{ String() string })
		_ = s
		return strings.TrimSpace(strings.ReplaceAll(
			strings.ReplaceAll(formatFloat(args[0].(float64)), "+", ""), "-0", "-"))
	}
	return format
}

func formatFloat(v float64) string {
	// 精度 6 位，定点表示。
	s := ""
	intPart := int64(v)
	frac := v - float64(intPart)
	if intPart == 0 && v < 0 {
		// 负小数
		s = "-"
		intPart = int64(-v)
		frac = -v - float64(intPart)
	}
	if intPart < 0 {
		s = "-"
		intPart = -intPart
	}
	s += itoa(intPart)
	if frac != 0 {
		s += "."
		// 6 位小数
		for i := 0; i < 6; i++ {
			frac *= 10
			d := int(frac)
			if d > 9 {
				d = 9
			}
			s += string(rune('0' + d))
			frac -= float64(d)
		}
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
		if s == "" || s == "-" {
			s = "0"
		}
	}
	return s
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

// TestCallValidResponse — 合法 JSON 返回 verdict=confirmed + audit 元数据完整。
func TestCallValidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("confirmed", 0.85, "实测 DM8 banner 与 kingbase 合同期望不一致"))))
	}))
	defer srv.Close()

	gw, err := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "test-key", Model: "gpt-4o-mini-test", Timeout: 5 * time.Second,
	}, srv.Client(), newTestLogger())
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	res, err := gw.Call(context.Background(), "对比：合同 kingbase vs 实测 DM8 TNS banner DM Database Server V8.1.0")
	if err != nil {
		t.Fatalf("Call err: %v", err)
	}
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("verdict=%q want %q", res.Verdict, VerdictConfirmed)
	}
	if res.Confidence < 0.8 || res.Confidence > 0.9 {
		t.Fatalf("confidence=%v want ~0.85", res.Confidence)
	}
	if res.Reason == "" {
		t.Fatalf("reason empty")
	}
	if res.Audit.LLMModel != "gpt-4o-mini-test" {
		t.Fatalf("audit model=%q", res.Audit.LLMModel)
	}
	if res.Audit.HTTPStatus != 200 {
		t.Fatalf("audit status=%d", res.Audit.HTTPStatus)
	}
	if res.Audit.LLMInSHA256 == "" || res.Audit.LLMOutSHA256 == "" {
		t.Fatalf("audit sha missing in=%q out=%q", res.Audit.LLMInSHA256, res.Audit.LLMOutSHA256)
	}
	if res.Audit.ErrorKind != "" {
		t.Fatalf("audit errkind=%q on success", res.Audit.ErrorKind)
	}
	if res.Audit.FallbackUsed {
		t.Fatalf("fallback used on success")
	}
	if res.Audit.NeedHumanReview {
		t.Fatalf("need_human_review=true on success")
	}
	if res.Audit.TsUTC == "" {
		t.Fatalf("ts_utc empty")
	}
	if res.Audit.LatencyMs < 0 {
		t.Fatalf("latency ms negative")
	}
}

// TestCallInvalidJSON — 模型返回的不是合法 JSON → ErrSchemaViolation + fallback。
func TestCallInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validResponseBody("这压根不是 JSON, 我在瞎聊")))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected schema violation error")
	}
	var sv *ErrSchemaViolation
	if !errors.As(err, &sv) {
		t.Fatalf("err type=%T want *ErrSchemaViolation: %v", err, err)
	}
}

// TestCallHTTPServer5xx — HTTP 500 → ErrLLMUnavailable + fallback + need_human_review。
func TestCallHTTPServer5xx(t *testing.T) {
	var saw atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream blew up"}}`))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected unavailable")
	}
	var unav *ErrLLMUnavailable
	if !errors.As(err, &unav) {
		t.Fatalf("err type=%T want *ErrLLMUnavailable: %v", err, err)
	}
	if unav.HTTPStatus != 500 {
		t.Fatalf("status=%d want 500", unav.HTTPStatus)
	}
	if unav.ErrorKind != "http_5xx" {
		t.Fatalf("kind=%q want http_5xx", unav.ErrorKind)
	}
	if saw.Load() != 1 {
		t.Fatalf("request count=%d want 1", saw.Load())
	}
}

// TestCallHTTP4xxNotRetry — 4xx 不重试（验证本包不做客户端重试，由调用方决定）。
func TestCallHTTP4xxNotRetry(t *testing.T) {
	var saw atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad model"}`))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected unavailable")
	}
	var unav *ErrLLMUnavailable
	if !errors.As(err, &unav) {
		t.Fatalf("err type=%T want *ErrLLMUnavailable: %v", err, err)
	}
	if unav.ErrorKind != "http_4xx" {
		t.Fatalf("kind=%q want http_4xx", unav.ErrorKind)
	}
	if saw.Load() != 1 {
		t.Fatalf("4xx should not retry, got %d", saw.Load())
	}
}

// TestCallTimeout — 服务端 hang 住超过 Timeout → ErrLLMUnavailable + kind=timeout。
func TestCallTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("trial", 0.5, "x"))))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 50 * time.Millisecond,
	}, srv.Client(), newTestLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected timeout")
	}
	var unav *ErrLLMUnavailable
	if !errors.As(err, &unav) {
		t.Fatalf("err type=%T want *ErrLLMUnavailable: %v", err, err)
	}
	if unav.ErrorKind != "timeout" && unav.ErrorKind != "network" {
		t.Fatalf("kind=%q want timeout or network", unav.ErrorKind)
	}
}

// TestCallVerdictNotInWhitelist — verdict 不在白名单 → ErrSchemaViolation。
func TestCallVerdictNotInWhitelist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("maybe_match", 0.6, "猜的"))))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected schema violation")
	}
	var sv *ErrSchemaViolation
	if !errors.As(err, &sv) {
		t.Fatalf("err type=%T want *ErrSchemaViolation", err)
	}
}

// TestCallConfidenceOutOfRange — confidence 越界（>1）→ ErrSchemaViolation。
func TestCallConfidenceOutOfRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("trial", 1.5, "too high"))))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected schema violation")
	}
	var sv *ErrSchemaViolation
	if !errors.As(err, &sv) {
		t.Fatalf("err type=%T", err)
	}
	if !strings.Contains(sv.Reason, "confidence") {
		t.Fatalf("reason=%q should mention confidence", sv.Reason)
	}
}

// TestCallConfidenceNegative — confidence 负值 → ErrSchemaViolation。
func TestCallConfidenceNegative(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("trial", -0.1, "neg"))))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected schema violation")
	}
	var sv *ErrSchemaViolation
	if !errors.As(err, &sv) {
		t.Fatalf("err type=%T", err)
	}
}

// TestCallReasonTooLong — reason 超过 80 汉字 → ErrSchemaViolation。
func TestCallReasonTooLong(t *testing.T) {
	longReason := strings.Repeat("漂移", 50) // 100 字
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("trial", 0.5, longReason))))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected schema violation")
	}
	var sv *ErrSchemaViolation
	if !errors.As(err, &sv) {
		t.Fatalf("err type=%T", err)
	}
}

// TestCallReasonEmpty — reason 空字符串 → ErrSchemaViolation。
func TestCallReasonEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("trial", 0.5, ""))))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected schema violation")
	}
	var sv *ErrSchemaViolation
	if !errors.As(err, &sv) {
		t.Fatalf("err type=%T", err)
	}
}

// TestCallAuditMetadataPopulatedOnFallback — 失败路径也要写 audit 元数据。
func TestCallAuditMetadataPopulatedOnFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "my-model", Timeout: 1 * time.Second,
	}, srv.Client(), newTestLogger())

	res, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected error")
	}
	if res.Audit.LLMInSHA256 == "" {
		t.Fatalf("in sha empty on fallback")
	}
	if res.Audit.LLMOutSHA256 == "" {
		t.Fatalf("out sha empty on fallback (body read)")
	}
	if res.Audit.LLMModel != "my-model" {
		t.Fatalf("model=%q", res.Audit.LLMModel)
	}
	if res.Audit.HTTPStatus != 503 {
		t.Fatalf("status=%d want 503", res.Audit.HTTPStatus)
	}
	if !res.Audit.FallbackUsed {
		t.Fatalf("fallback_used=false want true")
	}
	if !res.Audit.NeedHumanReview {
		t.Fatalf("need_human_review=false want true")
	}
	if res.Audit.ErrorKind != "http_5xx" {
		t.Fatalf("kind=%q", res.Audit.ErrorKind)
	}
}

// TestCallChoicesEmpty — choices 为空 → ErrSchemaViolation。
func TestCallChoicesEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","created":1,"model":"m","choices":[],"usage":{}}`))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 1 * time.Second,
	}, srv.Client(), newTestLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected schema violation")
	}
	var sv *ErrSchemaViolation
	if !errors.As(err, &sv) {
		t.Fatalf("err type=%T", err)
	}
}

// TestCallProtocolCompatibilityExtraFields — 响应含额外字段（system_fingerprint 等）正常解析。
func TestCallProtocolCompatibilityExtraFields(t *testing.T) {
	escapedContent, _ := json.Marshal(validVerdictJSON("re_verified", 0.7, "再次核实后通过"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 多给几个扩展字段：service_tier / system_fingerprint / citations；content 用合法 JSON 字符串。
		_, _ = w.Write([]byte(`{
  "id": "x",
  "object": "chat.completion",
  "created": 1,
  "model": "m",
  "system_fingerprint": "fp_abc",
  "service_tier": "default",
  "choices": [{"index":0,"message":{"role":"assistant","content":` + string(escapedContent) +
			`},"finish_reason":"stop"}],
  "usage": {"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
}`))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	res, err := gw.Call(context.Background(), "prompt")
	if err != nil {
		t.Fatalf("Call err: %v", err)
	}
	if res.Verdict != VerdictReVerified {
		t.Fatalf("verdict=%q want re_verified", res.Verdict)
	}
}

// TestCallBearerAuthHeader — Authorization: Bearer 必带正确 API key。
func TestCallBearerAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("trial", 0.5, "ok"))))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "my-secret", Model: "m", Timeout: 1 * time.Second,
	}, srv.Client(), newTestLogger())

	_, _ = gw.Call(context.Background(), "prompt")
	if gotAuth != "Bearer my-secret" {
		t.Fatalf("auth=%q want %q", gotAuth, "Bearer my-secret")
	}
}

// TestCallRequestBodyShape — request body 必须含 response_format=json_object + temperature=0 + system message。
func TestCallRequestBodyShape(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bb, _ := io.ReadAll(r.Body)
		body = string(bb)
		_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("trial", 0.5, "ok"))))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 1 * time.Second,
	}, srv.Client(), newTestLogger())

	_, _ = gw.Call(context.Background(), "用户问题")
	if !strings.Contains(body, `"temperature":0`) {
		t.Fatalf("body missing temperature:0: %s", body)
	}
	if !strings.Contains(body, `"response_format":{"type":"json_object"}`) {
		t.Fatalf("body missing response_format: %s", body)
	}
	if !strings.Contains(body, `"role":"system"`) {
		t.Fatalf("body missing system role: %s", body)
	}
	if !strings.Contains(body, `"role":"user"`) && !strings.Contains(body, `"role":"user"`) {
		t.Fatalf("body missing user role")
	}
	if !strings.Contains(body, "用户问题") {
		t.Fatalf("body missing user content: %s", body)
	}
}

// TestNewModelGatewayValidates — 缺关键配置项必须报错。
func TestNewModelGatewayValidates(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty base url", Config{APIKey: "k", Model: "m"}},
		{"empty api key", Config{BaseURL: "http://x", Model: "m"}},
		{"empty model", Config{BaseURL: "http://x", APIKey: "k"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewModelGateway(tc.cfg, newTestLogger()); err == nil {
				t.Fatalf("want error for %s", tc.name)
			}
		})
	}
}

// TestNewModelGatewayDefaultTimeout — 缺省 Timeout 落到 10s。
func TestNewModelGatewayDefaultTimeout(t *testing.T) {
	gw, err := NewModelGateway(Config{
		BaseURL: "http://example.com", APIKey: "k", Model: "m",
	}, newTestLogger())
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	if gw.Timeout() != 10*time.Second {
		t.Fatalf("timeout=%v want 10s", gw.Timeout())
	}
	if gw.BaseURL() != "http://example.com" {
		t.Fatalf("base url=%q", gw.BaseURL())
	}
	if gw.Model() != "m" {
		t.Fatalf("model=%q", gw.Model())
	}
}

// TestLoadConfigFromEnv — 缺 LLM_BASE_URL 报错；缺 LLM_API_KEY 报错；缺 LLM_MODEL 报错；LLM_TIMEOUT_SECS 数字可覆盖默认。
func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("LLM_BASE_URL", "")
	t.Setenv("LLM_API_KEY", "")
	t.Setenv("LLM_MODEL", "")
	t.Setenv("LLM_TIMEOUT_SECS", "")
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatalf("want error on empty env")
	}

	t.Setenv("LLM_BASE_URL", "http://example.com")
	t.Setenv("LLM_API_KEY", "k")
	t.Setenv("LLM_MODEL", "m")
	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load err: %v", err)
	}
	if cfg.Timeout != 10*time.Second {
		t.Fatalf("default timeout=%v", cfg.Timeout)
	}

	t.Setenv("LLM_TIMEOUT_SECS", "20")
	cfg, err = LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load err: %v", err)
	}
	if cfg.Timeout != 20*time.Second {
		t.Fatalf("custom timeout=%v", cfg.Timeout)
	}

	t.Setenv("LLM_TIMEOUT_SECS", "abc")
	cfg, err = LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load err: %v", err)
	}
	if cfg.Timeout != 10*time.Second {
		t.Fatalf("junk timeout should fall back to 10s, got %v", cfg.Timeout)
	}
}

// TestSchemaGuidanceStable — SchemaGuidance() 必须是确定性字符串，便于审计回放。
func TestSchemaGuidanceStable(t *testing.T) {
	a := SchemaGuidance()
	b := SchemaGuidance()
	if a != b {
		t.Fatalf("schema guidance not stable")
	}
	if !strings.Contains(a, "trial") || !strings.Contains(a, "confirmed") ||
		!strings.Contains(a, "remedied") || !strings.Contains(a, "re_verified") {
		t.Fatalf("schema guidance missing verdict tokens: %s", a)
	}
	if !strings.Contains(a, "confidence") {
		t.Fatalf("schema guidance missing confidence: %s", a)
	}
	if !strings.Contains(a, "0.0..1.0") {
		t.Fatalf("schema guidance missing confidence range: %s", a)
	}
}

// TestIsValidVerdict — 白名单检查应覆盖全部枚举值。
func TestIsValidVerdict(t *testing.T) {
	for _, v := range AllVerdicts {
		if !isValidVerdict(v) {
			t.Fatalf("verdict %q should be valid", v)
		}
	}
	if isValidVerdict(Verdict("nonsense")) {
		t.Fatalf("nonsense should be invalid")
	}
	if isValidVerdict(Verdict("")) {
		t.Fatalf("empty should be invalid")
	}
}

// TestCallNeverSilentlyPromotes — 不论成功/失败，Call 必须不写任何漂移状态推进；
// 本测试间接验证：err 路径下 verdict==""，调用方不应被诱导去推进 trial。
func TestCallNeverSilentlyPromotes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 1 * time.Second,
	}, srv.Client(), newTestLogger())

	res, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected err")
	}
	if res.Verdict != "" {
		t.Fatalf("verdict=%q on err (would mislead confirm-drift)", res.Verdict)
	}
	if !res.Audit.NeedHumanReview {
		t.Fatalf("need_human_review must be true on err so confirm-drift stays manual")
	}
}

// TestCallContextCancel — parent context 取消 → ErrLLMUnavailable + kind=timeout 或 network。
func TestCallContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("trial", 0.5, "x"))))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 5 * time.Second,
	}, srv.Client(), newTestLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := gw.Call(ctx, "prompt")
	if err == nil {
		t.Fatalf("expected err on context cancel")
	}
	var unav *ErrLLMUnavailable
	if !errors.As(err, &unav) {
		t.Fatalf("err type=%T want *ErrLLMUnavailable", err)
	}
}

// TestCallMissingVerdictField — T24 补 case #4：message.content 是合法 JSON
// 但**缺 verdict 字段**（其他字段 confidence / reason 完整）→ 应被严格
// JSON schema 校验拒绝，触发 ErrSchemaViolation + 全 fallback 路径生效
// （Audit.FallbackUsed=true + NeedHumanReview=true + ErrorKind="schema_violation"）。
//
// 这是 T24 spec 要求的"4 降级 case 各 1"中的"缺字段"分支。该 case 与
// TestCallVerdictNotInWhitelist 互补：后者测"verdict 字段值不在白名单"，
// 本测"verdict 字段本身缺失（unmarshal 后为零值）"。
func TestCallMissingVerdictField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 注意：content 里只有 confidence + reason，没有 verdict 字段。
		_, _ = w.Write([]byte(validResponseBody(`{"confidence":0.5,"reason":"我把 verdict 吞了"}`)))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	res, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected schema violation on missing verdict field")
	}
	var sv *ErrSchemaViolation
	if !errors.As(err, &sv) {
		t.Fatalf("err type=%T want *ErrSchemaViolation: %v", err, err)
	}
	// reason 应在消息里点出"verdict"，便于日志检索。
	if !strings.Contains(sv.Reason, "verdict") {
		t.Errorf("reason should mention verdict, got: %q", sv.Reason)
	}
	// 完整 fallback 元数据：Audit 字段不丢。
	if !res.Audit.FallbackUsed {
		t.Errorf("audit.fallback_used=false want true on missing verdict field")
	}
	if !res.Audit.NeedHumanReview {
		t.Errorf("audit.need_human_review=false want true (trial 状态不静默推进)")
	}
	if res.Audit.ErrorKind != "schema_violation" {
		t.Errorf("audit.error_kind=%q want schema_violation", res.Audit.ErrorKind)
	}
	if res.Audit.LLMInSHA256 == "" {
		t.Errorf("audit.llm_in_sha256 empty on fallback")
	}
	if res.Verdict != "" {
		t.Errorf("verdict=%q on err (would mislead confirm-drift)", res.Verdict)
	}
}

// TestCallMissingConfidenceField — message.content 缺 confidence 字段
// （unmarshal 后为零值 0.0）→ 区间校验 [0,1] 通过 → 进入 reason 校验，
// reason 缺则触发 ErrSchemaViolation（含"reason runes="）。
func TestCallMissingConfidenceField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(validResponseBody(`{"verdict":"trial","reason":""}`)))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected schema violation on missing/empty reason")
	}
	var sv *ErrSchemaViolation
	if !errors.As(err, &sv) {
		t.Fatalf("err type=%T want *ErrSchemaViolation", err)
	}
	if !strings.Contains(sv.Reason, "reason") {
		t.Errorf("reason should mention reason field, got: %q", sv.Reason)
	}
}

// TestCallMissingVerdictAndReasonTogether — verdict + reason 都缺（极端缺字段）。
// 应在前两个 schema 校验中选其一拒绝；任意路径都不让 trial 被静默推进。
func TestCallMissingVerdictAndReasonTogether(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 只有 confidence 字段，无 verdict / reason。
		_, _ = w.Write([]byte(validResponseBody(`{"confidence":0.7}`)))
	}))
	defer srv.Close()

	gw, _ := NewModelGatewayWithClient(Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), newTestLogger())

	res, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected schema violation on missing verdict + reason")
	}
	var sv *ErrSchemaViolation
	if !errors.As(err, &sv) {
		t.Fatalf("err type=%T want *ErrSchemaViolation", err)
	}
	if res.Audit.NeedHumanReview != true {
		t.Errorf("need_human_review must be true so confirm-drift stays manual")
	}
}

// TestCallMissingFieldNeverMarksVerdictValid — 即使 content 含一个合法 verdict 字段但缺 confidence / reason，
// 也必须**不**让 result.Verdict 被填上（即不会误导 confirm-drift 直接推进）。
//
// 这是 fallback "永不静默推进"语义的关键测试。
//
// 注意：missing_confidence 不在此列：confidence 缺省为 0.0，默认值在区间
// [0,1] 内合法，schema 校验并不强制 confidence 必填（这是有意为之：宁可
// 拿到一个保守的低 confidence verdict 也不要因字段缺一律拒绝）。这种路径
// Verdict 会被填入（如"trial"+0.0），但由 caller 通过 NeedHumanReview /
// finalConfidence 等做"低 confidence trial"判断。
func TestCallMissingFieldNeverMarksVerdictValid(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"missing_verdict", `{"confidence":0.5,"reason":"x"}`},
		{"missing_reason", `{"verdict":"trial","confidence":0.5}`},
		{"all_3_missing", `{}`},
		{"only_verdict", `{"verdict":"trial"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(validResponseBody(tc.content)))
			}))
			defer srv.Close()

			gw, _ := NewModelGatewayWithClient(Config{
				BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
			}, srv.Client(), newTestLogger())

			res, err := gw.Call(context.Background(), "prompt")
			if err == nil {
				t.Fatalf("case=%s expected schema violation, got nil err", tc.name)
			}
			var sv *ErrSchemaViolation
			if !errors.As(err, &sv) {
				t.Fatalf("case=%s err type=%T want *ErrSchemaViolation", tc.name, err)
			}
			if res.Verdict != "" {
				t.Fatalf("case=%s verdict=%q on err (would mislead confirm-drift)", tc.name, res.Verdict)
			}
			if !res.Audit.FallbackUsed || !res.Audit.NeedHumanReview {
				t.Fatalf("case=%s fallback=%v need_review=%v want true/true",
					tc.name, res.Audit.FallbackUsed, res.Audit.NeedHumanReview)
			}
		})
	}
}

// TestLLMGatewayProtocol — T25 协议兼容性测试聚合入口（6 case + 1 协议兼容）。
//
// 这是 T8（ModelGateway 主实现）的"协议兼容层"细分测试。同一 ChatCompletionsResponse
// shape 在不同 endpoint 实现下可能含 / 缺 / 多加字段；本测试在 httptest.NewServer 上
// 模拟真实 OpenAI 兼容端点（http.HandlerFunc 可被随意配置响应体 / 状态码 / 延迟），
// 验证 LLMGateway.Call 在 6 个典型 case 下 100% 命中。
//
// 6 case 全部通过 → `go test ./internal/llm/... -v -count=1 -run TestLLMGatewayProtocol`
// 输出 6 个 PASS 子用例 + 1 个协议兼容子用例 = 7 行 === RUN。
//
// 6 case 设计依据：
//   - Case 1（valid JSON）        → 主路径成功 → Verdict 填上、Audit 完整；
//   - Case 2（invalid JSON）       → schema_violation（content 不是合法 JSON）；
//   - Case 3（HTTP 500）           → http_5xx 降级；
//   - Case 4（context timeout）    → timeout 降级（服务端 hang 超 client Timeout）；
//   - Case 5（verdict 字段值非法） → schema_violation（不在 {trial, confirmed, remedied, re_verified} 白名单）；
//   - Case 6（confidence 越界）    → schema_violation（>1.0 或 <0.0）；
//   - Case 7（额外字段兼容）       → 协议 forward-compat：response 含 system_fingerprint / service_tier
//     等扩展字段仍能正确解析 verdict。
//
// 验收纪律（与 spec.md §3 严格对应）：
//   - 任何错误路径 → res.Verdict 必为 "" + Audit.NeedHumanReview=true（fallback 永不静默推进 trial）；
//   - 成功路径 → res.Verdict 必为白名单内 + Audit.HTTPStatus=200 + Audit.ErrorKind=""。
func TestLLMGatewayProtocol(t *testing.T) {
	// 一次性包装好的 prompt 与 config，与生产路径一致。
	const prompt = "对比：合同 kingbase vs 实测 PG 14.10 (Debian) banner"
	makeGW := func(t *testing.T, srvURL string, timeout time.Duration) *ModelGateway {
		t.Helper()
		gw, err := NewModelGatewayWithClient(Config{
			BaseURL: srvURL, APIKey: "k", Model: "gpt-4o-mini-test", Timeout: timeout,
		}, &http.Client{Timeout: timeout}, newTestLogger())
		if err != nil {
			t.Fatalf("new gateway: %v", err)
		}
		return gw
	}

	t.Run("case1_valid_json_verdict_parsed", func(t *testing.T) {
		// Case 1: 合法 JSON verdict → 解析成功，verdict=re_verified，audit 完整。
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/chat/completions" {
				http.Error(w, "wrong path", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("re_verified", 0.85, "KingbaseES 已重新对接成功"))))
		}))
		defer srv.Close()

		gw := makeGW(t, srv.URL, 3*time.Second)
		res, err := gw.Call(context.Background(), prompt)
		if err != nil {
			t.Fatalf("Call err: %v", err)
		}
		if res.Verdict != VerdictReVerified {
			t.Fatalf("verdict=%q want %q", res.Verdict, VerdictReVerified)
		}
		if res.Confidence < 0.8 || res.Confidence > 0.9 {
			t.Fatalf("confidence=%v want ~0.85", res.Confidence)
		}
		if res.Audit.HTTPStatus != 200 {
			t.Fatalf("audit HTTPStatus=%d want 200", res.Audit.HTTPStatus)
		}
		if res.Audit.ErrorKind != "" {
			t.Fatalf("audit ErrorKind=%q on success", res.Audit.ErrorKind)
		}
		if res.Audit.FallbackUsed || res.Audit.NeedHumanReview {
			t.Fatalf("fallback/need_review should be false on success, got fallback=%v need_review=%v",
				res.Audit.FallbackUsed, res.Audit.NeedHumanReview)
		}
		if res.Audit.LLMInSHA256 == "" || res.Audit.LLMOutSHA256 == "" {
			t.Fatalf("audit sha missing in=%q out=%q", res.Audit.LLMInSHA256, res.Audit.LLMOutSHA256)
		}
		if res.Audit.LatencyMs < 0 {
			t.Fatalf("latency ms=%d should be non-negative", res.Audit.LatencyMs)
		}
		if res.Audit.TsUTC == "" {
			t.Fatalf("ts_utc empty")
		}
	})

	t.Run("case2_invalid_json_schema_violation", func(t *testing.T) {
		// Case 2: invalid JSON（content 不是合法 JSON）→ ErrSchemaViolation。
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(validResponseBody("这压根不是 JSON, 我在瞎聊")))
		}))
		defer srv.Close()

		gw := makeGW(t, srv.URL, 2*time.Second)
		res, err := gw.Call(context.Background(), prompt)
		if err == nil {
			t.Fatalf("expected schema violation on invalid JSON")
		}
		var sv *ErrSchemaViolation
		if !errors.As(err, &sv) {
			t.Fatalf("err type=%T want *ErrSchemaViolation: %v", err, err)
		}
		if res.Verdict != "" {
			t.Fatalf("verdict=%q on err (would mislead confirm-drift)", res.Verdict)
		}
		if !res.Audit.FallbackUsed || !res.Audit.NeedHumanReview {
			t.Fatalf("fallback=%v need_review=%v want true/true",
				res.Audit.FallbackUsed, res.Audit.NeedHumanReview)
		}
		if res.Audit.ErrorKind != "schema_violation" {
			t.Fatalf("ErrorKind=%q want schema_violation", res.Audit.ErrorKind)
		}
		if res.Audit.HTTPStatus != 200 {
			t.Fatalf("audit HTTPStatus=%d want 200 (response parsed before schema check)", res.Audit.HTTPStatus)
		}
	})

	t.Run("case3_http_500_unavailable_fallback", func(t *testing.T) {
		// Case 3: HTTP 500 → ErrLLMUnavailable + kind=http_5xx + fallback。
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"message":"upstream blew up"}}`))
		}))
		defer srv.Close()

		gw := makeGW(t, srv.URL, 2*time.Second)
		res, err := gw.Call(context.Background(), prompt)
		if err == nil {
			t.Fatalf("expected unavailable on HTTP 500")
		}
		var unav *ErrLLMUnavailable
		if !errors.As(err, &unav) {
			t.Fatalf("err type=%T want *ErrLLMUnavailable: %v", err, err)
		}
		if unav.HTTPStatus != 500 {
			t.Fatalf("HTTPStatus=%d want 500", unav.HTTPStatus)
		}
		if unav.ErrorKind != "http_5xx" {
			t.Fatalf("ErrorKind=%q want http_5xx", unav.ErrorKind)
		}
		if !res.Audit.FallbackUsed || !res.Audit.NeedHumanReview {
			t.Fatalf("fallback/need_review should be true on 5xx, got fallback=%v need_review=%v",
				res.Audit.FallbackUsed, res.Audit.NeedHumanReview)
		}
		if res.Audit.ErrorKind != "http_5xx" {
			t.Fatalf("audit ErrorKind=%q want http_5xx", res.Audit.ErrorKind)
		}
		if res.Verdict != "" {
			t.Fatalf("verdict=%q on 5xx (would mislead confirm-drift)", res.Verdict)
		}
	})

	t.Run("case4_context_timeout_unavailable", func(t *testing.T) {
		// Case 4: 服务端 hang 住超过 client Timeout → ErrLLMUnavailable + kind=timeout/network。
		// 与生产路径一致：服务端 hang 300ms、客户端 Timeout 50ms → 超时。
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(300 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(validResponseBody(validVerdictJSON("trial", 0.5, "迟到的 verdict"))))
		}))
		defer srv.Close()

		gw := makeGW(t, srv.URL, 50*time.Millisecond)
		res, err := gw.Call(context.Background(), prompt)
		if err == nil {
			t.Fatalf("expected timeout err")
		}
		var unav *ErrLLMUnavailable
		if !errors.As(err, &unav) {
			t.Fatalf("err type=%T want *ErrLLMUnavailable: %v", err, err)
		}
		if unav.ErrorKind != "timeout" && unav.ErrorKind != "network" {
			t.Fatalf("ErrorKind=%q want timeout or network", unav.ErrorKind)
		}
		if !res.Audit.FallbackUsed || !res.Audit.NeedHumanReview {
			t.Fatalf("fallback/need_review should be true on timeout, got fallback=%v need_review=%v",
				res.Audit.FallbackUsed, res.Audit.NeedHumanReview)
		}
		if res.Verdict != "" {
			t.Fatalf("verdict=%q on timeout (would mislead confirm-drift)", res.Verdict)
		}
	})

	t.Run("case5_verdict_value_outside_whitelist", func(t *testing.T) {
		// Case 5: verdict 字段值不在白名单 → ErrSchemaViolation（spec 要求 verdict ∈
		// {trial, confirmed, remedied, re_verified}）。这里 "MATCH" / "DRIFT" / "AMBIGUOUS"
		// 来自另一套产品语义，**不在**本产品白名单，应被严格拒收。
		nonWhitelistVerdicts := []string{"MATCH", "DRIFT", "AMBIGUOUS", "unknown", "yes"}
		for _, bad := range nonWhitelistVerdicts {
			bad := bad
			t.Run("verdict="+bad, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(validResponseBody(validVerdictJSON(bad, 0.5, "x"))))
				}))
				defer srv.Close()

				gw := makeGW(t, srv.URL, 2*time.Second)
				res, err := gw.Call(context.Background(), prompt)
				if err == nil {
					t.Fatalf("verdict=%q expected schema violation, got nil err", bad)
				}
				var sv *ErrSchemaViolation
				if !errors.As(err, &sv) {
					t.Fatalf("verdict=%q err type=%T want *ErrSchemaViolation: %v", bad, err, err)
				}
				if !strings.Contains(sv.Reason, "verdict") {
					t.Fatalf("verdict=%q reason should mention verdict, got: %q", bad, sv.Reason)
				}
				if !res.Audit.FallbackUsed || !res.Audit.NeedHumanReview {
					t.Fatalf("verdict=%q fallback=%v need_review=%v want true/true",
						bad, res.Audit.FallbackUsed, res.Audit.NeedHumanReview)
				}
				if res.Audit.ErrorKind != "schema_violation" {
					t.Fatalf("verdict=%q ErrorKind=%q want schema_violation", bad, res.Audit.ErrorKind)
				}
				if res.Verdict != "" {
					t.Fatalf("verdict=%q result.Verdict=%q (must be empty on schema violation)", bad, res.Verdict)
				}
			})
		}
	})

	t.Run("case6_confidence_out_of_range", func(t *testing.T) {
		// Case 6: confidence 越界 → ErrSchemaViolation。spec 要求 confidence ∈ [0.0, 1.0]。
		// 测试三个越界值：>1.0 / <0.0 / NaN（边界外侧）。
		outOfRangeConfs := []float64{1.5, -0.1, 1.0001, -0.0001}
		for _, conf := range outOfRangeConfs {
			conf := conf
			t.Run(fmt.Sprintf("conf=%v", conf), func(t *testing.T) {
				// 直接构造 JSON 避开 f64str 的负小数格式化 bug（f64str 把
				// "-0.1" 经 ReplaceAll("-0","-") 误处理成 "-.1"，进而
				// 让 JSON 解析在 verdict JSON parse 处失败而非 confidence 区间校验。
				// 这里用 strconv.FormatFloat 严格输出标准 JSON 数字字面量。
				confJSON, _ := json.Marshal(conf)
				content := fmt.Sprintf(`{"verdict":"trial","confidence":%s,"reason":"x"}`, string(confJSON))
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(validResponseBody(content)))
				}))
				defer srv.Close()

				gw := makeGW(t, srv.URL, 2*time.Second)
				res, err := gw.Call(context.Background(), prompt)
				if err == nil {
					t.Fatalf("conf=%v expected schema violation, got nil err", conf)
				}
				var sv *ErrSchemaViolation
				if !errors.As(err, &sv) {
					t.Fatalf("conf=%v err type=%T want *ErrSchemaViolation: %v", conf, err, err)
				}
				if !strings.Contains(sv.Reason, "confidence") {
					t.Fatalf("conf=%v reason should mention confidence, got: %q", conf, sv.Reason)
				}
				if !res.Audit.FallbackUsed || !res.Audit.NeedHumanReview {
					t.Fatalf("conf=%v fallback=%v need_review=%v want true/true",
						conf, res.Audit.FallbackUsed, res.Audit.NeedHumanReview)
				}
				if res.Audit.ErrorKind != "schema_violation" {
					t.Fatalf("conf=%v ErrorKind=%q want schema_violation", conf, res.Audit.ErrorKind)
				}
				if res.Verdict != "" {
					t.Fatalf("conf=%v result.Verdict=%q (must be empty on schema violation)", conf, res.Verdict)
				}
			})
		}
	})

	t.Run("case7_protocol_forward_compat_extra_fields", func(t *testing.T) {
		// Case 7（协议兼容）：ChatCompletionsResponse 含 OpenAI 后续可能加入的扩展字段
		// （system_fingerprint / service_tier / citations / logprobs）→ 解析兼容，
		// verdict 与 confidence / reason 正确读取。
		escapedContent, _ := json.Marshal(validVerdictJSON("re_verified", 0.7, "再次核实后通过"))
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{
  "id": "chatcmpl-forward-compat",
  "object": "chat.completion",
  "created": 1735689600,
  "model": "gpt-4o-mini-test",
  "system_fingerprint": "fp_forward_compat",
  "service_tier": "default",
  "logprobs": null,
  "citations": [],
  "choices": [{"index":0,"message":{"role":"assistant","content":` + string(escapedContent) +
				`},"finish_reason":"stop"}],
  "usage": {"prompt_tokens":15,"completion_tokens":10,"total_tokens":25,"completion_tokens_details":{"reasoning_tokens":0}}
}`))
		}))
		defer srv.Close()

		gw := makeGW(t, srv.URL, 3*time.Second)
		res, err := gw.Call(context.Background(), prompt)
		if err != nil {
			t.Fatalf("Call err on forward-compat response: %v", err)
		}
		if res.Verdict != VerdictReVerified {
			t.Fatalf("verdict=%q want re_verified (forward-compat must not break parsing)", res.Verdict)
		}
		if res.Confidence < 0.65 || res.Confidence > 0.75 {
			t.Fatalf("confidence=%v want ~0.7", res.Confidence)
		}
		if res.Audit.HTTPStatus != 200 {
			t.Fatalf("HTTPStatus=%d want 200", res.Audit.HTTPStatus)
		}
		if res.Audit.FallbackUsed {
			t.Fatalf("forward-compat path should not fall back, got fallback=true")
		}
	})
}
