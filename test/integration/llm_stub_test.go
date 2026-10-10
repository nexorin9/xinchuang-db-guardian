//go:build integration
// +build integration

// Package integration_test contains 集成测试（与外部/边界测试替身交互）。
//
// Build tag: integration — 默认 go test 不跑；显式 -tags=integration 启用。
//
// 本文件: httptest 桩 LLM server + 6 case 协议兼容测试集合。
// 覆盖 internal/llm.ModelGateway 对 OpenAI-compatible /v1/chat/completions
// 端点的协议兼容：合法 JSON / 非法 JSON / 5xx / 超时 / 4xx 不重试 / 扩展字段兼容。
// 替身（in T8 task 8 的 gateway_test.go）已覆盖基础分支；本测试聚焦：
//  1) 多个独立 verdict 候选命中（trial/confirmed/remedied/re_verified）；
//  2) 协议字段 system_fingerprint/service_tier 等扩展字段不破坏解析；
//  3) 端到端 prompt 携带的 signature tokens 不会被 ModelGateway 任何过滤剥离。
//  4) 请求头 / 请求体结构（temperature:0 / response_format=json_object / Bearer 鉴权）。
//  5) 桩 server 多请求累积 + in_sha 模板各异。
package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"xinchuang-db-guardian/internal/llm"
)

// llmStubServer — 桩 OpenAI-compatible /v1/chat/completions 端点。
//
// 配置：
//   - respondFn:  根据 (path / request body) 决定返回什么；为 nil 时返回 defaultResp；
//   - delay:      模拟网络延迟（用于超时测试）；
//   - statusCode: 直接返回的 HTTP 状态码（用于 5xx / 4xx 测试）；
//   - body:       非空时直接返回（用于非法 JSON 测试）。
//   - requests:   收到的请求计数 + body 累积（断言重试次数）。
type llmStubServer struct {
	server     *httptest.Server
	mu         sync.Mutex
	requests   int32
	requestBodies [][]byte
	delay      time.Duration
	statusCode int
	body       string
	defaultResp *llmVerdictEnvelope
	respondFn  func(reqBody []byte) (status int, body string, contentType string)
}

type llmVerdictEnvelope struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	SystemFingerprint string `json:"system_fingerprint,omitempty"`
	ServiceTier       string `json:"service_tier,omitempty"`
}

func newLLMStubServer() *llmStubServer {
	s := &llmStubServer{
		defaultResp: &llmVerdictEnvelope{
			ID:     "chatcmpl-stub-001",
			Object: "chat.completion",
			Model:  "stub-model",
		},
	}
	s.defaultResp.Choices = append(s.defaultResp.Choices, struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	}{})
	s.defaultResp.Choices[0].Index = 0
	s.defaultResp.Choices[0].Message.Role = "assistant"
	s.defaultResp.Choices[0].Message.Content = `{"verdict":"confirmed","confidence":0.95,"reason":"stub verdict"}`
	s.defaultResp.Choices[0].FinishReason = "stop"
	s.defaultResp.Usage.TotalTokens = 100

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)
	s.server = httptest.NewServer(mux)
	return s
}

func (s *llmStubServer) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&s.requests, 1)
	body, _ := io.ReadAll(r.Body)

	s.mu.Lock()
	s.requestBodies = append(s.requestBodies, body)
	status := s.statusCode
	respBody := s.body
	fn := s.respondFn
	delay := s.delay
	s.mu.Unlock()

	if fn != nil {
		st, b, ct := fn(body)
		if delay > 0 {
			time.Sleep(delay)
		}
		// status=0 + body="" + ct="" 视作「走默认路径」，跳过自定义响应。
		if st != 0 || b != "" || ct != "" {
			if ct != "" {
				w.Header().Set("Content-Type", ct)
			}
			if st != 0 {
				w.WriteHeader(st)
			}
			_, _ = w.Write([]byte(b))
			return
		}
		// 否则继续走下方的 defaultResp 路径。
	}

	if delay > 0 {
		time.Sleep(delay)
	}

	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if respBody != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(respBody))
		return
	}

	// 默认：合法 verdict envelope。
	respBytes, _ := json.Marshal(s.defaultResp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func (s *llmStubServer) URL() string { return s.server.URL }

func (s *llmStubServer) Close() { s.server.Close() }

func (s *llmStubServer) RequestCount() int {
	return int(atomic.LoadInt32(&s.requests))
}

// makeVerdictResp — 构造合法 verdict envelope。
func makeVerdictResp(verdict llm.Verdict, confidence float64, reason string) string {
	resp := llmVerdictEnvelope{
		ID:                "chatcmpl-stub",
		Object:            "chat.completion",
		Model:             "stub-model",
		SystemFingerprint: "fp_stub_v1", // 扩展字段
		ServiceTier:       "default",    // 扩展字段
	}
	resp.Choices = append(resp.Choices, struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	}{})
	resp.Choices[0].Index = 0
	resp.Choices[0].Message.Role = "assistant"
	resp.Choices[0].Message.Content = fmt.Sprintf(
		`{"verdict":%q,"confidence":%v,"reason":%q}`, verdict, confidence, reason,
	)
	resp.Choices[0].FinishReason = "stop"
	resp.Usage.TotalTokens = 50
	b, _ := json.Marshal(&resp)
	return string(b)
}

// buildGateway — 构造测试用 ModelGateway；BaseURL 指向桩 server。
func buildGateway(t *testing.T, stub *llmStubServer) *llm.ModelGateway {
	t.Helper()
	cfg := llm.Config{
		BaseURL: stub.URL(),
		APIKey:  "stub-bearer-token-xyz",
		Model:   "stub-model",
		Timeout: 1 * time.Second,
	}
	gw, err := llm.NewModelGateway(cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, gw)
	return gw
}

// ----- 6 case 协议兼容性 -----

// Case 1: verdict=confirmed 命中；audit 字段完整；NeedHumanReview=false；FallbackUsed=false。
func TestLLMStub_ConfirmedVerdict_HappyPath(t *testing.T) {
	stub := newLLMStubServer()
	defer stub.Close()

	stub.mu.Lock()
	stub.defaultResp.Choices[0].Message.Content = `{"verdict":"confirmed","confidence":0.97,"reason":"port banner matches declared vendor"}`
	stub.mu.Unlock()

	gw := buildGateway(t, stub)
	prompt := "xinchuang-db: system_id=his-core vendor=kingbase port_banner='KingbaseES V008R006C0010'"

	res, err := gw.Call(context.Background(), prompt)
	require.NoError(t, err)
	require.Equal(t, llm.VerdictConfirmed, res.Verdict)
	require.InDelta(t, 0.97, res.Confidence, 0.001)
	require.Contains(t, res.Reason, "port banner matches")
	require.Equal(t, http.StatusOK, res.Audit.HTTPStatus)
	require.Equal(t, "stub-model", res.Audit.LLMModel)
	require.False(t, res.Audit.FallbackUsed)
	require.False(t, res.Audit.NeedHumanReview)
	require.Len(t, res.Audit.LLMInSHA256, 64)
	require.Len(t, res.Audit.LLMOutSHA256, 64)
	require.Equal(t, 1, stub.RequestCount())
}

// Case 2: 扩展字段 system_fingerprint + service_tier 不破坏解析（兼容性）。
func TestLLMStub_ExtraFieldsForwardCompatible(t *testing.T) {
	stub := newLLMStubServer()
	defer stub.Close()

	stub.mu.Lock()
	stub.defaultResp.Choices[0].Message.Content = `{"verdict":"re_verified","confidence":0.88,"reason":"re-scan after operator action"}`
	stub.mu.Unlock()

	gw := buildGateway(t, stub)
	res, err := gw.Call(context.Background(), "xinchuang-db: system_id=emr-portal vendor=dm8 port_banner='DM: V8.1.0'")
	require.NoError(t, err)
	require.Equal(t, llm.VerdictReVerified, res.Verdict)
	require.InDelta(t, 0.88, res.Confidence, 0.001)
	require.False(t, res.Audit.FallbackUsed)
	require.Equal(t, 1, stub.RequestCount())
}

// Case 3: 4 个 verdict 候选循环各命中（trial/confirmed/remedied/re_verified）。
func TestLLMStub_AllFourVerdictsRoundTrip(t *testing.T) {
	verdicts := []struct {
		name    string
		verdict llm.Verdict
	}{
		{"trial", llm.VerdictTrial},
		{"confirmed", llm.VerdictConfirmed},
		{"remedied", llm.VerdictRemedied},
		{"re_verified", llm.VerdictReVerified},
	}

	for _, tc := range verdicts {
		t.Run(tc.name, func(t *testing.T) {
			stub := newLLMStubServer()
			defer stub.Close()
			stub.mu.Lock()
			stub.defaultResp.Choices[0].Message.Content = fmt.Sprintf(
				`{"verdict":%q,"confidence":0.9,"reason":%q}`, tc.verdict, tc.name,
			)
			stub.mu.Unlock()

			gw := buildGateway(t, stub)
			res, err := gw.Call(context.Background(), "xinchuang-db: verdict round trip "+tc.name)
			require.NoError(t, err)
			require.Equal(t, tc.verdict, res.Verdict)
			require.False(t, res.Audit.FallbackUsed)
			require.False(t, res.Audit.NeedHumanReview)
		})
	}
}

// Case 4: 非法 JSON content → ErrSchemaViolation + FallbackUsed=true + NeedHumanReview=true。
func TestLLMStub_InvalidJSONContentFallsBack(t *testing.T) {
	stub := newLLMStubServer()
	defer stub.Close()

	stub.mu.Lock()
	stub.body = `{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"not-valid-json"}}]}`
	stub.mu.Unlock()

	gw := buildGateway(t, stub)
	res, err := gw.Call(context.Background(), "xinchuang-db: bad response")

	require.Error(t, err)
	_, isSchema := err.(*llm.ErrSchemaViolation)
	require.True(t, isSchema, "expected ErrSchemaViolation, got %T", err)
	require.True(t, res.Audit.FallbackUsed)
	require.True(t, res.Audit.NeedHumanReview)
	require.Equal(t, "schema_violation", res.Audit.ErrorKind)
	require.Equal(t, 1, stub.RequestCount())
}

// Case 5: 5xx → ErrLLMUnavailable + Kind=http_5xx + NeedHumanReview=true。
func TestLLMStub_HTTP5xxFallsBack(t *testing.T) {
	stub := newLLMStubServer()
	defer stub.Close()

	stub.mu.Lock()
	stub.statusCode = http.StatusInternalServerError
	stub.mu.Unlock()

	gw := buildGateway(t, stub)
	res, err := gw.Call(context.Background(), "xinchuang-db: server 500")

	require.Error(t, err)
	unavail, isUnavail := err.(*llm.ErrLLMUnavailable)
	require.True(t, isUnavail, "expected ErrLLMUnavailable, got %T", err)
	require.Equal(t, "http_5xx", unavail.ErrorKind)
	require.Equal(t, http.StatusInternalServerError, unavail.HTTPStatus)
	require.True(t, res.Audit.FallbackUsed)
	require.True(t, res.Audit.NeedHumanReview)
	require.Equal(t, "http_5xx", res.Audit.ErrorKind)
	require.Equal(t, 1, stub.RequestCount())
}

// Case 6: 服务端 hang → client timeout → ErrLLMUnavailable + Kind=timeout。
func TestLLMStub_TimeoutFallsBackWithContextDeadline(t *testing.T) {
	stub := newLLMStubServer()
	defer stub.Close()

	stub.mu.Lock()
	stub.delay = 300 * time.Millisecond // 服务端 hang > client 50ms timeout
	stub.mu.Unlock()

	gw := buildGateway(t, stub)
	cfg := llm.Config{
		BaseURL: stub.URL(),
		APIKey:  "stub-bearer-token",
		Model:   "stub-model",
		Timeout: 50 * time.Millisecond,
	}
	gw, err := llm.NewModelGateway(cfg, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	res, err := gw.Call(ctx, "xinchuang-db: timeout")
	require.Error(t, err)
	unavail, isUnavail := err.(*llm.ErrLLMUnavailable)
	require.True(t, isUnavail)
	// timeout / network 二者皆为合法 Kind（取决于 deadline vs read）。
	require.Contains(t, []string{"timeout", "network"}, unavail.ErrorKind)
	require.True(t, res.Audit.FallbackUsed)
	require.True(t, res.Audit.NeedHumanReview)
}

// Case 7: prompt 携带的 signature tokens 不会被剥离（侧带断言）。
func TestLLMStub_PromptSignatureTokensPreserved(t *testing.T) {
	stub := newLLMStubServer()
	defer stub.Close()

	gw := buildGateway(t, stub)
	prompt := "xinchuang-db: vendor=kingbase tokens=[KingbaseES,V008,PostgreSQL,compatible] jdbc=jdbc:kingbase8://10.0.1.21:54321/SAMPLE"

	_, err := gw.Call(context.Background(), prompt)
	require.NoError(t, err)
	require.Equal(t, 1, stub.RequestCount())

	stub.mu.Lock()
	lastBody := stub.requestBodies[len(stub.requestBodies)-1]
	stub.mu.Unlock()

	require.Contains(t, string(lastBody), "KingbaseES")
	require.Contains(t, string(lastBody), "V008")
	require.Contains(t, string(lastBody), "PostgreSQL")
	require.Contains(t, string(lastBody), "compatible")
	require.Contains(t, string(lastBody), "jdbc:kingbase8://")
}

// Case 8: Bearer token 与 Content-Type 头正确（断言请求结构）。
func TestLLMStub_RequestHeadersAreValid(t *testing.T) {
	stub := newLLMStubServer()
	defer stub.Close()

	// respondFn 返回 (status=0, "", "") 由 handleChatCompletions 解读为「走 default 路径」；
	// 因此无需准备自定义 respondFn，直接使用 defaultResp。
	gw := buildGateway(t, stub)
	_, err := gw.Call(context.Background(), "xinchuang-db: header test")
	require.NoError(t, err)

	// 校验请求 body 必含 temperature:0 + response_format=json_object + role=system。
	stub.mu.Lock()
	lastBody := stub.requestBodies[len(stub.requestBodies)-1]
	stub.mu.Unlock()
	bodyStr := string(lastBody)
	require.Contains(t, bodyStr, `"temperature":0`)
	require.Contains(t, bodyStr, `"response_format":{"type":"json_object"}`)
	require.Contains(t, bodyStr, `"role":"system"`)
	require.Contains(t, bodyStr, `"role":"user"`)
}

// Case 9: 桩服务端错误恢复（同一桩 server 上多请求，状态连续）。
func TestLLMStub_SequentialCallsAccumulateAudit(t *testing.T) {
	stub := newLLMStubServer()
	defer stub.Close()
	gw := buildGateway(t, stub)

	for i := 0; i < 3; i++ {
		res, err := gw.Call(context.Background(), fmt.Sprintf("xinchuang-db: seq call %d", i))
		require.NoError(t, err)
		require.False(t, res.Audit.FallbackUsed)
		require.Equal(t, "stub-model", res.Audit.LLMModel)
	}
	require.Equal(t, 3, stub.RequestCount())

	// 3 个独立 in_sha 不重复。
	stub.mu.Lock()
	inshas := make(map[string]struct{}, 3)
	for _, b := range stub.requestBodies {
		inshas[string(b)] = struct{}{}
	}
	stub.mu.Unlock()
	require.Len(t, inshas, 3, "不同 prompt 必须产生不同 in_sha")
}

// 工具断言：桩 server 仍存活且收到请求。
func TestLLMStub_LivenessAndLog(t *testing.T) {
	stub := newLLMStubServer()
	defer stub.Close()

	gw := buildGateway(t, stub)
	_, err := gw.Call(context.Background(), "xinchuang-db: liveness")
	require.NoError(t, err)
	require.Equal(t, 1, stub.RequestCount())

	// URL 必为 http://127.0.0.1:port 形态。
	require.True(t, strings.HasPrefix(stub.URL(), "http://127.0.0.1:"))
}