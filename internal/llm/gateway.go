// Package llm — 统一出站 LLM 调用的边界层（ModelGateway）。
//
// 设计哲学：
//
//	业务层（如 internal/check/llm_integration.go）只调用本包的 ModelGateway，
//	不直接耦合任何 OpenAI / Anthropic / 第三方厂商的 SDK；所有协议细节
//	（POST /v1/chat/completions + 严格 JSON schema）在本包内封闭。
//
//	LLM 在本产品里是**兜底解释器**，不是主路径裁定者：规则 confidence 落在
//	不能定论的区间时调用，拿一个 verdict 作为参考意见；规则 confidence ≥ 0.7
//	时**不会**调用 LLM（详见 internal/check/llm_integration.go 的组合策略，
//	本包只负责调用与降级，不决策是否调用）。
//
//	失败语义：5xx / 网络错 / 超时（默认 10s）/ JSON 非法 / schema 不合法 →
//	调用方收到 ErrLLMUnavailable 或 ErrSchemaViolation。fallback 路径必须
//	走规则 verdict + need_human_review=true；trial 状态**永不静默推进**到
//	confirmed / remedied / re-verified。
//
//	调用元数据（ts_utc / llm_in_sha / llm_out_sha / llm_model / latency_ms
//	/ error_kind / http_status）由本包计算并通过 Call 产出可写入审计行的
//	LLMCallAudit 结构，由调用方落入 append-only JSONL 审计链。
//
// 真实协议：本包实现 OpenAI-compatible POST /v1/chat/completions：
//   - request body：{model, messages:[{role, content}], temperature:0,
//     response_format:{type:"json_object"}}；
//   - response body：标准 ChatCompletionsResponse shape（id / object / created
//     / model / choices[].message.content / usage）；
//   - 凭据：Authorization: Bearer <LLM_API_KEY> 来自环境变量；
//   - 业务层**不**读 LLM_BASE_URL / LLM_API_KEY / LLM_MODEL，本包构造时一次
//     化，调用零参数 base_url。
//
// 脱敏替身：测试用 httptest.NewServer 模拟合规响应；本包代码**绝不**为测试
// 切换协议，调用协议在产品代码和测试代码里完全一致。
package llm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// Verdict — LLM 返回的四个候选 verdict（与 DriftState 一一对应）。
//
// 注意：这是 LLM 输出的 verdict，而不是规则出的 verdict。规则 verdict 由
// internal/check 决定；LLM verdict 在 confidence ∈ 不能定论区间时作为参考意见。
type Verdict string

const (
	VerdictTrial      Verdict = "trial"
	VerdictConfirmed  Verdict = "confirmed"
	VerdictRemedied   Verdict = "remedied"
	VerdictReVerified Verdict = "re_verified"
)

// AllVerdicts — 严格 JSON schema 白名单。
var AllVerdicts = []Verdict{
	VerdictTrial,
	VerdictConfirmed,
	VerdictRemedied,
	VerdictReVerified,
}

// ErrLLMUnavailable — 模型不可达 / 5xx / 超时 / 网络错。
type ErrLLMUnavailable struct {
	HTTPStatus int
	ErrorKind  string // "http_5xx" / "http_4xx" / "network" / "timeout"
	LatencyMs  int64
	Cause      error
}

func (e *ErrLLMUnavailable) Error() string {
	return fmt.Sprintf("llm_unavailable kind=%s status=%d latency_ms=%d: %v",
		e.ErrorKind, e.HTTPStatus, e.LatencyMs, e.Cause)
}

func (e *ErrLLMUnavailable) Unwrap() error { return e.Cause }

// ErrSchemaViolation — 响应不合法（JSON parse / 缺字段 / 越界值 / verdict 不在白名单）。
type ErrSchemaViolation struct {
	Reason string // 机器可读的违反原因
	Cause  error
}

func (e *ErrSchemaViolation) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("llm_schema_violation: %s: %v", e.Reason, e.Cause)
	}
	return "llm_schema_violation: " + e.Reason
}

func (e *ErrSchemaViolation) Unwrap() error { return e.Cause }

// ChatMessage — /v1/chat/completions 单轮消息。
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest — 出站请求体（response_format 强制 JSON，便于严格 schema 解析）。
type chatRequest struct {
	Model         string        `json:"model"`
	Messages      []ChatMessage `json:"messages"`
	Temperature   float64       `json:"temperature"`
	ResponseFormat struct {
		Type string `json:"type"`
	} `json:"response_format"`
}

// choice — 响应 choices[0]。
type choice struct {
	Index   int          `json:"index"`
	Message ChatMessage  `json:"message"`
	Finish  string       `json:"finish_reason"`
	// rawJSONMessage 解析后的结构化 verdict 字段；从 Content 解出后填充。
	RawJSON json.RawMessage `json:"-"`
}

// chatResponse — 出站响应体（OpenAI 兼容 shape）。
type chatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []choice `json:"choices"`
	Usage   struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// llmVerdictJSON — LLM 返回的 schema 受约束 JSON。
type llmVerdictJSON struct {
	Verdict    Verdict `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// Config — ModelGateway 不可变配置；从 env 一次性构造。
type Config struct {
	BaseURL string        // 完整前缀，例如 https://api.openai.com 或 https://llm.example.com
	APIKey  string        // Bearer token
	Model   string        // 模型标识符
	Timeout time.Duration // 单次调用超时（含建连 / 写 / 读 / 解析）
}

// LoadConfigFromEnv — 从环境变量读出 Config；缺关键项返回 error。
//
// 必读：
//   - LLM_BASE_URL  必填
//   - LLM_API_KEY   必填
//   - LLM_MODEL     必填
//   - LLM_TIMEOUT_SECS  可选，默认 10
func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		BaseURL: strings.TrimSpace(os.Getenv("LLM_BASE_URL")),
		APIKey:  strings.TrimSpace(os.Getenv("LLM_API_KEY")),
		Model:   strings.TrimSpace(os.Getenv("LLM_MODEL")),
		Timeout: 10 * time.Second,
	}
	if secs := strings.TrimSpace(os.Getenv("LLM_TIMEOUT_SECS")); secs != "" {
		var n int
		if _, err := fmt.Sscanf(secs, "%d", &n); err == nil && n > 0 {
			cfg.Timeout = time.Duration(n) * time.Second
		}
	}
	if cfg.BaseURL == "" {
		return cfg, errors.New("llm: LLM_BASE_URL empty")
	}
	if cfg.APIKey == "" {
		return cfg, errors.New("llm: LLM_API_KEY empty")
	}
	if cfg.Model == "" {
		return cfg, errors.New("llm: LLM_MODEL empty")
	}
	return cfg, nil
}

// LLMCallAudit — 写审计行的元数据；调用方拿这个结构 append JSONL。
//
// 即使 fallback（5xx / 超时 / schema 非法）路径，调用元数据仍落审计，证据完整。
type LLMCallAudit struct {
	TsUTC         string
	LLMInSHA256   string
	LLMOutSHA256  string
	LLMModel      string
	LatencyMs     int64
	HTTPStatus    int
	ErrorKind     string // "" 或 http_5xx / http_4xx / network / timeout / schema_violation
	FallbackUsed  bool
	NeedHumanReview bool
}

// LLMCallResult — Call 的完整产出。
type LLMCallResult struct {
	Verdict         Verdict
	Confidence      float64
	Reason          string
	Audit           LLMCallAudit
}

// ModelGateway — 唯一对外调用边界；多个守护实例可共享（HTTPClient 复用连接池）。
type ModelGateway struct {
	cfg    Config
	client *http.Client
	logger *slog.Logger
}

// NewModelGateway — 构造；Config 缺关键项返回 error；HTTP client 默认带 Timeout。
func NewModelGateway(cfg Config, logger *slog.Logger) (*ModelGateway, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("llm: BaseURL empty")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("llm: APIKey empty")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, errors.New("llm: Model empty")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ModelGateway{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		logger: logger,
	}, nil
}

// NewModelGatewayWithClient — 测试用：注入自定义 http.Client（便于 httptest）。
//
// 生产路径必须走 NewModelGateway；本入口只对测试包暴露。
func NewModelGatewayWithClient(cfg Config, client *http.Client, logger *slog.Logger) (*ModelGateway, error) {
	if client == nil {
		return nil, errors.New("llm: client nil")
	}
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("llm: BaseURL empty")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("llm: APIKey empty")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, errors.New("llm: Model empty")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ModelGateway{
		cfg:    cfg,
		client: client,
		logger: logger,
	}, nil
}

// SchemaGuidance — 系统提示词固定部分；告诉 LLM 严格 JSON schema。
//
// 注意：本函数返回的字符串**不**包含端口原文 / 业务数据原文；只携带结构化上下文
// （signature tokens + normalized version + 期望 vendor）。调用方在构造 prompt
// 时只把 SchemaGuidance + 已过滤的上下文拼起来。
func SchemaGuidance() string {
	return strings.Join([]string{
		"你是信创数据库合规漂移检测的兜底解释器。",
		"任务：基于给定的合同期望与观测，对一次漂移事件给 verdict + confidence + reason。",
		"严格 JSON schema 如下，禁止输出 schema 之外的任何字符：",
		`{"verdict":"trial|confirmed|remedied|re_verified",`,
		` "confidence":0.0..1.0,`,
		` "reason":"<中文一句话理由，≤80字>"}`,
		"verdict 必须是 trial / confirmed / remedied / re_verified 之一，否则响应无效。",
		"confidence ∈ [0.0, 1.0]，越界视为无效。",
		"reason 必须是中文，且 ≤ 80 个汉字。",
	}, "\n")
}

// Call — 单次 LLM 调用。
//
// 行为：
//  1. context.WithTimeout(parentCtx, m.cfg.Timeout) 自动取消；
//  2. POST {BaseURL}/v1/chat/completions 携带 Bearer + response_format=json_object；
//  3. JSON 解析 → llmVerdictJSON → schema 校验（verdict 白名单 + confidence 区间 + reason 长度）；
//  4. 任何失败 → 写 ErrLLMUnavailable / ErrSchemaViolation + Audit 字段填错误原因。
//
// fallback 责任：**本函数永不决定 trial 推进**；它只产出 verdict + need_human_review 提示。
// 是否将 trial 推进到 confirmed/remedied/re-verified 是 internal/check 的 CLI confirm-drift 命令的事。
func (g *ModelGateway) Call(ctx context.Context, prompt string) (LLMCallResult, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, g.cfg.Timeout)
	defer cancel()

	if strings.TrimSpace(prompt) == "" {
		return LLMCallResult{}, &ErrSchemaViolation{Reason: "prompt empty"}
	}

	// 构造请求体。
	reqBody := chatRequest{
		Model:       g.cfg.Model,
		Temperature: 0,
	}
	reqBody.Messages = []ChatMessage{
		{Role: "system", Content: SchemaGuidance()},
		{Role: "user", Content: prompt},
	}
	reqBody.ResponseFormat.Type = "json_object"

	bodyBytes, err := json.Marshal(&reqBody)
	if err != nil {
		return LLMCallResult{}, &ErrSchemaViolation{Reason: "marshal request", Cause: err}
	}

	inSHA := sha256Hex(bodyBytes)

	// 出站 HTTP。
	endpoint := strings.TrimRight(g.cfg.BaseURL, "/") + "/v1/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return LLMCallResult{}, &ErrLLMUnavailable{ErrorKind: "network", LatencyMs: ms(start), Cause: err}
	}
	httpReq.Header.Set("Authorization", "Bearer "+g.cfg.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(httpReq)
	if err != nil {
		kind := "network"
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			kind = "timeout"
		}
		return LLMCallResult{
			Audit: LLMCallAudit{
				TsUTC:        time.Now().UTC().Format(time.RFC3339Nano),
				LLMInSHA256:  inSHA,
				LLMOutSHA256: "",
				LLMModel:     g.cfg.Model,
				LatencyMs:    ms(start),
				HTTPStatus:   0,
				ErrorKind:    kind,
				FallbackUsed: true,
				NeedHumanReview: true,
			},
		}, &ErrLLMUnavailable{ErrorKind: kind, LatencyMs: ms(start), Cause: err}
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return LLMCallResult{
			Audit: LLMCallAudit{
				TsUTC:        time.Now().UTC().Format(time.RFC3339Nano),
				LLMInSHA256:  inSHA,
				LLMOutSHA256: "",
				LLMModel:     g.cfg.Model,
				LatencyMs:    ms(start),
				HTTPStatus:   resp.StatusCode,
				ErrorKind:    "network",
				FallbackUsed: true,
				NeedHumanReview: true,
			},
		}, &ErrLLMUnavailable{
			HTTPStatus: resp.StatusCode, ErrorKind: "network", LatencyMs: ms(start), Cause: readErr,
		}
	}
	outSHA := sha256Hex(respBytes)

	// HTTP 状态码分支。
	if resp.StatusCode >= 400 {
		kind := "http_5xx"
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			kind = "http_4xx"
		}
		return LLMCallResult{
			Audit: LLMCallAudit{
				TsUTC:        time.Now().UTC().Format(time.RFC3339Nano),
				LLMInSHA256:  inSHA,
				LLMOutSHA256: outSHA,
				LLMModel:     g.cfg.Model,
				LatencyMs:    ms(start),
				HTTPStatus:   resp.StatusCode,
				ErrorKind:    kind,
				FallbackUsed: true,
				NeedHumanReview: true,
			},
		}, &ErrLLMUnavailable{
			HTTPStatus: resp.StatusCode, ErrorKind: kind, LatencyMs: ms(start),
		}
	}

	// JSON 解析。
	var chatResp chatResponse
	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return LLMCallResult{
			Audit: LLMCallAudit{
				TsUTC:        time.Now().UTC().Format(time.RFC3339Nano),
				LLMInSHA256:  inSHA,
				LLMOutSHA256: outSHA,
				LLMModel:     g.cfg.Model,
				LatencyMs:    ms(start),
				HTTPStatus:   resp.StatusCode,
				ErrorKind:    "schema_violation",
				FallbackUsed: true,
				NeedHumanReview: true,
			},
		}, &ErrSchemaViolation{Reason: "top-level JSON unmarshal", Cause: err}
	}

	if len(chatResp.Choices) == 0 {
		return LLMCallResult{
			Audit: LLMCallAudit{
				TsUTC:        time.Now().UTC().Format(time.RFC3339Nano),
				LLMInSHA256:  inSHA,
				LLMOutSHA256: outSHA,
				LLMModel:     g.cfg.Model,
				LatencyMs:    ms(start),
				HTTPStatus:   resp.StatusCode,
				ErrorKind:    "schema_violation",
				FallbackUsed: true,
				NeedHumanReview: true,
			},
		}, &ErrSchemaViolation{Reason: "choices empty"}
	}

	// LLM 输出应严格 JSON；解析 message.content 里的 verdict 字段。
	content := chatResp.Choices[0].Message.Content
	var v llmVerdictJSON
	if err := json.Unmarshal([]byte(content), &v); err != nil {
		return LLMCallResult{
			Audit: LLMCallAudit{
				TsUTC:        time.Now().UTC().Format(time.RFC3339Nano),
				LLMInSHA256:  inSHA,
				LLMOutSHA256: outSHA,
				LLMModel:     g.cfg.Model,
				LatencyMs:    ms(start),
				HTTPStatus:   resp.StatusCode,
				ErrorKind:    "schema_violation",
				FallbackUsed: true,
				NeedHumanReview: true,
			},
		}, &ErrSchemaViolation{Reason: "verdict JSON parse", Cause: err}
	}

	// Schema 校验（verdict 白名单 + confidence 区间 + reason 长度）。
	if !isValidVerdict(v.Verdict) {
		return LLMCallResult{
			Audit: LLMCallAudit{
				TsUTC:        time.Now().UTC().Format(time.RFC3339Nano),
				LLMInSHA256:  inSHA,
				LLMOutSHA256: outSHA,
				LLMModel:     g.cfg.Model,
				LatencyMs:    ms(start),
				HTTPStatus:   resp.StatusCode,
				ErrorKind:    "schema_violation",
				FallbackUsed: true,
				NeedHumanReview: true,
			},
		}, &ErrSchemaViolation{
			Reason: fmt.Sprintf("verdict %q not in whitelist", string(v.Verdict)),
		}
	}
	if v.Confidence < 0 || v.Confidence > 1 {
		return LLMCallResult{
			Audit: LLMCallAudit{
				TsUTC:        time.Now().UTC().Format(time.RFC3339Nano),
				LLMInSHA256:  inSHA,
				LLMOutSHA256: outSHA,
				LLMModel:     g.cfg.Model,
				LatencyMs:    ms(start),
				HTTPStatus:   resp.StatusCode,
				ErrorKind:    "schema_violation",
				FallbackUsed: true,
				NeedHumanReview: true,
			},
		}, &ErrSchemaViolation{
			Reason: fmt.Sprintf("confidence %.4f out of [0,1]", v.Confidence),
		}
	}
	reasonLen := len([]rune(strings.TrimSpace(v.Reason)))
	if v.Reason == "" || reasonLen == 0 || reasonLen > 80 {
		return LLMCallResult{
			Audit: LLMCallAudit{
				TsUTC:        time.Now().UTC().Format(time.RFC3339Nano),
				LLMInSHA256:  inSHA,
				LLMOutSHA256: outSHA,
				LLMModel:     g.cfg.Model,
				LatencyMs:    ms(start),
				HTTPStatus:   resp.StatusCode,
				ErrorKind:    "schema_violation",
				FallbackUsed: true,
				NeedHumanReview: true,
			},
		}, &ErrSchemaViolation{
			Reason: fmt.Sprintf("reason runes=%d out of (0,80]", reasonLen),
		}
	}

	// 成功路径。
	return LLMCallResult{
		Verdict:    v.Verdict,
		Confidence: v.Confidence,
		Reason:     strings.TrimSpace(v.Reason),
		Audit: LLMCallAudit{
			TsUTC:        time.Now().UTC().Format(time.RFC3339Nano),
			LLMInSHA256:  inSHA,
			LLMOutSHA256: outSHA,
			LLMModel:     g.cfg.Model,
			LatencyMs:    ms(start),
			HTTPStatus:   resp.StatusCode,
			ErrorKind:     "",
			FallbackUsed:  false,
			NeedHumanReview: false,
		},
	}, nil
}

// isValidVerdict — verdict 白名单校验。
func isValidVerdict(v Verdict) bool {
	for _, ok := range AllVerdicts {
		if v == ok {
			return true
		}
	}
	return false
}

// sha256Hex — 32 字节摘要的 hex（与内部审计链一致）。
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ms — 把 time.Since 折成毫秒 int64。
func ms(t time.Time) int64 {
	return time.Since(t).Milliseconds()
}

// BaseURL — 暴露只读字段（便于 cmd 启动时打印当前配置）。
func (g *ModelGateway) BaseURL() string { return g.cfg.BaseURL }

// Model — 暴露只读模型标识。
func (g *ModelGateway) Model() string { return g.cfg.Model }

// Timeout — 暴露只读超时。
func (g *ModelGateway) Timeout() time.Duration { return g.cfg.Timeout }

// FallbackMetadata — 把 LLMCallAudit 在 caller 处降级为 audit 行所用的元数据视图。
//
// caller 在 ModelGateway.Call 返回 ErrLLMUnavailable 或 ErrSchemaViolation
// 时调用 output.AppendFallbackAudit(...)；本结构是跨包传递 LLM 调用的
// 可观测元数据的窄类型，避免 llm 包被 output 反向依赖。
type FallbackMetadata struct {
	// TsUTC 与 LLMCallAudit.TsUTC 对齐。
	TsUTC string
	// LLMInSHA256 / LLMOutSHA256 — 请求体 / 响应体 hex sha256。
	LLMInSHA256  string
	LLMOutSHA256 string
	// LLMModel — 实际调用的模型标识（已落 env 的 model 值）。
	LLMModel string
	// LatencyMs — 本次 LLM 调用总耗时（毫秒）。
	LatencyMs int64
	// HTTPStatus — 出站响应状态码（0 表示未拿到响应）。
	HTTPStatus int
	// ErrorKind — http_5xx / http_4xx / network / timeout / schema_violation。
	ErrorKind string
}

// ToFallbackMetadata — 把 LLMCallAudit 转换为跨包可传递的 FallbackMetadata。
//
// 仅暴露 LLMCallAudit 的可观测子集；NeedHumanReview / FallbackUsed 等由
// caller 在 output.AppendFallbackAudit 内自己判定（本方法不强制
// FallbackUsed=true，避免漏调一次失败写法的告警）。
func (a LLMCallAudit) ToFallbackMetadata() FallbackMetadata {
	return FallbackMetadata{
		TsUTC:        a.TsUTC,
		LLMInSHA256:  a.LLMInSHA256,
		LLMOutSHA256: a.LLMOutSHA256,
		LLMModel:     a.LLMModel,
		LatencyMs:    a.LatencyMs,
		HTTPStatus:   a.HTTPStatus,
		ErrorKind:    a.ErrorKind,
	}
}

// FallbackDriftContext — 落 kind=llm_fallback 审计行时所需的漂移事件上下文。
//
// 由 caller 在 ModelGateway.Call 返回 ErrLLMUnavailable 或 ErrSchemaViolation
// 时构造；本字段全部参与审计行的可核对回溯（不含业务数据原文，避免敏感
// 字段泄漏到告警上下文）。
type FallbackDriftContext struct {
	// EventID — 当前 drift 事件 ID；可与 trial_state 中 trial 行的 EventID 对齐。
	EventID string
	// ContractID — 当前 contract；用于追到具体合同条目。
	ContractID string
	// SystemID — 被探活的库 system_id（如 his-core / emr）。
	SystemID string
	// Vendor — 申报品牌（kingbase / dm8 / ...）。
	Vendor string
	// Declared — 合同期望描述（不携带原始 SQL，仅品牌 + 版本概要）。
	Declared string
	// Actual — 实测触发的版本串摘要（不携带完整 banner，可写 brand 标识）。
	Actual string
	// EvidenceSHA256 — 三维签名；用于把 llm_fallback 行与 trial 行对齐。
	EvidenceSHA256 string
	// RuleVerdict — 规则 verdict；fallback 不采用 LLM verdict，verdict
	// 字段写真实的规则 verdict。
	RuleVerdict string
}
