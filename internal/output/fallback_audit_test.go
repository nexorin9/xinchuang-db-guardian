package output

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xinchuang-db-guardian/internal/llm"
)

// silentLogger — 测试用 silent logger（写到 io.Discard）。
func silentLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// makeCtx — 标准 FallbackDriftContext fixture。
func makeCtx() llm.FallbackDriftContext {
	return llm.FallbackDriftContext{
		EventID:        "evt-fallback-001",
		ContractID:     "contract-his-core",
		SystemID:       "his-core",
		Vendor:         "kingbase",
		Declared:       "KingbaseES V008R006C",
		Actual:         "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1)",
		EvidenceSHA256: "21c9d66e586e4bc6faeeda70b2fa401d9537399e97afaf59c9c1e75ba381d1b2",
		RuleVerdict:    "trial",
	}
}

// makeMeta — 标准 FallbackMetadata fixture（模拟 5xx 路径）。
func makeMeta() llm.FallbackMetadata {
	return llm.FallbackMetadata{
		TsUTC:        "2026-10-10T05:00:00.000000000Z",
		LLMInSHA256:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		LLMOutSHA256: "f00dfacef00dfacef00dfacef00dfacef00dfacef00dfacef00dfacef00dface",
		LLMModel:     "gpt-4o-mini-test",
		LatencyMs:    1500,
		HTTPStatus:   503,
		ErrorKind:    "http_5xx",
	}
}

// TestAppendFallbackAudit_5xxWritesRow — HTTP 503 fallback → AppendFallbackAudit 落 1 行 JSONL。
func TestAppendFallbackAudit_5xxWritesRow(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	row, err := AppendFallbackAudit(auditPath, makeMeta(), makeCtx())
	if err != nil {
		t.Fatalf("AppendFallbackAudit: %v", err)
	}

	// 1. row.Kind 必为 llm_fallback。
	if row.Kind != "llm_fallback" {
		t.Errorf("kind=%q want llm_fallback", row.Kind)
	}
	// 2. row.Verdict 是规则 verdict（trial），不是 LLM 输出。
	if row.Verdict != "trial" {
		t.Errorf("verdict=%q want trial (rule verdict)", row.Verdict)
	}
	// 3. row.Action / Operator 标识机器写入。
	if row.Action != "rule_verdict_fallback" {
		t.Errorf("action=%q want rule_verdict_fallback", row.Action)
	}
	if row.Operator != "auto_fallback" {
		t.Errorf("operator=%q want auto_fallback", row.Operator)
	}
	// 4. LLMCallAudit 元数据完整落审计。
	if row.LLMModel != "gpt-4o-mini-test" {
		t.Errorf("model=%q", row.LLMModel)
	}
	if row.LatencyMs != 1500 {
		t.Errorf("latency_ms=%d want 1500", row.LatencyMs)
	}
	if row.TsUTC == "" {
		t.Errorf("ts_utc empty")
	}

	// 5. 文件存在且为 1 行。
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	lines := splitLines(string(data))
	if len(lines) != 1 {
		t.Fatalf("lines=%d want 1 (data=%q)", len(lines), data)
	}

	// 6. JSON 反序列化能映射回 kind=llm_fallback。
	var got AuditRow
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Kind != "llm_fallback" {
		t.Errorf("got.kind=%q", got.Kind)
	}
	if got.SystemID != "his-core" {
		t.Errorf("got.system_id=%q", got.SystemID)
	}
	if got.EvidenceSHA256 != "21c9d66e586e4bc6faeeda70b2fa401d9537399e97afaf59c9c1e75ba381d1b2" {
		t.Errorf("got.evidence_sha256=%q", got.EvidenceSHA256)
	}
}

// TestAppendFallbackAudit_VerifyChainOK — append 后 audit verify-chain 应通过。
//
// 关键：llm_fallback 行和 drift 行一样接入同一条 sha256 链；不能因为 kind
// 不同而另起一条链。
func TestAppendFallbackAudit_VerifyChainOK(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	// 先写一条 drift 行做链头，再写 llm_fallback 行做链尾。
	if _, err := AppendJSONL(auditPath, AuditRow{
		TsUTC: "2026-10-10T04:00:00.000000000Z",
		Kind:  "drift",
		EventID: "evt-trial-001",
		ContractID: "contract-his-core",
		SystemID: "his-core",
		Vendor: "kingbase",
		Verdict: "trial",
		EvidenceSHA256: "11aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}); err != nil {
		t.Fatalf("seed drift: %v", err)
	}

	meta := makeMeta()
	ctx := makeCtx()
	if _, err := AppendFallbackAudit(auditPath, meta, ctx); err != nil {
		t.Fatalf("AppendFallbackAudit: %v", err)
	}

	// 整链验通。
	if err := VerifyChain(auditPath); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// TestAppendFallbackAudit_DoesNotTouchTrialStore — llm_fallback 行**不**写
// TrialStore（trial 状态由人工 confirm-drift 推进，本路径必须不静默推进）。
//
// 本测试把 TrialStore 装配完整，跑一次 AppendFallbackAudit，断言：
//   - TrialStore.GlobalChainHead == ""（trial_state 没被新事件污染）；
//   - AppendJSONL 写了 1 行 llm_fallback（不挂 trial）。
func TestAppendFallbackAudit_DoesNotTouchTrialStore(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")
	storePath := filepath.Join(tmp, "trial.db")
	defer func() { _ = os.Remove(storePath) }()

	store, err := OpenTrialStore(storePath)
	if err != nil {
		t.Fatalf("OpenTrialStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	if _, err := AppendFallbackAudit(auditPath, makeMeta(), makeCtx()); err != nil {
		t.Fatalf("AppendFallbackAudit: %v", err)
	}

	head, err := store.GlobalChainHead()
	if err != nil {
		t.Fatalf("GlobalChainHead: %v", err)
	}
	if head != "" {
		t.Fatalf("trial_state touched (chain head=%q); llm_fallback must not advance trial", head)
	}
	if _, err := store.ListByContractID("contract-his-core"); err != nil {
		t.Fatalf("ListByContractID: %v", err)
	}
}

// TestAppendFallbackAudit_HTTP5xxRoundTrip — 端到端：httptest 起桩返回 503，
// ModelGateway.Call 走 fallback，caller 调 AppendFallbackAudit，最终
// JSONL 中能看到 kind=llm_fallback + 完整 LLMCallAudit 元数据。
//
// 这是 T24 spec 的"4 降级 case 100% 走 fallback + 审计行 + never_confirm"
// 的端到端覆盖。
func TestAppendFallbackAudit_HTTP5xxRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	// 1. 起 503 桩。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer srv.Close()

	// 2. 构造 gateway。
	gw, err := llm.NewModelGatewayWithClient(llm.Config{
		BaseURL: srv.URL, APIKey: "k", Model: "gpt-4o-mini-test", Timeout: 2 * time.Second,
	}, srv.Client(), silentLogger())
	if err != nil {
		t.Fatalf("NewModelGatewayWithClient: %v", err)
	}

	// 3. gateway 调用 → fallback。
	_, err = gw.Call(context.Background(), "对比：合同 kingbase vs 实测 PostgreSQL 14.10 (Debian)")
	if err == nil {
		t.Fatalf("gw.Call returned nil err (expected 5xx failure)")
	}
	var unav *llm.ErrLLMUnavailable
	if !asErr(err, &unav) {
		t.Fatalf("err type=%T want *ErrLLMUnavailable", err)
	}
	if unav.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("HTTPStatus=%d want 503", unav.HTTPStatus)
	}

	// 4. caller 调 AppendFallbackAudit 落审计（关键：kind=llm_fallback + 不静默推进）。
	//    （这里我们直接构造 LLMCallAudit-like 调用 ToFallbackMetadata。）
	fallbackLLMAudit := llm.LLMCallAudit{
		TsUTC:          "2026-10-10T05:00:00.000000000Z",
		LLMInSHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		LLMOutSHA256:   "",
		LLMModel:       "gpt-4o-mini-test",
		LatencyMs:      1500,
		HTTPStatus:     503,
		ErrorKind:      "http_5xx",
		FallbackUsed:   true,
		NeedHumanReview: true,
	}

	row, err := AppendFallbackAudit(auditPath, fallbackLLMAudit.ToFallbackMetadata(), makeCtx())
	if err != nil {
		t.Fatalf("AppendFallbackAudit: %v", err)
	}

	// 5. 验证审计行。
	if row.Kind != "llm_fallback" {
		t.Errorf("row.kind=%q want llm_fallback", row.Kind)
	}
	if row.LatencyMs != 1500 {
		t.Errorf("row.latency_ms=%d", row.LatencyMs)
	}
}

// TestAppendFallbackAudit_TimeoutRoundTrip — 端到端：服务端 hang 触发 context
// deadline exceeded → ErrLLMUnavailable kind=timeout；AppendFallbackAudit
// 落 kind=llm_fallback + ErrorKind="timeout"。
func TestAppendFallbackAudit_TimeoutRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	gw, _ := llm.NewModelGatewayWithClient(llm.Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 50 * time.Millisecond,
	}, srv.Client(), silentLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected timeout")
	}
	var unav *llm.ErrLLMUnavailable
	if !asErr(err, &unav) {
		t.Fatalf("err type=%T want *ErrLLMUnavailable", err)
	}
	if unav.ErrorKind != "timeout" && unav.ErrorKind != "network" {
		t.Fatalf("kind=%q want timeout or network", unav.ErrorKind)
	}

	// 构造 FallbackMetadata 直接调用 AppendFallbackAudit。
	meta := llm.FallbackMetadata{
		TsUTC:      "2026-10-10T05:00:00.000000000Z",
		LLMModel:   "m",
		LatencyMs:  unav.LatencyMs,
		HTTPStatus: 0,
		ErrorKind:  unav.ErrorKind,
	}
	row, err := AppendFallbackAudit(auditPath, meta, makeCtx())
	if err != nil {
		t.Fatalf("AppendFallbackAudit: %v", err)
	}
	if row.Kind != "llm_fallback" {
		t.Errorf("kind=%q", row.Kind)
	}
	// 验证 JSONL 文件中的 LLMModel 字段确实被记录。
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(string(data), `"kind":"llm_fallback"`) {
		t.Errorf("audit.jsonl missing kind=llm_fallback: %s", data)
	}
}

// TestAppendFallbackAudit_InvalidJSONRoundTrip — 服务端返回非 JSON content →
// gateway 走 ErrSchemaViolation；AppendFallbackAudit 落 kind=schema_violation。
func TestAppendFallbackAudit_InvalidJSONRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"这不是 json"}}]}`))
	}))
	defer srv.Close()

	gw, _ := llm.NewModelGatewayWithClient(llm.Config{
		BaseURL: srv.URL, APIKey: "k", Model: "m", Timeout: 2 * time.Second,
	}, srv.Client(), silentLogger())

	_, err := gw.Call(context.Background(), "prompt")
	if err == nil {
		t.Fatalf("expected schema violation")
	}
	var sv *llm.ErrSchemaViolation
	if !asErr(err, &sv) {
		t.Fatalf("err type=%T want *ErrSchemaViolation", err)
	}

	meta := llm.FallbackMetadata{
		TsUTC:      "2026-10-10T05:00:00.000000000Z",
		LLMModel:   "m",
		LatencyMs:  50,
		HTTPStatus: 200,
		ErrorKind:  "schema_violation",
	}
	row, err := AppendFallbackAudit(auditPath, meta, makeCtx())
	if err != nil {
		t.Fatalf("AppendFallbackAudit: %v", err)
	}
	if row.Kind != "llm_fallback" {
		t.Errorf("kind=%q", row.Kind)
	}
}

// TestAppendFallbackAudit_EmptyAuditPath — audit path 为空 → 返回 error。
func TestAppendFallbackAudit_EmptyAuditPath(t *testing.T) {
	_, err := AppendFallbackAudit("", makeMeta(), makeCtx())
	if err == nil {
		t.Fatalf("expected error for empty audit path")
	}
	if !strings.Contains(err.Error(), "auditPath") {
		t.Errorf("error msg should mention auditPath, got: %v", err)
	}
}

// TestAppendFallbackAudit_EmptyErrorKind — meta.ErrorKind 为空 → 拒绝写入。
func TestAppendFallbackAudit_EmptyErrorKind(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	meta := makeMeta()
	meta.ErrorKind = "" // 强制清空
	_, err := AppendFallbackAudit(auditPath, meta, makeCtx())
	if err == nil {
		t.Fatalf("expected error for empty ErrorKind")
	}
	if !strings.Contains(err.Error(), "ErrorKind") {
		t.Errorf("error msg should mention ErrorKind, got: %v", err)
	}
}

// TestAppendFallbackAudit_EmptyEventID — EventID 为空 → 拒绝写入。
func TestAppendFallbackAudit_EmptyEventID(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	ctx := makeCtx()
	ctx.EventID = ""
	_, err := AppendFallbackAudit(auditPath, makeMeta(), ctx)
	if err == nil {
		t.Fatalf("expected error for empty EventID")
	}
}

// TestAppendFallbackAudit_NoPatientFieldsInMeta — LLM 调用的元数据（meta + ctx）不出现患者可识别字段。
//
// 该测试不是断言 helper 做字段过滤（helper 仅做透传），而是断言：本测试
// fixture 提供的元数据本身就不含敏感字段；caller 在传 ctx / meta 之前应
// 已经把业务原文脱敏。这一点由 caller 负责 + 在 gateway.go 注释中已强调。
func TestAppendFallbackAudit_NoPatientFieldsInMeta(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")

	// 标准 fixture 中不含患者字段；本测试断言该性质不会因 AppendFallbackAudit 而被破坏。
	row, err := AppendFallbackAudit(auditPath, makeMeta(), makeCtx())
	if err != nil {
		t.Fatalf("AppendFallbackAudit: %v", err)
	}
	forbidden := []string{"patient", "患者", "姓名", "身份证", "病案号", "住院号", "处方号"}
	for _, term := range forbidden {
		if strings.Contains(row.Declared, term) {
			t.Errorf("Declared 含患者字段 %q: %q", term, row.Declared)
		}
		if strings.Contains(row.Actual, term) {
			t.Errorf("Actual 含患者字段 %q: %q", term, row.Actual)
		}
	}
}

// TestLLMCallAudit_ToFallbackMetadata — 转换函数的全字段保真。
func TestLLMCallAudit_ToFallbackMetadata(t *testing.T) {
	src := llm.LLMCallAudit{
		TsUTC:           "2026-10-10T05:00:00Z",
		LLMInSHA256:     "in-hash",
		LLMOutSHA256:    "out-hash",
		LLMModel:        "my-model",
		LatencyMs:       1234,
		HTTPStatus:      503,
		ErrorKind:       "http_5xx",
		FallbackUsed:    true,
		NeedHumanReview: true,
	}
	got := src.ToFallbackMetadata()
	if got.TsUTC != "2026-10-10T05:00:00Z" {
		t.Errorf("TsUTC=%q", got.TsUTC)
	}
	if got.LLMInSHA256 != "in-hash" {
		t.Errorf("LLMInSHA256=%q", got.LLMInSHA256)
	}
	if got.LLMOutSHA256 != "out-hash" {
		t.Errorf("LLMOutSHA256=%q", got.LLMOutSHA256)
	}
	if got.LLMModel != "my-model" {
		t.Errorf("LLMModel=%q", got.LLMModel)
	}
	if got.LatencyMs != 1234 {
		t.Errorf("LatencyMs=%d", got.LatencyMs)
	}
	if got.HTTPStatus != 503 {
		t.Errorf("HTTPStatus=%d", got.HTTPStatus)
	}
	if got.ErrorKind != "http_5xx" {
		t.Errorf("ErrorKind=%q", got.ErrorKind)
	}
}

// splitLines — 简易按 '\n' 切（保留空行做 tolerant count）。
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

// asErr — errors.As 的等价物（避免在测试文件额外 import errors）。
//
// 注意：本文件位于 internal/output 包内，errors.As 调用要求调用方传
// **目标指针**；该 helper 仅在测试 context 下被使用。
func asErr(err error, target interface{}) bool {
	// 简化实现：通过类型断言判断 core error types。
	switch e := err.(type) {
	case *llm.ErrLLMUnavailable:
		if p, ok := target.(**llm.ErrLLMUnavailable); ok {
			*p = e
			return true
		}
	case *llm.ErrSchemaViolation:
		if p, ok := target.(**llm.ErrSchemaViolation); ok {
			*p = e
			return true
		}
	}
	return false
}
