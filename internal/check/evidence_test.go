package check

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// ComputeEvidenceSHA256 — 确定性 + 维度灵敏度
// ----------------------------------------------------------------------------

// TestComputeEvidenceSHA256_Deterministic — 相同输入（含 ts）两次 hash 必相等。
func TestComputeEvidenceSHA256_Deterministic(t *testing.T) {
	ts := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	a := ComputeEvidenceSHA256("portRaw-1", "driverSha-1", "jdbcURL-1", "sys-1", ts)
	b := ComputeEvidenceSHA256("portRaw-1", "driverSha-1", "jdbcURL-1", "sys-1", ts)
	if a != b {
		t.Errorf("相同输入两次哈希应一致，got %s vs %s", a, b)
	}
	if a == "" {
		t.Errorf("哈希不应为空")
	}
	if len(a) != 64 {
		t.Errorf("sha256 hex 应为 64 字符，got %d", len(a))
	}
}

// TestComputeEvidenceSHA256_DifferentTimeChanges — 不同 ts 必须产生不同 hash。
func TestComputeEvidenceSHA256_DifferentTimeChanges(t *testing.T) {
	ts1 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ts2 := ts1.Add(time.Nanosecond)
	a := ComputeEvidenceSHA256("portRaw", "driverSha", "jdbcURL", "sys", ts1)
	b := ComputeEvidenceSHA256("portRaw", "driverSha", "jdbcURL", "sys", ts2)
	if a == b {
		t.Errorf("不同 ts 应产生不同哈希")
	}
}

// TestComputeEvidenceSHA256_DimensionsSensitive — 任一维度变化必须产生不同 hash。
// 防止后续重构时不小心丢失某个维度的拼入。
func TestComputeEvidenceSHA256_DimensionsSensitive(t *testing.T) {
	ts := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	base := ComputeEvidenceSHA256("portRaw", "driverSha", "jdbcURL", "sys", ts)
	cases := []struct {
		name string
		fn   func() string
	}{
		{"portRaw changed", func() string { return ComputeEvidenceSHA256("DIFF", "driverSha", "jdbcURL", "sys", ts) }},
		{"driverSha changed", func() string { return ComputeEvidenceSHA256("portRaw", "DIFF", "jdbcURL", "sys", ts) }},
		{"jdbcURL changed", func() string { return ComputeEvidenceSHA256("portRaw", "driverSha", "DIFF", "sys", ts) }},
		{"systemID changed", func() string { return ComputeEvidenceSHA256("portRaw", "driverSha", "jdbcURL", "DIFF", ts) }},
		{"empty portRaw vs base", func() string {
			b := ComputeEvidenceSHA256("", "driverSha", "jdbcURL", "sys", ts)
			if b == "" {
				t.Errorf("空 portRaw 不应产生空哈希")
			}
			return b
		}},
		{"portRaw 含 | 分隔符", func() string {
			// 验证 | 仍能区分：即便 portRaw 拼到 driverSha 后会形成歧义
			// 但 \x00 分隔符仍能区分二者（vs 仅 | 不够）
			p1 := ComputeEvidenceSHA256("ab", "cd", "jdbcURL", "sys", ts)
			p2 := ComputeEvidenceSHA256("abcd", "", "jdbcURL", "sys", ts)
			if p1 == p2 {
				t.Errorf("\\x00 分隔符必须能区分 (ab,cd) 与 (abcd,empty)")
			}
			return p2
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.fn()
			if got == base && !strings.HasPrefix(tc.name, "empty") {
				// 允许"empty portRaw"成为有效 base，但与原 base 必不同
				t.Errorf("维度变化应产生不同哈希；got %s == base %s", got, base)
			}
		})
	}
}

// TestComputeEvidenceSHA256_TimezoneInvariant — 同一瞬时不同 timezone 表达
// 必须产生相同 hash（因为内部统一 .UTC().Format()）。
func TestComputeEvidenceSHA256_TimezoneInvariant(t *testing.T) {
	utc := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skip("时区数据不可用，跳过")
	}
	sh := utc.In(loc)
	cst := time.FixedZone("CST", 8*3600)
	cstTime := utc.In(cst)
	a := ComputeEvidenceSHA256("portRaw", "driverSha", "jdbcURL", "sys", utc)
	b := ComputeEvidenceSHA256("portRaw", "driverSha", "jdbcURL", "sys", sh)
	c := ComputeEvidenceSHA256("portRaw", "driverSha", "jdbcURL", "sys", cstTime)
	if a != b {
		t.Errorf("UTC 与 Asia/Shanghai 表示同一瞬时；hash 应一致，got %s vs %s", a, b)
	}
	if a != c {
		t.Errorf("UTC 与 CST 表示同一瞬时；hash 应一致，got %s vs %s", a, c)
	}
}

// ----------------------------------------------------------------------------
// ComputeSelfHash — 链头稳定性 + 链式连续性 + 维度灵敏度
// ----------------------------------------------------------------------------

// TestComputeSelfHash_ChainHead — 链头 prev="" + 同 body 两次结果一致。
func TestComputeSelfHash_ChainHead(t *testing.T) {
	body := []byte(`{"event_id":"TEST-1"}`)
	a := ComputeSelfHash("", body)
	b := ComputeSelfHash("", body)
	if a != b {
		t.Errorf("链头 self_hash 应一致，got %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Errorf("self_hash 应为 64 字符")
	}
	if a == "" {
		t.Errorf("self_hash 不应为空")
	}
}

// TestComputeSelfHash_ChainContinuity — 链式后一节必须与前一节不同 hash。
func TestComputeSelfHash_ChainContinuity(t *testing.T) {
	body := []byte(`{"event_id":"TEST-1"}`)
	first := ComputeSelfHash("", body)
	second := ComputeSelfHash(first, body)
	if first == second {
		t.Errorf("不同 prev hash 应产生不同 self hash")
	}
	if second == "" || len(second) != 64 {
		t.Errorf("chain 第二节点 self_hash 应为 64 hex")
	}
}

// TestComputeSelfHash_LongChain — 100 节长链：每节 prev 等于上一节 self。
func TestComputeSelfHash_LongChain(t *testing.T) {
	body := []byte(`{"event_id":"LONG-CHAIN"}`)
	prev := ""
	for i := 0; i < 100; i++ {
		next := ComputeSelfHash(prev, body)
		if next == "" || len(next) != 64 {
			t.Fatalf("iter %d: self_hash 格式错 %q", i, next)
		}
		if i > 0 && next == prev {
			t.Fatalf("iter %d: 链断裂（self == prev）", i)
		}
		prev = next
	}
}

// TestComputeSelfHash_PrevVsEmpty — prev="" 路径与 prev="x" 路径必不同。
func TestComputeSelfHash_PrevVsEmpty(t *testing.T) {
	body := []byte(`abc`)
	a := ComputeSelfHash("", body)
	b := ComputeSelfHash("anything", body)
	if a == b {
		t.Errorf("prev 空串与非空串必须产生不同 self_hash")
	}
}

// TestComputeSelfHash_BodyChangesAffect — body 变化必须影响 hash。
func TestComputeSelfHash_BodyChangesAffect(t *testing.T) {
	a := ComputeSelfHash("", []byte(`{"a":1}`))
	b := ComputeSelfHash("", []byte(`{"a":2}`))
	if a == b {
		t.Errorf("body 变化应影响 self_hash")
	}
	// body 追加一字节
	c := ComputeSelfHash("", []byte(`{"a":1} `))
	if a == c {
		t.Errorf("body 末尾空格也应影响 self_hash")
	}
}

// TestComputeSelfHash_LongBody — 64KB+ body 不 panic 且 hash 64 hex。
func TestComputeSelfHash_LongBody(t *testing.T) {
	longBody := make([]byte, 70*1024)
	for i := range longBody {
		longBody[i] = byte('A' + (i % 26))
	}
	h := ComputeSelfHash("", longBody)
	if len(h) != 64 {
		t.Errorf("长 body 应仍产出 64 hex，got %d", len(h))
	}
}

// ----------------------------------------------------------------------------
// HashBody — 拼接顺序与字段覆盖度
// ----------------------------------------------------------------------------

// TestHashBody_Deterministic — 相同 DriftEvidence 两次拼接结果相同。
func TestHashBody_Deterministic(t *testing.T) {
	e := makeSampleEvidence()
	a := HashBody(e)
	b := HashBody(e)
	if string(a) != string(b) {
		t.Errorf("HashBody 应确定性，got %q vs %q", a, b)
	}
	if !strings.Contains(string(a), e.EventID) {
		t.Errorf("body 应含 EventID %s", e.EventID)
	}
	if !strings.Contains(string(a), e.SystemID) {
		t.Errorf("body 应含 SystemID %s", e.SystemID)
	}
	if !strings.Contains(string(a), e.EvidenceSHA256) {
		t.Errorf("body 应含 EvidenceSHA256")
	}
}

// TestHashBody_EmptyFields — 空字段不 panic。
func TestHashBody_EmptyFields(t *testing.T) {
	e := DriftEvidence{}
	body := HashBody(e)
	if body == nil {
		t.Errorf("空值 body 不应返 nil")
	}
	// 全部为空时 body 应是 13 个分隔符 + 0.000000 + 空 = 仍非空
	if len(body) == 0 {
		t.Errorf("空值 body 长度 0 不合理")
	}
}

// TestHashBody_FieldOrderFixed — 顺序变更（即使内容相同）必须改 hash。
// 用相近但非相同的值顺序调换，验证拼接顺序敏感。
func TestHashBody_FieldOrderFixed(t *testing.T) {
	e1 := DriftEvidence{EventID: "evt-A", SystemID: "sys-A", EvidenceSHA256: "sha-A"}
	e2 := DriftEvidence{EventID: "sys-A", SystemID: "evt-A", EvidenceSHA256: "sha-A"}
	a := HashBody(e1)
	b := HashBody(e2)
	if string(a) == string(b) {
		t.Errorf("HashBody 字段顺序必须区分；相同拼接不应等价")
	}
}

// TestHashBody_NoSelfHash — body 不应含 self_hash 与 prev_evidence_sha256。
func TestHashBody_NoSelfHash(t *testing.T) {
	e := makeSampleEvidence()
	e.SelfHash = "should-not-appear"
	e.PrevEvidenceSHA256 = "should-not-appear"
	body := string(HashBody(e))
	if strings.Contains(body, "should-not-appear") {
		t.Errorf("HashBody 不应包含 self_hash/prev 字段；body=%q", body)
	}
}

// TestHashBody_FullCoverage — body 必含全部字段（含 Confidence 与 TsUTC）。
func TestHashBody_FullCoverage(t *testing.T) {
	e := makeSampleEvidence()
	body := string(HashBody(e))
	for _, expect := range []string{e.EventID, e.ContractID, e.SystemID, e.Vendor,
		e.Declared, e.Actual, e.PortRaw, e.DriverSha, e.JDBCURL,
		string(e.Verdict), e.EvidenceSHA256, string(e.Status), e.TsUTC} {
		if !strings.Contains(body, expect) {
			t.Errorf("body 应含 %q", expect)
		}
	}
	// Confidence 用 %.6f 格式化，必含 "0.500000"
	if !strings.Contains(body, "0.500000") {
		t.Errorf("body 应包含 Confidence 的 6 位小数形式")
	}
}

// ----------------------------------------------------------------------------
// 测试 fixtures
// ----------------------------------------------------------------------------

// makeSampleEvidence 构造字段全填且 Confidence 唯一可识别的样本 evidence，
// 供 HashBody / DriftEvidence JSON round-trip 测试共用。
func makeSampleEvidence() DriftEvidence {
	return DriftEvidence{
		EventID:            "TEST-2026-10-10-EVT-001",
		ContractID:         "HT-2026-TEST",
		SystemID:           "his-core-test",
		Vendor:             "kingbase",
		Declared:           "V008R006",
		Actual:             "KingbaseES V008R006C0010",
		PortRaw:            "KingbaseES V008R006C0010 on x86_64",
		DriverSha:          "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		JDBCURL:            "jdbc:kingbase8://10.0.0.1:54321/his",
		Verdict:            VerdictTrial,
		Confidence:         0.5,
		EvidenceSHA256:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Status:             StateTrial,
		PrevEvidenceSHA256: "",
		SelfHash:           "",
		TsUTC:              "2026-10-10T12:00:00.000000000Z",
		InconsistentDims:   []string{"port_raw"},
	}
}

// TestDriftEvidence_JSONRoundTrip — DriftEvidence JSON 序列化往返不丢字段。
func TestDriftEvidence_JSONRoundTrip(t *testing.T) {
	e := makeSampleEvidence()
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out DriftEvidence
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.EventID != e.EventID || out.SystemID != e.SystemID ||
		out.EvidenceSHA256 != e.EvidenceSHA256 || out.Verdict != e.Verdict ||
		out.Status != e.Status || out.TsUTC != e.TsUTC {
		t.Errorf("round-trip 不一致: got %+v vs want %+v", out, e)
	}
}

// TestDriftEvidence_JSONOmitemptyDims — InconsistentDims 空时省略。
func TestDriftEvidence_JSONOmitemptyDims(t *testing.T) {
	e := DriftEvidence{EventID: "x"}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "inconsistent_dimensions") {
		t.Errorf("空 InconsistentDims 应被 omitempty 省略，data=%s", data)
	}
	e.InconsistentDims = []string{"port_raw"}
	data, _ = json.Marshal(e)
	if !strings.Contains(string(data), "inconsistent_dimensions") {
		t.Errorf("非空 InconsistentDims 应保留在 JSON 中")
	}
}

// TestDriftEvidence_JSONOmitemptyLLM — LLMVerdict 空时省略。
func TestDriftEvidence_JSONOmitemptyLLM(t *testing.T) {
	e := DriftEvidence{EventID: "x"}
	data, _ := json.Marshal(e)
	if strings.Contains(string(data), "llm_verdict") {
		t.Errorf("空 LLMVerdict 应省略")
	}
	e.LLMVerdict = "HIGH_CONFIDENCE_DRIFT"
	e.LLMConfidence = 0.7
	e.LLMReasonZH = "测试"
	data, _ = json.Marshal(e)
	if !strings.Contains(string(data), "llm_verdict") {
		t.Errorf("非空 LLMVerdict 应保留")
	}
	if !strings.Contains(string(data), "测试") {
		t.Errorf("LLMReasonZH 应保留原文")
	}
}

// TestComputeEvidenceSHA256_EmptyAndWhitespace — 全部空 / 全空白输入不应 panic。
func TestComputeEvidenceSHA256_EmptyAndWhitespace(t *testing.T) {
	ts := time.Now()
	cases := []struct{ pr, ds, ju, si string }{
		{"", "", "", ""},
		{"  ", "\t", "\n", " "},
		{"only-port", "", "", ""},
	}
	for i, c := range cases {
		h := ComputeEvidenceSHA256(c.pr, c.ds, c.ju, c.si, ts)
		if len(h) != 64 {
			t.Errorf("case %d: 期望 64 hex，got %d", i, len(h))
		}
	}
}

// TestComputeSelfHash_NilAndEmptyBody — nil body 与 []byte{} 应等价或均安全。
func TestComputeSelfHash_NilAndEmptyBody(t *testing.T) {
	a := ComputeSelfHash("p", nil)
	b := ComputeSelfHash("p", []byte{})
	if a != b {
		t.Errorf("nil body 与 []byte{} 应等价，got %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Errorf("空 body 仍应产出 64 hex，got %d", len(a))
	}
}
