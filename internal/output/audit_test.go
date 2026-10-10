// Package output_test — append-only JSONL 审计 + sha256 链 + VerifyChain 的单元测试。
//
// 覆盖：
//   - 连续追加 3 行 + 链路验通（合法链 → nil error）；
//   - 篡改 line 2 字段内容 → VerifyChain 报 self_hash_mismatch:2；
//   - 删除 line 2 → VerifyChain 报 chain_break:3（line 3 的 prev 与 line 2 的 self 不接）；
//   - 在 line 2 后插入新伪造行 → VerifyChain 报 chain_break:3；
//   - 首行 prev 非空 → bad_line:1；
//   - 行 JSON 损坏 → bad_line:N；
//   - 文件不存在 → nil error（视作合法空链）；
//   - 并发 10 goroutine 追加 → 链长 10 且 VerifyChain 通过；
//   - LoadChain 读全量 + SortedByTsUTC 顺序；
//   - ComputeSelfHash 链头/续链确定性；
//   - BadLineError 错误信息含 line / reason / expected / got。
package output_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xinchuang-db-guardian/internal/output"
)

// sampleAuditRow — 测试用 AuditRow 工厂；保证 ts_utc 单调递增（按调用顺序），
// 避免 SortedByTsUTC 排序时打破插入顺序。
//
// 注意：seq=0 时 Nanosecond=1000（保证 RFC3339Nano 总是输出 6 位小数部分），
// 否则 seq=0 会输出无小数部分的 "Z" 终止符，与 seq≥1 的 ".NNNNNNZ" 形成
// 字典序冲突；SortedByTsUTC 是按字符串字典序排序（RFC3339Nano 在小数位
// 宽度一致时字典序 == 时间序）。
func sampleAuditRow(seq int, systemID, vendor, evidenceSHA string) output.AuditRow {
	ts := time.Date(2026, 10, 10, 5, 0, 0, (seq+1)*1000, time.UTC).Format(time.RFC3339Nano)
	return output.AuditRow{
		TsUTC:              ts,
		EventID:            "evt-" + systemID + "-" + vendor + "-" + time.Now().Format("150405.000000000"),
		ContractID:         "c-" + systemID,
		SystemID:           systemID,
		Vendor:             vendor,
		Declared:           "v8.1",
		Actual:             "DM Database Server V8.1.0",
		PortRaw:            "DM Database Server V8.1.0",
		DriverSha:          "deadbeef" + string(rune('0'+seq)),
		JDBCURL:            "jdbc:dm://10.0.0.1:5236/DB",
		Verdict:            "trial",
		Confidence:         0.95,
		EvidenceSHA256:     evidenceSHA,
		Kind:               "drift",
		LLMInSHA256:        "llm-in-" + evidenceSHA,
		LLMOutSHA256:       "llm-out-" + evidenceSHA,
		LLMModel:           "stub-model",
		LatencyMs:          42,
		Action:             "auto",
		Operator:           "guardian",
	}
}

// appendRow — 单行追加；测试入口封装。
func appendRow(t *testing.T, path string, row output.AuditRow) {
	t.Helper()
	n, err := output.AppendJSONL(path, row)
	if err != nil {
		t.Fatalf("AppendJSONL failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("AppendJSONL n=%d, want 1", n)
	}
}

// TestAppendJSONL_3RowsChainOK — 3 行连续追加，链路完整，VerifyChain 通过。
func TestAppendJSONL_3RowsChainOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	r1 := sampleAuditRow(0, "his-core", "dm8", "sha-aaaa")
	r2 := sampleAuditRow(1, "his-core", "dm8", "sha-bbbb")
	r3 := sampleAuditRow(2, "lis-pacs", "kingbase", "sha-cccc")

	appendRow(t, path, r1)
	appendRow(t, path, r2)
	appendRow(t, path, r3)

	if err := output.VerifyChain(path); err != nil {
		t.Fatalf("VerifyChain failed on legal 3-row chain: %v", err)
	}

	rows, err := output.LoadChain(path)
	if err != nil {
		t.Fatalf("LoadChain failed: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("LoadChain len=%d, want 3", len(rows))
	}
	// 链头：prev = ""; 非首行 prev = 上一行 self_hash。
	if rows[0].PrevEvidenceSHA256 != "" {
		t.Errorf("row[0].PrevEvidenceSHA256=%q, want \"\"", rows[0].PrevEvidenceSHA256)
	}
	if rows[1].PrevEvidenceSHA256 != rows[0].SelfHash {
		t.Errorf("row[1].PrevEvidenceSHA256=%q, want row[0].SelfHash=%q", rows[1].PrevEvidenceSHA256, rows[0].SelfHash)
	}
	if rows[2].PrevEvidenceSHA256 != rows[1].SelfHash {
		t.Errorf("row[2].PrevEvidenceSHA256=%q, want row[1].SelfHash=%q", rows[2].PrevEvidenceSHA256, rows[1].SelfHash)
	}
	// 三行 self_hash 必须唯一。
	if rows[0].SelfHash == rows[1].SelfHash || rows[1].SelfHash == rows[2].SelfHash {
		t.Errorf("self_hash collision: %s / %s / %s", rows[0].SelfHash, rows[1].SelfHash, rows[2].SelfHash)
	}
}

// TestVerifyChain_TamperLine2Content — 篡改 line 2 内容 → self_hash_mismatch:2。
func TestVerifyChain_TamperLine2Content(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	appendRow(t, path, sampleAuditRow(0, "his-core", "dm8", "sha-aaaa"))
	appendRow(t, path, sampleAuditRow(1, "his-core", "dm8", "sha-bbbb"))
	appendRow(t, path, sampleAuditRow(2, "lis-pacs", "kingbase", "sha-cccc"))

	// 直接篡改磁盘上的 line 2 JSON：把 actual 字段值改掉，重写回原字节位置。
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected ≥3 lines, got %d", len(lines))
	}
	// 篡改 line 2：把 verdict 改成 mismatch（重写一段同长度字节）。
	original := lines[1]
	var row2 map[string]any
	if err := json.Unmarshal([]byte(original), &row2); err != nil {
		t.Fatalf("unmarshal line 2: %v", err)
	}
	row2["verdict"] = "mismatch"
	row2["confidence"] = 0.50
	tampered, _ := json.Marshal(row2)
	lines[1] = string(tampered)
	newContent := strings.Join(lines, "\n")
	if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}

	err = output.VerifyChain(path)
	if err == nil {
		t.Fatalf("VerifyChain must fail after tampering, got nil")
	}
	var bad *output.BadLineError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadLineError, got %T: %v", err, err)
	}
	if bad.LineNo != 2 {
		t.Errorf("BadLineError.LineNo=%d, want 2", bad.LineNo)
	}
	if bad.Reason != "self_hash_mismatch" {
		t.Errorf("BadLineError.Reason=%q, want %q", bad.Reason, "self_hash_mismatch")
	}
}

// TestVerifyChain_DeleteLine2 — 删除 line 2 → chain_break:3（line 3 的 prev 与 line 2 的 self 不接）。
func TestVerifyChain_DeleteLine2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	appendRow(t, path, sampleAuditRow(0, "his-core", "dm8", "sha-aaaa"))
	appendRow(t, path, sampleAuditRow(1, "his-core", "dm8", "sha-bbbb"))
	appendRow(t, path, sampleAuditRow(2, "lis-pacs", "kingbase", "sha-cccc"))

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	// 删 line 2：保留 line 1 + line 3 + trailing newline。
	newContent := lines[0] + "\n" + lines[2] + "\n" + lines[3]
	if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}

	err = output.VerifyChain(path)
	if err == nil {
		t.Fatalf("VerifyChain must fail after deleting line 2, got nil")
	}
	var bad *output.BadLineError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadLineError, got %T: %v", err, err)
	}
	if bad.LineNo != 2 {
		// 现在 file 是 [line1, line3] 两行；line 2（旧 line 3）的 prev 与 line 1 self 不接。
		t.Errorf("BadLineError.LineNo=%d, want 2", bad.LineNo)
	}
	if bad.Reason != "chain_break" {
		t.Errorf("BadLineError.Reason=%q, want %q", bad.Reason, "chain_break")
	}
}

// TestVerifyChain_InsertLine2 — 在 line 2 后插入伪造行 → chain_break:3（新行 prev 与 line 2 self 不接）。
func TestVerifyChain_InsertLine2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	appendRow(t, path, sampleAuditRow(0, "his-core", "dm8", "sha-aaaa"))
	appendRow(t, path, sampleAuditRow(1, "his-core", "dm8", "sha-bbbb"))
	appendRow(t, path, sampleAuditRow(2, "lis-pacs", "kingbase", "sha-cccc"))

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	// 构造伪造行（prev_evidence_sha256 用真实 prev 但 self_hash 写垃圾）。
	fake := output.AuditRow{
		TsUTC:              "2026-10-10T05:00:00.005Z",
		EventID:            "evt-fake",
		ContractID:         "c-fake",
		SystemID:           "fake-sys",
		Vendor:             "fake-vendor",
		Declared:           "v9.9",
		Actual:             "fake",
		Verdict:            "trial",
		Confidence:         0.5,
		EvidenceSHA256:     "fake-sha",
		PrevEvidenceSHA256: lines[1], // 假装接到 line 2 的 self_hash
		Kind:               "drift",
		SelfHash:           "deadbeef",
	}
	fakeBytes, _ := json.Marshal(fake)
	newLines := []string{lines[0], lines[1], string(fakeBytes), lines[2], lines[3]}
	if err := os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0o644); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}

	err = output.VerifyChain(path)
	if err == nil {
		t.Fatalf("VerifyChain must fail after inserting fake line, got nil")
	}
	var bad *output.BadLineError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadLineError, got %T: %v", err, err)
	}
	if bad.LineNo != 3 {
		t.Errorf("BadLineError.LineNo=%d, want 3", bad.LineNo)
	}
}

// TestVerifyChain_FirstLinePrevNonEmpty — 首行 prev_evidence_sha256 非空 → bad_line:1。
func TestVerifyChain_FirstLinePrevNonEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	row := sampleAuditRow(0, "his-core", "dm8", "sha-aaaa")
	row.PrevEvidenceSHA256 = "i-am-not-empty"
	body, _ := json.Marshal(row)
	if err := os.WriteFile(path, []byte(string(body)+"\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	err := output.VerifyChain(path)
	if err == nil {
		t.Fatalf("VerifyChain must fail on first-line non-empty prev, got nil")
	}
	var bad *output.BadLineError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadLineError, got %T", err)
	}
	if bad.LineNo != 1 {
		t.Errorf("BadLineError.LineNo=%d, want 1", bad.LineNo)
	}
	if bad.Reason != "bad_line" {
		t.Errorf("BadLineError.Reason=%q, want %q", bad.Reason, "bad_line")
	}
}

// TestVerifyChain_LineJSONCorrupt — 行 JSON 损坏 → bad_line:N。
func TestVerifyChain_LineJSONCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	appendRow(t, path, sampleAuditRow(0, "his-core", "dm8", "sha-aaaa"))
	// 在 line 2 写一段损坏的 JSON（不闭合）。
	if err := os.WriteFile(path, []byte("{\"event_id\":\"x\",\"kind\":\"drift\"\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	err := output.VerifyChain(path)
	if err == nil {
		t.Fatalf("VerifyChain must fail on corrupt JSON, got nil")
	}
	var bad *output.BadLineError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadLineError, got %T", err)
	}
	if bad.LineNo != 1 {
		t.Errorf("BadLineError.LineNo=%d, want 1", bad.LineNo)
	}
	if bad.Reason != "bad_line" {
		t.Errorf("BadLineError.Reason=%q, want %q", bad.Reason, "bad_line")
	}
}

// TestVerifyChain_BadInsert_MidChain — 在 line 2 之后插入伪造行 Lx，Lx 的 prev=""
//
//	→ VerifyChain 报 bad_insert:3（line 3 是 Lx；prev="" 表示 Lx 自称新链头）。
func TestVerifyChain_BadInsert_MidChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	appendRow(t, path, sampleAuditRow(0, "his-core", "dm8", "sha-aaaa"))
	appendRow(t, path, sampleAuditRow(1, "his-core", "dm8", "sha-bbbb"))
	appendRow(t, path, sampleAuditRow(2, "lis-pacs", "kingbase", "sha-cccc"))

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	// 构造伪造行：prev=""（自称新链头）+ self_hash 乱填
	fake := output.AuditRow{
		TsUTC:              "2026-10-10T05:00:00.005Z",
		EventID:            "evt-fake",
		ContractID:         "c-fake",
		SystemID:           "fake-sys",
		Vendor:             "fake-vendor",
		Declared:           "v9.9",
		Actual:             "fake",
		Verdict:            "trial",
		Confidence:         0.5,
		EvidenceSHA256:     "fake-sha",
		PrevEvidenceSHA256: "", // 关键：prev 为空 → bad_insert
		Kind:               "drift",
		SelfHash:           "deadbeef",
	}
	fakeBytes, _ := json.Marshal(fake)
	// 插入位置：在 line 2 后
	newLines := []string{lines[0], lines[1], string(fakeBytes), lines[2], lines[3]}
	if err := os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0o644); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}

	err = output.VerifyChain(path)
	if err == nil {
		t.Fatalf("VerifyChain must fail after inserting fake line with empty prev, got nil")
	}
	var bad *output.BadLineError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadLineError, got %T: %v", err, err)
	}
	if bad.LineNo != 3 {
		t.Errorf("BadLineError.LineNo=%d, want 3 (inserted line position)", bad.LineNo)
	}
	if bad.Reason != "bad_insert" {
		t.Errorf("BadLineError.Reason=%q, want %q", bad.Reason, "bad_insert")
	}
	if bad.Got != "" {
		t.Errorf("BadLineError.Got=%q, want empty (prev='')", bad.Got)
	}
}

// TestVerifyChain_BadInsert_ChainBreakVariant — 在 line 2 之后插入伪造行，伪造行的 prev
//
//	填了垃圾（既不是上一行 self_hash，也不为空）→ chain_break。
//
// 这个 case 表达：bad_insert 只在「插入者把新行伪造成链头」时触发；如果插入者用
// 真实 prev 继续伪造（更难），VerifyChain 退化为 chain_break 报告。
func TestVerifyChain_BadInsert_ChainBreakVariant(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	appendRow(t, path, sampleAuditRow(0, "his-core", "dm8", "sha-aaaa"))
	appendRow(t, path, sampleAuditRow(1, "his-core", "dm8", "sha-bbbb"))
	appendRow(t, path, sampleAuditRow(2, "lis-pacs", "kingbase", "sha-cccc"))

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	// 构造伪造行：prev=乱填（既不空也不等于 prevSelfHash）
	fake := output.AuditRow{
		TsUTC:              "2026-10-10T05:00:00.005Z",
		EventID:            "evt-fake",
		ContractID:         "c-fake",
		SystemID:           "fake-sys",
		Vendor:             "fake-vendor",
		Declared:           "v9.9",
		Actual:             "fake",
		Verdict:            "trial",
		Confidence:         0.5,
		EvidenceSHA256:     "fake-sha",
		PrevEvidenceSHA256: "garbage-junk-not-real-prev",
		Kind:               "drift",
		SelfHash:           "deadbeef",
	}
	fakeBytes, _ := json.Marshal(fake)
	newLines := []string{lines[0], lines[1], string(fakeBytes), lines[2], lines[3]}
	if err := os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0o644); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}

	err = output.VerifyChain(path)
	if err == nil {
		t.Fatalf("VerifyChain must fail on insertion with bad prev, got nil")
	}
	var bad *output.BadLineError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadLineError, got %T: %v", err, err)
	}
	if bad.LineNo != 3 {
		t.Errorf("BadLineError.LineNo=%d, want 3", bad.LineNo)
	}
	if bad.Reason != "chain_break" {
		t.Errorf("BadLineError.Reason=%q, want %q (inserted fake with garbage prev)", bad.Reason, "chain_break")
	}
}

// TestVerifyChain_NonExistentFile — 文件不存在 → nil error（合法空链）。
func TestVerifyChain_NonExistentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nope.jsonl")

	if err := output.VerifyChain(path); err != nil {
		t.Fatalf("VerifyChain on non-existent file must return nil, got %v", err)
	}
}

// TestVerifyChain_EmptyFile — 文件存在但 0 行 → nil error。
func TestVerifyChain_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	if err := output.VerifyChain(path); err != nil {
		t.Fatalf("VerifyChain on empty file must return nil, got %v", err)
	}
}

// TestAppendJSONL_Concurrent10Goroutines — 并发 10 goroutine 追加 → 链长 10 + VerifyChain 通过。
func TestAppendJSONL_Concurrent10Goroutines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	var wg sync.WaitGroup
	var fail atomic.Int64
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			row := sampleAuditRow(i, "concurrent-sys", "dm8", "sha-conc-"+string(rune('a'+i)))
			if _, err := output.AppendJSONL(path, row); err != nil {
				fail.Add(int64(1))
				t.Errorf("goroutine %d AppendJSONL: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if fail.Load() != 0 {
		t.Fatalf("%d goroutines failed", fail.Load())
	}

	rows, err := output.LoadChain(path)
	if err != nil {
		t.Fatalf("LoadChain: %v", err)
	}
	if len(rows) != 10 {
		t.Errorf("expected 10 rows, got %d", len(rows))
	}
	if err := output.VerifyChain(path); err != nil {
		t.Fatalf("VerifyChain on concurrent 10-row chain failed: %v", err)
	}
}

// TestAppendJSONL_AppendsAtEndAfterExisting — 已有 N 行后再追加 → self_hash 链续接。
func TestAppendJSONL_AppendsAtEndAfterExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	appendRow(t, path, sampleAuditRow(0, "his-core", "dm8", "sha-aaaa"))
	prevLast, err := output.LastSelfHash(path)
	if err != nil {
		t.Fatalf("LastSelfHash: %v", err)
	}
	if prevLast == "" {
		t.Fatalf("LastSelfHash after 1 row must be non-empty")
	}

	appendRow(t, path, sampleAuditRow(1, "his-core", "dm8", "sha-bbbb"))
	newLast, err := output.LastSelfHash(path)
	if err != nil {
		t.Fatalf("LastSelfHash: %v", err)
	}
	if newLast == prevLast {
		t.Fatalf("LastSelfHash must change after append: prev=%s new=%s", prevLast, newLast)
	}

	rows, _ := output.LoadChain(path)
	if rows[1].PrevEvidenceSHA256 != prevLast {
		t.Errorf("row[1].PrevEvidenceSHA256=%q, want %q", rows[1].PrevEvidenceSHA256, prevLast)
	}
}

// TestComputeSelfHash_Deterministic — 同 prev + 同 body → 同 self_hash。
func TestComputeSelfHash_Deterministic(t *testing.T) {
	body := []byte("hello\x1fworld")
	h1 := output.ComputeSelfHash("prev-hash", body)
	h2 := output.ComputeSelfHash("prev-hash", body)
	if h1 != h2 {
		t.Errorf("ComputeSelfHash non-deterministic: %s vs %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("self_hash hex length=%d, want 64", len(h1))
	}
}

// TestComputeSelfHash_DifferentPrevOrBody — 不同 prev 或 body → 不同 self_hash。
func TestComputeSelfHash_DifferentPrevOrBody(t *testing.T) {
	body := []byte("hello")
	h1 := output.ComputeSelfHash("prev-a", body)
	h2 := output.ComputeSelfHash("prev-b", body)
	h3 := output.ComputeSelfHash("prev-a", []byte("hellp"))
	if h1 == h2 || h1 == h3 || h2 == h3 {
		t.Errorf("ComputeSelfHash collision: %s / %s / %s", h1, h2, h3)
	}
}

// TestComputeSelfHash_ChainHeadEmpty — 链头 prev="" 仍计算。
func TestComputeSelfHash_ChainHeadEmpty(t *testing.T) {
	h := output.ComputeSelfHash("", []byte("body"))
	if len(h) != 64 {
		t.Errorf("chain head self_hash hex length=%d, want 64", len(h))
	}
}

// TestLoadChain_NonExistent — 文件不存在 → nil slice + nil error。
func TestLoadChain_NonExistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nope.jsonl")
	rows, err := output.LoadChain(path)
	if err != nil {
		t.Fatalf("LoadChain on non-existent: %v", err)
	}
	if rows != nil {
		t.Errorf("LoadChain on non-existent must return nil, got %v", rows)
	}
}

// TestSortedByTsUTC — 乱序输入 → 排序后按 ts_utc 升序。
func TestSortedByTsUTC(t *testing.T) {
	r1 := sampleAuditRow(0, "a", "dm8", "s1") // 05:00:00.000
	r2 := sampleAuditRow(2, "b", "dm8", "s2") // 05:00:00.002
	r3 := sampleAuditRow(1, "c", "dm8", "s3") // 05:00:00.001
	rows := []output.AuditRow{r2, r3, r1}
	sorted := output.SortedByTsUTC(rows)
	if sorted[0].TsUTC != r1.TsUTC || sorted[1].TsUTC != r3.TsUTC || sorted[2].TsUTC != r2.TsUTC {
		t.Errorf("SortedByTsUTC wrong order: %s / %s / %s", sorted[0].TsUTC, sorted[1].TsUTC, sorted[2].TsUTC)
	}
	// 原 slice 不变。
	if rows[0].TsUTC != r2.TsUTC {
		t.Errorf("SortedByTsUTC mutated input")
	}
}

// TestAppendJSONL_EmptyPath — path="" → 返回 error。
func TestAppendJSONL_EmptyPath(t *testing.T) {
	_, err := output.AppendJSONL("", output.AuditRow{})
	if err == nil {
		t.Fatalf("AppendJSONL with empty path must error")
	}
}

// TestAppendJSONL_NoRows — 0 行 → 不写文件，返回 0 + nil。
func TestAppendJSONL_NoRows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	n, err := output.AppendJSONL(path)
	if err != nil {
		t.Fatalf("AppendJSONL with 0 rows: %v", err)
	}
	if n != 0 {
		t.Errorf("AppendJSONL with 0 rows returned n=%d, want 0", n)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("AppendJSONL with 0 rows must not create file, stat err=%v", err)
	}
}

// TestBadLineError_ErrorMessage — 错误信息含 line / reason / expected / got / kind / event_id。
func TestBadLineError_ErrorMessage(t *testing.T) {
	e := &output.BadLineError{
		LineNo:    7,
		Reason:    "self_hash_mismatch",
		Expected:  "abcd",
		Got:       "wxyz",
		RowKind:   "drift",
		EventID:   "evt-7",
		SelfHash:  "wxyz",
	}
	msg := e.Error()
	for _, want := range []string{"7", "self_hash_mismatch", "abcd", "wxyz", "drift", "evt-7"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error()=%q missing %q", msg, want)
		}
	}
}

// TestVerifyChain_LongLineOver64K — 单行 ≥ 64KB（bufio.Scanner 默认上限）也能解析。
func TestVerifyChain_LongLineOver64K(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	row := sampleAuditRow(0, "his-core", "dm8", "sha-aaaa")
	// 把 PortRaw 撑到 100KB。
	row.PortRaw = strings.Repeat("x", 100*1024)
	appendRow(t, path, row)
	if err := output.VerifyChain(path); err != nil {
		t.Fatalf("VerifyChain on 100KB row failed: %v", err)
	}
}

// TestAppendJSONL_Batch3Rows — 一次 AppendJSONL 写 3 行 → 链长 3 + VerifyChain OK。
func TestAppendJSONL_Batch3Rows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	rows := []output.AuditRow{
		sampleAuditRow(0, "sys-a", "dm8", "sha-1"),
		sampleAuditRow(1, "sys-a", "dm8", "sha-2"),
		sampleAuditRow(2, "sys-a", "dm8", "sha-3"),
	}
	n, err := output.AppendJSONL(path, rows...)
	if err != nil {
		t.Fatalf("AppendJSONL batch: %v", err)
	}
	if n != 3 {
		t.Errorf("AppendJSONL batch n=%d, want 3", n)
	}
	if err := output.VerifyChain(path); err != nil {
		t.Fatalf("VerifyChain batch: %v", err)
	}
}