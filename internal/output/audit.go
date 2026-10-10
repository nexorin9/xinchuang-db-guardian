// Package output — append-only JSONL 审计 + sha256 链 + audit verify-chain 校验。
//
// 设计原则（spec.md §3.3 + spec.md §4 验收故事）：
//   - 每行 JSONL = 一次完整事件（drift / drift_confirmed / drift_remedied / llm_fallback / notify_error / probe_error / scan_error / audit_anchor）；
//   - self_hash = sha256(prev_evidence_sha256 || body)；body = 除 self_hash / prev_evidence_sha256 之外的字段；
//   - 链头 prev_evidence_sha256 = ""（空字符串）；
//   - audit verify-chain 子命令校验：每行 self_hash 与 body 重算一致 + 当前行 prev_evidence_sha256 == 上一行 self_hash；
//   - 任一不一致返回 BadLineError{LineNo, Expected, Got}；
//   - AppendLock 互斥（防并发写入穿插）；VerifyChain 不需要 AppendLock（只读）。
//
// 落盘目录由调用方传入（守护默认写到 logs/audit.jsonl；测试写到 t.TempDir()）。
// 文件不存在视作合法空链（零行 → OK）。
package output

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"sync"
)

// AuditRow — 一条 JSONL 审计行的事实包。
//
// 字段对应 spec.md §3.3：ts_utc / event_id / contract_id / system_id / vendor / declared / actual /
// port_raw / driver_sha / jdbc_url / verdict / confidence / evidence_sha256 / prev_evidence_sha256 /
// llm_in_sha / llm_out_sha / llm_model / latency_ms / action / operator / kind / self_hash。
//
// Kind 区分事件类别（drift / drift_confirmed / drift_remedied / llm_fallback / notify_error /
// probe_error / scan_error / audit_anchor）；审计链对所有 kind 一视同仁（同一条链）。
type AuditRow struct {
	TsUTC              string  `json:"ts_utc"`
	EventID            string  `json:"event_id"`
	ContractID         string  `json:"contract_id"`
	SystemID           string  `json:"system_id"`
	Vendor             string  `json:"vendor"`
	Declared           string  `json:"declared"`
	Actual             string  `json:"actual"`
	PortRaw            string  `json:"port_raw"`
	DriverSha          string  `json:"driver_sha"`
	JDBCURL            string  `json:"jdbc_url"`
	Verdict            string  `json:"verdict"`
	Confidence         float64 `json:"confidence"`
	EvidenceSHA256     string  `json:"evidence_sha256"`
	PrevEvidenceSHA256 string  `json:"prev_evidence_sha256"`
	LLMInSHA256        string  `json:"llm_in_sha256,omitempty"`
	LLMOutSHA256       string  `json:"llm_out_sha256,omitempty"`
	LLMModel           string  `json:"llm_model,omitempty"`
	LatencyMs          int64   `json:"latency_ms,omitempty"`
	Action             string  `json:"action,omitempty"`
	Operator           string  `json:"operator,omitempty"`
	Kind               string  `json:"kind"`
	SelfHash           string  `json:"self_hash"`
}

// appendLocks — per-file mutex map（key = 文件绝对路径）。
//
// 守护进程长期运行：append 与 verify-chain 由不同 goroutine 触发，AppendLock
// 仅对同一文件的并发 Append 互斥；不同文件不互相阻塞。
var (
	appendLocksMu sync.Mutex
	appendLocks   = make(map[string]*sync.Mutex)
)

func lockFor(path string) *sync.Mutex {
	appendLocksMu.Lock()
	defer appendLocksMu.Unlock()
	m, ok := appendLocks[path]
	if !ok {
		m = &sync.Mutex{}
		appendLocks[path] = m
	}
	return m
}

// HashBody — 用于 SelfHash 计算：除 self_hash 与 prev_evidence_sha256 之外的所有字段拼接。
//
// 拼接顺序固定（决定性）；任何字段顺序变动都会让既有链失效 —— 故本函数专门固化，
// 不得在非必要情况下调整拼接顺序。
func (r AuditRow) HashBody() []byte {
	// 固定分隔符：\x1f（Unit Separator），避免字段值中含 '|' 引发歧义。
	const sep = "\x1f"
	out := make([]byte, 0, 512)
	out = append(out, r.TsUTC...)
	out = append(out, sep...)
	out = append(out, r.EventID...)
	out = append(out, sep...)
	out = append(out, r.ContractID...)
	out = append(out, sep...)
	out = append(out, r.SystemID...)
	out = append(out, sep...)
	out = append(out, r.Vendor...)
	out = append(out, sep...)
	out = append(out, r.Declared...)
	out = append(out, sep...)
	out = append(out, r.Actual...)
	out = append(out, sep...)
	out = append(out, r.PortRaw...)
	out = append(out, sep...)
	out = append(out, r.DriverSha...)
	out = append(out, sep...)
	out = append(out, r.JDBCURL...)
	out = append(out, sep...)
	out = append(out, r.Verdict...)
	out = append(out, sep...)
	out = append(out, strconv.FormatFloat(r.Confidence, 'f', 6, 64)...)
	out = append(out, sep...)
	out = append(out, r.EvidenceSHA256...)
	out = append(out, sep...)
	out = append(out, r.LLMInSHA256...)
	out = append(out, sep...)
	out = append(out, r.LLMOutSHA256...)
	out = append(out, sep...)
	out = append(out, r.LLMModel...)
	out = append(out, sep...)
	out = append(out, strconv.FormatInt(r.LatencyMs, 10)...)
	out = append(out, sep...)
	out = append(out, r.Action...)
	out = append(out, sep...)
	out = append(out, r.Operator...)
	out = append(out, sep...)
	out = append(out, r.Kind...)
	return out
}

// ComputeSelfHash — self_hash = sha256(prevEvidenceSHA256 || body)。
//
// 链头 prevEvidenceSHA256 = ""（空字符串）。
func ComputeSelfHash(prevEvidenceSHA256 string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(prevEvidenceSHA256))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// AppendJSONL — 追加一行 JSONL；自动补 self_hash（基于上一行 self_hash + 当前行 body）。
//
// 入参：
//   - path:  JSONL 文件路径；
//   - rows:  待追加行（每条独立算 self_hash，链头 prev="")。
//
// 行为：
//   - 取 AppendLock 防并发穿插；
//   - 读末行 self_hash 作为新行 prev_evidence_sha256；文件不存在 → prev = ""；
//   - 写模式 O_APPEND|O_CREATE|O_WRONLY；
//   - 失败返回 error（不静默吞错）。
//
// 返回：成功写入的行数 + error。
func AppendJSONL(path string, rows ...AuditRow) (int, error) {
	if path == "" {
		return 0, errors.New("audit: path is empty")
	}
	if len(rows) == 0 {
		return 0, nil
	}
	mu := lockFor(path)
	mu.Lock()
	defer mu.Unlock()

	prev, err := readLastSelfHash(path)
	if err != nil {
		return 0, fmt.Errorf("audit: read last self_hash: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, fmt.Errorf("audit: open %q: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	written := 0
	for i, row := range rows {
		row.PrevEvidenceSHA256 = prev
		row.SelfHash = ComputeSelfHash(prev, row.HashBody())
		body, err := json.Marshal(row)
		if err != nil {
			return written, fmt.Errorf("audit: marshal row[%d]: %w", i, err)
		}
		if _, err := w.Write(body); err != nil {
			return written, fmt.Errorf("audit: write row[%d]: %w", i, err)
		}
		if err := w.WriteByte('\n'); err != nil {
			return written, fmt.Errorf("audit: write newline row[%d]: %w", i, err)
		}
		prev = row.SelfHash
		written++
	}
	if err := w.Flush(); err != nil {
		return written, fmt.Errorf("audit: flush: %w", err)
	}
	return written, nil
}

// readLastSelfHash — 读 JSONL 文件末行的 self_hash；文件不存在 → 返回 "" 与 nil error。
func readLastSelfHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()

	// 用 bufio.Scanner 反向扫：把文件读入 bufio.Reader，逐行后退。
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() == 0 {
		return "", nil
	}

	const maxBack = 64 * 1024 // 最多回扫 64KB，覆盖一行足够。
	back := int64(maxBack)
	if info.Size() < back {
		back = info.Size()
	}
	if _, err := f.Seek(-back, io.SeekEnd); err != nil {
		return "", err
	}
	r := bufio.NewReader(f)
	rest, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	// 去掉首行（可能不完整）。
	lines := splitNonEmptyLines(rest)
	if len(lines) == 0 {
		return "", nil
	}
	last := lines[len(lines)-1]
	var row AuditRow
	if err := json.Unmarshal([]byte(last), &row); err != nil {
		return "", fmt.Errorf("audit: parse last line: %w", err)
	}
	return row.SelfHash, nil
}

// splitNonEmptyLines — 按 \n 切 + 过滤空行。
func splitNonEmptyLines(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			line := string(b[start:i])
			if line != "" {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	if start < len(b) {
		line := string(b[start:])
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// BadLineError — 链校验失败的行级错误。
type BadLineError struct {
	LineNo    int    // 1-based 行号
	Reason    string // "bad_line" / "chain_break" / "bad_insert" / "self_hash_mismatch"
	Expected  string
	Got       string
	RowKind   string
	EventID   string
	SelfHash  string
}

func (e *BadLineError) Error() string {
	return fmt.Sprintf("audit: line %d %s: expected=%s got=%s kind=%s event_id=%s self_hash=%s",
		e.LineNo, e.Reason, e.Expected, e.Got, e.RowKind, e.EventID, e.SelfHash)
}

// VerifyChain — 读 JSONL 逐行校验：每行 self_hash 与 body 重算一致 + 当前行 prev_evidence_sha256 == 上一行 self_hash。
//
// 行为：
//   - 文件不存在 → 返回 nil error（视作合法空链）；
//   - 任一行 self_hash 与重算不一致 → 返回 *BadLineError（Reason="self_hash_mismatch"）；
//   - 任一行 prev_evidence_sha256 != 上一行 self_hash → 返回 *BadLineError（Reason="chain_break"）；
//   - 非首行 prev_evidence_sha256 为空字符串 → 返回 *BadLineError（Reason="bad_insert"），表明有人插入伪造链头；
//   - 首行 prev_evidence_sha256 必须为空字符串；否则 Reason="bad_line"；
//   - 行内 JSON 损坏 → 返回 *BadLineError（Reason="bad_line"）。
//
// 三种篡改场景对应的 Reason（spec.md §3.3 + T30）：
//   - 篡改行内容（line N）→ "self_hash_mismatch:N"（body 改了，self_hash 重算不一致）；
//   - 删除中间行（line N）→ "chain_break:N+1"（新位置 N+1 的 prev 与上一行 self 不接）；
//   - 插入伪造行（在 line N 后插入伪造行 Lx）→ "bad_insert:pos(Lx)"（Lx 位置 Px 的 prev 字段如果=空字符串，即为 Lx 被伪造为新链头；如果 prev 字段乱填，则报 "chain_break:pos(Lx)"）。
//
// VerifyChain 是只读操作，不获取 AppendLock（与并发 Append 安全）。
func VerifyChain(path string) error {
	if path == "" {
		return errors.New("audit: path is empty")
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("audit: open %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// 单行上限提到 1MB（兼容 evidence 含 port_raw 长响应）。
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		prevSelfHash string
		lineNo       int
	)
	for scanner.Scan() {
		lineNo++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var row AuditRow
		if err := json.Unmarshal(raw, &row); err != nil {
			return &BadLineError{
				LineNo:   lineNo,
				Reason:   "bad_line",
				Expected: "valid json",
				Got:      err.Error(),
			}
		}
		// 链头校验：首行 prev_evidence_sha256 必须为空字符串。
		if lineNo == 1 && row.PrevEvidenceSHA256 != "" {
			return &BadLineError{
				LineNo:    lineNo,
				Reason:    "bad_line",
				Expected:  "prev_evidence_sha256=\"\"",
				Got:       row.PrevEvidenceSHA256,
				RowKind:   row.Kind,
				EventID:   row.EventID,
				SelfHash:  row.SelfHash,
			}
		}
		// 反向插入检测：lineNo > 1 但 prev_evidence_sha256 为空 → 有人插入伪造链头。
		// 真实链只能有一个链头（lineNo==1），中段出现 prev="" 必为插入。
		if lineNo > 1 && row.PrevEvidenceSHA256 == "" {
			return &BadLineError{
				LineNo:    lineNo,
				Reason:    "bad_insert",
				Expected:  prevSelfHash,
				Got:       "",
				RowKind:   row.Kind,
				EventID:   row.EventID,
				SelfHash:  row.SelfHash,
			}
		}
		// 链接校验：非首行 prev 必须等于上一行 self_hash。
		if lineNo > 1 && row.PrevEvidenceSHA256 != prevSelfHash {
			return &BadLineError{
				LineNo:    lineNo,
				Reason:    "chain_break",
				Expected:  prevSelfHash,
				Got:       row.PrevEvidenceSHA256,
				RowKind:   row.Kind,
				EventID:   row.EventID,
				SelfHash:  row.SelfHash,
			}
		}
		// self_hash 校验：用 row 字段（保留 PrevEvidenceSHA256 与 SelfHash）重算 body。
		rowCopy := row
		rowCopy.PrevEvidenceSHA256 = row.PrevEvidenceSHA256
		rowCopy.SelfHash = ""
		want := ComputeSelfHash(row.PrevEvidenceSHA256, rowCopy.HashBody())
		if want != row.SelfHash {
			return &BadLineError{
				LineNo:    lineNo,
				Reason:    "self_hash_mismatch",
				Expected:  want,
				Got:       row.SelfHash,
				RowKind:   row.Kind,
				EventID:   row.EventID,
				SelfHash:  row.SelfHash,
			}
		}
		prevSelfHash = row.SelfHash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("audit: scan %q: %w", path, err)
	}
	return nil
}

// LoadChain — 读 JSONL 文件返回所有行（仅供 export-evidence 与 e2e 测试复用；不校验链）。
//
// 行为：
//   - 文件不存在 → 返回 nil slice 与 nil error；
//   - 行内 JSON 损坏 → 返回 error（不静默吞）；
//   - 顺序按文件中实际顺序（已 append-only）。
func LoadChain(path string) ([]AuditRow, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: open %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []AuditRow
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var row AuditRow
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil, fmt.Errorf("audit: parse line: %w", err)
		}
		out = append(out, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit: scan %q: %w", path, err)
	}
	return out, nil
}

// LastSelfHash — 读文件末行的 self_hash（AppendJSONL 复用 + 外部 verify 工具）。
//
// 文件不存在 → 返回 "" 与 nil error；行解析失败 → 返回 error。
func LastSelfHash(path string) (string, error) {
	return readLastSelfHash(path)
}

// SortedByTsUTC — 给定 []AuditRow 返回按 ts_utc 升序的副本（用于 evidence.zip 过滤窗口）。
//
// 不修改原 slice；新 slice 按 ts 字典序排序（RFC3339Nano 字典序 = 时间序）。
func SortedByTsUTC(rows []AuditRow) []AuditRow {
	out := make([]AuditRow, len(rows))
	copy(out, rows)
	sort.Slice(out, func(i, j int) bool {
		return out[i].TsUTC < out[j].TsUTC
	})
	return out
}