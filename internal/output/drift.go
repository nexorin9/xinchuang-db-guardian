// Package output — 漂移命中工厂 + 同 vendor 5 分钟抖动去重窗口。
//
// 设计原则（spec.md §3.2 + Phase 1 §三问）：
//   - 同 (system_id, vendor) 在 DedupWindow（默认 5 分钟）内只告警首次 → Deduped=true；
//   - 同 evidence_sha256 命中 → Idempotent=true，不再写新审计行；
//   - 漂移命中 → MakeDriftEvidence 入 output/store.go 的 trial KV；
//   - trial → confirmed/remedied 由 CLI 人工 confirm-drift 推进，永不静默推进；
//
// 窗口阈值可通过环境变量 DEDUP_WINDOW_SECS 覆盖（默认 300 秒）；
// 守护启动时由 NewDedupWindowFromEnv 读取；运行中变更需重启生效。
package output

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"xinchuang-db-guardian/internal/check"
)

// EnvDedupWindowSecs — 守护启动时读取的窗口配置环境变量名。
const EnvDedupWindowSecs = "DEDUP_WINDOW_SECS"

// AlertResult — 输出层做出"是否触发告警"的判定三态。
type AlertResult struct {
	AlertSent     bool   // true = 本次是首次命中或窗口已过，需要发企微/SMTP 卡片
	Deduped       bool   // true = 同 (system_id, vendor) 5 分钟内已告警过，本轮跳过告警（但审计行照常写）
	Idempotent    bool   // true = evidence_sha256 与上一轮完全一致，连审计行都不写（避免告警风暴）
	WindowReason  string // 命中原因："" / "dedup_window" / "evidence_sha_match"
	DedupedSHA256 string // 被去重时的旧 evidence_sha（用于日志追溯）
}

// dedupEntry — 抖动去重窗口的环形内存条目。
type dedupEntry struct {
	systemID     string
	vendor       string
	evidenceSHA  string
	firstSeen    time.Time
	lastSeen     time.Time
	alertedCount int
}

// DedupWindow — 同 (system_id, vendor) 在窗口内只告警首次；
// 同 evidence_sha256 直接幂等返回 Idempotent=true。
//
// 内存实现，守护重启后会清空；这是设计要求（重启意味着审计链从零开始
// 重新累计，去重窗口不复用进程内状态）。DDOS 抑制与告警风暴由本窗口承担。
type DedupWindow struct {
	mu      sync.Mutex
	window  time.Duration
	entries map[string]*dedupEntry // key = "systemID||vendor"
}

// DefaultDedupWindow — 默认 5 分钟窗口。
const DefaultDedupWindow = 5 * time.Minute

// NewDedupWindow 构造指定窗口的抖动去重器；window <= 0 用默认值。
func NewDedupWindow(window time.Duration) *DedupWindow {
	if window <= 0 {
		window = DefaultDedupWindow
	}
	return &DedupWindow{
		window:  window,
		entries: make(map[string]*dedupEntry),
	}
}

// NewDedupWindowFromEnv — 守护启动时从 DEDUP_WINDOW_SECS 读取窗口配置。
//
// 行为：
//   - 未设置或空 → DefaultDedupWindow (300s)；
//   - 解析为正整数 N → N 秒；
//   - 解析失败（非整数）或 ≤ 0 → 返回 ErrInvalidDedupWindow，守护 slog.Error 提示；调用方决定是否 fallback 到 default；
//   - 不修改环境、不读第二次，调用方需自行缓存。
//
// 仅调用一次 os.Getenv + strconv.Atoi + 区间校验，不反射、不读文件、不读取配置文件。
// 多个 DedupWindow 实例各自独立缓存窗口值，互不影响。
func NewDedupWindowFromEnv() (*DedupWindow, error) {
	raw := os.Getenv(EnvDedupWindowSecs)
	if raw == "" {
		return NewDedupWindow(DefaultDedupWindow), nil
	}
	secs, err := strconv.Atoi(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s=%q: %w", EnvDedupWindowSecs, raw, err)
	}
	if secs <= 0 {
		return nil, fmt.Errorf("%s must be positive seconds, got %d", EnvDedupWindowSecs, secs)
	}
	if secs > 24*3600 {
		// 上限 24 小时，防止误填 864000 之类 10 位数字让窗口永远不释放。
		return nil, fmt.Errorf("%s must be <= 86400 (24h), got %d", EnvDedupWindowSecs, secs)
	}
	return NewDedupWindow(time.Duration(secs) * time.Second), nil
}

// dedupKey — 内部拼接 key；不做归一化（system_id 在 contract 校验期已规范化为非空）。
func dedupKey(systemID, vendor string) string {
	return systemID + "||" + vendor
}

// RecordAndCheck — 记录一次漂移事件并返回去重判定结果。
//
// 行为：
//   - 同一 evidence_sha256 已存在 → Idempotent=true，AlertSent=false，entries 不增长计数；
//   - 同 (system_id, vendor) 在窗口内但 evidence_sha 不同 → Deduped=true，AlertSent=false；
//   - 首次 / 窗口已过 / evidence_sha 与上条不同 → AlertSent=true；
//
// 返回值不含任何外部副作用——本函数不写审计行、不发 webhook，仅做"该不该告警"的判定；
// 调用方拿到 AlertResult 后再决定写哪类审计行 + 调哪个 webhook / SMTP 出站函数。
func (d *DedupWindow) RecordAndCheck(ev check.DriftEvidence, now time.Time) AlertResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := dedupKey(ev.SystemID, ev.Vendor)
	now = now.UTC()

	if existing, ok := d.entries[key]; ok {
		// 同 evidence_sha 命中 → 完全幂等，不写新审计行。
		if existing.evidenceSHA == ev.EvidenceSHA256 {
			existing.lastSeen = now
			return AlertResult{
				Idempotent:    true,
				WindowReason:  "evidence_sha_match",
				DedupedSHA256: existing.evidenceSHA,
			}
		}
		// 窗口内重复 → 走 Deduped 路径。
		if now.Sub(existing.firstSeen) < d.window {
			existing.lastSeen = now
			existing.alertedCount++
			return AlertResult{
				Deduped:       true,
				WindowReason:  "dedup_window",
				DedupedSHA256: existing.evidenceSHA,
			}
		}
		// 窗口已过但 entry 仍残留 → 视为新一轮首次命中。
	}

	d.entries[key] = &dedupEntry{
		systemID:     ev.SystemID,
		vendor:       ev.Vendor,
		evidenceSHA:  ev.EvidenceSHA256,
		firstSeen:    now,
		lastSeen:     now,
		alertedCount: 1,
	}
	return AlertResult{AlertSent: true}
}

// GC — 清扫超出窗口的条目；由守护启动一个 ticker 每分钟调用一次；
// 防止长期运行 entries 累计无界增长。
func (d *DedupWindow) GC(now time.Time) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	removed := 0
	for k, e := range d.entries {
		if now.Sub(e.firstSeen) > d.window*2 {
			delete(d.entries, k)
			removed++
		}
	}
	return removed
}

// Size — 当前窗口内条目数（用于运维/可观测性）。
func (d *DedupWindow) Size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

// Window — 返回当前窗口长度。
func (d *DedupWindow) Window() time.Duration { return d.window }

// MakeDriftEvidence — 输出层封装 check.Compare 的产出：填 SelfHash、Prevs、把 trial 入 store。
//
// 入参：
//   - prev: 上一行已落审计的 self_hash（链头传 ""）；
//   - ev:   check.Compare 产出的 DriftEvidence（缺 self_hash / prev_evidence_sha256）；
//
// 返回值：完成 SelfHash 填充的 ev；Store 写入 trial KV 由调用方负责。
func MakeDriftEvidence(ev check.DriftEvidence, prev string) check.DriftEvidence {
	ev.PrevEvidenceSHA256 = prev
	body := check.HashBody(ev)
	ev.SelfHash = check.ComputeSelfHash(prev, body)
	return ev
}

// ComputeEvidenceChainID — 把 evidence event_id 做 SHA256，作为 dedup key 的二级指纹
// 备用；当前去重使用 (system_id, vendor) 主键 + evidence_sha 二级校验，本函数
// 留作审计行去重的兼容入口（外部脚本与 T11 audit 段都可能用到）。
func ComputeEvidenceChainID(ev check.DriftEvidence) string {
	h := sha256.New()
	h.Write([]byte(ev.EventID))
	h.Write([]byte{0x00})
	h.Write([]byte(ev.EvidenceSHA256))
	h.Write([]byte{0x00})
	h.Write([]byte(string(ev.Status)))
	h.Write([]byte(ev.TsUTC))
	h.Write([]byte{0x00})
	h.Write([]byte(ev.SelfHash))
	return hex.EncodeToString(h.Sum(nil))
}
