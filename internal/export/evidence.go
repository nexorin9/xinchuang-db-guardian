// Package export — 信创合规证据包装订器：把近 N 天审计链 + 合同白名单 +
// 漂移事件 + 端口响应原文 + 驱动 sha 整合为 evidence.zip，供飞检组现场调阅。
//
// 设计原则（spec.md §3 + spec.md §4.3 + §6）：
//   - 一份 zip = 一次完整取证单元，命名 evidence_<UTC-timestamp>.zip；
//   - 入口：Export() — 调用方传入时间窗（last_n_days）+ 路径（contracts/audit/output）；
//   - zip 内文件清单：README.txt + contract_registry.csv + drift_events.csv +
//     raw_probe_responses/<system_id>.txt + driver_sha256.csv + audit.jsonl +
//     manifest.json + manifest.sha256；
//   - manifest.json 含每个内嵌文件 sha256；manifest.sha256 = sha256(manifest.json)；
//   - audit.jsonl 子集保留原始 self_hash 链（不重新计算 hash）—— 飞检组用
//     audit verify-chain 二次校验即可；
//   - 任一文件读取 / 解析 / 写入失败 → 返回 error，不静默吞错；
//   - 不连真实生产库 / 不调任何外发接口（出站仅为最终 zip 写入本地路径）。
//
// 与 cilium 源产品的关系：cilium cloud-dep-check 是构建期一次性核对并退出，
// 并不打包证据。本包是**新建模块**，不承自源产品；落 zip 形态由 spec.md §3 §4
// 与医院飞检实务共同决定。
package export

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xinchuang-db-guardian/internal/config"
	"xinchuang-db-guardian/internal/output"
)

// ManifestEntry — manifest.json 内单条文件清单。
type ManifestEntry struct {
	Name     string `json:"name"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	Kind     string `json:"kind"` // "registry" / "events" / "audit" / "raw_probe" / "driver_sha" / "readme"
	Note     string `json:"note,omitempty"`
}

// Manifest — manifest.json 顶层结构。
type Manifest struct {
	GeneratedAtUTC string          `json:"generated_at_utc"`
	LastNDays      int             `json:"last_n_days"`
	CutoffUTC      string          `json:"cutoff_utc"`
	Files          []ManifestEntry `json:"files"`
	ToolVersion    string          `json:"tool_version"`
	HostHostname   string          `json:"hostname,omitempty"`
}

// ManifestSHA256FileName — 装订清单自身的 sha256（业内惯例 manifest.sha256）。
const ManifestSHA256FileName = "manifest.sha256"

// AuditFileName — zip 内审计链文件名（与 cmd audit verify-chain --file 兼容）。
const AuditFileName = "audit.jsonl"

// Options — Export 的可选配置；调用方只填关心的字段，未填走默认。
type Options struct {
	// ContractsPath — contracts.yaml 路径；必填。
	ContractsPath string
	// AuditPath — audit.jsonl 路径；必填（即使不存在视作空链）。
	AuditPath string
	// OutPath — 输出 zip 路径；必填。
	OutPath string
	// LastNDays — 时间窗（天）；>0 才生效。
	LastNDays int
	// ToolVersion — manifest.json 内的工具版本标识；空字符串 = "dev"。
	ToolVersion string
	// Now — 测试用注入；nil 时 = time.Now().UTC()。
	Now *time.Time
}

// ErrInvalidOptions — 调用方未填必填字段。
var ErrInvalidOptions = errors.New("export: invalid options")

// ErrEmptyOutPath — 输出路径空。
var ErrEmptyOutPath = errors.New("export: empty out_path")

// internal file names（zip 内）。
const (
	readmeFileName         = "README.txt"
	contractRegistryFile   = "contract_registry.csv"
	driftEventsFile        = "drift_events.csv"
	driverShaFile          = "driver_sha256.csv"
	rawProbeResponsesDir   = "raw_probe_responses"
	manifestFileName       = "manifest.json"
)

// Export — 主入口：组装 evidence.zip 到 Options.OutPath。
//
// 流程：
//  1. 校验必填字段（ContractsPath / AuditPath / OutPath 非空）；
//  2. 读 contracts.yaml → contract_registry.csv；
//  3. 读 audit.jsonl → 按 last_n_days 过滤 + 保留原始 self_hash 链 →
//     drift_events.csv + raw_probe_responses/<sid>.txt + driver_sha256.csv + audit.jsonl；
//  4. 写 README.txt；
//  5. 写 zip 流（archive/zip 标准库），同时算每个文件的 sha256 → manifest.json；
//  6. 写完所有文件后再算 manifest.sha256 写入 zip 末尾。
//
// 返回：生成的 zip 文件大小（字节）+ error。
func Export(opts Options) (int64, error) {
	if opts.ContractsPath == "" || opts.AuditPath == "" {
		return 0, fmt.Errorf("%w: contracts_path and audit_path are required", ErrInvalidOptions)
	}
	if opts.OutPath == "" {
		return 0, ErrEmptyOutPath
	}
	if opts.LastNDays <= 0 {
		opts.LastNDays = 30 // 默认 30 天
	}
	if opts.ToolVersion == "" {
		opts.ToolVersion = "dev"
	}
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now.UTC()
	}
	cutoff := now.Add(-time.Duration(opts.LastNDays) * 24 * time.Hour)

	// 1. 解析 contracts.yaml。
	contracts, err := config.LoadContracts(opts.ContractsPath)
	if err != nil {
		return 0, fmt.Errorf("export: load contracts: %w", err)
	}
	if err := config.ValidateContracts(contracts); err != nil {
		return 0, fmt.Errorf("export: validate contracts: %w", err)
	}

	// 2. 读 audit.jsonl → 行过滤（ts_utc >= cutoff）+ 保留原始 chain。
	allRows, err := output.LoadChain(opts.AuditPath)
	if err != nil {
		return 0, fmt.Errorf("export: load audit chain: %w", err)
	}
	filteredRows := filterByCutoff(allRows, cutoff)

	// 3. 创建临时工作目录用于在 zip 写入前持有所有 manifest entries。
	workDir, err := os.MkdirTemp("", "xc-guardian-evidence-*")
	if err != nil {
		return 0, fmt.Errorf("export: mkdir temp: %w", err)
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	// 4. 在临时目录构造各文件。
	if err := writeContractRegistryCSV(filepath.Join(workDir, contractRegistryFile), contracts); err != nil {
		return 0, fmt.Errorf("export: write contract_registry: %w", err)
	}
	if err := writeDriftEventsCSV(filepath.Join(workDir, driftEventsFile), filteredRows); err != nil {
		return 0, fmt.Errorf("export: write drift_events: %w", err)
	}
	if err := writeDriverSHA256CSV(filepath.Join(workDir, driverShaFile), filteredRows); err != nil {
		return 0, fmt.Errorf("export: write driver_sha256: %w", err)
	}
	if err := writeRawProbeResponses(filepath.Join(workDir, rawProbeResponsesDir), filteredRows, contracts); err != nil {
		return 0, fmt.Errorf("export: write raw_probe_responses: %w", err)
	}
	if err := writeAuditSubset(filepath.Join(workDir, AuditFileName), filteredRows); err != nil {
		return 0, fmt.Errorf("export: write audit subset: %w", err)
	}
	if err := writeReadme(filepath.Join(workDir, readmeFileName), opts, contracts, len(filteredRows), now); err != nil {
		return 0, fmt.Errorf("export: write README: %w", err)
	}

	// 5. 收集所有 zip 内文件清单（manifest.json 自身留到最后写）。
	allFiles, err := collectWorkDirFiles(workDir)
	if err != nil {
		return 0, fmt.Errorf("export: collect files: %w", err)
	}

	// 6. 写 manifest.json（先基于 allFiles 的 sha256 生成 → 再写 manifest.sha256）。
	manifest := Manifest{
		GeneratedAtUTC: now.Format(time.RFC3339Nano),
		LastNDays:      opts.LastNDays,
		CutoffUTC:      cutoff.Format(time.RFC3339Nano),
		ToolVersion:    opts.ToolVersion,
	}
	if hn, herr := os.Hostname(); herr == nil {
		manifest.HostHostname = hn
	}
	for _, f := range allFiles {
		manifest.Files = append(manifest.Files, ManifestEntry{
			Name:   f.Name,
			SHA256: f.SHA256,
			Bytes:  f.Bytes,
			Kind:   classifyKind(f.Name),
		})
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Name < manifest.Files[j].Name })

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("export: marshal manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, manifestFileName), manifestJSON, 0o644); err != nil {
		return 0, fmt.Errorf("export: write manifest.json: %w", err)
	}
	manifestSHA := sha256Hex(manifestJSON)
	manifestSHALine := manifestSHA + "  " + manifestFileName + "\n"
	if err := os.WriteFile(filepath.Join(workDir, ManifestSHA256FileName), []byte(manifestSHALine), 0o644); err != nil {
		return 0, fmt.Errorf("export: write manifest.sha256: %w", err)
	}

	// 7. 打开输出 zip + 把临时目录里的所有文件写入 zip。
	if err := os.MkdirAll(filepath.Dir(opts.OutPath), 0o755); err != nil {
		return 0, fmt.Errorf("export: mkdir out dir: %w", err)
	}
	outF, err := os.OpenFile(opts.OutPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("export: open out_path: %w", err)
	}
	defer outF.Close()

	zw := zip.NewWriter(outF)
	if err := writeZipFromWorkDir(zw, workDir); err != nil {
		_ = zw.Close()
		return 0, fmt.Errorf("export: write zip: %w", err)
	}
	if err := zw.Close(); err != nil {
		return 0, fmt.Errorf("export: close zip: %w", err)
	}

	// 8. 取得最终文件大小。
	st, err := outF.Stat()
	if err != nil {
		return 0, fmt.Errorf("export: stat out_path: %w", err)
	}
	return st.Size(), nil
}

// filterByCutoff — 按 cutoff (inclusive) 过滤 audit rows。
//
// ts_utc 解析失败的行**保留**（保守原则：飞检需要看到原始异常）。
// 返回值是新切片（不修改原 slice）。
func filterByCutoff(rows []output.AuditRow, cutoff time.Time) []output.AuditRow {
	out := make([]output.AuditRow, 0, len(rows))
	cutoffStr := cutoff.UTC().Format(time.RFC3339Nano)
	for _, r := range rows {
		if r.TsUTC == "" {
			out = append(out, r)
			continue
		}
		// RFC3339Nano 字典序 = 时间序，直接比较字符串即可。
		if r.TsUTC >= cutoffStr {
			out = append(out, r)
		}
	}
	return out
}

// writeContractRegistryCSV — 合同白名单 CSV。
func writeContractRegistryCSV(path string, contracts []config.ContractV) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{
		"system_id", "vendor", "version_pattern", "contract_id",
		"host", "port", "scan_interval_seconds", "event_id_prefix",
		"allow_drift_sha256_count", "jdbc_driver_dirs_count",
	}); err != nil {
		return err
	}
	for _, c := range contracts {
		if err := w.Write([]string{
			c.SystemID,
			c.Vendor,
			c.VersionPattern,
			c.ContractID,
			c.Host,
			fmt.Sprintf("%d", c.Port),
			fmt.Sprintf("%d", int64(c.ScanInterval.Seconds())),
			c.EventIDPrefix,
			fmt.Sprintf("%d", len(c.AllowDriftSHA256)),
			fmt.Sprintf("%d", len(c.JdbcDriverDirs)),
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

// writeDriftEventsCSV — 漂移事件 CSV（来自 audit.jsonl 中的 drift 类行）。
//
// 仅含 kind ∈ {drift, drift_confirmed, drift_remedied, drift_disputed}；
// probe_error / scan_error / notify_error / llm_fallback 等运维类行不进 csv
// （保留在 audit.jsonl 内，飞检可自行 jq 抽）。
func writeDriftEventsCSV(path string, rows []output.AuditRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{
		"ts_utc", "event_id", "contract_id", "system_id", "vendor",
		"declared", "actual", "verdict", "confidence",
		"evidence_sha256", "action", "operator", "self_hash",
	}); err != nil {
		return err
	}
	for _, r := range rows {
		switch r.Kind {
		case "drift", "drift_confirmed", "drift_remedied", "drift_disputed":
			// include
		default:
			continue
		}
		if err := w.Write([]string{
			r.TsUTC,
			r.EventID,
			r.ContractID,
			r.SystemID,
			r.Vendor,
			r.Declared,
			r.Actual,
			r.Verdict,
			fmt.Sprintf("%.6f", r.Confidence),
			r.EvidenceSHA256,
			r.Action,
			r.Operator,
			r.SelfHash,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

// writeDriverSHA256CSV — 驱动 jar sha 清单（去重）。
func writeDriverSHA256CSV(path string, rows []output.AuditRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{
		"ts_utc", "system_id", "vendor", "driver_sha256", "evidence_sha256", "self_hash",
	}); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, r := range rows {
		if r.DriverSha == "" {
			continue
		}
		key := r.SystemID + "|" + r.DriverSha
		if seen[key] {
			continue
		}
		seen[key] = true
		if err := w.Write([]string{
			r.TsUTC, r.SystemID, r.Vendor, r.DriverSha, r.EvidenceSHA256, r.SelfHash,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

// writeRawProbeResponses — 每个 system_id 一份最新 port_raw 原文。
//
// 取每个 system_id 在 filtered rows 中 ts_utc 最大的 drift 行（含原始 PortRaw）；
// 若该 system 无 drift 命中 → 跳过（不创建空文件）。
func writeRawProbeResponses(dir string, rows []output.AuditRow, contracts []config.ContractV) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	latest := make(map[string]output.AuditRow) // key = system_id
	for _, r := range rows {
		if r.Kind != "drift" {
			continue
		}
		if r.PortRaw == "" {
			continue
		}
		existing, ok := latest[r.SystemID]
		if !ok || r.TsUTC > existing.TsUTC {
			latest[r.SystemID] = r
		}
	}

	for sid, r := range latest {
		// 文件名：safe system_id + .txt（防路径遍历）
		safe := safeFilename(sid)
		path := filepath.Join(dir, safe+".txt")
		body := buildRawProbeBody(r)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return err
		}
	}
	_ = contracts // 暂时未直接使用 contracts（drift rows 自带 system_id）
	return nil
}

// buildRawProbeBody — 单份 raw_probe_responses/<sid>.txt 内容。
func buildRawProbeBody(r output.AuditRow) string {
	var b strings.Builder
	fmt.Fprintf(&b, "system_id: %s\n", r.SystemID)
	fmt.Fprintf(&b, "vendor: %s\n", r.Vendor)
	fmt.Fprintf(&b, "contract_id: %s\n", r.ContractID)
	fmt.Fprintf(&b, "ts_utc: %s\n", r.TsUTC)
	fmt.Fprintf(&b, "event_id: %s\n", r.EventID)
	fmt.Fprintf(&b, "verdict: %s\n", r.Verdict)
	fmt.Fprintf(&b, "confidence: %.6f\n", r.Confidence)
	fmt.Fprintf(&b, "evidence_sha256: %s\n", r.EvidenceSHA256)
	fmt.Fprintf(&b, "self_hash: %s\n", r.SelfHash)
	fmt.Fprintf(&b, "prev_evidence_sha256: %s\n", r.PrevEvidenceSHA256)
	fmt.Fprintf(&b, "kind: %s\n", r.Kind)
	fmt.Fprintf(&b, "declared: %s\n", r.Declared)
	if r.LLMModel != "" {
		fmt.Fprintf(&b, "llm_model: %s\n", r.LLMModel)
		fmt.Fprintf(&b, "llm_in_sha256: %s\n", r.LLMInSHA256)
		fmt.Fprintf(&b, "llm_out_sha256: %s\n", r.LLMOutSHA256)
		fmt.Fprintf(&b, "latency_ms: %d\n", r.LatencyMs)
	}
	b.WriteString("\n----- raw port response (BEGIN) -----\n")
	b.WriteString(r.PortRaw)
	if !strings.HasSuffix(r.PortRaw, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("----- raw port response (END) -----\n")
	return b.String()
}

// writeAuditSubset — audit.jsonl 子集（按 ts_utc 过滤后保留原始 hash 链）。
func writeAuditSubset(path string, rows []output.AuditRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// 保持原顺序（已 append-only 写入）；每行 marshal 一份独立 AuditRow（不重新 hash）。
	for _, r := range rows {
		body, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := f.Write(body); err != nil {
			return err
		}
		if _, err := f.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return nil
}

// writeReadme — README.txt（飞检组阅读入口）。
func writeReadme(path string, opts Options, contracts []config.ContractV, driftCount int, now time.Time) error {
	var b strings.Builder
	fmt.Fprintf(&b, "信创数据库合规漂移守护 · 飞检证据包\n")
	fmt.Fprintf(&b, "======================================\n\n")
	fmt.Fprintf(&b, "生成时间 (UTC): %s\n", now.Format(time.RFC3339Nano))
	fmt.Fprintf(&b, "工具版本: %s\n", opts.ToolVersion)
	fmt.Fprintf(&b, "时间窗: 最近 %d 天（cutoff = %s UTC）\n\n", opts.LastNDays, now.Add(-time.Duration(opts.LastNDays)*24*time.Hour).Format(time.RFC3339Nano))
	fmt.Fprintf(&b, "本证据包包含以下内容：\n")
	fmt.Fprintf(&b, "  - README.txt                  本说明\n")
	fmt.Fprintf(&b, "  - contract_registry.csv       院内声明数据库白名单（%d 条 system）\n", len(contracts))
	fmt.Fprintf(&b, "  - drift_events.csv            时间窗内的漂移事件（%d 条）\n", driftCount)
	fmt.Fprintf(&b, "  - raw_probe_responses/*.txt   各 system_id 最新一次端口握手响应原文（脱敏，不含患者字段）\n")
	fmt.Fprintf(&b, "  - driver_sha256.csv           驱动 jar sha 清单（去重）\n")
	fmt.Fprintf(&b, "  - audit.jsonl                 时间窗内的 append-only JSONL 审计链\n")
	fmt.Fprintf(&b, "  - manifest.json               本证据包内文件清单 + 每个文件的 sha256\n")
	fmt.Fprintf(&b, "  - manifest.sha256             manifest.json 自身的 sha256 校验文件\n\n")
	fmt.Fprintf(&b, "验证方法：\n")
	fmt.Fprintf(&b, "  1. 解压本 zip 到任意目录；\n")
	fmt.Fprintf(&b, "  2. 进入解压目录；\n")
	fmt.Fprintf(&b, "  3. 校验 manifest.json 完整性：\n")
	fmt.Fprintf(&b, "       sha256sum -c manifest.sha256\n")
	fmt.Fprintf(&b, "     （应当看到 OK 字样；若 NOT OK 则本证据包已被篡改）\n")
	fmt.Fprintf(&b, "  4. 校验 audit.jsonl 审计链：\n")
	fmt.Fprintf(&b, "       xinchuang-guardian audit verify-chain --file audit.jsonl\n")
	fmt.Fprintf(&b, "     （exit 0 + {\"status\":\"ok\",\"rows\":N} 表示链完整）\n\n")
	fmt.Fprintf(&b, "注意事项：\n")
	fmt.Fprintf(&b, "  - 本证据包不含患者可识别信息（任何可回溯到具体就诊人的标识）；\n")
	fmt.Fprintf(&b, "  - 仅含信创合规相关的「合同声明 vs 实际握手响应」核对事实；\n")
	fmt.Fprintf(&b, "  - 任何针对本证据包的质疑可基于 manifest.sha256 与 audit verify-chain 双重验证。\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// collectWorkDirFiles — 收集临时目录所有文件（不含 manifest.json 与 manifest.sha256 自身）。
type workFile struct {
	Name   string // zip 内路径
	SHA256 string
	Bytes  int64
}

func collectWorkDirFiles(workDir string) ([]workFile, error) {
	var out []workFile
	err := filepath.WalkDir(workDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(workDir, path)
		if err != nil {
			return err
		}
		// 跳过 manifest 自身（留到 manifest 算完后写）。
		if rel == manifestFileName || rel == ManifestSHA256FileName {
			return nil
		}
		sha, sz, err := hashFile(path)
		if err != nil {
			return err
		}
		// zip 内路径用 /（zip 规范）。
		out = append(out, workFile{
			Name:   filepath.ToSlash(rel),
			SHA256: sha,
			Bytes:  sz,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// writeZipFromWorkDir — 把临时目录所有文件写入 zip writer。
func writeZipFromWorkDir(zw *zip.Writer, workDir string) error {
	files, err := collectWorkDirFiles(workDir)
	if err != nil {
		return err
	}
	// 包含 manifest.json 与 manifest.sha256（在 workDir 里已写好；此处统一写入）。
	manifestPath := filepath.Join(workDir, manifestFileName)
	manifestSHA, _, err := hashFile(manifestPath)
	if err != nil {
		return err
	}
	files = append(files, workFile{
		Name:   manifestFileName,
		SHA256: manifestSHA,
	})
	manifestSHAPath := filepath.Join(workDir, ManifestSHA256FileName)
	shaSHA, _, err := hashFile(manifestSHAPath)
	if err != nil {
		return err
	}
	files = append(files, workFile{
		Name:   ManifestSHA256FileName,
		SHA256: shaSHA,
	})

	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	for _, f := range files {
		src := filepath.Join(workDir, f.Name)
		// 创建 zip 内的目录条目（如 raw_probe_responses/）。
		if err := writeZipEntry(zw, f.Name, src); err != nil {
			return err
		}
	}
	return nil
}

// writeZipEntry — 单文件写入 zip（含目录条目）。
func writeZipEntry(zw *zip.Writer, zipName, srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	hdr := &zip.FileHeader{
		Name:   zipName,
		Method: zip.Deflate,
	}
	// raw_probe_responses/ 作为目录条目显式创建。
	if strings.HasSuffix(zipName, "/") {
		hdr.Method = zip.Store
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{})
		return err
	}

	st, err := src.Stat()
	if err != nil {
		return err
	}
	hdr.SetMode(0o644)

	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(w, src, st.Size()); err != nil {
		return err
	}
	return nil
}

// hashFile — 算 sha256 + 文件大小；空文件 sha = sha256("")。
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), st.Size(), nil
}

// sha256Hex — 算 sha256 + 16 进制编码（用于内存中的 manifest）。
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// safeFilename — 把 system_id 中可能引起路径异常的字符替换为 _。
func safeFilename(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "_"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-' || c == '_' || c == '.':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// classifyKind — 把文件名映射到 manifest.kind 分类。
func classifyKind(name string) string {
	switch {
	case name == readmeFileName:
		return "readme"
	case name == contractRegistryFile:
		return "registry"
	case name == driftEventsFile:
		return "events"
	case name == driverShaFile:
		return "driver_sha"
	case name == AuditFileName:
		return "audit"
	case strings.HasPrefix(name, rawProbeResponsesDir+"/"):
		return "raw_probe"
	case name == manifestFileName:
		return "manifest"
	case name == ManifestSHA256FileName:
		return "manifest_sha"
	default:
		return "other"
	}
}

// ParseLastNDays — 把 CLI --last 参数解析为整数天。
//
// 支持：
//   - "30d" / "7d" → 30 / 7；
//   - "720h" → 30；
//   - "2592000s" / "30"（裸数字）→ 30；
//
// 非法格式返回 error。
func ParseLastNDays(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("export: --last is empty")
	}
	// 裸数字（默认单位 = 天）。
	if n, err := atoi(s); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("export: --last must be > 0 days, got %d", n)
		}
		return n, nil
	}
	// 带单位。
	if len(s) < 2 {
		return 0, fmt.Errorf("export: --last malformed %q", s)
	}
	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	num, err := atoi(numStr)
	if err != nil {
		return 0, fmt.Errorf("export: --last malformed %q", s)
	}
	if num <= 0 {
		return 0, fmt.Errorf("export: --last must be > 0, got %d", num)
	}
	switch unit {
	case 'd':
		return num, nil
	case 'h':
		days := num / 24
		if days < 1 {
			days = 1
		}
		return days, nil
	case 'm':
		days := num / (24 * 60)
		if days < 1 {
			days = 1
		}
		return days, nil
	default:
		return 0, fmt.Errorf("export: --last unsupported unit %q", string(unit))
	}
}

// atoi — 内部小工具，避免 import strconv。
func atoi(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(c-'0')
		if n > 100000 {
			return 0, fmt.Errorf("too large: %q", s)
		}
	}
	return n, nil
}