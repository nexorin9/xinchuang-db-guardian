// cmd_export.go — 注册 `xinchuang-guardian export-evidence --last Nd --out <path>` 子命令。
//
// 行为：
//   - --last 必填，支持 "30d" / "720h" / "1440m" / "30"（裸数字 = 天）；
//   - --config 必填（contracts.yaml 路径）；
//   - --audit 必填（audit.jsonl 路径；缺省时 fallback $XINCHUANG_AUDIT_FILE 或
//     ./logs/audit.jsonl）；
//   - --out 必填（输出 zip 路径）；
//   - --tool-version 可选，manifest.json 内工具版本标识（默认 "dev"）；
//   - 缺 flag 走 cobra "required flag(s) missing" → 退出码 exitSubcommandFailed；
//   - 成功 → stdout 输出紧凑 JSON {"status":"ok","path":"...","bytes":N}；
//   - 失败 → stderr 输出 JSON 错误 + slog.Error + 退出码非 0。
//
// 与 audit verify-chain 同样的输出纪律：紧凑 JSON 写到 stdout，所有日志走 stderr，
// 便于脚本 `bin ... | jq` 直接管道。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"xinchuang-db-guardian/internal/export"
)

// exportFlags — flag 引用 + 解析后的最终值。
type exportFlags struct {
	Last        string
	Config      string
	Audit       string
	Out         string
	ToolVersion string
}

var ef exportFlags

// cmdExportEvidence — `export-evidence` 子命令。
var cmdExportEvidence = &cobra.Command{
	Use:   "export-evidence",
	Short: "导出飞检证据 zip（含合同白名单 + 漂移事件 + 端口响应 + 审计链 + manifest.sha256）",
	Long: `export-evidence 把近 N 天的审计链 + 合同白名单 + 漂移事件 + 端口响应原文 + 驱动 sha
整合为 evidence.zip，供飞检组现场调阅。

  - --last 必须：支持 "30d" / "720h" / "1440m" / "30"（裸数字 = 天）
  - --config 必须：contracts.yaml 路径
  - --audit 可选：audit.jsonl 路径（默认 $XINCHUANG_AUDIT_FILE 或 ./logs/audit.jsonl）
  - --out 必须：输出 zip 路径（父目录不存在会自动创建）
  - --tool-version 可选：写入 manifest.json 的工具版本标识

输出 zip 内容：
  README.txt + contract_registry.csv + drift_events.csv + driver_sha256.csv +
  audit.jsonl + raw_probe_responses/<sid>.txt + manifest.json + manifest.sha256

飞检组校验：
  1. cd <unzip dir>
  2. sha256sum -c manifest.sha256   # 应当 OK
  3. xinchuang-guardian audit verify-chain --file audit.jsonl   # exit 0`,
	SilenceErrors: false,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		InitLogger()

		writeJSON := func(w *os.File, v any) {
			b, err := json.Marshal(v)
			if err != nil {
				fmt.Fprintf(w, "%s\n", err.Error())
				return
			}
			fmt.Fprintln(w, string(b))
		}

		if ef.Last == "" {
			return errors.New("--last is required (e.g. 30d / 720h / 30)")
		}
		if ef.Config == "" {
			return errors.New("--config is required (contracts.yaml)")
		}
		if ef.Out == "" {
			return errors.New("--out is required (output zip path)")
		}

		// 默认 audit 路径：env > ./logs/audit.jsonl。
		auditPath := ef.Audit
		if auditPath == "" {
			auditPath = os.Getenv("XINCHUANG_AUDIT_FILE")
		}
		if auditPath == "" {
			auditPath = "./logs/audit.jsonl"
		}

		days, err := export.ParseLastNDays(ef.Last)
		if err != nil {
			writeJSON(os.Stderr, map[string]any{
				"status": "invalid_last",
				"input":  ef.Last,
				"error":  err.Error(),
			})
			return err
		}

		logger.Info("export_evidence_starting",
			slog.String("last", ef.Last),
			slog.Int("days", days),
			slog.String("config", ef.Config),
			slog.String("audit", auditPath),
			slog.String("out", ef.Out),
		)

		size, err := export.Export(export.Options{
			ContractsPath: ef.Config,
			AuditPath:     auditPath,
			OutPath:       ef.Out,
			LastNDays:     days,
			ToolVersion:   ef.ToolVersion,
		})
		if err != nil {
			logger.Error("export_evidence_failed", slog.String("err", err.Error()))
			writeJSON(os.Stderr, map[string]any{
				"status": "export_failed",
				"error":  err.Error(),
			})
			return err
		}

		logger.Info("export_evidence_done",
			slog.String("path", ef.Out),
			slog.Int64("bytes", size),
		)

		writeJSON(os.Stdout, map[string]any{
			"status":     "ok",
			"path":       ef.Out,
			"bytes":      size,
			"days":       days,
			"audit_path": auditPath,
			"contracts":  ef.Config,
		})
		return nil
	},
}

// init — 注册 flag 与 rootCmd。
func init() {
	cmdExportEvidence.Flags().StringVar(&ef.Last, "last", "", "时间窗，如 30d / 720h / 1440m / 30（必填）")
	cmdExportEvidence.Flags().StringVar(&ef.Config, "config", "", "contracts.yaml 路径（必填）")
	cmdExportEvidence.Flags().StringVar(&ef.Audit, "audit", "", "audit.jsonl 路径（默认 $XINCHUANG_AUDIT_FILE 或 ./logs/audit.jsonl）")
	cmdExportEvidence.Flags().StringVar(&ef.Out, "out", "", "输出 zip 路径（必填）")
	cmdExportEvidence.Flags().StringVar(&ef.ToolVersion, "tool-version", "dev", "manifest.json 中的工具版本标识")

	_ = cmdExportEvidence.MarkFlagRequired("last")
	_ = cmdExportEvidence.MarkFlagRequired("config")
	_ = cmdExportEvidence.MarkFlagRequired("out")

	rootCmd.AddCommand(cmdExportEvidence)
}