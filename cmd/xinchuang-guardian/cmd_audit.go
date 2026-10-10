// cmd_audit.go — 注册 `xinchuang-guardian audit verify-chain` 子命令。
//
// 行为：
//   - 必传 --file；缺 flag 报 "required flag(s) missing"；
//   - 调用 internal/output.VerifyChain；
//   - 合法链 → 退出码 0 + stdout 输出 {"status":"ok","rows":N}（单行紧凑 JSON）；
//   - 非法链 → 退出码 1 + stderr 输出 BadLineError + 紧凑 JSON；
//   - 文件不存在 → 退出码 0 + stdout 输出 {"status":"empty_chain"}（视作空链 OK）；
//
// 注意：本命令把 JSON 结果写到 stdout，把所有 slog 日志通过 fmt.Fprintln 写到 stderr，
// 避免污染 stdout 上的 JSON 解析（脚本可 `bin audit verify-chain --file x.jsonl | jq`）。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"xinchuang-db-guardian/internal/output"
)

// cmdAuditVerifyChain — `audit verify-chain --file <path>` 子命令。
var cmdAuditVerifyChain = &cobra.Command{
	Use:   "verify-chain",
	Short: "校验 audit.jsonl sha256 链完整性",
	Long: `audit verify-chain 读取指定 JSONL 文件，按行校验 self_hash + prev/next 链接：

  - 文件不存在：视为合法空链，exit 0；
  - 合法链：exit 0 + 输出 {"status":"ok","rows":N}；
  - 行 JSON 损坏：exit 1 + stderr 输出 BadLineError；
  - self_hash 不匹配：exit 1 + Reason="self_hash_mismatch"；
  - prev_evidence_sha256 不接上一行 self_hash：exit 1 + Reason="chain_break"；
  - 首行 prev 非空：exit 1 + Reason="bad_line"。`,
	SilenceErrors: false, // 让 cobra 把 flag 错误（缺 --file 等）写到 stderr 而不是仅返回 error。
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		InitLogger()
		file, err := cmd.Flags().GetString("file")
		if err != nil {
			return fmt.Errorf("get --file flag: %w", err)
		}
		if file == "" {
			return errors.New("--file is required")
		}

		writeJSON := func(w *os.File, v any) {
			b, err := json.Marshal(v)
			if err != nil {
				fmt.Fprintf(w, "%s\n", err.Error())
				return
			}
			fmt.Fprintln(w, string(b))
		}

		// 文件不存在 → 空链 OK。
		if _, statErr := os.Stat(file); errors.Is(statErr, os.ErrNotExist) {
			writeJSON(os.Stdout, map[string]any{
				"status": "empty_chain",
				"file":   file,
				"rows":   0,
			})
			return nil
		}

		// 先统计行数（空链 OK 也算合法）。
		rows, loadErr := output.LoadChain(file)
		if loadErr != nil {
			writeJSON(os.Stderr, map[string]any{
				"status": "load_error",
				"file":   file,
				"error":  loadErr.Error(),
			})
			return loadErr
		}

		if err := output.VerifyChain(file); err != nil {
			var bad *output.BadLineError
			if errors.As(err, &bad) {
				writeJSON(os.Stderr, map[string]any{
					"status":    "broken",
					"file":      file,
					"reason":    bad.Reason,
					"line":      bad.LineNo,
					"expected":  bad.Expected,
					"got":       bad.Got,
					"kind":      bad.RowKind,
					"event_id":  bad.EventID,
					"self_hash": bad.SelfHash,
				})
				fmt.Fprintln(os.Stderr, err.Error())
				return err
			}
			writeJSON(os.Stderr, map[string]any{
				"status": "error",
				"file":   file,
				"error":  err.Error(),
			})
			return err
		}

		writeJSON(os.Stdout, map[string]any{
			"status": "ok",
			"file":   file,
			"rows":   len(rows),
		})
		return nil
	},
}

// auditCmd — `audit` 父命令，挂载子命令。
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "审计链校验与操作",
	Long: `audit 子命令集合：当前仅提供 verify-chain（append-only JSONL 校验）。

后续 task 可在此父命令下挂载 verify-anchor / rehash-history 等子命令。`,
}

func init() {
	cmdAuditVerifyChain.Flags().String("file", "", "audit.jsonl 文件路径（必填）")
	_ = cmdAuditVerifyChain.MarkFlagRequired("file")
	auditCmd.AddCommand(cmdAuditVerifyChain)
}