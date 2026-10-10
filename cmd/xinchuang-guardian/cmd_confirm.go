// cmd_confirm.go — 注册 `xinchuang-guardian confirm-drift <event_id> --action <remedied|confirmed|disputed> --operator <name>` 子命令。
//
// 设计原则（spec.md §3.3 + §4 验收故事）：
//   - trial → confirmed / remedied / disputed 由人工 CLI 推进；
//   - LLM verdict 只入 trial，不直接推进；
//   - 状态机推进由 check.CanTransition 校验；非法转移返回 wrap ErrInvalidTransition；
//   - 每次推进：append audit.jsonl 一行（kind=drift_confirmed | drift_remedied | drift_disputed | invalid_transition），含 operator / action / 时间戳；
//   - trial 永不静默推进到 confirmed / re_verified；
//   - operator 缺失 → 返回 required_flag 错误（exit 4 = exitSubcommandFailed）；
//   - action 取值受限；非法 action → 返回 invalid_action 错误。
//
// 入口 / 出参输出纪律（与 audit / export 一致）：
//   - 成功 → stdout 紧凑 JSON {status, event_id, from_state, to_state, operator, audit_path}；
//   - 失败 → stderr 紧凑 JSON {status, error} + slog.Error 走 stdout；
//   - audit.jsonl 行由 AppendJSONL 落 sha256 链（与 verify-chain 配套校验）。
//
// Action 语义（spec.md §3.3）：
//   - confirmed → 信息科确认漂移（trial → confirmed）；
//   - remedied  → 厂商已整改（trial / confirmed → remedied；后续 re-verified 由 T21 自动检测）；
//   - disputed  → 信息科驳回（trial / confirmed → disputed；后续可重新入 confirmed / remedied）。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"xinchuang-db-guardian/internal/check"
	"xinchuang-db-guardian/internal/output"
)

// 默认 trial store 路径与 audit.jsonl 路径（env 可覆盖）。
const (
	defaultTrialDBPath = "./data/trial.db"
	defaultAuditPath   = "./logs/audit.jsonl"
)

// confirmFlags — flag 引用 + 解析后的最终值。
type confirmFlags struct {
	Action    string
	Operator  string
	AuditFile string
	DBPath    string
}

var cf confirmFlags

// cmdConfirmDrift — `confirm-drift <event_id>` 子命令。
var cmdConfirmDrift = &cobra.Command{
	Use:   "confirm-drift <event_id>",
	Short: "人工推进 trial 状态（trial → confirmed / remedied / disputed）",
	Long: `confirm-drift 从 bbolt trial_state 取 <event_id> 对应的漂移证据，
校验状态机 CanTransition 后调用 store.PromoteTrial 推进状态，
并向 audit.jsonl 追加一行（kind=drift_confirmed|drift_remedied|drift_disputed）。

  --action   必填：confirmed（信息科确认漂移）/ remedied（厂商已整改）/ disputed（信息科驳回）
  --operator 必填：操作人姓名 / 工号（写入审计行 audit.operator 字段）
  --file     可选：audit.jsonl 路径（默认 $XINCHUANG_AUDIT_FILE 或 ./logs/audit.jsonl）
  --db       可选：trial store bbolt 路径（默认 $XINCHUANG_DB_FILE 或 ./data/trial.db）

状态机合法转移（trial/confirmed/remedied/disputed/re_verified）：
  trial      → {confirmed, remedied, disputed}
  confirmed  → {remedied, disputed}
  remedied   → {re_verified}     （由 T21 自动检测，本命令不触发）
  re_verified → ∅ （终止态）
  disputed   → {confirmed, remedied}

非法转移 → 不修改 State + 写 kind=invalid_transition 审计行 + 退出码 1。`,
	Args:    cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		InitLogger()
		eventID := strings.TrimSpace(args[0])

		writeJSON := func(w *os.File, v any) {
			b, err := json.Marshal(v)
			if err != nil {
				fmt.Fprintf(w, "%s\n", err.Error())
				return
			}
			fmt.Fprintln(w, string(b))
		}

		if eventID == "" {
			return errors.New("event_id is required")
		}
		if cf.Action == "" {
			return errors.New("--action is required (remedied|confirmed|disputed)")
		}
		if strings.TrimSpace(cf.Operator) == "" {
			return errors.New("--operator is required (操作人姓名 / 工号)")
		}

		target := check.State(cf.Action)
		if !check.ValidState(string(target)) {
			writeJSON(os.Stderr, map[string]any{
				"status": "invalid_action",
				"event_id": eventID,
				"action":   cf.Action,
				"allowed":  []string{"confirmed", "remedied", "disputed"},
			})
			return fmt.Errorf("invalid action %q (allowed: confirmed/remedied/disputed)", cf.Action)
		}

		// 路径解析：flag > env > 默认值。
		dbPath := cf.DBPath
		if dbPath == "" {
			dbPath = os.Getenv("XINCHUANG_DB_FILE")
		}
		if dbPath == "" {
			dbPath = defaultTrialDBPath
		}
		auditPath := cf.AuditFile
		if auditPath == "" {
			auditPath = os.Getenv("XINCHUANG_AUDIT_FILE")
		}
		if auditPath == "" {
			auditPath = defaultAuditPath
		}

		store, err := output.OpenTrialStore(dbPath)
		if err != nil {
			writeJSON(os.Stderr, map[string]any{
				"status":  "open_store_failed",
				"event_id": eventID,
				"db_path": dbPath,
				"error":   err.Error(),
			})
			return err
		}
		defer func() { _ = store.Close() }()

		current, err := store.LoadTrial(eventID)
		if err != nil {
			// event_id 不存在 → 不写审计行（无法对不存在的 trial 操作）；直接报错返回。
			if errors.Is(err, output.ErrTrialNotFound) {
				writeJSON(os.Stderr, map[string]any{
					"status":   "trial_not_found",
					"event_id": eventID,
					"db_path":  dbPath,
				})
				return err
			}
			writeJSON(os.Stderr, map[string]any{
				"status":   "load_trial_failed",
				"event_id": eventID,
				"error":    err.Error(),
			})
			return err
		}

		// 状态机校验。
		if err := check.CanTransition(current.Status, target); err != nil {
			// 非法推进：写一条 kind=invalid_transition 审计行（含 operator / action / from / to），
			// 不修改 trial store。审计行让信息科可事后追责"为何没拦住"。
			invalidRow := output.AuditRow{
				TsUTC:          time.Now().UTC().Format(time.RFC3339Nano),
				EventID:        eventID,
				ContractID:     current.ContractID,
				SystemID:       current.SystemID,
				Vendor:         current.Vendor,
				Declared:       current.Declared,
				Actual:         current.Actual,
				PortRaw:        current.PortRaw,
				DriverSha:      current.DriverSha,
				JDBCURL:        current.JDBCURL,
				Verdict:        string(current.Verdict),
				Confidence:     current.Confidence,
				EvidenceSHA256: current.EvidenceSHA256,
				Action:         cf.Action,
				Operator:       cf.Operator,
				Kind:           "invalid_transition",
			}
			if _, apperr := output.AppendJSONL(auditPath, invalidRow); apperr != nil {
				logger.Error("confirm_drift_audit_append_failed",
					slog.String("event_id", eventID),
					slog.String("kind", "invalid_transition"),
					slog.String("err", apperr.Error()),
				)
			}
			logger.Error("confirm_drift_invalid_transition",
				slog.String("event_id", eventID),
				slog.String("from_state", string(current.Status)),
				slog.String("to_state", string(target)),
				slog.String("operator", cf.Operator),
				slog.String("audit_path", auditPath),
			)
			writeJSON(os.Stderr, map[string]any{
				"status":     "invalid_transition",
				"event_id":   eventID,
				"from_state": string(current.Status),
				"to_state":   string(target),
				"operator":   cf.Operator,
				"allowed":    stateNames(check.AllowedTransitions(current.Status)),
				"audit_path": auditPath,
			})
			return err
		}

		// 合法转移：调用 PromoteTrial 推进 store 状态（自身已链 prev_hash）。
		updated, err := store.PromoteTrial(eventID, target, cf.Operator)
		if err != nil {
			writeJSON(os.Stderr, map[string]any{
				"status":   "promote_failed",
				"event_id": eventID,
				"error":    err.Error(),
			})
			return err
		}

		// 追加审计行（kind 按 target 区分）。
		kind := "drift_" + string(target)
		auditRow := output.AuditRow{
			TsUTC:              time.Now().UTC().Format(time.RFC3339Nano),
			EventID:            updated.EventID,
			ContractID:         updated.ContractID,
			SystemID:           updated.SystemID,
			Vendor:             updated.Vendor,
			Declared:           updated.Declared,
			Actual:             updated.Actual,
			PortRaw:            updated.PortRaw,
			DriverSha:          updated.DriverSha,
			JDBCURL:            updated.JDBCURL,
			Verdict:            string(updated.Verdict),
			Confidence:         updated.Confidence,
			EvidenceSHA256:     updated.EvidenceSHA256,
			PrevEvidenceSHA256: updated.PrevEvidenceSHA256,
			Action:             cf.Action,
			Operator:           cf.Operator,
			Kind:               kind,
		}
		if _, apperr := output.AppendJSONL(auditPath, auditRow); apperr != nil {
			// store 已推进，但审计落盘失败：报告但不静默吞错。
			logger.Error("confirm_drift_audit_append_failed",
				slog.String("event_id", eventID),
				slog.String("kind", kind),
				slog.String("err", apperr.Error()),
			)
			writeJSON(os.Stderr, map[string]any{
				"status":   "audit_append_failed",
				"event_id": eventID,
				"from_state": string(current.Status),
				"to_state":   string(target),
				"audit_path": auditPath,
				"error":      apperr.Error(),
			})
			return apperr
		}

		logger.Info("confirm_drift_done",
			slog.String("event_id", eventID),
			slog.String("from_state", string(current.Status)),
			slog.String("to_state", string(target)),
			slog.String("operator", cf.Operator),
			slog.String("kind", kind),
			slog.String("audit_path", auditPath),
		)

		writeJSON(os.Stdout, map[string]any{
			"status":      "ok",
			"event_id":    eventID,
			"from_state":  string(current.Status),
			"to_state":    string(target),
			"operator":    cf.Operator,
			"audit_path":  auditPath,
			"kind":        kind,
			"self_hash":   updated.SelfHash,
			"ts_utc":      updated.TsUTC,
		})
		return nil
	},
}

// stateNames — 把 []check.State 转成 []string（CLI allowed 字段用）。
func stateNames(states []check.State) []string {
	out := make([]string, 0, len(states))
	for _, s := range states {
		out = append(out, string(s))
	}
	return out
}

// init — 注册 flag 与 rootCmd。
func init() {
	cmdConfirmDrift.Flags().StringVar(&cf.Action, "action", "", "目标状态：confirmed|remedied|disputed（必填）")
	cmdConfirmDrift.Flags().StringVar(&cf.Operator, "operator", "", "操作人姓名 / 工号（必填，写入审计行）")
	cmdConfirmDrift.Flags().StringVar(&cf.AuditFile, "file", "", "audit.jsonl 路径（默认 $XINCHUANG_AUDIT_FILE 或 ./logs/audit.jsonl）")
	cmdConfirmDrift.Flags().StringVar(&cf.DBPath, "db", "", "trial store bbolt 路径（默认 $XINCHUANG_DB_FILE 或 ./data/trial.db）")

	_ = cmdConfirmDrift.MarkFlagRequired("action")
	_ = cmdConfirmDrift.MarkFlagRequired("operator")

	rootCmd.AddCommand(cmdConfirmDrift)
}