// Package main 提供信创数据库合规漂移守护的命令行入口。
//
// 设计参考 cilium cilium-health/responder/main.go:22-52 的守护运行时结构：
// signal.NotifyContext 包装 SIGINT/SIGHUP/SIGTERM/SIGQUIT、启动期写 pidfile、
// <-ctx.Done() 退出时清理 pidfile 并优雅关闭。
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// 默认 pidfile 路径（可被 XINCHUANG_PIDFILE 环境变量覆盖）。
const defaultPidfilePath = "/var/run/xc-guardian.pid"

// 守护退出码：成功 / 通用错误 / 配置错 / 启动期错 / 子命令执行错。
const (
	exitOK               = 0
	exitGeneric          = 1
	exitConfig           = 2
	exitStartup          = 3
	exitSubcommandFailed = 4
)

// 全局 slog JSON handler；main 启动期初始化；测试可重写。
var (
	logger     *slog.Logger
	loggerOnce sync.Once
)

// ResolvePidfilePath 计算 pidfile 路径：env > 默认值。
func ResolvePidfilePath() string {
	if v := strings.TrimSpace(os.Getenv("XINCHUANG_PIDFILE")); v != "" {
		return v
	}
	return defaultPidfilePath
}

// ResolveLogLevel 把字符串映射到 slog.Level；非法值回落 info。
func ResolveLogLevel() slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("XINCHUANG_LOG_LEVEL"))) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// InitLogger 初始化全局 JSON handler；在 main 启动期 + 测试 init 各调一次幂等。
func InitLogger() {
	loggerOnce.Do(func() {
		h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: ResolveLogLevel()})
		logger = slog.New(h)
		slog.SetDefault(logger)
	})
}

// WritePidfile 确保父目录存在后写入当前进程 pid；失败返回错误。
func WritePidfile(path string) error {
	if path == "" {
		return errors.New("pidfile path is empty")
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir pidfile dir: %w", err)
		}
	}
	pid := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(path, []byte(pid+"\n"), 0o644); err != nil {
		return fmt.Errorf("write pidfile %q: %w", path, err)
	}
	return nil
}

// RemovePidfile 删 pidfile；不存在视作成功（idempotent）。
func RemovePidfile(path string) error {
	if path == "" {
		return nil
	}
	err := os.Remove(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("remove pidfile %q: %w", path, err)
}

// RunDaemon 是 start 子命令的核心循环：占位 — 后续 task 接入 probe/check/audit 主路径。
// 当前仅做：写 pidfile + 等 ctx 退出 + 退出前清理。
func RunDaemon(ctx context.Context, pidfilePath string) error {
	InitLogger()
	logger.Info("daemon_starting", slog.String("pidfile", pidfilePath), slog.Int("pid", os.Getpid()))

	if err := WritePidfile(pidfilePath); err != nil {
		logger.Error("pidfile_write_failed", slog.String("err", err.Error()))
		return err
	}

	g, gctx := errgroup.WithContext(ctx)

	// 子协程：每秒心跳，证明守护处于活跃状态（后续 task 可替换为 probe 调度）。
	g.Go(func() error {
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		var beats uint64
		for {
			select {
			case <-gctx.Done():
				logger.Info("daemon_heartbeat_stop", slog.Uint64("beats", beats))
				return nil
			case <-t.C:
				beats++
				if beats%10 == 0 {
					logger.Debug("daemon_heartbeat", slog.Uint64("beats", beats))
				}
			}
		}
	})

	<-gctx.Done()
	logger.Info("graceful_shutdown_initiated")

	// 关闭 errgroup；等待子协程退出。
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("daemon_subtask_error", slog.String("err", err.Error()))
	}

	if err := RemovePidfile(pidfilePath); err != nil {
		logger.Error("pidfile_remove_failed", slog.String("err", err.Error()))
	} else {
		logger.Info("pidfile_removed", slog.String("path", pidfilePath))
	}

	logger.Info("graceful_shutdown")
	return nil
}

// rootCmd 是 Cobra 根命令。
var rootCmd = &cobra.Command{
	Use:   "xinchuang-guardian",
	Short: "信创数据库合规漂移守护",
	Long: `xinchuang-db-guardian 是面向信息科值班工位的单机常驻守护：

  - 按 contracts.yaml 合同白名单对院内 12 个声明信创数据库做三维核对
    （portRaw vs version_pattern + driverSha vs allow_drift_sha256 + jdbcURL pattern）
  - 命中漂移入 trial 状态并通过企业微信 webhook + SMTP 推送卡片
  - 落 append-only sha256 JSONL 审计链
  - LLM（OpenAI-compatible）仅在规则不能定论时给 verdict 兜底解释，
    不可达自动降级回规则 verdict；trial 永不静默推进，
    由人工 confirm-drift CLI 推进 trial → confirmed / remedied / disputed
  - 飞检前 1 分钟 export-evidence --last 30d 输出 evidence.zip`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		InitLogger()
		return nil
	},
}

// cmdStart 启动守护进程（写 pidfile + 等信号 + 优雅退出）。
var cmdStart = &cobra.Command{
	Use:   "start",
	Short: "启动守护进程（前台常驻）",
	RunE: func(cmd *cobra.Command, args []string) error {
		InitLogger()
		pidfilePath, _ := cmd.Flags().GetString("pidfile")
		if v := strings.TrimSpace(os.Getenv("XINCHUANG_PIDFILE")); v != "" {
			pidfilePath = v
		}
		if pidfilePath == "" {
			pidfilePath = ResolvePidfilePath()
		}

		parentCtx, cancel := signal.NotifyContext(
			context.Background(),
			syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT,
		)
		defer cancel()

		if err := RunDaemon(parentCtx, pidfilePath); err != nil {
			return err
		}
		return nil
	},
}

// cmdStatus 查询守护状态（读 pidfile + 探测进程是否存活）。
var cmdStatus = &cobra.Command{
	Use:   "status",
	Short: "查询守护状态",
	RunE: func(cmd *cobra.Command, args []string) error {
		InitLogger()
		pidfilePath, _ := cmd.Flags().GetString("pidfile")
		if pidfilePath == "" {
			pidfilePath = ResolvePidfilePath()
		}
		data, err := os.ReadFile(pidfilePath)
		if err != nil {
			logger.Error("status_read_pidfile_failed", slog.String("err", err.Error()))
			return err
		}
		pid, perr := strconv.Atoi(strings.TrimSpace(string(data)))
		if perr != nil {
			logger.Error("status_parse_pid_failed", slog.String("err", perr.Error()))
			return perr
		}
		proc, perr := os.FindProcess(pid)
		if perr != nil {
			logger.Warn("status_process_lookup", slog.Int("pid", pid), slog.String("err", perr.Error()))
			return nil
		}
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			logger.Warn("status_process_dead", slog.Int("pid", pid), slog.String("err", err.Error()))
			return nil
		}
		logger.Info("status_ok", slog.Int("pid", pid), slog.String("pidfile", pidfilePath))
		return nil
	},
}

// cmdStop 停止守护进程（发 SIGTERM + 等待 pidfile 清理）。
var cmdStop = &cobra.Command{
	Use:   "stop",
	Short: "停止守护进程",
	RunE: func(cmd *cobra.Command, args []string) error {
		InitLogger()
		pidfilePath, _ := cmd.Flags().GetString("pidfile")
		if pidfilePath == "" {
			pidfilePath = ResolvePidfilePath()
		}
		data, err := os.ReadFile(pidfilePath)
		if err != nil {
			logger.Error("stop_read_pidfile_failed", slog.String("err", err.Error()))
			return err
		}
		pid, perr := strconv.Atoi(strings.TrimSpace(string(data)))
		if perr != nil {
			return perr
		}
		proc, _ := os.FindProcess(pid)
		if err := proc.Signal(syscall.SIGTERM); err != nil {
			logger.Error("stop_signal_failed", slog.Int("pid", pid), slog.String("err", err.Error()))
			return err
		}
		logger.Info("stop_signal_sent", slog.Int("pid", pid))
		// 等 pidfile 清理（守护 graceful_shutdown 会删 pidfile）
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, ferr := os.Stat(pidfilePath); errors.Is(ferr, os.ErrNotExist) {
				logger.Info("stop_acked", slog.Int("pid", pid))
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		logger.Warn("stop_timeout", slog.Int("pid", pid))
		return nil
	},
}

// cmdVerifyOnly 单次扫描验证（不进入守护循环）。
var cmdVerifyOnly = &cobra.Command{
	Use:   "verify-only",
	Short: "单次扫描验证（不进入守护循环；占位 — 后续 task 接入 probe/check/audit）",
	RunE: func(cmd *cobra.Command, args []string) error {
		InitLogger()
		logger.Info("verify_only_placeholder", slog.String("note", "T2 stub — 后续 task 接入三维核对主路径"))
		return nil
	},
}

// cmdExportEvidence 导出飞检证据 zip — 真实实现在 cmd_export.go。
// （本文件保留 stub 仅作为注释占位，便于阅读 daemon 完整命令集。）
// 实际注册见 cmd_export.go 的 init()。

// cmdConfirmDrift 人工推进 trial 状态 — 真实实现在 cmd_confirm.go。
// （本文件保留 stub 注释占位，便于阅读 daemon 完整命令集。）
// 实际注册见 cmd_confirm.go 的 init()。

func init() {
	// pidfile 默认值（可被 env 覆盖）
	pidfileFlag := ""
	cmdStart.Flags().StringVar(&pidfileFlag, "pidfile", "", "pidfile 路径（默认 $XINCHUANG_PIDFILE 或 /var/run/xc-guardian.pid）")
	cmdStatus.Flags().StringVar(&pidfileFlag, "pidfile", "", "pidfile 路径")
	cmdStop.Flags().StringVar(&pidfileFlag, "pidfile", "", "pidfile 路径")

	rootCmd.AddCommand(cmdStart, cmdStatus, cmdStop, cmdVerifyOnly, cmdExportEvidence, auditCmd)
}

// main 启动期：init logger → 解析 cobra → 运行子命令。
func main() {
	InitLogger()

	// Cobra 执行：所有子命令错误经 PersistentPreRunE 包装后写到 stderr + slog。
	rootCmd.SetErr(os.Stderr)
	if err := rootCmd.Execute(); err != nil {
		logger.Error("command_execution_failed", slog.String("err", err.Error()))
		// 区分：flag 解析错走 exitSubcommandFailed，其余走 exitGeneric
		if isFlagParseErr(err) {
			os.Exit(exitSubcommandFailed)
		}
		os.Exit(exitGeneric)
	}
	os.Exit(exitOK)
}

// isFlagParseErr 通过错误信息前缀匹配 cobra/pflag 的 parse 错。
func isFlagParseErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "unknown flag") ||
		strings.Contains(msg, "required flag(s) missing") ||
		strings.Contains(msg, "required flag(s) \"") || // cobra 实际格式：`required flag(s) "action" not set`
		strings.Contains(msg, "no such flag") ||
		strings.Contains(msg, "invalid argument") ||
		strings.Contains(msg, "bad flag syntax") ||
		strings.Contains(msg, "accepts ") // cobra.ExactArgs 错：`accepts 1 arg(s), received 0`
}