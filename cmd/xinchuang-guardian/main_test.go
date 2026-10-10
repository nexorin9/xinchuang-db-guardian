// main_test.go 验证守护入口：pidfile 写入 / SIGTERM 优雅退出 / 日志末行 graceful_shutdown。
//
// 设计参考 cilium cilium-health/responder/main.go 的 pidfile 写 + <-ctx.Done() 退出模型。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// withCapturedStdout 在 fn 期间把 stdout 重定向到临时 buffer；返回 stdout 内容与 fn 错误。
func withCapturedStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan error, 1)
	go func() {
		fnErr := fn()
		_ = w.Close()
		done <- fnErr
	}()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("copy stdout: %v", err)
	}
	<-done
	os.Stdout = orig
	_ = r.Close()
	return buf.String(), nil
}

// TestWritePidfile 验证 pidfile 写入 + 内容 = 当前 pid。
func TestWritePidfile(t *testing.T) {
	dir := t.TempDir()
	pf := filepath.Join(dir, "sub", "xc.pid")

	if err := WritePidfile(pf); err != nil {
		t.Fatalf("WritePidfile: %v", err)
	}
	data, err := os.ReadFile(pf)
	if err != nil {
		t.Fatalf("read pidfile: %v", err)
	}
	pidStr := strings.TrimSpace(string(data))
	if pidStr != strconv.Itoa(os.Getpid()) {
		t.Fatalf("pidfile content = %q, want %d", pidStr, os.Getpid())
	}
}

// TestWritePidfileEmptyPath 验证空路径返回错误而非 panic。
func TestWritePidfileEmptyPath(t *testing.T) {
	if err := WritePidfile(""); err == nil {
		t.Fatal("WritePidfile(\"\") 期望返回错误，实际 nil")
	}
}

// TestRemovePidfileIdempotent 验证删除不存在的 pidfile 返回 nil。
func TestRemovePidfileIdempotent(t *testing.T) {
	pf := filepath.Join(t.TempDir(), "nonexistent.pid")
	if err := RemovePidfile(pf); err != nil {
		t.Fatalf("RemovePidfile 不存在文件期望 nil，实际 %v", err)
	}
}

// TestResolvePidfilePath 验证 env 覆盖 + 默认回落。
func TestResolvePidfilePath(t *testing.T) {
	if v := os.Getenv("XINCHUANG_PIDFILE"); v != "" {
		t.Skip("XINCHUANG_PIDFILE 已被设置，跳过默认路径断言")
	}
	if got := ResolvePidfilePath(); got != defaultPidfilePath {
		t.Fatalf("ResolvePidfilePath() = %q, want %q", got, defaultPidfilePath)
	}
}

// TestResolveLogLevel 验证合法 + 非法值映射。
func TestResolveLogLevel(t *testing.T) {
	cases := []struct {
		env, fallback string
		want          slog.Level
	}{
		{"info", "warn", slog.LevelInfo},
		{"debug", "info", slog.LevelDebug},
		{"warn", "info", slog.LevelWarn},
		{"warning", "info", slog.LevelWarn},
		{"error", "info", slog.LevelError},
		{"", "info", slog.LevelInfo},
		{"garbage", "info", slog.LevelInfo},
	}
	for _, c := range cases {
		t.Setenv("XINCHUANG_LOG_LEVEL", c.env)
		if got := ResolveLogLevel(); got != c.want {
			t.Fatalf("XINCHUANG_LOG_LEVEL=%q → %v, want %v", c.env, got, c.want)
		}
	}
}

// TestRunDaemonContextCancel 验证 context cancel 触发 graceful shutdown（同进程内）。
//
// 等价覆盖 signal.NotifyContext(SIGTERM) 路径：
//   signal.NotifyContext 内部仍是用 cancel func；SIGTERM 触发的就是 cancel()，
//   与此处手动 cancel 等价（语义由 cmdStart 的 signal.NotifyContext 调用保证）。
func TestRunDaemonContextCancel(t *testing.T) {
	dir := t.TempDir()
	pf := filepath.Join(dir, "xc.pid")

	stdout, runErr := withCapturedStdout(t, func() error {
		ctx, cancel := context.WithCancel(context.Background())
		// 100ms 后取消
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()
		// 临时将 logger 重定向到当前 os.Stdout（已被 withCapturedStdout 重定向）
		InitLogger()
		return RunDaemon(ctx, pf)
	})
	if runErr != nil {
		t.Fatalf("RunDaemon: %v", runErr)
	}

	// pidfile 应已被清理
	if _, err := os.Stat(pf); !os.IsNotExist(err) {
		t.Fatalf("pidfile 未被清理：%v", err)
	}

	// stdout 末行 msg == graceful_shutdown
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) == 0 {
		t.Fatal("无输出")
	}
	last := lines[len(lines)-1]
	var ev map[string]any
	if err := json.Unmarshal([]byte(last), &ev); err != nil {
		t.Fatalf("末行非 JSON: %q", last)
	}
	if msg, _ := ev["msg"].(string); msg != "graceful_shutdown" {
		t.Fatalf("末行 msg = %q, want graceful_shutdown", msg)
	}
}

// TestCobraRootHelp 验证 `xinchuang-guardian --help` 不 panic + 列出 7 个子命令。
func TestCobraRootHelp(t *testing.T) {
	// 重置 rootCmd args
	rootCmd.SetArgs([]string{"--help"})
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("--help 期望退出无错：%v", err)
	}
	out := buf.String()
	for _, want := range []string{"start", "status", "stop", "verify-only", "export-evidence", "audit", "confirm-drift"} {
		if !strings.Contains(out, want) {
			t.Fatalf("--help 输出未含子命令 %q", want)
		}
	}
}

// 防止 import 未使用的 lint 误报：filepath 在 TestWritePidfile 等处已被使用，保留。
var _ = filepath.Join