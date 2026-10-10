#!/usr/bin/env bash
# demo.sh · 信创数据库合规漂移守护 · 一键端到端体验
#
# 流程（仿信息科工位第一次接触本工具）：
#   1. 检查 Go ≥ 1.22
#   2. go mod download 拉依赖
#   3. go build 编译守护二进制到 /tmp/xinchuang-guardian-demo/xinchuang-guardian
#   4. 准备 demo 工作目录（contracts.yaml / vendor_signatures.yaml / audit.jsonl / pidfile）
#   5. 装载 stub env（LLM_BASE_URL=http://127.0.0.1:0 → 不可达 → 自动降级规则 verdict）
#   6. 后台启动守护二进制（写 pidfile + 阻塞在 <-ctx.Done()）
#   7. 模拟一次漂移（go test -run TestE2ESmoke 走真实代码路径：起 PG wire mock
#      → 声明 mock 为 kingbase → 真实 port.Handshake → 真实 check.Compare →
#      真实 AppendJSONL → 落 3 行审计 + evidence.zip + manifest.sha256）
#   8. 用守护二进制 `export-evidence --last 1h --out <new_zip>` 再装订一份证据包
#      （验证 CLI 入口真实可跑，不是 mock）
#   9. 用守护二进制 `audit verify-chain --file <audit.jsonl>` 校验 hash 链完整
#  10. `stop` 守护（发 SIGTERM → pidfile 自动清理）
#  11. 显示所有产物路径 + tail 日志
#
# 设计取舍：
#   - 不依赖 docker（与 smoke_test.sh 共享同一策略）；
#   - 不引入 Python/Node 替身；测试替身一律用 Go test + Go 程序实现；
#   - 仅修改 /tmp 路径下的临时文件；项目目录零污染；
#   - 出错不静默吞错：set -euo pipefail + 显式 exit code；
#   - LLM_BASE_URL 故意指向 127.0.0.1:0（端口占位）→ connect refused → 走
#     规则 verdict fallback，验证 5xx/不可达降级路径真实生效。

set -euo pipefail

# --- 路径常量 ----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEMO_ROOT="${XINCHUANG_DEMO_ROOT:-/tmp/xinchuang-guardian-demo}"
BIN_PATH="${DEMO_ROOT}/xinchuang-guardian"
LOG_PATH="${DEMO_ROOT}/demo.log"
TEST_LOG="${PROJECT_ROOT}/../logs/task33-demo.log"

# 颜色
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_step() { printf "${GREEN}[demo]${NC} %s\n" "$*"; }
log_warn() { printf "${YELLOW}[demo][warn]${NC} %s\n" "$*"; }
log_err()  { printf "${RED}[demo][err]${NC} %s\n" "$*" >&2; }

mkdir -p "$(dirname "$TEST_LOG")"

cleanup() {
  local rc=$?
  # 尝试优雅停止守护
  if [ -f "${DEMO_ROOT}/xc-guardian.pid" ]; then
    local pid
    pid="$(cat "${DEMO_ROOT}/xc-guardian.pid" 2>/dev/null || true)"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      log_step "cleanup: kill -TERM ${pid}"
      kill -TERM "$pid" 2>/dev/null || true
      # 等待 pidfile 清理
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ ! -f "${DEMO_ROOT}/xc-guardian.pid" ] && break
        sleep 0.2
      done
    fi
  fi
  if [ $rc -eq 0 ]; then
    log_step "demo.sh 完成 ✓ (exit 0)"
  else
    log_err "demo.sh 退出 (exit ${rc})"
  fi
  return $rc
}
trap cleanup EXIT INT TERM

# --- 1. Go 版本检查 -----------------------------------------------------------
log_step "1/10 检查 Go 版本..."
if ! command -v go >/dev/null 2>&1; then
  log_err "Go 不在 PATH；请安装 Go ≥ 1.22 后再跑 demo"
  exit 2
fi
GO_VERSION="$(go version | awk '{print $3}' | sed 's/go//')"
GO_MAJOR="$(echo "$GO_VERSION" | cut -d. -f1)"
GO_MINOR="$(echo "$GO_VERSION" | cut -d. -f2)"
log_step "Go 版本: ${GO_VERSION}"
if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 22 ]; }; then
  log_err "Go ≥ 1.22 required (have ${GO_VERSION})"
  exit 3
fi

# --- 2. 准备 demo 工作目录 ----------------------------------------------------
log_step "2/10 准备 demo 工作目录 ${DEMO_ROOT} ..."
rm -rf "$DEMO_ROOT"
mkdir -p "$DEMO_ROOT"
mkdir -p "${DEMO_ROOT}/jdbc/kingbase"  # 占位 jdbc_driver_dirs
mkdir -p "${DEMO_ROOT}/jdbc/dm"
mkdir -p "${DEMO_ROOT}/jdbc/opengauss"

# --- 3. 写 demo 专用 contracts.yaml（仅 1 条 system：demo-pg drift）-----------
log_step "3/10 写 demo contracts.yaml / vendor_signatures.yaml ..."
cat > "${DEMO_ROOT}/contracts.yaml" <<'EOF'
declared:
  - system_id: demo-pg
    vendor: kingbase
    version_pattern: "(?i)KingbaseES\\s+V\\d+R\\d+C\\d+"
    allow_drift_sha256: []
    contract_id: HT-DEMO-001
    host: 127.0.0.1
    port: 65530  # demo 测试桩默认占位端口；TestE2ESmoke 会动态替换
    scan_interval: 5s
    jdbc_driver_dirs:
      - /tmp/xinchuang-guardian-demo/jdbc/kingbase
    event_id_prefix: EVT-DEMO
EOF

cat > "${DEMO_ROOT}/vendor_signatures.yaml" <<'EOF'
brands:
  - brand: kingbase
    version_regex:
      - "(?i)KingbaseES\\s+V\\d+R\\d+C\\d+"
    jdbc_url_pattern:
      - "jdbc:kingbase8://[^:]+:[0-9]+/[^?]+"
    signature_tokens:
      - "KingbaseES"
      - "V008"
    known_jar_sha256: []

  - brand: pg-compat
    version_regex:
      - "PostgreSQL\\s+\\d+\\.\\d+(\\.\\d+)?"
    jdbc_url_pattern:
      - "jdbc:postgresql://[^:]+:[0-9]+/[^?]+"
    signature_tokens:
      - "PostgreSQL"
    known_jar_sha256: []
EOF

# --- 4. 装载 stub env（LLM 不可达 → 走规则 verdict fallback）------------------
log_step "4/10 装载 stub env（LLM_BASE_URL → 127.0.0.1:0 不可达）..."
cat > "${DEMO_ROOT}/demo.env" <<'EOF'
XINCHUANG_PIDFILE=/tmp/xinchuang-guardian-demo/xc-guardian.pid
XINCHUANG_LOG_LEVEL=info
XINCHUANG_AUDIT_FILE=/tmp/xinchuang-guardian-demo/audit.jsonl
XINCHUANG_DB_FILE=/tmp/xinchuang-guardian-demo/trial_state.db
DEDUP_WINDOW_SECS=300
DB_PROBE_USER=xc_probe
WECHAT_WEBHOOK_URL=
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=xc-demo@example.com
SMTP_PASSWORD=
LLM_BASE_URL=http://127.0.0.1:0
LLM_API_KEY=demo-stub-key
LLM_MODEL=gpt-4o-mini-demo
LLM_TIMEOUT_SECS=2
EOF

# --- 5. go mod download -------------------------------------------------------
log_step "5/10 go mod download ..."
cd "$PROJECT_ROOT"
if [ ! -f go.sum ] || [ go.mod -nt go.sum ]; then
  go mod download >/dev/null 2>&1 || log_warn "go mod download 非零退出（可能依赖已就绪）"
else
  log_step "go.sum 已就绪，跳过 download"
fi

# --- 6. 编译守护二进制 --------------------------------------------------------
log_step "6/10 go build -o ${BIN_PATH} ./cmd/xinchuang-guardian ..."
cd "$PROJECT_ROOT"
go build -trimpath -o "$BIN_PATH" ./cmd/xinchuang-guardian
if [ ! -x "$BIN_PATH" ]; then
  log_err "二进制未生成：$BIN_PATH"
  exit 4
fi
log_step "二进制大小: $(du -h "$BIN_PATH" | awk '{print $1}')"

# --- 7. 后台启动守护（写 pidfile + 阻塞在 ctx.Done）-------------------------
# 说明：当前 start 子命令只接受 --pidfile flag（XINCHUANG_PIDFILE env 已覆盖默认
# /var/run/xc-guardian.pid）。守护主循环的具体 probe 调度在后续 task 落地，
# demo 阶段守护仅负责：写 pidfile → 阻塞在 <-ctx.Done() → SIGTERM 时清理
# pidfile 并 graceful_shutdown。这一段验证的是 **生命周期 + 进程通信**。
log_step "7/10 后台启动守护 ..."
# shellcheck disable=SC1090
set -a; source "${DEMO_ROOT}/demo.env"; set +a
# 用 env 装载 stub；然后后台跑 start
nohup "$BIN_PATH" start >"$LOG_PATH" 2>&1 &
DPID=$!
disown $DPID 2>/dev/null || true
# 等待 pidfile 出现（守护启动时写）
DEADLINE=$((SECONDS + 8))
while [ $SECONDS -lt $DEADLINE ]; do
  if [ -f "${DEMO_ROOT}/xc-guardian.pid" ]; then
    READ_PID="$(cat "${DEMO_ROOT}/xc-guardian.pid" 2>/dev/null || echo '')"
    if [ -n "$READ_PID" ] && kill -0 "$READ_PID" 2>/dev/null; then
      log_step "守护已启动 pid=${READ_PID}"
      break
    fi
  fi
  sleep 0.2
done
if [ ! -f "${DEMO_ROOT}/xc-guardian.pid" ]; then
  log_err "守护未在 8s 内写 pidfile；tail 日志："
  tail -30 "$LOG_PATH" || true
  exit 5
fi

# 健康检查（cobra --help 验证二进制 CLI OK）
if "$BIN_PATH" --help >/dev/null 2>&1; then
  log_step "二进制 --help 健康检查通过 ✓"
else
  log_err "二进制 --help 失败"
  exit 5
fi

# --- 8. 模拟一次漂移（走真实代码路径：PG mock → drift → audit.jsonl → evidence.zip）
log_step "8/10 模拟一次漂移（TestE2ESmoke 走真实代码路径）..."
cd "$PROJECT_ROOT"
export XINCHUANG_SMOKE_TMPDIR="$DEMO_ROOT"
# TestE2ESmoke 内部已经写 audit.jsonl / evidence.zip / manifest.json / manifest.sha256 到 tmpDir
# 同时也复制到 XINCHUANG_SMOKE_TMPDIR（详见 smoke_e2e_test.go 第 450-460 行）
if go test ./cmd/xinchuang-guardian/ -run TestE2ESmoke -v -count=1 -timeout 60s \
     >>"$TEST_LOG" 2>&1; then
  log_step "TestE2ESmoke 通过 ✓"
else
  log_err "TestE2ESmoke 失败（详见 $TEST_LOG）"
  tail -30 "$TEST_LOG" || true
  exit 6
fi

# 等待 evidence.zip 落盘（理论上 test 内部已写；再保险 sleep 200ms）
sleep 0.3
for f in evidence.zip audit.jsonl manifest.json manifest.sha256; do
  if [ ! -f "${DEMO_ROOT}/${f}" ]; then
    log_err "demo 产物缺失: ${DEMO_ROOT}/${f}"
    exit 7
  fi
done
log_step "落盘产物：evidence.zip + audit.jsonl + manifest.json + manifest.sha256 全部就位 ✓"

# --- 9. 用守护二进制 export-evidence --last 1h 重新装订一份（验证 CLI 真入口）--
log_step "9/10 xinchuang-guardian export-evidence --last 1h --out ${DEMO_ROOT}/evidence-fresh.zip ..."
if "$BIN_PATH" export-evidence \
     --config "${DEMO_ROOT}/contracts.yaml" \
     --last 1h \
     --out "${DEMO_ROOT}/evidence-fresh.zip" \
     >>"$LOG_PATH" 2>&1; then
  log_step "export-evidence 完成 ✓ ($(du -h "${DEMO_ROOT}/evidence-fresh.zip" | awk '{print $1}'))"
else
  log_err "export-evidence 失败（详见 ${LOG_PATH}）"
  exit 8
fi
# 二次保险：sha256sum -c manifest.sha256 校验
log_step "sha256sum -c manifest.sha256 二次校验 ..."
cd "$DEMO_ROOT"
SHA_OUT="$(sha256sum -c manifest.sha256 2>&1)" || {
  log_err "sha256sum -c 失败: $SHA_OUT"
  exit 9
}
echo "$SHA_OUT"
case "$SHA_OUT" in
  *": OK"*) log_step "manifest.sha256 校验通过 ✓" ;;
  *) log_err "manifest.sha256 校验失败: $SHA_OUT"; exit 9 ;;
esac

# --- 10. audit verify-chain ----------------------------------------------------
log_step "10/10 xinchuang-guardian audit verify-chain --file ${DEMO_ROOT}/audit.jsonl ..."
if "$BIN_PATH" audit verify-chain --file "${DEMO_ROOT}/audit.jsonl" >>"$LOG_PATH" 2>&1; then
  log_step "audit verify-chain 通过 ✓"
else
  log_err "audit verify-chain 失败"
  exit 10
fi

# --- 落盘产物清单 -------------------------------------------------------------
log_step "demo 落盘产物清单（${DEMO_ROOT}）："
ls -la "$DEMO_ROOT" 2>/dev/null | tail -n +2 | awk '{printf "  %s  (%s bytes)\n", $NF, $5}' | grep -v '^\s*\.$\|^\s*\.\.$\|^\s*$' || true

# --- 产物 manifest 摘要 ------------------------------------------------------
log_step "manifest.json 摘要："
if [ -f "${DEMO_ROOT}/manifest.json" ]; then
  cat "${DEMO_ROOT}/manifest.json"
fi
echo

# --- 审计链 tail 摘要 --------------------------------------------------------
log_step "audit.jsonl 摘要（前 3 行）："
if [ -f "${DEMO_ROOT}/audit.jsonl" ]; then
  head -3 "${DEMO_ROOT}/audit.jsonl" || true
fi
echo

# 守护会在 cleanup trap 里被 SIGTERM 杀掉；显式退出 0
log_step "全部 10 步完成 ✓"
exit 0
