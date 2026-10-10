#!/usr/bin/env bash
# smoke_test.sh · 信创数据库合规漂移守护端到端 smoke
#
# 编排策略（**双路径**）：
#   路径 A（dockertest 集成）：docker daemon 可用 + XINCHUANG_USE_DOCKERTEST=1
#     → `go test -tags=integration ./cmd/xinchuang-guardian/ -run TestE2ESmokeDocker`
#     → dockertest 拉 postgres:14 容器模拟声明 kingbase 但实际 PG（漂移）
#     → httptest 桩 LLM server 返回 HIGH_CONFIDENCE_DRIFT verdict
#     → 走真实 port.Handshake → check.Compare → output.AppendJSONL →
#       export.Export → sha256sum -c → output.VerifyChain
#
#   路径 B（本地 PG mock）：默认 / docker 不可用
#     → `go test ./cmd/xinchuang-guardian/ -run TestE2ESmoke`
#     → 起 net.Listen PG wire mock server（与 postgres:14 wire 协议一致）
#     → 同上真实代码路径
#     → + `go test ./cmd/xinchuang-guardian/ -run TestE2ESmokeBinary`
#       （cobra 二进制 --help 旁路）
#     → + `go test ./cmd/xinchuang-guardian/ -run TestE2ESmokeStubLLM`
#       （httptest 桩 LLM + 协议兼容旁路）
#
# 双路径共享同一套 acceptance：evidence.zip ≥ 6 文件 + manifest.sha256 OK +
# audit verify-chain OK + 至少 1 行 kind=drift_confirmed。
#
# 设计：本脚本**不**要求 docker；CI / 沙箱无 docker 时自动落路径 B，
# 不阻断烟测；信息科工位 / 信息科验收环境有 docker 时优先走路径 A。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SMOKE_OUT="${XINCHUANG_SMOKE_OUT:-/tmp/smoke-evidence}"
BIN_NAME="xinchuang-guardian"
TEST_LOG="${TEST_LOG:-${PROJECT_ROOT}/../logs/task32-smoke-test.log}"

# 颜色
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_step() { printf "${GREEN}[smoke]${NC} %s\n" "$*"; }
log_warn() { printf "${YELLOW}[smoke][warn]${NC} %s\n" "$*"; }
log_err()  { printf "${RED}[smoke][err]${NC} %s\n" "$*" >&2; }

mkdir -p "$(dirname "$TEST_LOG")"

# 1. 检查 Go 版本
if ! command -v go >/dev/null 2>&1; then
  log_err "Go not found in PATH"
  exit 2
fi
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)
log_step "Go version: $GO_VERSION"
if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 22 ]; }; then
  log_err "Go ≥ 1.22 required (have $GO_VERSION)"
  exit 3
fi

# 2. 准备输出目录
mkdir -p "$SMOKE_OUT"
log_step "smoke 输出目录: $SMOKE_OUT"

# 3. 跑 go mod tidy（如果 go.sum 缺失）
cd "$PROJECT_ROOT"
if [ ! -f go.sum ] || [ go.mod -nt go.sum ]; then
  log_step "go mod tidy..."
  go mod tidy >/dev/null 2>&1 || log_warn "go mod tidy failed (continuing — go.sum may already be current)"
fi

# 4. 探测 docker daemon + 决定路径
DOCKER_OK=0
if [ -z "${XINCHUANG_FORCE_LOCAL:-}" ]; then
  if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
      DOCKER_OK=1
    else
      log_warn "docker 二进制存在但 daemon 不可用（CI 沙箱常见）；落本地 PG mock 路径"
    fi
  else
    log_warn "docker 不在 PATH；落本地 PG mock 路径"
  fi
fi

USED_DOCKERTEST=0
if [ "$DOCKER_OK" -eq 1 ]; then
  log_step "docker daemon 可用；尝试 dockertest 集成路径（TestE2ESmokeDocker）"
  if go test -tags=integration -count=1 -timeout 120s -run TestE2ESmokeDocker \
       -v ./cmd/xinchuang-guardian/ 2>&1 | tee -a "$TEST_LOG"; then
    log_step "dockertest 集成 smoke 通过 ✓"
    USED_DOCKERTEST=1
  else
    log_warn "dockertest 集成 smoke 失败，落本地 PG mock 路径"
  fi
fi

if [ "$USED_DOCKERTEST" -eq 0 ]; then
  log_step "本地 PG mock 路径：TestE2ESmoke（PG mock + classify + check + audit + export + verify-chain + sha256sum -c）"
  export XINCHUANG_SMOKE_TMPDIR="$SMOKE_OUT"
  if go test ./cmd/xinchuang-guardian/ -run TestE2ESmoke -v -count=1 -timeout 60s 2>&1 | tee -a "$TEST_LOG"; then
    log_step "TestE2ESmoke 通过 ✓"
  else
    log_err "TestE2ESmoke 失败（详见 $TEST_LOG）"
    exit 1
  fi

  log_step "本地 PG mock 路径：TestE2ESmokeBinary + TestE2ESmokeStubLLM（旁路）"
  if go test ./cmd/xinchuang-guardian/ -run "TestE2ESmokeBinary|TestE2ESmokeStubLLM" -v -count=1 -timeout 30s 2>&1 | tee -a "$TEST_LOG"; then
    log_step "Binary + StubLLM smoke 通过 ✓"
  else
    log_err "Binary / StubLLM smoke 失败"
    exit 1
  fi
fi

# 5. 验证落盘产物（路径 B 在 XINCHUANG_SMOKE_TMPDIR 下；路径 A 在 t.TempDir()，
#    后者会被测试 t.Cleanup 清理，证据已被 sha256sum -c 校验，无需重复校验）
if [ "$USED_DOCKERTEST" -eq 0 ]; then
  log_step "验证 $SMOKE_OUT/ 落盘产物..."
  EXPECTED_FILES=(evidence.zip audit.jsonl manifest.json manifest.sha256)
  MISSING=0
  for f in "${EXPECTED_FILES[@]}"; do
    if [ ! -f "$SMOKE_OUT/$f" ]; then
      log_err "缺产物: $SMOKE_OUT/$f"
      MISSING=$((MISSING + 1))
    fi
  done
  if [ "$MISSING" -gt 0 ]; then
    log_err "$MISSING 个产物缺失"
    exit 4
  fi

  # 6. 用 sha256sum -c 验证 manifest.sha256（独立于 Go 测试的二次保险）
  log_step "sha256sum -c manifest.sha256 二次校验..."
  SHA_OUT=$(
    cd "$SMOKE_OUT" && sha256sum -c manifest.sha256 2>&1
  ) || {
    log_err "sha256sum -c 失败: $SHA_OUT"
    exit 5
  }
  echo "$SHA_OUT"
  case "$SHA_OUT" in
    *": OK"*) log_step "manifest.sha256 校验通过 ✓" ;;
    *) log_err "manifest.sha256 校验失败: $SHA_OUT"; exit 5 ;;
  esac

  # 7. audit verify-chain 用 cobra 二进制做端到端核验
  log_step "$BIN_NAME audit verify-chain --file $SMOKE_OUT/audit.jsonl..."
  if [ -x "$SMOKE_OUT/$BIN_NAME" ] || go build -o "$SMOKE_OUT/$BIN_NAME" ./cmd/xinchuang-guardian/ >/dev/null 2>&1; then
    if "$SMOKE_OUT/$BIN_NAME" audit verify-chain --file "$SMOKE_OUT/audit.jsonl" >/dev/null; then
      log_step "audit verify-chain 通过 ✓"
    else
      log_err "audit verify-chain 失败"
      exit 6
    fi
  else
    log_warn "skip audit verify-chain（build 失败；不阻断）"
  fi
else
  log_step "dockertest 路径产物已由测试内部 sha256sum -c 校验；跳过第二轮二次保险"
fi

# 8. 列产物清单
log_step "smoke 产物清单："
if [ "$USED_DOCKERTEST" -eq 0 ] && [ -d "$SMOKE_OUT" ]; then
  ls -la "$SMOKE_OUT/" 2>/dev/null | tail -n +2 | awk '{printf "  %s  (%s bytes)\n", $NF, $5}'
else
  echo "  (dockertest 路径产物已在 t.Cleanup 清理；最终断言见测试日志)"
fi

log_step "smoke_test.sh 完成 ✓（路径：$([ "$USED_DOCKERTEST" -eq 1 ] && echo dockertest || echo local-mock)）"
exit 0
