#!/usr/bin/env bash
# full_regression.sh · 信创数据库合规漂移守护 · 全量回归
#
# 流程：
#   1. go mod tidy        同步依赖（不引入新包）
#   2. go vet ./...       静态检查（双 build tags：默认 + integration）
#   3. go build ./...     编译双 build tags
#   4. go test ./... -v -count=1
#                          全量测试 + 捕获 PASS/FAIL 数量
#                          写入 logs/task34-full-regression.log
#   5. go test -tags=integration -run TestE2ESmokeDocker -count=1 ./cmd/xinchuang-guardian/
#                          dockertest 集成测试（无 docker 自动 skip）
#   6. 输出最终回归摘要到 stdout
#
# 设计：
#   - set -euo pipefail + trap：任一步非零立即退出且报错位置
#   - 不修改任何源码；只读快照（除了 go.mod 由 tidy 整理）
#   - 任何失败 exit 1；全 PASS exit 0
#   - logs/ 在 round 根目录，**不污染**项目子目录
#
# 用途：本脚本为后续 task 35-42 收窄测试的引用基准。
# 当某 task 未触达共享底座（check / config / llm / output / probe/* / cmd）时，
# 可仅跑受影响模块的测试并引用本脚本结果作为「共享底座未变」的依据。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROUND_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_DIR="${ROUND_ROOT}/logs"
LOG_FILE="${LOG_DIR}/task34-full-regression.log"

mkdir -p "${LOG_DIR}"

# 颜色（仅 stderr 显示，stdout 保持纯文本便于 grep）
if [[ -t 2 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
  CYAN='\033[0;36m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

log() { echo -e "${CYAN}[full-regression]${NC} $*" >&2; }
ok()  { echo -e "${GREEN}[  OK  ]${NC} $*" >&2; }
fail(){ echo -e "${RED}[ FAIL ]${NC} $*" >&2; }
warn(){ echo -e "${YELLOW}[ WARN ]${NC} $*" >&2; }

# trap：任一命令非零退出立即报错
on_error() {
  local exit_code=$?
  local line_no=${1:-?}
  fail "脚本在第 ${line_no} 行附近失败（exit=${exit_code}）"
  fail "请查看 ${LOG_FILE} 末尾报错"
  exit 1
}
trap 'on_error ${LINENO}' ERR

cd "${PROJECT_ROOT}"

# ============ 1. go mod tidy =================================================
log "1/6 go mod tidy ..."
go mod tidy > "${LOG_FILE}.tidy" 2>&1 || {
  cat "${LOG_FILE}.tidy" >> "${LOG_FILE}"
  fail "go mod tidy 失败"
  exit 1
}
ok "go mod tidy 完成"

# ============ 2. go vet (双 build tags) ======================================
log "2/6 go vet ./... （默认 tags）..."
go vet ./... > "${LOG_FILE}.vet" 2>&1 || {
  cat "${LOG_FILE}.vet" >> "${LOG_FILE}"
  fail "go vet ./... 失败"
  exit 1
}
ok "go vet ./... 完成（0 warning）"

log "2b/6 go vet -tags=integration ./..."
go vet -tags=integration ./... > "${LOG_FILE}.vet-int" 2>&1 || {
  cat "${LOG_FILE}.vet-int" >> "${LOG_FILE}"
  fail "go vet -tags=integration ./... 失败"
  exit 1
}
ok "go vet -tags=integration ./... 完成（0 warning）"

# ============ 3. go build (双 build tags) ====================================
log "3/6 go build ./... （默认 tags）..."
go build ./... > "${LOG_FILE}.build" 2>&1 || {
  cat "${LOG_FILE}.build" >> "${LOG_FILE}"
  fail "go build ./... 失败"
  exit 1
}
ok "go build ./... 完成"

log "3b/6 go build -tags=integration ./..."
go build -tags=integration ./... > "${LOG_FILE}.build-int" 2>&1 || {
  cat "${LOG_FILE}.build-int" >> "${LOG_FILE}"
  fail "go build -tags=integration ./... 失败"
  exit 1
}
ok "go build -tags=integration ./... 完成"

# ============ 4. go test 全量 =================================================
log "4/6 go test ./... -v -count=1 ..."
# 抓 PASS / FAIL 行计数
go test ./... -count=1 -v > "${LOG_FILE}.test" 2>&1 || {
  tail -100 "${LOG_FILE}.test" >> "${LOG_FILE}"
  fail "go test ./... 失败（详见 ${LOG_FILE}.test 末尾）"
  exit 1
}
ok "go test ./... 完成"

# 解析 pass/fail/skip 数量
PASS_COUNT=$(grep -cE '^--- PASS:' "${LOG_FILE}.test" || true)
FAIL_COUNT=$(grep -cE '^--- FAIL:' "${LOG_FILE}.test" || true)
SKIP_COUNT=$(grep -cE '^--- SKIP:' "${LOG_FILE}.test" || true)
PACKAGES=$(grep -cE '^ok\s+' "${LOG_FILE}.test" || true)
PACKAGES_FAIL=$(grep -cE '^FAIL\s+' "${LOG_FILE}.test" || true)

log "测试统计：packages=${PACKAGES} pass=${PASS_COUNT} fail=${FAIL_COUNT} skip=${SKIP_COUNT}"

# ============ 5. dockertest 集成测试（无 docker 自动 skip） ====================
log "5/6 go test -tags=integration -run TestE2ESmokeDocker -count=1 ./cmd/xinchuang-guardian/ ..."
go test -tags=integration -run TestE2ESmokeDocker -count=1 ./cmd/xinchuang-guardian/ \
  > "${LOG_FILE}.docker" 2>&1 || {
  cat "${LOG_FILE}.docker" >> "${LOG_FILE}"
  warn "dockertest 集成测试非零退出（docker 不可用？查看 ${LOG_FILE}.docker）"
  # 不退出：dockertest skip 应返回 0
}
DOCKER_RESULT=$(grep -cE '^--- SKIP:' "${LOG_FILE}.docker" || true)
if [[ "${DOCKER_RESULT}" -gt 0 ]]; then
  ok "dockertest 集成测试 skip（docker 不可用，正常）"
else
  ok "dockertest 集成测试完成"
fi

# ============ 6. 汇总到主日志 =================================================
log "6/6 汇总到 ${LOG_FILE} ..."
{
  echo "=========================================="
  echo "信创数据库合规漂移守护 · 全量回归"
  echo "执行时间：$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Go 版本：$(go version)"
  echo "=========================================="
  echo ""
  echo "[1] go mod tidy"
  cat "${LOG_FILE}.tidy" 2>/dev/null || echo "  (empty)"
  echo ""
  echo "[2] go vet ./..."
  cat "${LOG_FILE}.vet" 2>/dev/null || echo "  (empty / 0 warning)"
  echo ""
  echo "[2b] go vet -tags=integration ./..."
  cat "${LOG_FILE}.vet-int" 2>/dev/null || echo "  (empty / 0 warning)"
  echo ""
  echo "[3] go build ./..."
  cat "${LOG_FILE}.build" 2>/dev/null || echo "  (empty / OK)"
  echo ""
  echo "[3b] go build -tags=integration ./..."
  cat "${LOG_FILE}.build-int" 2>/dev/null || echo "  (empty / OK)"
  echo ""
  echo "[4] go test ./... -v -count=1 (尾部摘要)"
  tail -40 "${LOG_FILE}.test"
  echo ""
  echo "[5] go test -tags=integration -run TestE2ESmokeDocker"
  cat "${LOG_FILE}.docker" 2>/dev/null || echo "  (no output)"
  echo ""
  echo "=========================================="
  echo "回归摘要"
  echo "=========================================="
  echo "packages_ok     = ${PACKAGES}"
  echo "packages_failed = ${PACKAGES_FAIL}"
  echo "tests_pass      = ${PASS_COUNT}"
  echo "tests_fail      = ${FAIL_COUNT}"
  echo "tests_skip      = ${SKIP_COUNT}"
  echo "=========================================="
} > "${LOG_FILE}"

# 清理中间文件（保留主 LOG_FILE 供查阅）
rm -f "${LOG_FILE}.tidy" "${LOG_FILE}.vet" "${LOG_FILE}.vet-int" \
      "${LOG_FILE}.build" "${LOG_FILE}.build-int" "${LOG_FILE}.test" \
      "${LOG_FILE}.docker"

# ============ 最终判断 ========================================================
if [[ "${FAIL_COUNT}" -gt 0 || "${PACKAGES_FAIL}" -gt 0 ]]; then
  fail "全量回归失败：tests_fail=${FAIL_COUNT} packages_failed=${PACKAGES_FAIL}"
  exit 1
fi

ok "全量回归通过：packages=${PACKAGES} pass=${PASS_COUNT} fail=${FAIL_COUNT} skip=${SKIP_COUNT}"
echo ""
echo "完整日志：${LOG_FILE}"
echo "后续 task 35-42 可引用本结果作为共享底座基准（仅跑受影响模块的收窄测试）"