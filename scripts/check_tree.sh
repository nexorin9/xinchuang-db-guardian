#!/usr/bin/env bash
# check_tree.sh · 任务数与目录树最终自检
#
# 目的：核对本轮 45 task 全部已落盘 + 目录结构完整 + 关键命令在 README 中
#       已对照 + 构建脚本存在性检查。
#
# 检查范围（不阻断 exit code，全部为 PASS/WARN/FAIL 标注）：
#   1. 目录结构：find xinchuang-db-guardian -type d >= 14 个
#   2. 必需子目录：cmd/ internal/{app,check,classify,config,export,llm,output,probe/{driver,port,version}}
#      docs/{concepts,screenshots} scripts config deployment docker test testdata
#   3. 关键源文件：go.mod / go.sum / README.md / qrcode.jpg / .gitignore / .env.example
#   4. scripts/ 三件套 + 辅助：demo.sh / smoke_test.sh / full_regression.sh
#   5. task.json 任务统计：>= MIN_TASKS (12) + 上限 MAX_TASKS (80) 区间内
#   6. README.md 丰度下限：>= 10 个 `##` / >= 8 个 `###` / >= 5 行表格 / >= 8 代码块 / >= 5000 字符
#   7. README.md 关键命令出现：go test / go build / go vet / xinchuang-guardian / scripts/
#   8. Makefile 或 build.sh 存在性（**WARN 级别**：T39 任务将创建二者之一）
#   9. task.json proof 字段非空率：passes=true 的任务必须有可复核 proof
#  10. 部署交付物：deployment/systemd/*.service / docker/Dockerfile / docker-compose.example.yml
#
# 用法：
#   bash scripts/check_tree.sh
#   bash scripts/check_tree.sh --strict    # 把 WARN 也升级为 exit 1
#   bash scripts/check_tree.sh --json      # JSON 输出便于 CI 抓取
#
# 退出码：0 = 关键检查全部通过；1 = 关键检查失败（FAIL）；3 = 参数错
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROUND_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ---- 参数解析 ----
STRICT=0
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --strict) STRICT=1; shift ;;
    --json)   JSON_OUT=1; shift ;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0 ;;
    *)
      echo "ERROR: 未知参数 $1（仅 --strict / --json / -h）" >&2
      exit 3 ;;
  esac
done

# ---- 计数器 ----
PASS=0
WARN=0
FAIL=0
JSON_LINES=()

record() {
  local status="$1" name="$2" detail="$3"
  case "$status" in
    PASS) PASS=$((PASS+1)); [ "$JSON_OUT" -eq 0 ] && printf "  [PASS] %-50s %s\n" "$name" "$detail" ;;
    WARN) WARN=$((WARN+1)); [ "$JSON_OUT" -eq 0 ] && printf "  [WARN] %-50s %s\n" "$name" "$detail" ;;
    FAIL) FAIL=$((FAIL+1)); [ "$JSON_OUT" -eq 0 ] && printf "  [FAIL] %-50s %s\n" "$name" "$detail" ;;
  esac
  JSON_LINES+=("{\"status\":\"$status\",\"check\":\"$name\",\"detail\":\"$detail\"}")
}

# ---- 1. 目录结构总数 ----
DIR_COUNT=$(find "${PROJECT_ROOT}" -type d 2>/dev/null | wc -l | tr -d ' ')
if [ "$DIR_COUNT" -ge 14 ]; then
  record PASS "directory_count" "${DIR_COUNT} 个（≥14 达标）"
else
  record FAIL "directory_count" "${DIR_COUNT} 个（<14 未达标）"
fi

# ---- 2. 必需子目录存在性 ----
REQUIRED_DIRS=(
  "cmd" "cmd/xinchuang-guardian"
  "internal/app" "internal/check" "internal/classify" "internal/config"
  "internal/export" "internal/llm" "internal/output"
  "internal/probe" "internal/probe/driver" "internal/probe/port" "internal/probe/version"
  "docs/concepts" "docs/screenshots"
  "scripts" "config" "testdata" "test" "test/integration" "test/mockservers"
  "deployment" "deployment/systemd" "docker"
)
MISSING_DIRS=()
for d in "${REQUIRED_DIRS[@]}"; do
  if [ ! -d "${PROJECT_ROOT}/${d}" ]; then
    MISSING_DIRS+=("$d")
  fi
done
if [ "${#MISSING_DIRS[@]}" -eq 0 ]; then
  record PASS "required_dirs" "${#REQUIRED_DIRS[@]}/${#REQUIRED_DIRS[@]} 全部存在"
else
  record FAIL "required_dirs" "缺失 ${#MISSING_DIRS[@]} 个：${MISSING_DIRS[*]}"
fi

# ---- 3. 关键源文件 ----
REQUIRED_FILES=(
  "go.mod" "go.sum" "README.md" "qrcode.jpg" ".gitignore" ".env.example"
)
MISSING_FILES=()
for f in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "${PROJECT_ROOT}/${f}" ]; then
    MISSING_FILES+=("$f")
  fi
done
if [ "${#MISSING_FILES[@]}" -eq 0 ]; then
  record PASS "required_files" "${#REQUIRED_FILES[@]}/${#REQUIRED_FILES[@]} 全部存在"
else
  record FAIL "required_files" "缺失 ${#MISSING_FILES[@]} 个：${MISSING_FILES[*]}"
fi

# ---- 4. scripts/ 三件套 ----
SCRIPT_FILES=("demo.sh" "smoke_test.sh" "full_regression.sh")
MISSING_SCRIPTS=()
for s in "${SCRIPT_FILES[@]}"; do
  if [ ! -f "${PROJECT_ROOT}/scripts/${s}" ]; then
    MISSING_SCRIPTS+=("$s")
  fi
done
if [ "${#MISSING_SCRIPTS[@]}" -eq 0 ]; then
  record PASS "scripts_trio" "demo.sh + smoke_test.sh + full_regression.sh 齐全"
else
  record FAIL "scripts_trio" "缺失：${MISSING_SCRIPTS[*]}"
fi

# ---- 5. task.json 任务统计 ----
TASK_JSON="${ROUND_ROOT}/task.json"
if [ ! -f "${TASK_JSON}" ]; then
  record FAIL "task_json" "${TASK_JSON} 不存在"
else
  TOTAL=$(grep -c '"id":' "${TASK_JSON}")
  PASSED=$(grep -c '"passes": true' "${TASK_JSON}")
  INPROG=$(grep -c '"passes": false' "${TASK_JSON}")
  if [ "$TOTAL" -ge 12 ] && [ "$TOTAL" -le 80 ]; then
    record PASS "task_count" "${TOTAL} 个（在 12–80 区间内；已通过 ${PASSED}，未通过 ${INPROG}）"
  else
    record FAIL "task_count" "${TOTAL} 个（不在 12–80 区间）"
  fi
fi

# ---- 6. README.md 丰度下限 ----
README="${PROJECT_ROOT}/README.md"
if [ ! -f "${README}" ]; then
  record FAIL "readme_exists" "README.md 不存在"
else
  H2=$(grep -c '^## ' "${README}")
  H3=$(grep -c '^### ' "${README}")
  TB=$(grep -c '^|' "${README}")
  CF=$(grep -c '^```' "${README}")
  WC=$(wc -c < "${README}" | tr -d ' ')
  if [ "$H2" -ge 10 ] && [ "$H3" -ge 8 ] && [ "$TB" -ge 5 ] && [ "$CF" -ge 8 ] && [ "$WC" -ge 5000 ]; then
    record PASS "readme_richness" "##=${H2} ###=${H3} 表格=${TB} 代码块=${CF} 字符=${WC}（全部达标）"
  else
    record FAIL "readme_richness" "##=${H2} ###=${H3} 表格=${TB} 代码块=${CF} 字符=${WC}（部分未达标）"
  fi
fi

# ---- 7. README.md 关键命令出现 ----
KEY_CMDS=("go test" "go build" "go vet" "xinchuang-guardian" "scripts/")
MISSING_CMDS=()
for c in "${KEY_CMDS[@]}"; do
  cnt=$(grep -c "$c" "${README}" 2>/dev/null || echo 0)
  if [ "$cnt" -lt 1 ]; then
    MISSING_CMDS+=("$c")
  fi
done
if [ "${#MISSING_CMDS[@]}" -eq 0 ]; then
  record PASS "readme_commands" "5/5 关键命令串均出现"
else
  record FAIL "readme_commands" "缺失：${MISSING_CMDS[*]}"
fi

# ---- 8. Makefile 或 build.sh 存在性 ----
# 备注：T39 任务将创建二者之一；T38 检查时可能尚未创建，故为 WARN。
HAS_MAKEFILE=0
[ -f "${PROJECT_ROOT}/Makefile" ] && HAS_MAKEFILE=1
HAS_BUILDSH=0
[ -f "${PROJECT_ROOT}/build.sh" ] && HAS_BUILDSH=1
if [ "$HAS_MAKEFILE" -eq 1 ] || [ "$HAS_BUILDSH" -eq 1 ]; then
  WHICH=""
  [ "$HAS_MAKEFILE" -eq 1 ] && WHICH="${WHICH}Makefile "
  [ "$HAS_BUILDSH" -eq 1 ]   && WHICH="${WHICH}build.sh "
  record PASS "build_target" "存在构建入口：${WHICH}"
else
  record WARN "build_target" "Makefile 与 build.sh 均不存在（T39 任务将创建其一）"
fi

# ---- 9. task.json proof 字段非空率 ----
if [ -f "${TASK_JSON}" ]; then
  # 通过 Python 解析（macOS 默认 sed 体系下避免 BRE/ERE 切换麻烦）
  PROOF_STATS=$(python3 -c "
import json, sys
with open('${TASK_JSON}') as f:
    data = json.load(f)
tasks = data.get('tasks', [])
total = len(tasks)
passed = sum(1 for t in tasks if t.get('passes') is True)
empty_proof = sum(1 for t in tasks if t.get('passes') is True and not (t.get('proof') or '').strip())
print(f'{total} {passed} {empty_proof}')
" 2>/dev/null || echo "0 0 0")
  TOTAL=$(echo "$PROOF_STATS" | awk '{print $1}')
  PASSED=$(echo "$PROOF_STATS" | awk '{print $2}')
  EMPTY=$(echo "$PROOF_STATS" | awk '{print $3}')
  if [ "$EMPTY" -eq 0 ] && [ "$PASSED" -gt 0 ]; then
    record PASS "proof_density" "${PASSED}/${PASSED} 已通过任务 proof 非空"
  elif [ "$PASSED" -eq 0 ]; then
    record WARN "proof_density" "尚无通过任务（T38 处于早期阶段）"
  else
    record FAIL "proof_density" "${EMPTY}/${PASSED} 已通过任务 proof 为空"
  fi
fi

# ---- 10. 部署交付物 ----
DEPLOY_FILES=("deployment/systemd/xinchuang-guardian.service" "docker/Dockerfile" "docker-compose.example.yml" "docs/deployment.md")
MISSING_DEPLOY=()
for f in "${DEPLOY_FILES[@]}"; do
  if [ ! -f "${PROJECT_ROOT}/${f}" ]; then
    MISSING_DEPLOY+=("$f")
  fi
done
if [ "${#MISSING_DEPLOY[@]}" -eq 0 ]; then
  record PASS "deploy_artifacts" "systemd unit + Dockerfile + compose + docs/deployment.md 齐全"
else
  record FAIL "deploy_artifacts" "缺失：${MISSING_DEPLOY[*]}"
fi

# ---- 汇总 ----
TOTAL=$((PASS + WARN + FAIL))
[ "$JSON_OUT" -eq 0 ] && echo "" && echo "=========================================="
[ "$JSON_OUT" -eq 0 ] && echo "check_tree.sh 汇总：${PASS} PASS / ${WARN} WARN / ${FAIL} FAIL（共 ${TOTAL} 项）"
[ "$JSON_OUT" -eq 0 ] && echo "=========================================="

if [ "$JSON_OUT" -eq 1 ]; then
  printf '{"summary":{"pass":%d,"warn":%d,"fail":%d},"checks":[\n' "$PASS" "$WARN" "$FAIL"
  FIRST=1
  for line in "${JSON_LINES[@]}"; do
    if [ "$FIRST" -eq 1 ]; then
      printf '  %s\n' "$line"
      FIRST=0
    else
      printf ', %s\n' "$line"
    fi
  done
  printf ']}\n'
fi

# ---- 退出码决策 ----
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
if [ "$STRICT" -eq 1 ] && [ "$WARN" -gt 0 ]; then
  exit 1
fi
exit 0