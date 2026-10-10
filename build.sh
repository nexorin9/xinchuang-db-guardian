#!/usr/bin/env bash
# xinchuang-db-guardian · build.sh
# 与 Makefile `build` 等价的 shell 实现
# 用途：CI / 容器 / 无 make 的环境下单独编译入口二进制

set -euo pipefail

BIN_DIR="bin"
BIN_NAME="xinchuang-guardian"
BIN_PATH="${BIN_DIR}/${BIN_NAME}"
PKG="./cmd/xinchuang-guardian"

echo "[build] target = ${BIN_PATH}"
mkdir -p "${BIN_DIR}"

# 拉依赖（幂等，已 cached 时秒返）
go mod download

# 编译（-trimpath 抹掉本机路径以保证二进制可复现）
go build -trimpath -o "${BIN_PATH}" "${PKG}"

echo "[build] OK → ${BIN_PATH}"
echo "[build] sha256 = $(sha256sum "${BIN_PATH}" | awk '{print $1}')"
