# xinchuang-db-guardian · Makefile
# 一键 build / test / lint / run / clean
# 入口二进制默认落在 ./bin/xinchuang-guardian
# 详细命令见 README.md「主命令速查」

BIN_DIR     := bin
BIN_NAME    := xinchuang-guardian
BIN_PATH    := $(BIN_DIR)/$(BIN_NAME)
PKG         := ./cmd/xinchuang-guardian
CONFIG_EX   := config/contracts.example.yaml
LOG_DIR     := logs

.PHONY: build test test-race lint run clean help

## help: 列出所有 make target 及其用途
help:
	@echo "xinchuang-db-guardian · make targets"
	@echo "  build       编译入口二进制到 $(BIN_PATH)"
	@echo "  test        全量单元测试（go test ./... -count=1）"
	@echo "  test-race   全量测试 + race detector（耗时较长）"
	@echo "  lint        go vet ./...（零 warning 才视为通过）"
	@echo "  run         以 contracts.example.yaml 启动守护（需先 build）"
	@echo "  clean       删除 $(LOG_DIR)/ 与 $(BIN_DIR)/ 的运行时产物"

## build: 编译入口二进制
build:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -o $(BIN_PATH) $(PKG)
	@echo "[build] OK → $(BIN_PATH)"

## test: 全量单元测试（与 scripts/full_regression.sh 行为一致但更轻）
test:
	go test ./... -count=1

## test-race: 全量测试 + race detector（CI / 并发层回归专用）
test-race:
	go test -race ./... -count=1

## lint: 静态检查（go vet，无 warning 视为通过）
lint:
	go vet ./...

## run: 用示例 contracts 启动守护（先 build）
run: build
	$(BIN_PATH) start --config $(CONFIG_EX)

## clean: 删除 logs/ 与 bin/（保留 docs/ / testdata/ / config/）
clean:
	rm -rf $(LOG_DIR) $(BIN_DIR)
	@echo "[clean] removed $(LOG_DIR)/ and $(BIN_DIR)/"
