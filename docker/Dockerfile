# 信创数据库合规漂移守护（xinchuang-db-guardian）— 单镜像构建
#
# 构建方式：
#   docker build -t xinchuang-db-guardian:test -f docker/Dockerfile .
#
# 运行方式：
#   docker run --rm -v "$PWD/config:/etc/xinchuang-guardian:ro" \
#     -v "$PWD/logs:/var/log/xinchuang-guardian" \
#     xinchuang-db-guardian:test --help

# ----- 阶段 1：编译（multi-stage · alpine + Go 1.22+）-----
FROM golang:1.25-alpine AS builder

# 安装 git（go mod download 需要）+ ca-certificates（出站 HTTPS 需要）
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# 先复制 go.mod / go.sum：依赖未变时利用 Docker layer cache
COPY go.mod go.sum ./
RUN go mod download

# 复制源码
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# 静态链接（alpine 静态二进制便于单文件发布 + alpine runtime 兼容）
ARG VERSION=dev
ARG GIT_COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -ldflags="-s -w \
        -X 'main.Version=${VERSION}' \
        -X 'main.GitCommit=${GIT_COMMIT}'" \
      -trimpath \
      -o /out/xinchuang-guardian \
      ./cmd/xinchuang-guardian

# 验证二进制可启动 + Cobra help 输出
RUN /out/xinchuang-guardian --help > /dev/null && \
    /out/xinchuang-guardian start --help > /dev/null

# ----- 阶段 2：运行时（alpine 3.19 · 小体积）-----
FROM alpine:3.19

# 安装 tzdata + ca-certificates + tini（PID 1 信号转发）
RUN apk add --no-cache ca-certificates tzdata tini

# 创建系统用户 xcg（与 systemd unit 保持一致；容器内非必须但便于一致性）
RUN addgroup -S xcg && adduser -S -G xcg -h /var/lib/xcg -s /sbin/nologin xcg

# 工作目录 + 日志 + 配置目录
RUN mkdir -p /etc/xinchuang-guardian \
             /var/log/xinchuang-guardian \
             /var/run && \
    chown -R xcg:xcg /etc/xinchuang-guardian \
                       /var/log/xinchuang-guardian \
                       /var/run

# 从 builder 阶段拷贝二进制
COPY --from=builder /out/xinchuang-guardian /usr/local/bin/xinchuang-guardian

# 二进制可执行 + 验证
RUN chmod +x /usr/local/bin/xinchuang-guardian && \
    /usr/local/bin/xinchuang-guardian --version || true

# 默认环境变量（覆盖可由 docker run -e 或 docker-compose 注入）
ENV XINCHUANG_LOG_LEVEL=info \
    XINCHUANG_PIDFILE=/var/run/xc-guardian.pid \
    XINCHUANG_AUDIT_FILE=/var/log/xinchuang-guardian/audit.jsonl

# 默认 UID/GID（非 root 启动，符合 systemd 单元安全配置）
USER xcg:xcg
WORKDIR /var/lib/xcg

# 暴露端口：本守护是事件驱动 + 出站 webhook / SMTP / LLM，零入站 HTTP
# EXPOSE 仅作文档提示；无任何入站监听
# EXPOSE 0

# tini 作为 PID 1：转发 SIGTERM 给守护进程触发 graceful_shutdown
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/xinchuang-guardian"]

# 默认命令：显示 Cobra help（docker run 默认看到产品清单）
CMD ["--help"]

# 健康检查：调用 --version 验证二进制可启动
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
  CMD /usr/local/bin/xinchuang-guardian --version > /dev/null || exit 1

# 元数据
LABEL org.opencontainers.image.title="xinchuang-db-guardian" \
      org.opencontainers.image.description="信创数据库合规漂移守护：声明合同 vs 实际握手 + 驱动 sha + JDBC URL 三维核对" \
      org.opencontainers.image.source="https://github.com/xinchuang/db-guardian" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
