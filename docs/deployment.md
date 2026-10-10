# 部署指南（Systemd + Docker）

本文档说明 **信创数据库合规漂移守护（xinchuang-db-guardian）** 的两种标准部署路径：

1. **Systemd unit**（推荐用于生产信息科工位 · 裸机/虚拟机部署）
2. **Docker 单镜像**（推荐用于 PoC / 容器化环境 / 快速验证）

> 两种部署共享同一份 `contracts.yaml` / `vendor_signatures.yaml` / `.env` 配置文件；差异仅在进程托管方式。

---

## 路径 1：Systemd 部署（推荐）

### 前置条件

| 项 | 要求 |
|----|------|
| 操作系统 | Linux（CentOS 7+ / Ubuntu 18.04+ / openEuler 20.03+ 等）；systemd ≥ 230（支持 `Type=notify`） |
| 二进制 | `xinchuang-guardian`（Go 1.22+ 静态链接，单文件 ~8 MB） |
| 配置目录 | `/etc/xinchuang-guardian/`（含 `contracts.yaml` / `vendor_signatures.yaml` / `.env`） |
| 日志目录 | `/var/log/xinchuang-guardian/` |
| 系统用户 | `xcg`（`useradd -r -s /usr/sbin/nologin xcg`） |

### 安装步骤

```bash
# 1. 创建系统用户（仅首次）
sudo useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/xcg xcg

# 2. 准备配置目录
sudo mkdir -p /etc/xinchuang-guardian \
              /var/log/xinchuang-guardian \
              /var/lib/xcg
sudo chown -R xcg:xcg /var/log/xinchuang-guardian /var/lib/xcg
sudo chmod 0750 /etc/xinchuang-guardian

# 3. 安装二进制（从 GitHub Release 下载或本地编译）
sudo install -m 0755 ./xinchuang-guardian /usr/local/bin/xinchuang-guardian

# 4. 复制合同白名单与凭据
sudo install -m 0644 ./config/contracts.example.yaml \
                 /etc/xinchuang-guardian/contracts.yaml
sudo install -m 0644 ./config/vendor_signatures.example.yaml \
                 /etc/xinchuang-guardian/vendor_signatures.yaml
# .env 由信息科手工创建，**不要**复制 example
sudo cp .env.example /etc/xinchuang-guardian/.env
sudo chmod 0640 /etc/xinchuang-guardian/.env
sudo chown root:xcg /etc/xinchuang-guardian/.env

# 5. 安装 systemd unit
sudo install -m 0644 ./deployment/systemd/xinchuang-guardian.service \
                 /etc/systemd/system/xinchuang-guardian.service

# 6. 重新加载 + 开机自启 + 立即启动
sudo systemctl daemon-reload
sudo systemctl enable xinchuang-guardian
sudo systemctl start xinchuang-guardian
```

### 健康检查

```bash
# 查看服务状态
sudo systemctl status xinchuang-guardian

# 查看实时日志（journald → slog JSON）
sudo journalctl -u xinchuang-guardian -f

# 健康探针（守护自带 ping）
sudo systemctl is-active xinchuang-guardian
sudo journalctl -u xinchuang-guardian -n 50 --no-pager

# 验证 pidfile + 进程存活
cat /var/run/xc-guardian.pid
ps -fp $(cat /var/run/xc-guardian.pid)
```

### 优雅重启 / 停止

```bash
# 优雅重启（飞检期间不轻易重启；如必须先确认审计链已 VerifyChain）
sudo systemctl reload xinchuang-guardian

# 优雅停止（30s 等待 graceful_shutdown）
sudo systemctl stop xinchuang-guardian

# 立即停止（**不推荐**：可能丢失本次扫描结果；不清理 pidfile）
sudo systemctl kill --signal=SIGKILL xinchuang-guardian
sudo rm -f /var/run/xc-guardian.pid
```

### 飞检前证据导出

```bash
# 在宿主机直接调二进制导出 30 天证据包
sudo -u xcg /usr/local/bin/xinchuang-guardian export-evidence \
  --config /etc/xinchuang-guardian/contracts.yaml \
  --last 30d \
  --out /var/log/xinchuang-guardian/evidence-$(date +%Y%m%d).zip

# 校验证据包完整性
cd /var/log/xinchuang-guardian
unzip -p evidence-*.zip manifest.sha256 | sha256sum -c -

# 校验审计链完整
sudo -u xcg /usr/local/bin/xinchuang-guardian audit verify-chain \
  --file /var/log/xinchuang-guardian/audit.jsonl
# 期望输出：{"status":"ok","rows":N}
```

### 升级 / 卸载

```bash
# 升级：先停服 → 备份配置 → 替换二进制 → 启服
sudo systemctl stop xinchuang-guardian
sudo cp -a /etc/xinchuang-guardian /etc/xinchuang-guardian.bak.$(date +%Y%m%d)
sudo install -m 0755 ./xinchuang-guardian /usr/local/bin/xinchuang-guardian
sudo systemctl start xinchuang-guardian

# 卸载
sudo systemctl disable --now xinchuang-guardian
sudo rm -f /etc/systemd/system/xinchuang-guardian.service
sudo rm -f /usr/local/bin/xinchuang-guardian
# 配置 / 日志 / 证据包按信息科保留策略决定是否删除
```

---

## 路径 2：Docker 单镜像部署

### 前置条件

| 项 | 要求 |
|----|------|
| Docker Engine | ≥ 20.10（支持 BuildKit + multi-stage） |
| Docker Compose | v2.20+（`docker compose` 子命令） |
| 宿主机目录 | `./config/` `./logs/` `./.env` `./run/` |

### 构建镜像

```bash
# 在项目根目录
docker build -t xinchuang-db-guardian:1.0.0 \
  -f docker/Dockerfile \
  --build-arg VERSION=1.0.0 \
  --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) .

# 验证镜像可启动
docker run --rm xinchuang-db-guardian:1.0.0 --help
# 期望：输出 Cobra help + 7 个子命令列表（start / status / stop / verify-only /
#       export-evidence / audit verify-chain / confirm-drift）
```

### 准备配置

```bash
# 1. 复制并编辑合同白名单
cp config/contracts.example.yaml config/contracts.yaml
vim config/contracts.yaml  # 填入 12 个 system_id 的 host / port / 驱动目录

# 2. 复制并编辑凭据
cp .env.example .env
vim .env  # 填入 WECHAT_WEBHOOK_URL / SMTP_PASSWORD / LLM_API_KEY 等

# 3. 准备运行目录
mkdir -p logs run
```

### 启动容器

```bash
# 前台（调试用）
docker compose -f docker-compose.example.yml up

# 后台守护
docker compose -f docker-compose.example.yml up -d

# 查看实时日志
docker compose -f docker-compose.example.yml logs -f

# 健康状态
docker compose -f docker-compose.example.yml ps
```

### 容器内运维操作

```bash
# 查看守护状态
docker compose -f docker-compose.example.yml exec xinchuang-guardian status

# 飞检前证据导出
docker compose -f docker-compose.example.yml exec xinchuang-guardian \
  xinchuang-guardian export-evidence \
  --last 30d \
  --out /var/log/xinchuang-guardian/evidence-$(date +%Y%m%d).zip

# 审计链校验
docker compose -f docker-compose.example.yml exec xinchuang-guardian \
  xinchuang-guardian audit verify-chain \
  --file /var/log/xinchuang-guardian/audit.jsonl

# 手工推进漂移状态（如已与厂商确认）
docker compose -f docker-compose.example.yml exec xinchuang-guardian \
  xinchuang-guardian confirm-drift <event_id> \
  --action remedied --operator 张主任

# 优雅停止（compose 给 30s graceful_shutdown）
docker compose -f docker-compose.example.yml down

# 强制停止 + 清理
docker compose -f docker-compose.example.yml down --remove-orphans
```

### 镜像清理

```bash
# 停止并删除容器（保留卷与镜像）
docker compose -f docker-compose.example.yml down

# 删除镜像
docker rmi xinchuang-db-guardian:1.0.0
```

---

## 路径选择建议

| 场景 | 推荐路径 | 理由 |
|------|----------|------|
| 信息科工位裸机/虚拟机 | **Systemd** | 启动最快、journald 原生日志、systemctl 直接管理、飞检组熟悉 |
| 等保 / 等保三级环境 | **Systemd** | 可与 SELinux / AppArmor 联动；守护以非 root 用户运行 |
| PoC / 临时验证 / CI 测试 | **Docker** | 一行命令启动；与本机其它服务隔离 |
| Kubernetes 集群 | 自定义 Helm Chart（本仓库不提供） | 二进制可作为 DaemonSet 部署，但 contracts.yaml / pidfile 需要 ConfigMap + hostPath |

---

## 凭据与权限

**所有凭据均从环境变量读取，禁止硬编码**：

| 环境变量 | 用途 | 是否必填 |
|----------|------|----------|
| `XINCHUANG_PIDFILE` | pidfile 路径 | 否（默认 `/var/run/xc-guardian.pid`） |
| `XINCHUANG_LOG_LEVEL` | slog 级别 `debug/info/warn/error` | 否（默认 `info`） |
| `XINCHUANG_AUDIT_FILE` | 审计 JSONL 路径 | 否（默认 `./logs/audit.jsonl`） |
| `DB_PROBE_USER` | 数据库握手探测用户名（仅 `Q SELECT 1`） | 是 |
| `WECHAT_WEBHOOK_URL` | 企业微信 webhook | 是 |
| `SMTP_HOST/PORT/USERNAME/PASSWORD/TO/FROM` | SMTP 出站 | 是 |
| `LLM_BASE_URL/API_KEY/MODEL` | OpenAI-compatible LLM 网关 | 是 |

**`/etc/xinchuang-guardian/.env` 必须 0640 + `root:xcg`**；**禁止**进 Git 仓库（`.gitignore` 已排除 `.env`）。

---

## 故障排查

| 现象 | 排查路径 |
|------|----------|
| 守护启动后立即退出 | `journalctl -u xinchuang-guardian -n 50`；检查 `contracts.yaml` 是否含 12 条 system_id、port 范围、version_pattern 编译 |
| 漂移命中但企微卡片未送达 | `WECHAT_WEBHOOK_URL` 是否可达（`curl -X POST -d '{...}' $WECHAT_WEBHOOK_URL`）；HTTP 4xx 不重试，5xx 重试 1 次 |
| `audit verify-chain` 报 `bad_insert` | 审计链中检测到反插行为；立即保留 `audit.jsonl` 现场 + 通知安全岗 |
| 容器启动后 `--version` 报 binary not found | `docker-compose.example.yml` volumes 路径在 Linux 宿主机大小写敏感；检查 `./.env` 是否存在 |
| 端口 5xx 后 SMTP 收不到邮件 | SMTP 端口 465/587 区分（`SMTP_MODE=tls` vs `starttls`）；SMTP_PASSWORD 错误不重试 |

---

## 与飞检流程的衔接

| 飞检节点 | 守护交付 |
|----------|----------|
| 飞检前 1 周 | 日常 trial/remedied 状态已收敛；`audit verify-chain` 通过 |
| 飞检前 1 分钟 | `export-evidence --last 30d --out evidence-30d.zip` 一键导出 |
| 飞检现场质疑「此库真为声明品牌」 | 拆 `evidence-30d.zip` → `raw_probe_responses/<system_id>.txt` 直接给飞检组看 |
| 飞检组追溯某条漂移 | `audit verify-chain` + `evidence.jsonl` 自带 sha256 链；不可篡改 |
| 飞检后整改 | `confirm-drift <event_id> --action remedied --operator 张主任` 推进状态 |

