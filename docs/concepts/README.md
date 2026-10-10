# 视觉目标卡（结构化 · 无图像生成能力时使用）

> 本项目运行环境无图像生成能力，故仅写结构化视觉目标卡；不伪造图片。
> 实测证据（终端真实运行截图 / 报告样本）见 `../screenshots/`。

## 起始态：信息科值班工位 · 守护未启

- **画面类型**：终端会话（多窗 tmux 或 Systemd 主机日志）
- **元素**：`xinchuang-guardian start` 命令已发出；屏幕等待首行 JSON 日志
- **配色**：黑底浅字（标准终端）；日志为白底 JSON（`slog` JSONHandler）
- **首屏信息**：当前时间、加载的 contracts.yaml 路径、12 条 system_id 计数

## 首个可用瞬间：守护已就绪 + 首轮 probe ok

- **画面类型**：终端持续输出 JSON 日志
- **元素**：
  - `{"event":"contracts_loaded","systems":12,"vendors":5}`
  - `{"event":"probe_ok","system_id":"his-core","vendor":"kingbase","evidence_sha":"a1b2..."}`
  - `{"event":"ready","ts_utc":"..."}`
- **配色**：JSON 日志每个键高亮（如 cyan=`event`、yellow=`system_id`）；值用默认色
- **首屏信息**：守护心跳（每 10 分钟一次）+ last_scan_at 时间戳

## 成形态：漂移命中 + 企微卡片 + evidence.zip

- **画面类型**：终端日志 + 企微群消息 + 文件树
- **元素**：
  - 守护日志：`{"event":"drift_trial","system_id":"his-core","vendor":"kingbase","declared":"KingbaseES V008R006C10B0010","actual":"PostgreSQL 14.10 (Debian ...)","evidence_sha":"...","verdict":"trial","ts_utc":"..."}`
  - 企微卡片 markdown（含 system_id / vendor / declared / actual / evidence_sha）
  - evidence.zip：`README.txt + contract_registry.csv + drift_events.csv + raw_probe_responses/*.txt + driver_sha256.csv + audit.jsonl + manifest.json + manifest.sha256`
- **配色**：JSON 日志中 `verdict=trial` 高亮红色；卡片标题加粗；evidence.zip 列表按章节分组

## 必须可达的约束（不许画出现有依赖做不出的效果）

- 终端仅显示 `log/slog` JSON 文本与 exit code，无图形化仪表盘
- 卡片仅是企业微信 markdown，不含按钮或交互
- evidence.zip 是标准 zip 格式，解压后是 6-8 个常规文件
- 不画 WebGL / 3D 场景、不画大屏可视化、不画内置浏览器
- 不引入额外图形库（chromedp / playwright 等）