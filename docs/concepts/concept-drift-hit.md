# 视觉目标卡 · 漂移命中与告警（drift trial）

## 状态名

漂移命中（drift trial）—— 三维核对任一不一致，状态入 trial 等待人工 confirm-drift。

## 画面类型

终端持续日志（事件驱动守护 slog JSON）+ 企业微信群卡片（markdown 文本）+ 文件树（trial 状态入 bbolt）。

## 元素清单

- **终端日志**：`{"event":"drift_trial","system_id":"his-core","vendor":"kingbase","declared":"KingbaseES V008R006C10B0010","actual":"PostgreSQL 14.10 (Debian ...)","evidence_sha":"...","verdict":"trial","ts_utc":"..."}` —— 一行 JSON 含 system_id / vendor / declared / actual / verdict / evidence_sha 六字段
- **企微卡片 markdown**：信创合规漂移命中 - his-core\n 厂商：kingbase\n 申报：KingbaseES V008R006C10B0010\n 实际：PostgreSQL 14.10 (Debian ...)\n 证据：9\列 sha256\n 时间：ts_utc
- **bbolt trial_state**：bucket=`trial_state`，key=event_id，value=DriftEvidence JSON（含 State=trial + PrevEvidenceSHA256 + SelfHash）
- **JSONL 审计行**：`kind=drift` + PrevEvidenceSHA256 + SelfHash + Operator=`auto` + Action=`drift_trial` 写入 append-only audit.jsonl

## 配色（终端）

- `event` 键 cyan
- `verdict=trial` 高亮红色
- `evidence_sha` 黄色（便于复核时定位）
- `declared / actual` 字段对比色（declared 灰、actual 黄以提示差异）

## 信息层级

- **最显眼**：verdict=trial（红色高亮）
- **次显眼**：evidence_sha（黄色）→ 信息科复制粘贴到工单
- **次次**：vendor / system_id → 用于路由到对应厂商群
- **最末**：ts_utc（操作追溯时间戳）

## 必须可达的约束

- 不画交互按钮（卡片是只读 markdown）
- 不画内嵌详情面板（证据全在 audit.jsonl 与 evidence.zip）
- 不画流程图 / 时序图（仅 slog 单行 JSON）
- 颜色仅用 ANSI 转义序列（8 色 + 加粗），无 24-bit 颜色