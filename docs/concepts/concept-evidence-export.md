# 视觉目标卡 · 飞检证据装订（export-evidence）

## 状态名

飞检前 1 分钟 —— 信息科执行 export-evidence --last 30d 输出 evidence.zip 交飞检组。

## 画面类型

终端一次性命令输出 + 文件树（zip 解压到临时目录）+ sha256sum 校验流程。

## 元素清单

- **CLI 命令**：`xinchuang-guardian export-evidence --last 30d --out /tmp/evidence.zip` —— 二进制从 cobra 子命令入口接住，写入 archive/zip
- **evidence.zip 内 8 个文件**：
  ```
  evidence.zip
  ├── README.txt                  # 证据包组成 + 校验方法说明
  ├── contract_registry.csv       # 12 条 system_id 的合同白名单（vendor / version / host:port / allow_drift_sha256 / jdbc_driver_dirs）
  ├── drift_events.csv            # last_n_days 内全部 DriftEvidence（含 verdict / evidence_sha / status）
  ├── driver_sha256.csv           # 当前驱动目录中所有 .jar 的 sha256 清单（含 registered/unknown 标注）
  ├── raw_probe_responses/        # 每个 system_id 一份最新 port_raw 文本
  │   ├── his-core.txt
  │   ├── emr.txt
  │   └── ... (12 份)
  ├── audit.jsonl                 # last_n_days 内的审计行（保留原 hash 链，不重新 hash）
  ├── manifest.json               # 每个文件的 sha256（生成时间 + last_n_days）
  └── manifest.sha256             # manifest.json 自身的 sha256（64 hex）
```

- **manifest.json 内容**：`{"generated_at_utc":"...","last_n_days":30,"tool_version":"v1.x.y","files":[{"name":"README.txt","sha256":"...","bytes":N},...]}`（files 按 name 字典序排序）
- **manifest.sha256 内容**：64 hex 字符串（manifest.json 全文 sha256），与 `sha256sum -c manifest.sha256` 兼容

## 配色（终端）

- 命令路径 cyan
- 文件大小黄色
- 校验成功 `manifest.json: OK` 绿色
- 校验失败红色（含 mismatch 详情）

## 信息层级

- **最显眼**：evidence.zip 路径（输出末尾）
- **次显眼**：manifest.json sha256 校验成功
- **次次**：文件树（README.txt → manifest.sha256 按章节）
- **最末**：每个文件 sha256 对审计字段

## 必须可达的约束

- zip 仅含标准文本/CSV/JSON/JSONL 文件，无二进制大文件（驱动 jar 不进 zip）
- 校验时间基于 listing 阶段（不再二次扫描）
- 不画 PDF 报告（飞检组看 manifest.sha256 与 audit.jsonl 即可）
- 不内嵌证书 / 时间戳服务（飞检组 sha256sum -c 即可）