# Xinchuang Database Compliance Drift Guardian

> A single-binary resident daemon for the on-call information-technology workstation that reconciles "declared database brand vs. actual handshake response + driver jar sha256 + JDBC URL" every ten minutes and bundles the resulting evidence into a sha256-verified zip one minute before an unscheduled inspection.

## What & Who

**Xinchuang Database Compliance Drift Guardian** is a Go-resident watchdog built for the hospital information-technology department. It continuously probes twelve contracted database systems (KingbaseES, DM8, openGauss, IvorySQL, GBase, Shentong, Oracle and PG-compatible families), cross-checks the declared brand against three independent evidence channels (TCP wire handshake, driver jar sha256, JDBC URL pattern), and escalates any mismatch as a "trial" verdict that requires human `confirm-drift` action. The intended users are the on-shift IT engineer, the database-vendor engineer swapping drivers, the compliance officer preparing for an unscheduled inspection, and the IT director who has to defend the contract in front of inspectors.

## Core Capabilities

- **Three-dimensional drift reconciliation**: declared vendor vs. port handshake banner + driver jar sha256 + JDBC URL pattern; any mismatch ⇒ `verdict=trial` (operator-only promotion)
- **Resident daemon with graceful shutdown**: single Go binary + Cobra CLI; `signal.NotifyContext` on SIGINT/SIGTERM/SIGHUP/SIGQUIT; pidfile auto-cleanup
- **Tamper-evident audit chain**: append-only JSONL with `sha256(prev_self_hash || body)` chaining; `audit verify-chain` detects tamper/delete/insert
- **One-command evidence bundling**: `export-evidence --last 30d --out evidence.zip` ships README + contract registry + drift events + raw probe responses + driver sha256 table + audit JSONL + manifest.json + manifest.sha256
- **LLM fallback explanation (only when rules cannot conclude)**: OpenAI-compatible gateway; unreachable / 5xx / timeout / schema-invalid ⇒ always downgrades to rule verdict; never silently promotes a trial
- **Deduplication and state machine**: same `(system_id, vendor)` only alerts once per five minutes; identical `evidence_sha` is idempotent and does not rewrite audit; `trial / confirmed / remedied / re_verified / disputed` states only advance via the `confirm-drift` CLI

## Quick Start

```bash
# Build
git clone <repo> xinchuang-db-guardian
cd xinchuang-db-guardian
go mod download
make build              # → bin/xinchuang-guardian

# Configure
cp .env.example .env    # fill DB_PROBE_USER / WECHAT_WEBHOOK_URL / SMTP_PASSWORD / LLM_* from environment

# Run the resident daemon
./bin/xinchuang-guardian start --config config/contracts.example.yaml

# Operate
./bin/xinchuang-guardian status                       # PID + heartbeat
./bin/xinchuang-guardian stop                         # SIGTERM + graceful shutdown
./bin/xinchuang-guardian verify-only                  # one-shot three-dim check
./bin/xinchuang-guardian export-evidence --last 30d --out evidence.zip
./bin/xinchuang-guardian audit verify-chain --file /var/log/xinchuang-guardian/audit.jsonl
./bin/xinchuang-guardian confirm-drift <event_id> --action remedied --operator <name>

# Verify
go test ./internal/config/... -v -count=1            # targeted tests
bash scripts/full_regression.sh                       # full regression (go mod tidy + vet + build + test)
bash scripts/smoke_test.sh                            # end-to-end (requires Docker)
```

For complete configuration, every CLI flag, error / degradation matrix, integration endpoints, full architecture, and acceptance checklist, see `README.md` (Chinese, 13 sections).

## Repository Structure

```
xinchuang-db-guardian/
├── cmd/xinchuang-guardian/     # Cobra entrypoint (start / stop / status / verify-only / export-evidence / audit verify-chain / confirm-drift / smoketest)
├── internal/                   # 11 packages: app, config, probe (port/driver/version), check, classify, llm, output, export
├── config/                     # contracts.example.yaml + vendor_signatures.example.yaml
├── docs/concepts/              # Structured visual-target card (start / first usable moment / finished)
├── docs/screenshots/           # Real-run screenshots (startup / drift / export / audit-verify / wecom-card)
├── scripts/                    # demo.sh / smoke_test.sh / full_regression.sh / check_tree.sh
├── test/                       # integration (dockertest) + mockservers (5 vendor mocks)
├── testdata/fixtures/          # 5 vendors × 15 real version strings + mock driver sha list
├── deployment/systemd/         # xinchuang-guardian.service (Type=notify + Restart=always)
├── docker/                     # multi-stage Dockerfile (golang:1.25-alpine → alpine:3.19 + tini)
├── .env.example                # Environment-variable sample (no real credentials)
├── go.mod / go.sum             # spf13/cobra + yaml.v3 + fsnotify + bbolt + dockertest + go-mail + testify
├── Makefile / build.sh         # build / test / test-race / lint / run / clean
├── README.md                   # Chinese product specification (full, 13 sections)
└── README_EN.md                # English summary (this file)
```

Full documentation: see `README.md` (Chinese).

---

## Follow Us

Scan the QR code to follow our official account for updates and community access:

![Follow Us](qrcode.jpg)