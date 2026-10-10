package main

import (
	"fmt"
	"os"
	"time"

	"xinchuang-db-guardian/internal/output"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: buildchain <audit.jsonl>")
		os.Exit(2)
	}
	path := os.Args[1]
	now := time.Now().UTC()
	rows := []output.AuditRow{
		{TsUTC: now.Add(-5 * 24 * time.Hour).Format(time.RFC3339Nano), EventID: "EVT-LIS-1", ContractID: "HT-2024-LIS", SystemID: "lis", Vendor: "dm8", Declared: "DM Database Server V8.1.*", Actual: "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1)", PortRaw: "PostgreSQL 14.10 (Debian 14.10-1.pgdg120+1) on x86_64", DriverSha: "aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaaa", JDBCURL: "jdbc:postgresql://10.0.1.23:15432/lis", Verdict: "trial", Confidence: 0.98, EvidenceSHA256: "ev1111111111111111111111111111111111111111111111111111111111111", Kind: "drift", Action: "trial"},
		{TsUTC: now.Add(-3 * 24 * time.Hour).Format(time.RFC3339Nano), EventID: "EVT-PACS-1", ContractID: "HT-2024-PACS", SystemID: "pacs", Vendor: "IvorySQL", Declared: "IvorySQL.*1.4.*", Actual: "PostgreSQL 13.6", PortRaw: "PostgreSQL 13.6 (Debian 13.6-1.pgdg120+1)", DriverSha: "bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb", JDBCURL: "jdbc:postgresql://10.0.1.24:19600/pacs", Verdict: "trial", Confidence: 0.95, EvidenceSHA256: "ev2222222222222222222222222222222222222222222222222222222222222", Kind: "drift", Action: "trial"},
		{TsUTC: now.Add(-1 * 24 * time.Hour).Format(time.RFC3339Nano), EventID: "EVT-PACS-REMEDIED", ContractID: "HT-2024-PACS", SystemID: "pacs", Vendor: "IvorySQL", Declared: "IvorySQL.*1.4.*", Actual: "IvorySQL 1.4", PortRaw: "IvorySQL 1.4 on x86_64", DriverSha: "ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc333ccc", JDBCURL: "jdbc:postgresql://10.0.1.24:19600/pacs", Verdict: "ok", Confidence: 1.0, EvidenceSHA256: "ev3333333333333333333333333333333333333333333333333333333333333", Kind: "drift_remedied", Action: "remedied", Operator: "张主任"},
	}
	n, err := output.AppendJSONL(path, rows...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "AppendJSONL:", err)
		os.Exit(1)
	}
	fmt.Printf("appended %d rows\n", n)
}