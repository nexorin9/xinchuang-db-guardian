// 单元测试：contracts.yaml 解析、校验、holder snapshot。
package config

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const sampleContractsYAML = `
declared:
  - system_id: his-core
    vendor: kingbase
    version_pattern: "V008R006C10.*"
    allow_drift_sha256:
      - "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    contract_id: HT-2024-HIS-CORE
    host: 10.0.1.21
    port: 54321
    scan_interval: 10m
    jdbc_driver_dirs:
      - /opt/jdbc/kingbase
    event_id_prefix: EVT-HIS
  - system_id: emr
    vendor: dm8
    version_pattern: "DM Database Server V8\\.1\\..*"
    allow_drift_sha256: []
    contract_id: HT-2024-EMR
    host: 10.0.1.22
    port: 5236
    scan_interval: 10m
    jdbc_driver_dirs:
      - /opt/jdbc/dm
    event_id_prefix: EVT-EMR
`

func TestParseContractsOK(t *testing.T) {
	cs, err := ParseContracts([]byte(sampleContractsYAML))
	if err != nil {
		t.Fatalf("ParseContracts: %v", err)
	}
	if len(cs) != 2 {
		t.Fatalf("len = %d, want 2", len(cs))
	}
	if cs[0].SystemID != "his-core" || cs[0].Vendor != "kingbase" || cs[0].Port != 54321 {
		t.Fatalf("cs[0] = %+v, want his-core/kingbase/54321", cs[0])
	}
	if cs[1].Vendor != "dm8" || cs[1].Port != 5236 {
		t.Fatalf("cs[1] = %+v", cs[1])
	}
}

func TestParseContractsEmpty(t *testing.T) {
	cs, err := ParseContracts([]byte(""))
	if err != nil {
		t.Fatalf("ParseContracts 空: %v", err)
	}
	if cs != nil {
		t.Fatalf("空 yaml 应返回 nil，实际 %v", cs)
	}
}

func TestValidateContractsOK(t *testing.T) {
	cs, _ := ParseContracts([]byte(sampleContractsYAML))
	if err := ValidateContracts(cs); err != nil {
		t.Fatalf("ValidateContracts: %v", err)
	}
}

func TestValidateContractsDuplicateSystemID(t *testing.T) {
	yaml := `
declared:
  - {system_id: "a", vendor: "kingbase", version_pattern: "", contract_id: "C1", host: "10.0.0.1", port: 5432, event_id_prefix: "P1"}
  - {system_id: "a", vendor: "dm8", version_pattern: "", contract_id: "C2", host: "10.0.0.2", port: 5236, event_id_prefix: "P2"}
`
	cs, _ := ParseContracts([]byte(yaml))
	if err := ValidateContracts(cs); err == nil {
		t.Fatal("duplicate system_id 期望错误")
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("错误信息应含 'duplicate'，实际 %q", err.Error())
	}
}

func TestValidateContractsBadHost(t *testing.T) {
	yaml := `
declared:
  - {system_id: "a", vendor: "kingbase", version_pattern: "", contract_id: "C1", host: "not-ip", port: 5432, event_id_prefix: "P1"}
`
	cs, _ := ParseContracts([]byte(yaml))
	if err := ValidateContracts(cs); err == nil {
		t.Fatal("bad host 期望错误")
	} else if !strings.Contains(err.Error(), "host") {
		t.Fatalf("错误信息应含 'host'，实际 %q", err.Error())
	}
}

func TestValidateContractsBadPort(t *testing.T) {
	yaml := `
declared:
  - {system_id: "a", vendor: "kingbase", version_pattern: "", contract_id: "C1", host: "10.0.0.1", port: 70000, event_id_prefix: "P1"}
`
	cs, _ := ParseContracts([]byte(yaml))
	if err := ValidateContracts(cs); err == nil {
		t.Fatal("port 70000 期望错误")
	} else if !strings.Contains(err.Error(), "port") {
		t.Fatalf("错误信息应含 'port'，实际 %q", err.Error())
	}
}

func TestValidateContractsBadRegex(t *testing.T) {
	yaml := `
declared:
  - {system_id: "a", vendor: "kingbase", version_pattern: "[invalid", contract_id: "C1", host: "10.0.0.1", port: 5432, event_id_prefix: "P1"}
`
	cs, _ := ParseContracts([]byte(yaml))
	if err := ValidateContracts(cs); err == nil {
		t.Fatal("坏 regex 期望错误")
	} else if !strings.Contains(err.Error(), "compile") {
		t.Fatalf("错误信息应含 'compile'，实际 %q", err.Error())
	}
}

func TestValidateContractsEmptySystemID(t *testing.T) {
	yaml := `
declared:
  - {system_id: "", vendor: "kingbase", version_pattern: "", contract_id: "C1", host: "10.0.0.1", port: 5432, event_id_prefix: "P1"}
`
	cs, _ := ParseContracts([]byte(yaml))
	if err := ValidateContracts(cs); err == nil {
		t.Fatal("空 system_id 期望错误")
	}
}

func TestContractsHolderSetSnapshot(t *testing.T) {
	h := NewContractsHolder()
	cs, _ := ParseContracts([]byte(sampleContractsYAML))
	h.Set(cs)

	snap := h.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot len = %d, want 2", len(snap))
	}
	// 改 snap 不应影响 holder 内部数据
	snap[0].SystemID = "mutated"
	again := h.Snapshot()
	if again[0].SystemID != "his-core" {
		t.Fatalf("改 snapshot 不应影响内部，再次 snapshot = %q, want his-core", again[0].SystemID)
	}
}

func TestContractsHolderConcurrentRead(t *testing.T) {
	h := NewContractsHolder()
	cs, _ := ParseContracts([]byte(sampleContractsYAML))
	h.Set(cs)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := h.Snapshot(); len(got) != 2 {
				t.Errorf("并发读不一致: %d", len(got))
			}
		}()
	}
	wg.Wait()
}

func TestLoadContractsFromExample(t *testing.T) {
	// 真实 example 文件必须存在且含 12 条
	path := filepath.Join("..", "..", "config", "contracts.example.yaml")
	cs, err := LoadContracts(path)
	if err != nil {
		t.Fatalf("LoadContracts(example): %v", err)
	}
	if len(cs) != 12 {
		t.Fatalf("example 应有 12 条 system，实际 %d", len(cs))
	}
	if err := ValidateContracts(cs); err != nil {
		t.Fatalf("example 应通过校验: %v", err)
	}
	// host 全部应是 IP
	for i, c := range cs {
		if c.Host == "" {
			t.Fatalf("cs[%d] host 为空", i)
		}
		if c.SystemID == "" {
			t.Fatalf("cs[%d] system_id 为空", i)
		}
	}
}

func TestBadYAMLFriendlyError(t *testing.T) {
	bad := "declared: [[["
	_, err := ParseContracts([]byte(bad))
	if err == nil {
		t.Fatal("坏 yaml 期望错误")
	}
}
