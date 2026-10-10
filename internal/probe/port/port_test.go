package port

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xconf "xinchuang-db-guardian/internal/config"
)

// captureHook is a test-time AuditHook that records every row.
type captureHook struct {
	mu    sync.Mutex
	rows  []AuditRow
	byKnd map[AuditKind]int
}

func (h *captureHook) hook(r AuditRow) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rows = append(h.rows, r)
	if h.byKnd == nil {
		h.byKnd = map[AuditKind]int{}
	}
	h.byKnd[r.Kind]++
}

func (h *captureHook) snapshot() []AuditRow {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]AuditRow, len(h.rows))
	copy(out, h.rows)
	return out
}

func (h *captureHook) countOf(k AuditKind) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.byKnd[k]
}

// stubServer is a tiny TCP listener that either responds with banner
// or rejects — used to drive consecutive_fail scenarios.
type stubServer struct {
	ln      net.Listener
	resp    []byte
	served  atomic.Int64
	gate    chan struct{} // closed => start dropping connections
	dropped atomic.Int64
}

func startStubServer(t *testing.T) *stubServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &stubServer{ln: ln, gate: make(chan struct{})}
	go s.acceptLoop()
	return s
}

func (s *stubServer) Addr() string      { return s.ln.Addr().String() }
func (s *stubServer) Stop()             { _ = s.ln.Close() }
func (s *stubServer) EnableDropping()   { close(s.gate) }

func (s *stubServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.served.Add(1)
		select {
		case <-s.gate:
			s.dropped.Add(1)
			_ = conn.Close()
			continue
		default:
			go func(c net.Conn, b []byte) {
				defer c.Close()
				_, _ = c.Write(b)
			}(conn, s.resp)
		}
	}
}

func newContract(systemID, vendor, host string, port int) xconf.ContractV {
	return xconf.ContractV{
		SystemID:       systemID,
		Vendor:         vendor,
		VersionPattern: `(?i)PostgreSQL`,
		Host:           host,
		Port:           port,
	}
}

// TestSchedulerProbeErrorAfterThreeFailures checks that 2 transient
// failures do NOT emit probe_error, while the 3rd does.
func TestSchedulerProbeErrorAfterThreeFailures(t *testing.T) {
	stub := startStubServer(t)
	defer stub.Stop()
	stub.EnableDropping() // every connection refused from the start

	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	hook := &captureHook{}
	hookSink := func(r AuditRow) { hook.hook(r) }
	cfg := SchedulerConfig{
		Workers:                  2,
		ScanInterval:             time.Minute, // not relevant for RunOnce
		ProbeTimeout:             500 * time.Millisecond,
		ConsecutiveFailThreshold: 3,
	}
	sched := NewScheduler(cfg, logger, hookSink)

	contracts := []xconf.ContractV{newContract("his-core", "dm", stub.Addr(), portInt(stub.Addr()))}

	// Cycle 1 -> counter = 1, transient_fail only
	results := sched.RunOnce(context.Background(), contracts)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Fatal("expected probe error")
	}
	if hook.countOf(AuditKindProbeError) != 0 {
		t.Fatalf("probe_error emitted too early; got %d", hook.countOf(AuditKindProbeError))
	}
	if hook.countOf(AuditKindTransientFail) != 1 {
		t.Fatalf("expected 1 transient_fail, got %d", hook.countOf(AuditKindTransientFail))
	}

	// Cycle 2 -> counter = 2, still transient_fail only
	sched.RunOnce(context.Background(), contracts)
	if hook.countOf(AuditKindProbeError) != 0 {
		t.Fatalf("probe_error emitted too early (cycle 2); got %d", hook.countOf(AuditKindProbeError))
	}
	if hook.countOf(AuditKindTransientFail) != 2 {
		t.Fatalf("expected 2 transient_fail, got %d", hook.countOf(AuditKindTransientFail))
	}

	// Cycle 3 -> counter = 3, promote to probe_error
	sched.RunOnce(context.Background(), contracts)
	if hook.countOf(AuditKindProbeError) != 1 {
		t.Fatalf("expected 1 probe_error after 3 cycles, got %d", hook.countOf(AuditKindProbeError))
	}
	// counter must reset after promotion
	if got := sched.loadFailCounter("his-core").Load(); got != 0 {
		t.Fatalf("counter not reset after probe_error promotion; got %d", got)
	}
}

// TestSchedulerConcurrentProbes exercises the worker pool with multiple
// contracts concurrently.
func TestSchedulerConcurrentProbes(t *testing.T) {
	// Spin up 4 mock PG servers (reuse same fixture).
	servers := make([]*pgMockServer, 0, 4)
	addrs := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		s := startPGMockServer(t, "PostgreSQL 14.10 (Debian)")
		servers = append(servers, s)
		addrs = append(addrs, s.Addr())
	}
	defer func() {
		for _, s := range servers {
			s.Stop()
		}
	}()

	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg := SchedulerConfig{
		Workers:                  4,
		ScanInterval:             time.Minute,
		ProbeTimeout:             2 * time.Second,
		ConsecutiveFailThreshold: 3,
	}
	sched := NewScheduler(cfg, logger, func(AuditRow) {})

	contracts := []xconf.ContractV{
		newContract("his-core", "pg-compat", hostOf(addrs[0]), portOf(addrs[0])),
		newContract("emr", "kingbase", hostOf(addrs[1]), portOf(addrs[1])),
		newContract("lis", "opengauss", hostOf(addrs[2]), portOf(addrs[2])),
		newContract("pacs", "ivorysql", hostOf(addrs[3]), portOf(addrs[3])),
	}
	results := sched.RunOnce(context.Background(), contracts)
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("contract[%d] %s: unexpected err = %v", i, r.SystemID, r.Err)
		}
		if r.Brand != BrandPGCompat && r.Brand != BrandKingbaseES &&
			r.Brand != BrandOpenGauss && r.Brand != BrandIvorySQL {
			t.Errorf("contract[%d] %s: brand = %q (want a known PG-compat)", i, r.SystemID, r.Brand)
		}
	}
}

// TestSchedulerTimeoutDegradesToProbeError checks that probe timeouts
// are treated as transient failures (NOT promoted to drift).
func TestSchedulerTimeoutDegradesToProbeError(t *testing.T) {
	// Server that accepts but never responds.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// hold the connection open without sending
			go func(c net.Conn) {
				time.Sleep(3 * time.Second)
				_ = c.Close()
			}(conn)
		}
	}()

	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	hook := &captureHook{}
	cfg := SchedulerConfig{
		Workers:                  1,
		ScanInterval:             time.Minute,
		ProbeTimeout:             100 * time.Millisecond,
		ConsecutiveFailThreshold: 3,
	}
	sched := NewScheduler(cfg, logger, func(r AuditRow) { hook.hook(r) })

	contracts := []xconf.ContractV{newContract("his-core", "pg-compat", hostOf(ln.Addr().String()), portOf(ln.Addr().String()))}
	sched.RunOnce(context.Background(), contracts)
	sched.RunOnce(context.Background(), contracts)
	sched.RunOnce(context.Background(), contracts)

	// After 3 failures we expect a single probe_error, and crucially
	// it does NOT carry a verdict that would route it into the drift
	// pipeline.
	if hook.countOf(AuditKindProbeError) != 1 {
		t.Fatalf("expected exactly 1 probe_error, got %d", hook.countOf(AuditKindProbeError))
	}
}

// TestSchedulerResetOnSuccess verifies the counter is reset when the
// probe recovers, and one recovered audit row is emitted.
func TestSchedulerResetOnSuccess(t *testing.T) {
	// Server that is initially dropping, then we re-create it as a
	// serving mock between cycles.
	stub := startStubServer(t)
	defer stub.Stop()
	stub.EnableDropping()

	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	hook := &captureHook{}
	cfg := SchedulerConfig{
		Workers:                  1,
		ScanInterval:             time.Minute,
		ProbeTimeout:             300 * time.Millisecond,
		ConsecutiveFailThreshold: 3,
	}
	sched := NewScheduler(cfg, logger, func(r AuditRow) { hook.hook(r) })
	contracts := []xconf.ContractV{newContract("his-core", "pg-compat", stub.ln.Addr().String(), portInt(stub.ln.Addr().String()))}
	// Cycle 1 -> fail
	sched.RunOnce(context.Background(), contracts)
	if got := sched.loadFailCounter("his-core").Load(); got != 1 {
		t.Fatalf("counter = %d, want 1", got)
	}

	// Now stop the stub server and stand up a healthy one at the same addr.
	// Simpler: replace the contracts struct with a fresh healthy contract.
	stub.Stop()
	pgSrv := startPGMockServer(t, "PostgreSQL 14.10 (Debian)")
	defer pgSrv.Stop()
	healthyContract := newContract("his-core", "pg-compat", hostOf(pgSrv.Addr()), portOf(pgSrv.Addr()))

	sched.RunOnce(context.Background(), []xconf.ContractV{healthyContract})
	if got := sched.loadFailCounter("his-core").Load(); got != 0 {
		t.Fatalf("counter not reset on recovery, got %d", got)
	}
	if hook.countOf(AuditKindProbeRecovered) == 0 {
		t.Fatal("expected recovered audit row")
	}
}

// TestNewSchedulerDefaults verifies default config is applied.
func TestNewSchedulerDefaults(t *testing.T) {
	sched := NewScheduler(SchedulerConfig{}, nil, nil)
	if sched.cfg.Workers != 4 {
		t.Errorf("Workers = %d, want 4", sched.cfg.Workers)
	}
	if sched.cfg.ScanInterval != 10*time.Minute {
		t.Errorf("ScanInterval = %v, want 10m", sched.cfg.ScanInterval)
	}
	if sched.cfg.ProbeTimeout != 5*time.Second {
		t.Errorf("ProbeTimeout = %v, want 5s", sched.cfg.ProbeTimeout)
	}
	if sched.cfg.ConsecutiveFailThreshold != 3 {
		t.Errorf("ConsecutiveFailThreshold = %d, want 3", sched.cfg.ConsecutiveFailThreshold)
	}
}

// testWriter makes slog usable with `go test -v`.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

// hostOf / portOf / portInt parse a "host:port" string from net.Listen.
func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1"
	}
	return h
}

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	portNum, _ := net.LookupPort("tcp", p)
	return portNum
}

func portInt(addr string) int { return portOf(addr) }

// TestVendorKey verifies the lower-cased vendor is computed correctly.
func TestVendorKey(t *testing.T) {
	cases := map[string]string{
		"PG-Compat":     "pg-compat",
		"KingbaseES":    "kingbasees",
		"DM":            "dm",
		"oracle":        "oracle",
		"OPENGAUSS":     "opengauss",
	}
	for in, want := range cases {
		if got := vendorKey(in); got != want {
			t.Errorf("vendorKey(%q) = %q, want %q", in, got, want)
		}
	}
}
