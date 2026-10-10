package port

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	xconf "xinchuang-db-guardian/internal/config"
)

// ProbeResult is the outcome of a single probe attempt against one
// declared system. FailedCount is the per-system consecutive failure
// counter at the moment the result was computed (0 if this attempt
// succeeded). Err is non-nil iff the handshake itself failed.
type ProbeResult struct {
	SystemID    string
	Brand       string
	Raw         []byte
	Err         error
	FailedCount int
	Timestamp   time.Time
}

// AuditKind enumerates the kinds of audit rows this package can
// generate. They mirror the contract.registry of audit kinds for
// `internal/output/audit.go`; the producer keeps the API surface
// minimal so the audit-append step stays testable on its own.
type AuditKind string

const (
	AuditKindTransientFail  AuditKind = "transient_fail"
	AuditKindProbeError     AuditKind = "probe_error"
	AuditKindProbeRecovered AuditKind = "probe_recovered"
)

// AuditRow is what Scheduler emits when it needs a downstream audit
// row. The downstream audit writer is responsible for sha256 chaining;
// we only produce the (kind, payload, ts) tuple here.
type AuditRow struct {
	Kind      AuditKind
	SystemID  string
	Host      string
	Port      int
	Brand     string
	Err       string
	Timestamp time.Time
}

// SchedulerConfig bundles the tunables for the per-cycle probe scheduler.
// Defaults are the values used by the production daemon; tests can
// override them to exercise the failure-threshold transitions quickly.
type SchedulerConfig struct {
	Workers                  int
	ScanInterval             time.Duration
	ProbeTimeout             time.Duration
	ConsecutiveFailThreshold int
}

// DefaultSchedulerConfig returns the production tunables called out in
// spec.md / plan.md: a 4-worker pool, 10-minute scan cadence, 5-second
// per-probe timeout, and a 3-strike threshold before we promote a
// transient failure to a probe_error audit row.
func DefaultSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{
		Workers:                  4,
		ScanInterval:             10 * time.Minute,
		ProbeTimeout:             5 * time.Second,
		ConsecutiveFailThreshold: 3,
	}
}

// AuditHook is the consumer-supplied callback that receives audit rows.
// We use a function type (not an interface) to keep the Scheduler
// minimal; tests pass an in-memory recorder.
type AuditHook func(AuditRow)

// Scheduler probes a list of declared Contracts on a fixed cadence.
//
// Per the spec: a Contract has a Vendor field; the current implementation
// routes by Vendor onto Handshake() (PG-compatible family), DMHandshake(),
// or OracleHandshake(). Routes can be extended without changing the
// public API of Scheduler.
//
// Concurrent failure counter: each SystemID gets its own atomic
// counter. Successful probes reset it to zero; failed probes increment
// it. When the counter reaches ConsecutiveFailThreshold, exactly one
// AuditKindProbeError audit row is emitted and the counter resets.
// This avoids spamming the audit log on a persistent outage.
type Scheduler struct {
	cfg     SchedulerConfig
	logger  *slog.Logger
	hook    AuditHook
	failCtr sync.Map // map[systemID]*atomic.Int64

	// In-memory counter for tests; production code uses an appender
	// downstream. Exposed for tests via counters().
	counters atomic.Int64
}

// NewScheduler wires up a Scheduler. hook may be nil, in which case
// audit rows are silently dropped (useful for dry runs).
func NewScheduler(cfg SchedulerConfig, logger *slog.Logger, hook AuditHook) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.ScanInterval <= 0 {
		cfg.ScanInterval = 10 * time.Minute
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 5 * time.Second
	}
	if cfg.ConsecutiveFailThreshold <= 0 {
		cfg.ConsecutiveFailThreshold = 3
	}
	if hook == nil {
		hook = func(AuditRow) {}
	}
	return &Scheduler{cfg: cfg, logger: logger, hook: hook}
}

// counters exposes counters for tests. (Not part of the production API
// contract — just a convenience accessor.)
func (s *Scheduler) countersSinceStart() int64 { return s.counters.Load() }

// bumpCounter increments the running audit-row counter; exposed for
// tests to assert "audit row was produced" without inspecting the hook.
func (s *Scheduler) bumpCounter() { s.counters.Add(1) }

// loadFailCounter returns the atomic counter for the given systemID,
// creating one on first observation.
func (s *Scheduler) loadFailCounter(systemID string) *atomic.Int64 {
	actual, _ := s.failCtr.LoadOrStore(systemID, &atomic.Int64{})
	v, _ := actual.(*atomic.Int64)
	return v
}

// ResetFailCounter wipes the failure counter for a system. Used by
// the "remedied" path and during operator-initiated recovery.
func (s *Scheduler) ResetFailCounter(systemID string) {
	s.failCtr.Delete(systemID)
}

// runOnce probes every contract once and returns the slice of results.
// Callers can also subscribe via the hook. Each contract probe is
// dispatched to a fixed worker pool so that a slow probe can't stall
// the cadence indefinitely.
func (s *Scheduler) runOnce(ctx context.Context, contracts []xconf.ContractV) []ProbeResult {
	if len(contracts) == 0 {
		return nil
	}

	type job struct {
		i        int
		contract xconf.ContractV
	}
	results := make([]ProbeResult, len(contracts))

	jobs := make(chan job)
	var wg sync.WaitGroup

	for w := 0; w < s.cfg.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				results[j.i] = s.probeOne(ctx, j.contract)
			}
		}()
	}

	for i, c := range contracts {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results
		case jobs <- job{i: i, contract: c}:
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func (s *Scheduler) probeOne(parentCtx context.Context, c xconf.ContractV) ProbeResult {
	probeCtx, cancel := context.WithTimeout(parentCtx, s.cfg.ProbeTimeout)
	defer cancel()

	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	res := ProbeResult{
		SystemID:  c.SystemID,
		Timestamp: time.Now().UTC(),
	}

	vendorLower := vendorKey(c.Vendor)
	switch vendorLower {
	case "kingbase", "opengauss", "ivorysql", "hg", "shentong", "pg", "pg-compat":
		hsRes, hsErr := Handshake(probeCtx, addr)
		res.Brand = hsRes.Brand
		res.Raw = hsRes.Raw
		res.Err = hsErr
	case "dm", "dm8":
		raw, brand, err := DMHandshake(probeCtx, addr)
		res.Brand = brand
		res.Raw = raw
		res.Err = err
	case "oracle":
		raw, brand, err := OracleHandshake(probeCtx, addr)
		res.Brand = brand
		res.Raw = raw
		res.Err = err
	default:
		// Unknown vendor: skip recording a brand and surface a probe
		// error so the configure step must be repeated. Operators
		// fix this by editing contracts.yaml.
		res.Err = fmt.Errorf("port: unknown vendor %q", c.Vendor)
	}

	ctr := s.loadFailCounter(c.SystemID)
	if res.Err != nil {
		// Promote repeated failures into probe_error audit rows.
		newCount := ctr.Add(1)
		res.FailedCount = int(newCount)
		if newCount >= int64(s.cfg.ConsecutiveFailThreshold) {
			s.hook(AuditRow{
				Kind:      AuditKindProbeError,
				SystemID:  c.SystemID,
				Host:      c.Host,
				Port:      c.Port,
				Err:       res.Err.Error(),
				Timestamp: res.Timestamp,
			})
			s.bumpCounter()
			// Reset so a sustained outage doesn't keep emitting audit
			// rows every cycle; we'll see the next failure again next
			// time the threshold trips.
			ctr.Store(0)
			res.FailedCount = 0
		} else {
			s.hook(AuditRow{
				Kind:      AuditKindTransientFail,
				SystemID:  c.SystemID,
				Host:      c.Host,
				Port:      c.Port,
				Err:       res.Err.Error(),
				Timestamp: res.Timestamp,
			})
			s.bumpCounter()
		}
	} else {
		// Probe recovered: clear the counter and emit a positive marker
		// only on the recovery edge (when the counter had been bumped).
		prev := ctr.Swap(0)
		if prev > 0 {
			s.hook(AuditRow{
				Kind:      AuditKindProbeRecovered,
				SystemID:  c.SystemID,
				Host:      c.Host,
				Port:      c.Port,
				Brand:     res.Brand,
				Timestamp: res.Timestamp,
			})
			s.bumpCounter()
		}
		res.FailedCount = 0
	}

	return res
}

// Run blocks running one scan every ScanInterval until ctx is cancelled.
// On each cycle it probes every contract and dispatches per-system
// audit rows through hook. Between cycles the goroutine sleeps via
// the same job.Timer pattern adopted from cilium-agent-liveness — i.e.
// context-aware wait, never a fixed time.Sleep.
func (s *Scheduler) Run(ctx context.Context, contracts []xconf.ContractV) error {
	if len(contracts) == 0 {
		return errors.New("port.Scheduler.Run: no contracts configured")
	}
	t := time.NewTicker(s.cfg.ScanInterval)
	defer t.Stop()

	// Run the first scan immediately so operators see results in the
	// first few seconds of startup.
	s.runOnce(ctx, contracts)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.runOnce(ctx, contracts)
		}
	}
}

// RunOnce is a non-blocking single cycle for tests and CLI subcommands
// that want to drive a single deterministic pass.
func (s *Scheduler) RunOnce(ctx context.Context, contracts []xconf.ContractV) []ProbeResult {
	return s.runOnce(ctx, contracts)
}

func vendorKey(vendor string) string {
	out := make([]byte, 0, len(vendor))
	for i := 0; i < len(vendor); i++ {
		c := vendor[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}
