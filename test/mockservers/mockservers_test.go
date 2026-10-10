package mockservers

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestPGMockServerStartStop is the canonical lifecycle test: bind, accept
// at least one dial, close cleanly, no goroutine leak observable from
// this test alone.
func TestPGMockServerStartStop(t *testing.T) {
	srv := StartPGMockServer(t, "PostgreSQL 14.10 (Debian)")
	defer srv.Stop()

	if srv.Addr() == "" {
		t.Fatal("expected non-empty addr")
	}
	if err := EnsurePGMockServerReachable(srv); err != nil {
		t.Fatalf("reachability: %v", err)
	}
	if srv.Served() != 0 {
		// EnsureReachable did one dial; we count actual accept hits, so
		// served can still be 0 if the listener hadn't yet picked the
		// connection up. We don't assert > 0 here — only that the server
		// is listening and dialable.
		t.Logf("served=%d (acceptable: 0 if accept loop hasn't ticked yet)", srv.Served())
	}
}

// TestPGMockServerAcceptsAndResponds dials the mock, sends a 'Q' frame
// like the production probe does, and verifies the response contains
// the configured banner plus a ReadyForQuery 'Z' terminator. This is
// the same shape the production Handshake() reads.
func TestPGMockServerAcceptsAndResponds(t *testing.T) {
	srv := StartPGMockServer(t, "PostgreSQL 14.10 (Debian)")
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a minimal Q frame: 'Q' + 4-byte length + "SELECT 1\0".
	qMsg := []byte{'Q', 0, 0, 0, 9, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}
	if _, err := conn.Write(qMsg); err != nil {
		t.Fatalf("write Q: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	var sb strings.Builder
	for {
		b, err := reader.ReadByte()
		if err != nil {
			break
		}
		sb.WriteByte(b)
		if b == 'Z' {
			// Read the next 4 bytes (length) and the 'I' status, then stop.
			rest := make([]byte, 5)
			n, _ := reader.Read(rest)
			sb.Write(rest[:n])
			break
		}
	}

	resp := sb.String()
	if !strings.Contains(resp, "PostgreSQL 14.10 (Debian)") {
		t.Errorf("response missing banner; got %q", resp)
	}
	if !strings.Contains(resp, "Z") {
		t.Errorf("response missing ReadyForQuery 'Z'; got %q", resp)
	}
}

// TestPGMockServerSetVersionHotReload verifies the banner can be swapped
// at runtime; subsequent connections see the new banner.
func TestPGMockServerSetVersionHotReload(t *testing.T) {
	srv := StartPGMockServer(t, "PostgreSQL 14.10 (Debian)")
	defer srv.Stop()

	srv.SetVersion("KingbaseES V008R006C10B0010")
	if got := *srv.version.Load(); got != "KingbaseES V008R006C10B0010" {
		t.Fatalf("SetVersion didn't take; got %q", got)
	}
}

// TestPGMockServerStopIsIdempotent ensures Stop() can be called
// multiple times without panicking.
func TestPGMockServerStopIsIdempotent(t *testing.T) {
	srv := StartPGMockServer(t, "PostgreSQL 14.10 (Debian)")
	if err := srv.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// TestPGMockServerReusableAcrossGoroutines ensures concurrent dials
// all succeed and Served() reflects the cumulative count. We don't
// assert exact equality on Served (the accept loop is async) but we
// do assert the listener still answers every dial within the budget.
func TestPGMockServerReusableAcrossGoroutines(t *testing.T) {
	srv := StartPGMockServer(t, "PostgreSQL 14.10 (Debian)")
	defer srv.Stop()

	const N = 5
	done := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
			if err != nil {
				done <- err
				return
			}
			_ = conn.Close()
			done <- nil
		}()
	}
	for i := 0; i < N; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent dial: %v", err)
		}
	}
	// Give the accept loop a moment to count.
	time.Sleep(50 * time.Millisecond)
	if srv.Served() < 1 {
		t.Errorf("Served()=%d, want >=1", srv.Served())
	}
}

// ---------------------------------------------------------------------------
// DM mock
// ---------------------------------------------------------------------------

// TestDMMockServerStartStop confirms bind + reachability + clean close.
func TestDMMockServerStartStop(t *testing.T) {
	srv := StartDMMockServer(t, "DM: Database Server V8.1.0")
	defer srv.Stop()

	if err := EnsureDMMockServerReachable(srv); err != nil {
		t.Fatalf("reachability: %v", err)
	}
}

// TestDMMockServerBannerContainsKeyword dials, reads up to 512 bytes
// (the production cap) and verifies the configured banner is present.
func TestDMMockServerBannerContainsKeyword(t *testing.T) {
	srv := StartDMMockServer(t, "DM: Database Server V8.1.0")
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	total := 0
	for total < 512 {
		n, rerr := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if rerr != nil {
			break
		}
	}
	if total == 0 {
		t.Fatal("empty banner read")
	}
	got := string(buf[:total])
	if !strings.Contains(strings.ToUpper(got), "DM:") {
		t.Errorf("banner missing 'DM:'; got first 80 bytes=%q", first80(got))
	}
}

// TestDMMockServerDAMENGKeyword covers the second keyword path the
// production classifier also accepts.
func TestDMMockServerDAMENGKeyword(t *testing.T) {
	srv := StartDMMockServer(t, "DAMENG Database Server V8")
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	total := 0
	for total < 512 {
		n, rerr := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if rerr != nil {
			break
		}
	}
	got := strings.ToUpper(string(buf[:total]))
	if !strings.Contains(got, "DAMENG") {
		t.Errorf("banner missing 'DAMENG'; got first 80 bytes=%q", first80(got))
	}
}

// TestDMMockServerSetBannerHotReload verifies the banner is swappable.
func TestDMMockServerSetBannerHotReload(t *testing.T) {
	srv := StartDMMockServer(t, "DM: Database Server V8.1.0")
	defer srv.Stop()
	srv.SetBanner("DAMENG V8.1.2")
	if got := *srv.banner.Load(); got != "DAMENG V8.1.2" {
		t.Fatalf("SetBanner didn't take; got %q", got)
	}
}

// TestDMMockServerStopIsIdempotent matches the PG equivalent.
func TestDMMockServerStopIsIdempotent(t *testing.T) {
	srv := StartDMMockServer(t, "DM: Database Server V8.1.0")
	if err := srv.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Oracle mock
// ---------------------------------------------------------------------------

// TestOracleMockServerStartStop binds and reaches.
func TestOracleMockServerStartStop(t *testing.T) {
	srv := StartOracleMockServer(t, "")
	defer srv.Stop()
	if err := EnsureOracleMockServerReachable(srv); err != nil {
		t.Fatalf("reachability: %v", err)
	}
}

// TestOracleMockServerDefaultBannerContainsTNS verifies the default
// banner has both the (ADDRESS=...) marker and the TNS literal.
func TestOracleMockServerDefaultBannerContainsTNS(t *testing.T) {
	srv := StartOracleMockServer(t, "")
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	total := 0
	for total < 1024 {
		n, rerr := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if rerr != nil {
			break
		}
	}
	got := string(buf[:total])
	if !strings.Contains(got, "(ADDRESS=") {
		t.Errorf("banner missing '(ADDRESS='; got first 80 bytes=%q", first80(got))
	}
	if !strings.Contains(strings.ToUpper(got), "TNS") {
		t.Errorf("banner missing 'TNS'; got first 80 bytes=%q", first80(strings.ToUpper(got)))
	}
}

// TestOracleMockServerCustomBanner respects a caller-supplied banner.
func TestOracleMockServerCustomBanner(t *testing.T) {
	const custom = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1521)))\nTNS-ORACLE Custom Listener"
	srv := StartOracleMockServer(t, custom)
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	total := 0
	for total < 1024 {
		n, rerr := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if rerr != nil {
			break
		}
	}
	if !strings.Contains(string(buf[:total]), "Custom Listener") {
		t.Errorf("custom banner not echoed; got first 80 bytes=%q", first80(string(buf[:total])))
	}
}

// TestOracleMockServerStopIsIdempotent matches the PG/DM equivalents.
func TestOracleMockServerStopIsIdempotent(t *testing.T) {
	srv := StartOracleMockServer(t, "")
	if err := srv.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// ---------------------------------------------------------------------------
// openGauss mock
// ---------------------------------------------------------------------------

// TestOpenGaussMockServerStartStop binds and reaches.
func TestOpenGaussMockServerStartStop(t *testing.T) {
	srv := StartOpenGaussMockServer(t, "")
	defer srv.Stop()
	if err := EnsureOpenGaussMockServerReachable(srv); err != nil {
		t.Fatalf("reachability: %v", err)
	}
}

// TestOpenGaussMockServerRespondsWithBannerAndReadyForQuery mirrors the
// PG mock test but with an openGauss banner.
func TestOpenGaussMockServerRespondsWithBannerAndReadyForQuery(t *testing.T) {
	srv := StartOpenGaussMockServer(t, "openGauss 5.0.0")
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	qMsg := []byte{'Q', 0, 0, 0, 9, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}
	if _, err := conn.Write(qMsg); err != nil {
		t.Fatalf("write Q: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	var sb strings.Builder
	for {
		b, err := reader.ReadByte()
		if err != nil {
			break
		}
		sb.WriteByte(b)
		if b == 'Z' {
			rest := make([]byte, 5)
			n, _ := reader.Read(rest)
			sb.Write(rest[:n])
			break
		}
	}
	resp := sb.String()
	if !strings.Contains(resp, "openGauss 5.0.0") {
		t.Errorf("response missing openGauss banner; got %q", resp)
	}
	if !strings.Contains(resp, "Z") {
		t.Errorf("response missing ReadyForQuery 'Z'; got %q", resp)
	}
}

// TestOpenGaussMockServerSetVersionHotReload ensures the banner is
// swappable.
func TestOpenGaussMockServerSetVersionHotReload(t *testing.T) {
	srv := StartOpenGaussMockServer(t, "openGauss 5.0.0")
	defer srv.Stop()
	srv.SetVersion("openGauss 3.0.0")
	if got := *srv.version.Load(); got != "openGauss 3.0.0" {
		t.Fatalf("SetVersion didn't take; got %q", got)
	}
}

// TestOpenGaussMockServerStopIsIdempotent.
func TestOpenGaussMockServerStopIsIdempotent(t *testing.T) {
	srv := StartOpenGaussMockServer(t, "")
	if err := srv.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// ---------------------------------------------------------------------------
// IvorySQL mock
// ---------------------------------------------------------------------------

// TestIvorySQLMockServerStartStop binds and reaches.
func TestIvorySQLMockServerStartStop(t *testing.T) {
	srv := StartIvorySQLMockServer(t, "")
	defer srv.Stop()
	if err := EnsureIvorySQLMockServerReachable(srv); err != nil {
		t.Fatalf("reachability: %v", err)
	}
}

// TestIvorySQLMockServerRespondsWithBannerAndReadyForQuery mirrors
// the PG / openGauss handshake test with an IvorySQL banner.
func TestIvorySQLMockServerRespondsWithBannerAndReadyForQuery(t *testing.T) {
	srv := StartIvorySQLMockServer(t, "IvorySQL 1.4")
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	qMsg := []byte{'Q', 0, 0, 0, 9, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}
	if _, err := conn.Write(qMsg); err != nil {
		t.Fatalf("write Q: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	var sb strings.Builder
	for {
		b, err := reader.ReadByte()
		if err != nil {
			break
		}
		sb.WriteByte(b)
		if b == 'Z' {
			rest := make([]byte, 5)
			n, _ := reader.Read(rest)
			sb.Write(rest[:n])
			break
		}
	}
	resp := sb.String()
	if !strings.Contains(resp, "IvorySQL 1.4") {
		t.Errorf("response missing IvorySQL banner; got %q", resp)
	}
	if !strings.Contains(resp, "Z") {
		t.Errorf("response missing ReadyForQuery 'Z'; got %q", resp)
	}
}

// TestIvorySQLMockServerHighGoBanner covers the dual-token banner
// variant (IvorySQL + 瀚高) the production classifier also accepts.
func TestIvorySQLMockServerHighGoBanner(t *testing.T) {
	srv := StartIvorySQLMockServer(t, "IvorySQL 1.4 (瀚高 HG)")
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	qMsg := []byte{'Q', 0, 0, 0, 9, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}
	if _, err := conn.Write(qMsg); err != nil {
		t.Fatalf("write Q: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	reader := bufio.NewReader(conn)
	var sb strings.Builder
	for {
		b, err := reader.ReadByte()
		if err != nil {
			break
		}
		sb.WriteByte(b)
		if b == 'Z' {
			rest := make([]byte, 5)
			n, _ := reader.Read(rest)
			sb.Write(rest[:n])
			break
		}
	}
	resp := sb.String()
	if !strings.Contains(resp, "IvorySQL 1.4") {
		t.Errorf("response missing IvorySQL banner; got %q", resp)
	}
}

// TestIvorySQLMockServerSetVersionHotReload.
func TestIvorySQLMockServerSetVersionHotReload(t *testing.T) {
	srv := StartIvorySQLMockServer(t, "IvorySQL 1.4")
	defer srv.Stop()
	srv.SetVersion("IvorySQL 1.2")
	if got := *srv.version.Load(); got != "IvorySQL 1.2" {
		t.Fatalf("SetVersion didn't take; got %q", got)
	}
}

// TestIvorySQLMockServerStopIsIdempotent.
func TestIvorySQLMockServerStopIsIdempotent(t *testing.T) {
	srv := StartIvorySQLMockServer(t, "")
	if err := srv.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// ---------------------------------------------------------------------------
// BrandForPGServer helper
// ---------------------------------------------------------------------------

// TestBrandForPGServerMapping pins the brand mapping for the banners
// this package emits. If a future maintainer changes the banner
// keyword table, they should update both the mock default banners and
// this mapping in lockstep.
func TestBrandForPGServerMapping(t *testing.T) {
	cases := []struct {
		banner string
		want   string
	}{
		{"PostgreSQL 14.10 (Debian)", "pg-compat"},
		{"KingbaseES V008R006C10B0010", "kingbase"},
		{"openGauss 5.0.0", "opengauss"},
		{"IvorySQL 1.4", "ivorysql"},
		{"HighGo Database 4", "hg"},
		{"HG Database 1.0", "hg"},
		{"神通数据库 V7", "shentong"},
		{"Shentong V7", "shentong"},
		{"random banner", "unknown"},
	}
	for _, tc := range cases {
		got := BrandForPGServer(tc.banner)
		if got != tc.want {
			t.Errorf("BrandForPGServer(%q) = %q, want %q", tc.banner, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Cross-mock integration
// ---------------------------------------------------------------------------

// TestAllFiveMocksRunTogether brings up all 5 mocks simultaneously,
// confirms each binds a distinct port, and tears them down. This is
// the integration scenario integration tests will need: each mock
// exposes its own Addr() so callers can wire them up as separate
// probe targets.
func TestAllFiveMocksRunTogether(t *testing.T) {
	pg := StartPGMockServer(t, "PostgreSQL 14.10 (Debian)")
	defer pg.Stop()
	dm := StartDMMockServer(t, "DM: Database Server V8.1.0")
	defer dm.Stop()
	ora := StartOracleMockServer(t, "")
	defer ora.Stop()
	og := StartOpenGaussMockServer(t, "openGauss 5.0.0")
	defer og.Stop()
	iv := StartIvorySQLMockServer(t, "IvorySQL 1.4")
	defer iv.Stop()

	addrs := map[string]string{
		"pg":     pg.Addr(),
		"dm":     dm.Addr(),
		"oracle": ora.Addr(),
		"og":     og.Addr(),
		"iv":     iv.Addr(),
	}
	seen := map[string]bool{}
	for name, addr := range addrs {
		if addr == "" {
			t.Errorf("%s empty addr", name)
		}
		if seen[addr] {
			t.Errorf("%s addr collision: %s reused", name, addr)
		}
		seen[addr] = true
	}
}

// TestAllFiveMocksDialableUnderCtxCancel verifies each server still
// answers dials under a tight context deadline (we cancel after 2s
// to give Go's test infra time to wind down).
func TestAllFiveMocksDialableUnderCtxCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	type dialCheck struct {
		name string
		addr string
	}
	pg := StartPGMockServer(t, "PostgreSQL 14.10 (Debian)")
	defer pg.Stop()
	dm := StartDMMockServer(t, "DM: Database Server V8.1.0")
	defer dm.Stop()
	ora := StartOracleMockServer(t, "")
	defer ora.Stop()
	og := StartOpenGaussMockServer(t, "openGauss 5.0.0")
	defer og.Stop()
	iv := StartIvorySQLMockServer(t, "IvorySQL 1.4")
	defer iv.Stop()

	checks := []dialCheck{
		{"pg", pg.Addr()}, {"dm", dm.Addr()}, {"oracle", ora.Addr()},
		{"og", og.Addr()}, {"iv", iv.Addr()},
	}
	for _, c := range checks {
		d := net.Dialer{Timeout: 1 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", c.addr)
		if err != nil {
			t.Errorf("%s dial: %v", c.name, err)
			continue
		}
		_ = conn.Close()
	}
}

func first80(s string) string {
	if len(s) <= 80 {
		return s
	}
	return s[:80]
}