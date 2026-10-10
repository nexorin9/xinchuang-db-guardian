package port

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// pgMockServer is a minimal libpq-style responder: it reads one Q frame
// and replays a plausible PostgreSQL simple-query response ending in
// ReadyForQuery. The version string is configurable so tests can pin
// expected brands.
type pgMockServer struct {
	listener net.Listener
	version string
	srvMu   sync.Mutex
	served  int
}

func startPGMockServer(t *testing.T, version string) *pgMockServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &pgMockServer{listener: ln, version: version}
	go srv.acceptLoop()
	return srv
}

func (s *pgMockServer) Addr() string { return s.listener.Addr().String() }

func (s *pgMockServer) Stop() { _ = s.listener.Close() }

func (s *pgMockServer) Served() int {
	s.srvMu.Lock()
	defer s.srvMu.Unlock()
	return s.served
}

func (s *pgMockServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.srvMu.Lock()
		s.served++
		s.srvMu.Unlock()
		go s.serve(conn)
	}
}

// serve reads one Q frame, then writes a minimal PG response that
// satisfies the Handshake() contract: it MUST contain the version
// banner (so the classifier can pick a Brand) and end with a ReadyForQuery
// 'Z' frame. We are deliberately not implementing every PG wire rule —
// this is a test-time mock.
func (s *pgMockServer) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	qBuf := make([]byte, 256)
	n, err := conn.Read(qBuf)
	if err != nil || n == 0 || qBuf[0] != 'Q' {
		return
	}

	// ReadyForQuery idle frame: 'Z' + int32(5) + 'I'.
	readyForQuery := []byte{'Z', 0, 0, 0, 5, 'I'}

	var reply []byte
	banner := []byte(s.version)
	if len(banner) > 0 {
		reply = append(reply, banner...)
		reply = append(reply, '\n')
	}
	reply = append(reply, readyForQuery...)

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(reply)
}

// TestPGHandshakePGCompatBrand verifies Handshake() picks up
// BrandPGCompat for a generic Postgres banner.
func TestPGHandshakePGCompatBrand(t *testing.T) {
	srv := startPGMockServer(t, "PostgreSQL 14.10 (Debian)")
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := Handshake(ctx, srv.Addr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if res.Brand != BrandPGCompat {
		t.Errorf("brand = %q, want %q", res.Brand, BrandPGCompat)
	}
	if len(res.Raw) == 0 {
		t.Fatal("expected non-empty raw bytes")
	}
}

// TestPGHandshakeKingbaseBrand verifies KingbaseES server responds with
// BrandKingbaseES.
func TestPGHandshakeKingbaseBrand(t *testing.T) {
	srv := startPGMockServer(t, "KingbaseES V008R006C10B0010")
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := Handshake(ctx, srv.Addr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if res.Brand != BrandKingbaseES {
		t.Errorf("brand = %q, want %q", res.Brand, BrandKingbaseES)
	}
}

// TestPGHandshakeOpenGaussBrand verifies openGauss server is identified.
func TestPGHandshakeOpenGaussBrand(t *testing.T) {
	srv := startPGMockServer(t, "openGauss 5.0.0")
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := Handshake(ctx, srv.Addr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if res.Brand != BrandOpenGauss {
		t.Errorf("brand = %q, want %q", res.Brand, BrandOpenGauss)
	}
}

// TestPGHandshakeIvorySQLBrand verifies IvorySQL server is identified.
func TestPGHandshakeIvorySQLBrand(t *testing.T) {
	srv := startPGMockServer(t, "IvorySQL 1.4")
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := Handshake(ctx, srv.Addr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if res.Brand != BrandIvorySQL {
		t.Errorf("brand = %q, want %q", res.Brand, BrandIvorySQL)
	}
}

// TestPGHandshakeDialFailure verifies a bad address yields an error
// rather than panicking or hanging.
func TestPGHandshakeDialFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	res, err := Handshake(ctx, "127.0.0.1:1") // unlikely to be open
	if err == nil {
		t.Fatalf("expected dial error, got %+v", res)
	}
}

// TestPGHandshakeEmptyAddr makes sure empty input is caught without
// hitting net.Dial.
func TestPGHandshakeEmptyAddr(t *testing.T) {
	_, err := Handshake(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty addr")
	}
}

// TestClassifyPGBannerExhaustive covers the classifier for every
// supported brand plus an unknown fallback.
func TestClassifyPGBannerExhaustive(t *testing.T) {
	cases := map[string]string{
		"KingbaseES V008R006": BrandKingbaseES,
		"openGauss 5.0.0":     BrandOpenGauss,
		"IvorySQL 1.4":        BrandIvorySQL,
		"HighGo Database 4":   BrandHG,
		"神通数据库 V7":            BrandShentong,
		"PostgreSQL 14":       BrandPGCompat,
		"random banner":       BrandUnknown,
	}
	for raw, want := range cases {
		got := classifyPGBanner([]byte(raw))
		if got != want {
			t.Errorf("classify(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestHandshakeFingerprintStable checks the fingerprint derivation is
// stable across calls.
func TestHandshakeFingerprintStable(t *testing.T) {
	raw := []byte("PostgreSQL 14.10 (Debian) — fingerprint test")
	if HandshakeFingerprint(raw) != HandshakeFingerprint(raw) {
		t.Fatal("fingerprint should be stable for same input")
	}
	// And distinct for different input.
	if HandshakeFingerprint(raw) == HandshakeFingerprint([]byte("different")) {
		t.Fatal("fingerprint should be distinct for different input")
	}
}
