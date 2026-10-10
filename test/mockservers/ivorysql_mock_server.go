package mockservers

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// IvorySQLMockServer is a PG-wire-protocol responder with the banner
// "IvorySQL X.Y". It shares the PGMockServer wire shape (Q frame +
// textual greeting + ReadyForQuery) but pre-loads the banner with
// the IvorySQL version token so the production classifier labels the
// brand as "ivorysql" rather than the generic "pg-compat".
//
// The banner is configurable so tests can simulate the "IvorySQL +
// HighGo 瀚高" dual-token variant that the production classifier
// accepts via the "highgo"/"hg" token table.
type IvorySQLMockServer struct {
	listener net.Listener
	version  atomic.Pointer[string]
	served   atomic.Int64

	mu     sync.Mutex
	closed bool
}

// StartIvorySQLMockServer starts an IvorySQL-style PG wire responder.
// Default banner is "IvorySQL 1.4".
func StartIvorySQLMockServer(t interface {
	Fatalf(format string, args ...interface{})
}, version string) *IvorySQLMockServer {
	return startIvorySQLMockServer(version, t.Fatalf)
}

func startIvorySQLMockServer(version string, fatalf func(string, ...interface{})) *IvorySQLMockServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatalf("ivorysql mock listen: %v", err)
	}
	s := &IvorySQLMockServer{listener: ln}
	if version == "" {
		version = "IvorySQL 1.4"
	}
	vCopy := version
	s.version.Store(&vCopy)
	go s.acceptLoop()
	return s
}

// Addr returns the host:port the mock is listening on.
func (s *IvorySQLMockServer) Addr() string {
	return s.listener.Addr().String()
}

// SetVersion swaps the banner returned to subsequent handshakes.
func (s *IvorySQLMockServer) SetVersion(v string) {
	vCopy := v
	s.version.Store(&vCopy)
}

// Served returns the cumulative count of accepted connections.
func (s *IvorySQLMockServer) Served() int64 {
	return s.served.Load()
}

// Stop closes the listener.
func (s *IvorySQLMockServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.listener.Close()
}

func (s *IvorySQLMockServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.served.Add(1)
		go s.serve(conn)
	}
}

// serve reads one Q frame, then writes the IvorySQL banner followed
// by a ReadyForQuery frame. Wire shape matches the production
// PGMockServer exactly so the same production Handshake() classifier
// recognises it.
func (s *IvorySQLMockServer) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	qBuf := make([]byte, 256)
	n, err := conn.Read(qBuf)
	if err != nil || n == 0 || qBuf[0] != 'Q' {
		return
	}

	ver := *s.version.Load()
	reply := pgWireHandshakeResponse(ver)

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(reply)
}

// EnsureIvorySQLMockServerReachable dials the mock to confirm bind.
func EnsureIvorySQLMockServerReachable(s *IvorySQLMockServer) error {
	if s == nil {
		return errors.New("ivorysql mock: nil server")
	}
	conn, err := net.DialTimeout("tcp", s.Addr(), 2*time.Second)
	if err != nil {
		return fmt.Errorf("ivorysql mock dial %s: %w", s.Addr(), err)
	}
	_ = conn.Close()
	return nil
}

// BrandForPGServer is a small helper used by integration tests that
// have already dialed a PG-wire server and want to translate the
// banner bytes into the brand label the production classifier would
// emit. It calls the same private classifyPGBanner path indirectly
// by mapping the well-known token prefixes used by the mocks. This
// avoids exporting classifyPGBanner from internal/probe/port.
//
// The mapping is intentionally narrow — it is intended only for the
// banner strings this package emits. If you need a real brand lookup
// against arbitrary banners, import internal/probe/port directly.
func BrandForPGServer(banner string) string {
	switch {
	case containsAnyFold(banner, "KingbaseES"):
		return "kingbase"
	case containsAnyFold(banner, "openGauss"):
		return "opengauss"
	case containsAnyFold(banner, "IvorySQL"):
		return "ivorysql"
	case containsAnyFold(banner, "HighGo", "HG"):
		return "hg"
	case containsAnyFold(banner, "神通", "Shentong"):
		return "shentong"
	case containsAnyFold(banner, "PostgreSQL", "postgres"):
		return "pg-compat"
	default:
		return "unknown"
	}
}

func containsAnyFold(s string, needles ...string) bool {
	for _, n := range needles {
		if foldContains(s, n) {
			return true
		}
	}
	return false
}

// foldContains is a tiny ASCII-only case-insensitive contains so we
// don't pull strings.ToLower into every call site. CJK characters
// (e.g. "神通") are compared as-is because Go's strings.EqualFold
// does not lowercase CJK; production brand matching uses the same
// pattern (lowercase via strings.ToLower, then byte-level Contains).
func foldContains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			a := s[i+j]
			b := substr[j]
			// ASCII-only case fold; non-ASCII bytes must match exactly.
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}