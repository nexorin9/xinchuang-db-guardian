// Package mockservers provides reusable in-process wire-protocol mock
// servers for the 5 brand families xinchuang-db-guardian targets. They are
// intended for unit tests in internal/probe/port and integration tests
// in test/integration. The mocks are deliberately minimal — they only
// reproduce enough of each wire protocol for the handshake classifiers
// to identify a brand; they do not implement full server semantics.
package mockservers

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PGMockServer is a minimal PostgreSQL wire-protocol responder. It
// accepts a single Q frame, writes the configured banner plus a
// ReadyForQuery frame, and closes. The banner is the only payload the
// classifiers inspect; nothing else needs to be valid.
//
// The defaults are tuned to mirror what the production probe code
// expects: a 5 second read deadline, a banner containing
// "PostgreSQL 14.10 (Debian)", and a single conn handler per Accept.
type PGMockServer struct {
	listener net.Listener
	version  atomic.Pointer[string]
	served   atomic.Int64

	mu      sync.Mutex
	closed  bool
	started time.Time
}

// StartPGMockServer binds to a random local port and starts accepting
// connections. The server stops when Stop() is called or the test
// process exits. The version banner is what the handshake classifier
// will key off of, so tests can swap it via SetVersion() at any time.
func StartPGMockServer(t interface {
	Fatalf(format string, args ...interface{})
}, version string) *PGMockServer {
	return startPGMockServer(version, t.Fatalf)
}

// startPGMockServer is the worker used by StartPGMockServer and is
// exported in pieces so tests can construct a server without a *testing.T
// (e.g. for integration tests driven by dockertest).
func startPGMockServer(version string, fatalf func(string, ...interface{})) *PGMockServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatalf("pg mock listen: %v", err)
	}
	s := &PGMockServer{
		listener: ln,
		started:  time.Now(),
	}
	v := version
	s.version.Store(&v)
	go s.acceptLoop()
	return s
}

// Addr returns the host:port the mock is listening on.
func (s *PGMockServer) Addr() string {
	return s.listener.Addr().String()
}

// SetVersion swaps the banner returned to the next handshake. Existing
// in-flight connections keep the version they captured at conn start.
func (s *PGMockServer) SetVersion(v string) {
	vCopy := v
	s.version.Store(&vCopy)
}

// Served returns the cumulative count of accepted connections.
func (s *PGMockServer) Served() int64 {
	return s.served.Load()
}

// Stop closes the listener. Active connections are not interrupted —
// they will see a read error and exit on their own.
func (s *PGMockServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.listener.Close()
}

// acceptLoop runs until Stop() is called.
func (s *PGMockServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.served.Add(1)
		go s.serve(conn)
	}
}

// serve handles exactly one connection: read one Q frame, write banner +
// ReadyForQuery, close.
func (s *PGMockServer) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	qBuf := make([]byte, 256)
	n, err := conn.Read(qBuf)
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	if n == 0 || qBuf[0] != 'Q' {
		return
	}

	ver := *s.version.Load()
	reply := pgWireHandshakeResponse(ver)

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(reply)
}

// pgWireHandshakeResponse builds the smallest response that satisfies
// the production Handshake() classifier: a textual greeting containing
// the brand banner, terminated by a ReadyForQuery 'Z' idle frame. The
// production code looks for 'T' RowDescription + 'D' DataRow, but in
// practice any bytes ending with 'Z' are accepted because the classifier
// only inspects the textual banner content. We keep the response honest
// anyway, in case future classifiers look deeper.
func pgWireHandshakeResponse(version string) []byte {
	// ReadyForQuery idle frame: 'Z' tag + 4-byte length (5) + 'I' status.
	readyForQuery := []byte{'Z', 0, 0, 0, 5, 'I'}
	// RowDescription (empty): 'T' tag + length 6 + 0 fields.
	rowDesc := []byte{'T', 0, 0, 0, 6, 0, 0, 0, 0, 0}
	// DataRow single column "1": 'D' tag + length 8 + 2-byte col count +
	// 4-byte col length + '1'.
	dataRow := []byte{'D', 0, 0, 0, 8, 0, 1, 0, 0, 0, 1, '1'}
	// CommandComplete: 'C' tag + length 8 + "SELECT 1\0".
	cmdComplete := []byte{'C', 0, 0, 0, 9, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}

	banner := []byte(version)
	out := make([]byte, 0, len(banner)+len(rowDesc)+len(dataRow)+len(cmdComplete)+len(readyForQuery)+2)
	out = append(out, banner...)
	if len(banner) > 0 && banner[len(banner)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, rowDesc...)
	out = append(out, dataRow...)
	out = append(out, cmdComplete...)
	out = append(out, readyForQuery...)
	return out
}

// EnsurePGMockServerReachable is a quick smoke helper: dial Addr() and
// drop. It returns nil on success.
func EnsurePGMockServerReachable(s *PGMockServer) error {
	if s == nil {
		return errors.New("pg mock: nil server")
	}
	conn, err := net.DialTimeout("tcp", s.Addr(), 2*time.Second)
	if err != nil {
		return fmt.Errorf("pg mock dial %s: %w", s.Addr(), err)
	}
	_ = conn.Close()
	return nil
}