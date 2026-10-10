package mockservers

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// OpenGaussMockServer is a PG-wire-protocol responder with the
// banner "openGauss X.Y.Z". It shares the PGMockServer wire shape
// (Q frame + textual greeting + ReadyForQuery) but pre-loads the
// banner with the openGauss version token so the production
// classifier labels the brand as "opengauss" rather than the
// generic "pg-compat".
type OpenGaussMockServer struct {
	listener net.Listener
	version  atomic.Pointer[string]
	served   atomic.Int64

	mu     sync.Mutex
	closed bool
}

// StartOpenGaussMockServer starts an openGauss-style PG wire responder
// with the configured banner. Default banner is "openGauss 5.0.0".
func StartOpenGaussMockServer(t interface {
	Fatalf(format string, args ...interface{})
}, version string) *OpenGaussMockServer {
	return startOpenGaussMockServer(version, t.Fatalf)
}

func startOpenGaussMockServer(version string, fatalf func(string, ...interface{})) *OpenGaussMockServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatalf("opengauss mock listen: %v", err)
	}
	s := &OpenGaussMockServer{listener: ln}
	if version == "" {
		version = "openGauss 5.0.0"
	}
	vCopy := version
	s.version.Store(&vCopy)
	go s.acceptLoop()
	return s
}

// Addr returns the host:port the mock is listening on.
func (s *OpenGaussMockServer) Addr() string {
	return s.listener.Addr().String()
}

// SetVersion swaps the banner returned to subsequent handshakes.
func (s *OpenGaussMockServer) SetVersion(v string) {
	vCopy := v
	s.version.Store(&vCopy)
}

// Served returns the cumulative count of accepted connections.
func (s *OpenGaussMockServer) Served() int64 {
	return s.served.Load()
}

// Stop closes the listener.
func (s *OpenGaussMockServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.listener.Close()
}

func (s *OpenGaussMockServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.served.Add(1)
		go s.serve(conn)
	}
}

// serve reads one Q frame, then writes the openGauss banner followed
// by a ReadyForQuery frame. Wire shape matches the production
// PGMockServer exactly so the same production Handshake() classifier
// recognises it.
func (s *OpenGaussMockServer) serve(conn net.Conn) {
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

// EnsureOpenGaussMockServerReachable dials the mock to confirm bind.
func EnsureOpenGaussMockServerReachable(s *OpenGaussMockServer) error {
	if s == nil {
		return errors.New("opengauss mock: nil server")
	}
	conn, err := net.DialTimeout("tcp", s.Addr(), 2*time.Second)
	if err != nil {
		return fmt.Errorf("opengauss mock dial %s: %w", s.Addr(), err)
	}
	_ = conn.Close()
	return nil
}