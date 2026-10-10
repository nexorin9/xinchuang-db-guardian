package mockservers

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// OracleMockServer emits a TNS-style banner that the production
// OracleHandshake classifier recognises: it contains
// "(DESCRIPTION=(ADDRESS=" ... ")" plus the literal "TNS" or
// "ORACLE" token. The classifier inspects only the first 1 KiB.
type OracleMockServer struct {
	listener net.Listener
	banner   atomic.Pointer[string]
	served   atomic.Int64

	mu     sync.Mutex
	closed bool
}

// StartOracleMockServer starts an oracle-style TNS redirect banner
// responder. Default banner is one that the production classifier
// recognises as "oracle":
//
//	"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=ORCL)))"
func StartOracleMockServer(t interface {
	Fatalf(format string, args ...interface{})
}, banner string) *OracleMockServer {
	return startOracleMockServer(banner, t.Fatalf)
}

func startOracleMockServer(banner string, fatalf func(string, ...interface{})) *OracleMockServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatalf("oracle mock listen: %v", err)
	}
	s := &OracleMockServer{listener: ln}
	if banner == "" {
		banner = oracleDefaultBanner
	}
	bCopy := banner
	s.banner.Store(&bCopy)
	go s.acceptLoop()
	return s
}

// oracleDefaultBanner is a small but well-formed TNS redirect banner
// containing both the (ADDRESS=...) marker and the literal "TNS" /
// "ORACLE" tokens the classifier keys on.
const oracleDefaultBanner = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=ORCL)))\nTNS listener for ORACLE Database 19c\n"

// Addr returns the host:port the mock is listening on.
func (s *OracleMockServer) Addr() string {
	return s.listener.Addr().String()
}

// SetBanner updates the banner for subsequent connections.
func (s *OracleMockServer) SetBanner(b string) {
	bCopy := b
	s.banner.Store(&bCopy)
}

// Served returns the cumulative count of accepted connections.
func (s *OracleMockServer) Served() int64 {
	return s.served.Load()
}

// Stop closes the listener.
func (s *OracleMockServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.listener.Close()
}

func (s *OracleMockServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.served.Add(1)
		go s.serve(conn)
	}
}

// serve writes the configured TNS banner + padding and closes.
func (s *OracleMockServer) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	banner := *s.banner.Load()
	padding := make([]byte, 256)
	for i := range padding {
		padding[i] = ' '
	}
	out := append([]byte(banner), padding...)

	_, _ = conn.Write(out)
	time.Sleep(50 * time.Millisecond)
}

// EnsureOracleMockServerReachable dials the mock to confirm bind.
func EnsureOracleMockServerReachable(s *OracleMockServer) error {
	if s == nil {
		return errors.New("oracle mock: nil server")
	}
	conn, err := net.DialTimeout("tcp", s.Addr(), 2*time.Second)
	if err != nil {
		return fmt.Errorf("oracle mock dial %s: %w", s.Addr(), err)
	}
	_ = conn.Close()
	return nil
}