package mockservers

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DMMockServer is a minimal DaMeng (DM8) TNS banner responder. DM8
// identifies itself in the first connection-time banner with the
// strings "DM: " or "DAMENG"; the production DMHandshake classifier
// looks for both. We write the configured banner immediately and then
// hold the connection briefly to mimic a real server that would have
// continued negotiation.
type DMMockServer struct {
	listener net.Listener
	banner   atomic.Pointer[string]
	served   atomic.Int64

	mu     sync.Mutex
	closed bool
}

// StartDMMockServer binds a random local port and writes the DM8 banner
// to every connecting client. The banner must contain "DM:" or
// "DAMENG" (case-insensitive) for the production classifier to label
// the brand as "dm8".
func StartDMMockServer(t interface {
	Fatalf(format string, args ...interface{})
}, banner string) *DMMockServer {
	return startDMMockServer(banner, t.Fatalf)
}

func startDMMockServer(banner string, fatalf func(string, ...interface{})) *DMMockServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatalf("dm mock listen: %v", err)
	}
	s := &DMMockServer{listener: ln}
	bCopy := banner
	s.banner.Store(&bCopy)
	go s.acceptLoop()
	return s
}

// Addr returns the host:port the mock is listening on.
func (s *DMMockServer) Addr() string {
	return s.listener.Addr().String()
}

// SetBanner updates the greeting for the next connection.
func (s *DMMockServer) SetBanner(b string) {
	bCopy := b
	s.banner.Store(&bCopy)
}

// Served returns the cumulative count of accepted connections.
func (s *DMMockServer) Served() int64 {
	return s.served.Load()
}

// Stop closes the listener. Active connections finish their read loop
// and exit.
func (s *DMMockServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.listener.Close()
}

func (s *DMMockServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.served.Add(1)
		go s.serve(conn)
	}
}

// serve writes the DM8 banner + a short padding payload (so the read
// fills more than a single TCP segment) and closes. The DM classifier
// only inspects the first 512 bytes.
func (s *DMMockServer) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	banner := *s.banner.Load()
	if banner == "" {
		// Default DM8 banner.
		banner = "DM: Database Server V8.1.0\n"
	}
	// Pad out to a plausible banner length so the read loop completes
	// in one go without holding the connection idle.
	padding := make([]byte, 256)
	for i := range padding {
		padding[i] = ' '
	}
	out := append([]byte(banner), padding...)

	_, _ = conn.Write(out)
	// Hold briefly so client has a chance to read; then close.
	time.Sleep(50 * time.Millisecond)
}

// EnsureDMMockServerReachable dials the mock to confirm it bound
// successfully. Returns nil on success.
func EnsureDMMockServerReachable(s *DMMockServer) error {
	if s == nil {
		return errors.New("dm mock: nil server")
	}
	conn, err := net.DialTimeout("tcp", s.Addr(), 2*time.Second)
	if err != nil {
		return fmt.Errorf("dm mock dial %s: %w", s.Addr(), err)
	}
	_ = conn.Close()
	return nil
}