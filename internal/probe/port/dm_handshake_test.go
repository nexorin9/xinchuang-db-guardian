package port

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// startDMBannerServer stands up a one-shot TCP server that emits the
// requested banner immediately after accept, then closes the
// connection. This is enough for DMHandshake() to read the banner.
func startDMBannerServer(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte(banner))
		_ = conn.Close()
		// keep listener alive briefly so the client has time to read.
		time.Sleep(200 * time.Millisecond)
		_ = ln.Close()
	}()
	return ln.Addr().String()
}

// TestDMHandshakeKeywordDM verifies the "DM: " keyword is detected.
func TestDMHandshakeKeywordDM(t *testing.T) {
	addr := startDMBannerServer(t, "DM: Database Server V8.1.0\n")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	raw, brand, err := DMHandshake(ctx, addr)
	if err != nil {
		t.Fatalf("DMHandshake: %v raw=%s", err, raw)
	}
	if brand != "dm8" {
		t.Errorf("brand = %q, want dm8", brand)
	}
	if !strings.Contains(strings.ToUpper(string(raw)), "DM") {
		t.Errorf("raw missing DM, got %q", raw)
	}
}

// TestDMHandshakeKeywordDAMENG verifies the "DAMENG" keyword is detected.
func TestDMHandshakeKeywordDAMENG(t *testing.T) {
	addr := startDMBannerServer(t, "DAMENG DBMS Server V8.1.2 build(12345)\n")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, brand, err := DMHandshake(ctx, addr)
	if err != nil {
		t.Fatalf("DMHandshake: %v", err)
	}
	if brand != "dm8" {
		t.Errorf("brand = %q, want dm8", brand)
	}
}

// TestDMHandshakeNoKeyword fails classification when no keyword present.
func TestDMHandshakeNoKeyword(t *testing.T) {
	addr := startDMBannerServer(t, "Generic SQL Server 1.0\n")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, brand, err := DMHandshake(ctx, addr)
	if err == nil {
		t.Fatalf("expected error, brand=%q", brand)
	}
	if brand == "dm8" {
		t.Errorf("should not classify as dm8")
	}
}

// TestDMHandshakeEmptyAddr ensures no panic on empty addr.
func TestDMHandshakeEmptyAddr(t *testing.T) {
	_, _, err := DMHandshake(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty addr")
	}
}

// TestDMHandshakeDialFailure ensures unreachable addr returns an error
// rather than panicking.
func TestDMHandshakeDialFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, _, err := DMHandshake(ctx, "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected dial failure")
	}
}
