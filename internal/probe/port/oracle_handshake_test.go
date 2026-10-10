package port

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// startOracleBannerServer emits a TNS-style banner optionally
// containing the canonical "(ADDRESS=" marker.
func startOracleBannerServer(t *testing.T, banner string) string {
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
		time.Sleep(200 * time.Millisecond)
		_ = ln.Close()
	}()
	return ln.Addr().String()
}

// TestOracleHandshakeAddressMarker verifies acceptance via the
// (ADDRESS=...) accept-redirect marker.
func TestOracleHandshakeAddressMarker(t *testing.T) {
	banner := "(DESCRIPTION=(ADDRESS=...)(CONNECT_DATA=(SERVICE_NAME=ORCL)))\n"
	addr := startOracleBannerServer(t, banner)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	raw, brand, err := OracleHandshake(ctx, addr)
	if err != nil {
		t.Fatalf("OracleHandshake: %v", err)
	}
	if brand != "oracle" {
		t.Errorf("brand = %q, want oracle", brand)
	}
	if !strings.Contains(string(raw), "(ADDRESS=") {
		t.Errorf("raw missing (ADDRESS=, got %q", raw)
	}
}

// TestOracleHandshakeTNSKeyword verifies detection via TNS keyword.
func TestOracleHandshakeTNSKeyword(t *testing.T) {
	banner := "TNSLSNR for Linux: Version 19.0.0.0.0\n"
	addr := startOracleBannerServer(t, banner)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, brand, err := OracleHandshake(ctx, addr)
	if err != nil {
		t.Fatalf("OracleHandshake: %v", err)
	}
	if brand != "oracle" {
		t.Errorf("brand = %q, want oracle", brand)
	}
}

// TestOracleHandshakeNoKeyword rejects banners that don't carry any
// Oracle fingerprint.
func TestOracleHandshakeNoKeyword(t *testing.T) {
	addr := startOracleBannerServer(t, "Generic DB\n")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, brand, err := OracleHandshake(ctx, addr)
	if err == nil {
		t.Fatalf("expected error, brand=%q", brand)
	}
}

// TestOracleHandshakeEmptyAddr short-circuits on empty input.
func TestOracleHandshakeEmptyAddr(t *testing.T) {
	_, _, err := OracleHandshake(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty addr")
	}
}

// TestExtractRedirectAddress parses nested (ADDRESS=...) structures.
func TestExtractRedirectAddress(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "simple",
			raw:  []byte("(ADDRESS=(PROTOCOL=tcp)(HOST=foo)(PORT=1521))"),
			want: "(ADDRESS=(PROTOCOL=tcp)(HOST=foo)(PORT=1521))",
		},
		{
			name: "nested",
			raw:  []byte("HDR(DESCRIPTION=(ADDRESS=(HOST=x))(PORT=1522))"),
			want: "(ADDRESS=(HOST=x))",
		},
		{
			name: "missing",
			raw:  []byte("no marker here"),
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractRedirectAddress(tc.raw)
			if got != tc.want {
				t.Errorf("extractRedirectAddress = %q, want %q", got, tc.want)
			}
		})
	}
}
