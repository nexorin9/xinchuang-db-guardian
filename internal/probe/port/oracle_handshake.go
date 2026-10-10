package port

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Oracle TNS banner size and timeouts. The TNS redirect packet is short
// (well under 1 KiB) but is fragmented across a multi-byte length prefix;
// we therefore cap reads at 1 KiB total. See My Oracle Support note
// 793306.1 for the exact TNS negotiation layout.
const (
	oracleBannerReadMax = 1024
	oracleBrandLabel    = "oracle"
	oracleHandshakeTO   = 5 * time.Second
)

// oracleAcceptRedirectMarker is the well-known TNS packet type that
// signals "I will redirect you to a different endpoint". Oracle databases
// emit this during the very first handshake when the listener routes the
// client to a specific instance.
var oracleAcceptRedirectMarker = []byte("(DESCRIPTION=(ADDRESS=...")

// OracleHandshake reads the Oracle 1521 initial banner and classifies the
// brand as "oracle" if the accept-redirect / TNS markers are present.
// We do NOT proceed past the handshake: no SELECT is issued, no
// authentication step is attempted.
//
// extractRedirectAddress is best-effort and returns the first
// (ADDRESS=...) string found in the banner; it's an implementation
// helper for callers that want to log the redirect target.
func OracleHandshake(ctx context.Context, addr string) ([]byte, string, error) {
	if addr == "" {
		return nil, "unknown", errors.New("oracle: empty addr")
	}

	dialer := net.Dialer{Timeout: oracleHandshakeTO}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "unknown", fmt.Errorf("oracle dial %s: %w", addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(oracleHandshakeTO)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, "unknown", fmt.Errorf("oracle set deadline: %w", err)
	}

	buf := make([]byte, oracleBannerReadMax)
	total := 0
	for total < oracleBannerReadMax {
		n, readErr := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if readErr != nil {
			break
		}
	}
	raw := buf[:total]
	if total == 0 {
		return raw, "unknown", errors.New("oracle: empty banner")
	}

	upper := strings.ToUpper(string(raw))
	if bytes.Contains(raw, oracleAcceptRedirectMarker) ||
		strings.Contains(upper, "TNS") ||
		strings.Contains(upper, "ORACLE") {
		return raw, oracleBrandLabel, nil
	}
	return raw, "unknown", fmt.Errorf("oracle: no TNS/accept-redirect marker in banner (%d bytes)", total)
}

// extractRedirectAddress parses "(ADDRESS=...)" out of an Oracle TNS
// banner. It is a helper for callers that want to log the routing
// destination; probe correctness does not depend on its result.
func extractRedirectAddress(raw []byte) string {
	openIdx := bytes.Index(raw, []byte("(ADDRESS="))
	if openIdx < 0 {
		return ""
	}
	// Find the matching closing parenthesis. TNS ADDRESS strings contain
	// only well-parenthesised key=value pairs, so we walk a depth counter.
	depth := 0
	for i := openIdx; i < len(raw); i++ {
		switch raw[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return string(raw[openIdx : i+1])
			}
		}
	}
	return ""
}
