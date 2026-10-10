// Package port contains TCP-level handshake probes for xinchuang DB brands.
// The probes are intentionally minimal: they only confirm the wire-level
// greeting + a single SELECT 1 round-trip; they do NOT touch business
// tables or read sensitive data.
package port

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Brand labels recognised by the PG-handshake classifier. All of these
// vendors implement the PostgreSQL wire protocol on the wire, so they all
// pass through Handshake() — the difference shows up in the server greeting
// banner content returned in BackendKeyData / RowDescription frames.
const (
	BrandKingbaseES = "kingbase"
	BrandOpenGauss  = "opengauss"
	BrandIvorySQL   = "ivorysql"
	BrandHG         = "hg"
	BrandShentong   = "shentong"
	BrandPGCompat   = "pg-compat"
	BrandUnknown    = "unknown"
)

// pgHandshakeTimeout is the wall-clock cap for a single Handshake() call.
// Typical PG-compatible servers respond within ~150 ms; we leave 5 s of
// headroom before declaring probe_error downstream.
const pgHandshakeTimeout = 5 * time.Second

// pgQueryRowMax is the maximum number of bytes we will buffer for the
// response body; 8 KiB is comfortable for a SELECT 1 row.
const pgQueryRowMax = 8 * 1024

// PGQueryMessage is the on-wire form of the simple-query "Q" message for
// `SELECT 1\x00`. The structure is: 1-byte tag 'Q' + 4-byte length
// (big-endian) + query string + terminating NUL. See libpq protocol docs.
var pgQueryMessage = []byte{
	'Q', 0, 0, 0, byte(len("SELECT 1") + 1),
	'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0,
}

// HandshakeResult is the on-the-wire outcome of a single probe. Raw
// contains the raw bytes returned by the server up to (and including)
// the ReadyForQuery 'Z' frame; Brand is the classifier's identification.
type HandshakeResult struct {
	Brand string
	Raw   []byte
}

// classifyPGBanner examines the raw greeting bytes to pick a Brand.
// All PG-wire compatible servers emit an identifying token in their
// banner or BackendKeyData payload. We prefer explicit brand tokens
// over the generic "PostgreSQL" fallback.
func classifyPGBanner(raw []byte) string {
	banner := strings.ToLower(string(raw))
	switch {
	case strings.Contains(banner, "kingbasees"):
		return BrandKingbaseES
	case strings.Contains(banner, "opengauss"):
		return BrandOpenGauss
	case strings.Contains(banner, "ivorysql"):
		return BrandIvorySQL
	case strings.Contains(banner, "highgo") || strings.Contains(banner, "hg"):
		return BrandHG
	case strings.Contains(banner, "shentong") || strings.Contains(banner, "神通"):
		return BrandShentong
	case strings.Contains(banner, "postgres"):
		return BrandPGCompat
	default:
		return BrandUnknown
	}
}

// Handshake connects to addr, sends the minimal `Q SELECT 1` query, and
// reads back the response up to ReadyForQuery. It returns the assembled
// response bytes plus the classified Brand label.
//
// The function never panics on bad input or partial reads; every error
// path returns a (zero-result, err) pair that the Scheduler can record
// as a transient_fail.
func Handshake(ctx context.Context, addr string) (HandshakeResult, error) {
	if addr == "" {
		return HandshakeResult{}, errors.New("port: empty addr")
	}

	// Apply our per-call timeout. We honour ctx cancellation first.
	dialer := net.Dialer{Timeout: pgHandshakeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return HandshakeResult{}, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(pgHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return HandshakeResult{}, fmt.Errorf("set deadline: %w", err)
	}

	// Send the minimal SELECT 1 simple-query message.
	if _, err := conn.Write(pgQueryMessage); err != nil {
		return HandshakeResult{}, fmt.Errorf("write Q message: %w", err)
	}

	// Read until we see ReadyForQuery 'Z'. Stream-by-stream collect so we
	// don't blow up on multi-frame responses.
	collected := bytes.NewBuffer(nil)
	seenZ := false
	tmp := make([]byte, 4096)
	for !seenZ && collected.Len() < pgQueryRowMax*4 {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			collected.Write(tmp[:n])
			// PG simple-query response always ends with ReadyForQuery 'Z'.
			// See: https://www.postgresql.org/docs/current/protocol-flow.html
			if bytes.IndexByte(collected.Bytes(), 'Z') >= 0 {
				seenZ = true
			}
		}
		if readErr != nil {
			if errors.Is(readErr, net.ErrClosed) {
				break
			}
			if collected.Len() == 0 {
				return HandshakeResult{}, fmt.Errorf("read response: %w", readErr)
			}
			break
		}
	}

	rawBytes := collected.Bytes()
	if len(rawBytes) == 0 {
		return HandshakeResult{}, errors.New("port: empty response")
	}
	if !seenZ {
		// If we never saw the terminating frame, treat the response as
		// malformed rather than guessing brand.
		return HandshakeResult{}, fmt.Errorf("port: missing ReadyForQuery frame in %d bytes", len(rawBytes))
	}

	return HandshakeResult{
		Brand: classifyPGBanner(rawBytes),
		Raw:   rawBytes,
	}, nil
}

// HandshakeFingerprint returns a stable SHA256 of the first 512 bytes
// of the raw response. This is what gets compared against the contract's
// AllowDrift fingerprint list.
func HandshakeFingerprint(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
