package port

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// DM handshake banner keywords. DaMeng (DM8) emits "DM: " or "DAMENG" in
// the first connection-time banner; the protocol is proprietary TNS but
// the banner is sufficient to identify the brand without going past the
// handshake layer.
const (
	dmBannerKeyword1 = "DM:"
	dmBannerKeyword2 = "DAMENG"
	dmBrandLabel     = "dm8"
	dmBannerReadMax  = 512
	dmHandshakeTO    = 5 * time.Second
)

// DMHandshake connects to addr, reads the initial banner, and classifies
// the brand as dm8 if either DM: or DAMENG appears in the first 512 bytes.
// We deliberately do NOT proceed past the handshake — we never issue a
// SELECT or read schema metadata.
//
// Returns (raw, brand, err). On success brand == "dm8". On any
// non-identification outcome brand == "unknown" and err is non-nil.
func DMHandshake(ctx context.Context, addr string) ([]byte, string, error) {
	if addr == "" {
		return nil, "unknown", errors.New("dm: empty addr")
	}

	dialer := net.Dialer{Timeout: dmHandshakeTO}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "unknown", fmt.Errorf("dm dial %s: %w", addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(dmHandshakeTO)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, "unknown", fmt.Errorf("dm set deadline: %w", err)
	}

	buf := make([]byte, dmBannerReadMax)
	total := 0
	for total < dmBannerReadMax {
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
		return raw, "unknown", errors.New("dm: empty banner")
	}

	banner := strings.ToUpper(string(raw))
	if strings.Contains(banner, dmBannerKeyword1) || strings.Contains(banner, dmBannerKeyword2) {
		return raw, dmBrandLabel, nil
	}
	return raw, "unknown", fmt.Errorf("dm: no brand keyword in banner (%d bytes)", total)
}
