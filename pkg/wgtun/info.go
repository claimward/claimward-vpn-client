package wgtun

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Info is what a running tunnel reports about itself: the peer as the device
// holds it now (the endpoint can roam, the allowed IPs change with a route
// push), its transfer counters, and what the tunnel was configured with.
//
// It carries no key: neither the device's private key nor the peer's public
// one is read out of the device.
type Info struct {
	Endpoint   string   // peer host:port, "" until one is known
	AllowedIPs []string // CIDRs routed into the tunnel
	DNS        []string // as configured
	MTU        int      // the interface's, after fitting it to the path
	RxBytes    uint64   // received from the peer
	TxBytes    uint64   // sent to the peer
	// LastHandshake is the last completed handshake with the peer; zero when
	// there has been none.
	LastHandshake time.Time
}

// maxUAPILines bounds what parseInfo reads of a "get" answer: one peer is a
// dozen lines plus its allowed IPs.
const maxUAPILines = 1 << 16

// Info reads the tunnel's live state from the device (the UAPI "get=1"
// operation of the WireGuard cross-platform protocol).
func (t *Tunnel) Info() (Info, error) { return infoOf(t.dev.IpcGet, t.cfg) }

// infoOf is Info over any way of asking the device, with what the tunnel was
// configured with.
func infoOf(get func() (string, error), cfg Config) (Info, error) {
	out, err := get()
	if err != nil {
		return Info{}, fmt.Errorf("read device state: %w", err)
	}
	in, err := parseInfo(out)
	if err != nil {
		return Info{}, err
	}
	in.DNS = append([]string(nil), cfg.DNS...)
	in.MTU = cfg.MTU
	return in, nil
}

// parseInfo reads the answer of UAPI "get=1": "key=value" lines, the device's
// first and then each peer's after its public_key line. Keys it does not
// need (private_key, preshared_key, ...) are skipped, never kept. Counters of
// several peers add up and the latest handshake wins: the tunnel has one.
func parseInfo(s string) (Info, error) {
	var in Info
	var sec, nsec int64
	n := 0
	for line := range strings.Lines(s) {
		if n++; n > maxUAPILines {
			return Info{}, fmt.Errorf("device state: more than %d lines", maxUAPILines)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Info{}, fmt.Errorf("device state: malformed line %q", line)
		}
		switch k {
		case "endpoint":
			if _, err := netip.ParseAddrPort(v); err != nil {
				return Info{}, fmt.Errorf("device state: endpoint %q: %w", v, err)
			}
			in.Endpoint = v
		case "allowed_ip":
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return Info{}, fmt.Errorf("device state: allowed ip %q: %w", v, err)
			}
			in.AllowedIPs = append(in.AllowedIPs, p.String())
		case "rx_bytes", "tx_bytes":
			u, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return Info{}, fmt.Errorf("device state: %s %q: %w", k, v, err)
			}
			if k == "rx_bytes" {
				in.RxBytes += u
			} else {
				in.TxBytes += u
			}
		case "last_handshake_time_sec", "last_handshake_time_nsec":
			i, err := strconv.ParseInt(v, 10, 64)
			if err != nil || i < 0 {
				return Info{}, fmt.Errorf("device state: %s %q", k, v)
			}
			if k == "last_handshake_time_sec" {
				sec = i
			} else {
				nsec = i
				// nsec closes the pair: the device writes sec first.
				if h := time.Unix(sec, nsec); sec > 0 || nsec > 0 {
					if h.After(in.LastHandshake) {
						in.LastHandshake = h
					}
				}
			}
		}
	}
	return in, nil
}
