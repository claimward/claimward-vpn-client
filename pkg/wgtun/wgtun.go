// Package wgtun brings up a userspace WireGuard tunnel using wireguard-go.
//
// It creates a utun/tun device, configures the peer via the WireGuard UAPI, and
// then delegates interface addressing and routing to the platform-specific
// configureNetwork/teardownNetwork methods (see wgtun_darwin.go).
//
// Creating the tun device and changing routes require elevated privileges. The
// CLI is expected to run under sudo; the macOS app delegates this package to its
// privileged helper.
package wgtun

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config is the resolved tunnel configuration (typically built from an
// EnrollResponse plus the device's private key).
type Config struct {
	PrivateKey      wgtypes.Key
	ServerPublicKey wgtypes.Key
	Endpoint        string   // host:port
	AllowedIPs      []string // CIDRs routed into the tunnel
	Address         string   // client address in CIDR form, e.g. 10.80.0.5/32
	DNS             []string // optional
	MTU             int      // 0 = default
	Keepalive       int      // seconds, 0 = disabled
}

// Tunnel is a running tunnel. Close it to tear everything down.
type Tunnel struct {
	dev  *device.Device
	tun  tun.Device
	name string
	cfg  Config
}

// uapiConfig renders the WireGuard UAPI "set" payload. UAPI uses lowercase hex
// keys (not the base64 wg encoding).
//
// Nothing the server sent is written verbatim: the endpoint and the allowed
// IPs are parsed and rendered from the parsed value, so a newline in one of
// them cannot become a UAPI line of the server's choosing. A configuration
// that does not parse renders as a payload the device refuses.
func uapiConfig(cfg Config) string {
	s, err := renderUAPI(cfg)
	if err != nil {
		return "invalid=" + "configuration\n"
	}
	return s
}

// MTU bounds: IPv4's minimum reassembly size and a jumbo frame.
const (
	minMTU = 576
	maxMTU = 9000
)

// clampMTU is the MTU to use for a server-supplied one: 0 is the default,
// anything else is held within [minMTU, maxMTU].
func clampMTU(mtu int) int {
	if mtu == 0 {
		return device.DefaultMTU
	}
	return min(max(mtu, minMTU), maxMTU)
}

// canonPrefixes parses every entry as a CIDR and returns its canonical form.
func canonPrefixes(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, a := range in {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return nil, fmt.Errorf("allowed ip %q: %w", a, err)
		}
		out = append(out, p.String())
	}
	return out, nil
}

func renderUAPI(cfg Config) (string, error) {
	ep, err := netip.ParseAddrPort(cfg.Endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", cfg.Endpoint, err)
	}
	ips, err := canonPrefixes(cfg.AllowedIPs)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(cfg.ServerPublicKey[:]))
	fmt.Fprintf(&b, "endpoint=%s\n", ep)
	if cfg.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", min(cfg.Keepalive, 65535))
	}
	for _, a := range ips {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a)
	}
	return b.String(), nil
}

// renderRoutes is the UAPI payload replacing the peer's allowed IPs, and the
// canonical list it carries.
func renderRoutes(pub wgtypes.Key, allowedIPs []string) (string, []string, error) {
	ips, err := canonPrefixes(allowedIPs)
	if err != nil {
		return "", nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pub[:]))
	b.WriteString("replace_allowed_ips=true\n")
	for _, a := range ips {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a)
	}
	return b.String(), ips, nil
}

// Up creates the interface, configures WireGuard, and applies addressing/routes.
func Up(cfg Config) (*Tunnel, error) {
	if _, err := renderUAPI(cfg); err != nil {
		return nil, fmt.Errorf("invalid tunnel configuration: %w", err)
	}
	ips, _ := canonPrefixes(cfg.AllowedIPs)
	cfg.AllowedIPs = ips
	cfg.MTU = tunnelMTU(cfg.MTU, cfg.Endpoint)
	mtu := cfg.MTU
	tunDev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun device (need root?): %w", err)
	}
	name, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("read tun name: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("claimward/%s ", name))
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	if err := dev.IpcSet(uapiConfig(cfg)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure wireguard: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring up device: %w", err)
	}

	t := &Tunnel{dev: dev, tun: tunDev, name: name, cfg: cfg}
	if err := t.configureNetwork(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure interface %s: %w", name, err)
	}
	return t, nil
}

// Name returns the OS interface name (e.g. utun5).
func (t *Tunnel) Name() string { return t.name }

// UpdateRoutes reconfigures the tunnel's routed CIDRs at runtime: it updates the
// WireGuard peer's AllowedIPs and adds/removes the corresponding OS routes
// (diffed against the current set). Used to apply route pushes from the server.
func (t *Tunnel) UpdateRoutes(allowedIPs []string) error {
	payload, allowedIPs, err := renderRoutes(t.cfg.ServerPublicKey, allowedIPs)
	if err != nil {
		return fmt.Errorf("update allowed ips: %w", err)
	}
	if err := t.dev.IpcSet(payload); err != nil {
		return fmt.Errorf("update allowed ips: %w", err)
	}

	old := make(map[string]bool, len(t.cfg.AllowedIPs))
	for _, a := range t.cfg.AllowedIPs {
		old[a] = true
	}
	want := make(map[string]bool, len(allowedIPs))
	for _, a := range allowedIPs {
		want[a] = true
	}
	for a := range old {
		if !want[a] {
			t.routeDel(a)
		}
	}
	for _, a := range allowedIPs {
		if !old[a] {
			if err := t.routeAdd(a); err != nil {
				return err
			}
		}
	}
	t.cfg.AllowedIPs = allowedIPs
	return nil
}

// Close tears down routes/addresses and stops the device. Best-effort on the
// network side; always stops the device.
func (t *Tunnel) Close() error {
	t.teardownNetwork()
	t.dev.Close()
	return nil
}

// Wait blocks until the device is stopped (e.g. via Close).
func (t *Tunnel) Wait() {
	t.dev.Wait()
}
