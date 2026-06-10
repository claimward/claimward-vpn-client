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
func uapiConfig(cfg Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(cfg.ServerPublicKey[:]))
	fmt.Fprintf(&b, "endpoint=%s\n", cfg.Endpoint)
	if cfg.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", cfg.Keepalive)
	}
	for _, a := range cfg.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a)
	}
	return b.String()
}

// Up creates the interface, configures WireGuard, and applies addressing/routes.
func Up(cfg Config) (*Tunnel, error) {
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	tunDev, err := tun.CreateTUN("utun", mtu)
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
