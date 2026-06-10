//go:build !darwin

package wgtun

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// configureNetwork applies addressing/routes on non-darwin platforms.
//
// Linux is implemented with `ip`; other platforms are not yet supported and
// return an explicit error so callers fail loudly rather than silently routing
// nothing. (The Linux/Windows apps live in their own repos and will refine this.)
func (t *Tunnel) configureNetwork() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("wgtun: network configuration not implemented for %s", runtime.GOOS)
	}
	ip, _, err := net.ParseCIDR(t.cfg.Address)
	if err != nil {
		return fmt.Errorf("parse address %q: %w", t.cfg.Address, err)
	}
	if out, err := run("ip", "address", "add", fmt.Sprintf("%s/32", ip), "dev", t.name); err != nil {
		return fmt.Errorf("ip address add: %v: %s", err, out)
	}
	if out, err := run("ip", "link", "set", "up", "dev", t.name); err != nil {
		return fmt.Errorf("ip link up: %v: %s", err, out)
	}
	for _, cidr := range t.cfg.AllowedIPs {
		if _, _, perr := net.ParseCIDR(cidr); perr != nil {
			continue
		}
		if out, err := run("ip", "route", "add", cidr, "dev", t.name); err != nil {
			return fmt.Errorf("ip route add %s: %v: %s", cidr, err, out)
		}
	}
	return nil
}

func (t *Tunnel) teardownNetwork() {
	if runtime.GOOS != "linux" {
		return
	}
	for _, cidr := range t.cfg.AllowedIPs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			continue
		}
		_, _ = run("ip", "route", "del", cidr, "dev", t.name)
	}
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
