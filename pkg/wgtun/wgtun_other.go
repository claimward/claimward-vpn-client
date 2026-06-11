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
// Linux is implemented with `ip`; other platforms return an explicit error.
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
		if err := t.routeAdd(cidr); err != nil {
			return err
		}
	}
	return nil
}

func (t *Tunnel) teardownNetwork() {
	if runtime.GOOS != "linux" {
		return
	}
	for _, cidr := range t.cfg.AllowedIPs {
		t.routeDel(cidr)
	}
}

func (t *Tunnel) routeAdd(cidr string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return nil
	}
	if out, err := run("ip", "route", "add", cidr, "dev", t.name); err != nil {
		return fmt.Errorf("ip route add %s: %v: %s", cidr, err, out)
	}
	return nil
}

func (t *Tunnel) routeDel(cidr string) {
	if runtime.GOOS != "linux" {
		return
	}
	if _, _, err := net.ParseCIDR(cidr); err == nil {
		_, _ = run("ip", "route", "del", cidr, "dev", t.name)
	}
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
