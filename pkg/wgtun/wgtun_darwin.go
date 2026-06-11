//go:build darwin

package wgtun

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// configureNetwork assigns the tunnel address and installs routes on macOS using
// ifconfig and route. utun interfaces are point-to-point, so we set the address
// on both ends and add per-destination routes scoped to the interface.
func (t *Tunnel) configureNetwork() error {
	ip, _, err := net.ParseCIDR(t.cfg.Address)
	if err != nil {
		return fmt.Errorf("parse address %q: %w", t.cfg.Address, err)
	}
	if out, err := run("ifconfig", t.name, "inet", ip.String(), ip.String(), "netmask", "255.255.255.255"); err != nil {
		return fmt.Errorf("ifconfig: %v: %s", err, out)
	}
	if out, err := run("ifconfig", t.name, "up"); err != nil {
		return fmt.Errorf("ifconfig up: %v: %s", err, out)
	}
	for _, cidr := range t.cfg.AllowedIPs {
		if err := t.routeAdd(cidr); err != nil {
			return err
		}
	}
	return nil
}

// teardownNetwork removes the routes we added. Best-effort.
func (t *Tunnel) teardownNetwork() {
	for _, cidr := range t.cfg.AllowedIPs {
		t.routeDel(cidr)
	}
}

func (t *Tunnel) routeAdd(cidr string) error {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil // skip malformed
	}
	if out, err := run("route", "-q", "-n", "add", "-inet", dst.String(), "-interface", t.name); err != nil {
		return fmt.Errorf("route add %s: %v: %s", dst, err, out)
	}
	return nil
}

func (t *Tunnel) routeDel(cidr string) {
	if _, dst, err := net.ParseCIDR(cidr); err == nil {
		_, _ = run("route", "-q", "-n", "delete", "-inet", dst.String(), "-interface", t.name)
	}
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
