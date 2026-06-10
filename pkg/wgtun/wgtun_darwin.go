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

	// Assign the address (point-to-point, /32 host route on the interface).
	if out, err := run("ifconfig", t.name, "inet", ip.String(), ip.String(), "netmask", "255.255.255.255"); err != nil {
		return fmt.Errorf("ifconfig: %v: %s", err, out)
	}
	if out, err := run("ifconfig", t.name, "up"); err != nil {
		return fmt.Errorf("ifconfig up: %v: %s", err, out)
	}

	for _, cidr := range t.cfg.AllowedIPs {
		_, dst, perr := net.ParseCIDR(cidr)
		if perr != nil {
			continue
		}
		// -n numeric, replace any existing route (-q quiet).
		if out, err := run("route", "-q", "-n", "add", "-inet", dst.String(), "-interface", t.name); err != nil {
			return fmt.Errorf("route add %s: %v: %s", dst, err, out)
		}
	}
	return nil
}

// teardownNetwork removes the routes we added. Best-effort; errors are ignored
// because the interface is about to disappear with the device anyway.
func (t *Tunnel) teardownNetwork() {
	for _, cidr := range t.cfg.AllowedIPs {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		_, _ = run("route", "-q", "-n", "delete", "-inet", dst.String(), "-interface", t.name)
	}
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
