//go:build linux

package wgtun

import (
	"fmt"
	"net"
)

// InterfaceName is "cw-" plus ten hex digits of the key's hash: one
// deterministic name per server, within IFNAMSIZ.
func InterfaceName(key string) string { return linuxIfName(key) }

// removeStale deletes an interface of that name that is still there. A TUN
// device made by wireguard-go is not persistent, so the kernel removes it when
// the process that made it exits, crash included; what can be left is a
// device somebody made persistent, or a process that outlived its helper. A
// name this helper derived is its own to take back.
func removeStale(name string) error {
	if _, err := net.InterfaceByName(name); err != nil {
		return nil // not there
	}
	if out, err := run("ip", "link", "delete", "dev", name); err != nil {
		return fmt.Errorf("ip link delete: %v: %s", err, out)
	}
	return nil
}
