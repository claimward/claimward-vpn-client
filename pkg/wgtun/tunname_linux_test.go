//go:build linux

package wgtun

import (
	"net"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func linuxTunnel(t *testing.T, name, addr string) *Tunnel {
	t.Helper()
	priv, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	tun, err := Up(Config{
		PrivateKey: priv, ServerPublicKey: peer.PublicKey(),
		Endpoint: "192.0.2.1:51820", AllowedIPs: []string{"10.200.0.0/16"},
		Address: addr, MTU: 1380, Name: name,
	})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return tun
}

func exists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// TestLinuxTunnelsPerServer needs root, /dev/net/tun and `ip`: it runs only
// when asked (CLAIMWARD_TUN_TEST=1, under sudo), which the CI's linux
// tunnels job does.
func TestLinuxTunnelsPerServer(t *testing.T) {
	if os.Getenv("CLAIMWARD_TUN_TEST") != "1" {
		t.Skip("set CLAIMWARD_TUN_TEST=1, as root")
	}
	a := linuxTunnel(t, "https://a.example.org", "10.201.0.5/32")
	b := linuxTunnel(t, "https://b.example.org", "10.202.0.5/32")
	if a.Name() != InterfaceName("https://a.example.org") || b.Name() != InterfaceName("https://b.example.org") {
		t.Errorf("names %q %q", a.Name(), b.Name())
	}
	if a.Name() == b.Name() || !exists(a.Name()) || !exists(b.Name()) {
		t.Fatalf("two servers, two interfaces: %q %q", a.Name(), b.Name())
	}
	// Closing one leaves the other, and the closed one is gone.
	b.Close()
	if exists(b.Name()) {
		t.Errorf("%s outlived Close", b.Name())
	}
	if !exists(a.Name()) {
		t.Errorf("%s went with its neighbour", a.Name())
	}

	// A helper that crashed leaves nothing (the kernel frees a TUN with its
	// process); one that was killed without that, or a device left behind,
	// is replaced by the next Up of the same server.
	stale := linuxTunnel(t, "https://c.example.org", "10.203.0.5/32")
	again := linuxTunnel(t, "https://c.example.org", "10.203.0.5/32")
	if !exists(again.Name()) {
		t.Error("the replacement is not there")
	}
	again.Close()
	stale.Close()
	a.Close()
	if exists(a.Name()) {
		t.Errorf("%s outlived Close", a.Name())
	}
}

func TestRemoveStaleLeavesAbsentNamesAlone(t *testing.T) {
	if err := removeStale("cw-nonexistent"); err != nil {
		t.Errorf("absent interface: %v", err)
	}
}
