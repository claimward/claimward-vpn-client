//go:build windows

package wgtun

import (
	"net/netip"
	"os"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// TestUpConfiguresTheWintunAdapter brings a real tunnel up and reads back
// from Windows what configureNetwork set. It needs an elevated process and
// wintun.dll beside the test binary, so it runs only when asked:
//
//	go test -c -o wgtun.test.exe ./pkg/wgtun
//	copy wintun\bin\amd64\wintun.dll .
//	set CLAIMWARD_WINTUN_TEST=1 && wgtun.test.exe -test.run Wintun -test.v
//
// The CI's windows job does exactly that.
func TestUpConfiguresTheWintunAdapter(t *testing.T) {
	if os.Getenv("CLAIMWARD_WINTUN_TEST") != "1" {
		t.Skip("set CLAIMWARD_WINTUN_TEST=1, elevated, with wintun.dll beside the test binary")
	}
	priv, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	tun, err := Up(Config{
		PrivateKey:      priv,
		ServerPublicKey: peer.PublicKey(),
		Endpoint:        "192.0.2.1:51820", // TEST-NET-1: nothing answers, nothing needs to
		AllowedIPs:      []string{"10.123.0.0/16", "fd12:3456::/48"},
		Address:         "10.124.0.5/32",
		DNS:             []string{"10.123.0.53"},
		MTU:             1380,
		Keepalive:       25,
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			tun.Close()
		}
	}()
	if tun.Name() != tunName {
		t.Errorf("adapter %q, want %q", tun.Name(), tunName)
	}
	luid, err := tun.luid()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := luid.IPAddress(netip.MustParseAddr("10.124.0.5")); err != nil {
		t.Errorf("the address is not on the adapter: %v", err)
	}
	hasRoute := func(dst string) bool {
		_, err := luid.Route(netip.MustParsePrefix(dst), unspecified(netip.MustParsePrefix(dst)))
		return err == nil
	}
	for _, r := range []string{"10.123.0.0/16", "fd12:3456::/48"} {
		if !hasRoute(r) {
			t.Errorf("no route to %s through the adapter", r)
		}
	}
	dns, err := luid.DNS()
	if err != nil {
		t.Fatal(err)
	}
	if len(dns) != 1 || dns[0] != netip.MustParseAddr("10.123.0.53") {
		t.Errorf("DNS %v, want [10.123.0.53]", dns)
	}
	ipif, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	if ipif.NLMTU != 1380 {
		t.Errorf("MTU %d, want 1380", ipif.NLMTU)
	}

	// A route push replaces one route with another.
	if err := tun.UpdateRoutes([]string{"10.123.0.0/16", "10.125.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	if !hasRoute("10.125.0.0/16") {
		t.Error("the pushed route is missing")
	}
	if hasRoute("fd12:3456::/48") {
		t.Error("the withdrawn route is still there")
	}

	tun.Close()
	closed = true
	ifs, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range ifs {
		if a.LUID == luid {
			t.Errorf("the adapter outlived Close: %s", a.FriendlyName())
		}
	}
}
