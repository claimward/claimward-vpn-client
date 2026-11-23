package wgtun

import (
	"net/netip"
	"testing"
)

func TestEffectiveMTU(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")
	for _, c := range []struct {
		name         string
		server, path int
		ep           netip.Addr
		want         int
	}{
		{"unknown path keeps server", 1420, 0, v4, 1420},
		{"ethernet path keeps server", 1420, 1500, v4, 1420},
		{"1450 path over v4", 1420, 1450, v4, 1390},
		{"1450 path over v6", 1420, 1450, v6, 1370},
		{"never above server", 1380, 9000, v4, 1380},
		{"path floor", 1420, 1300, v4, 1280},
		{"tiny path floor", 1420, 600, v6, 1280},
		{"server below floor honoured", 1200, 1450, v4, 1200},
		{"4in6 is v4", 1420, 1450, netip.MustParseAddr("::ffff:192.0.2.1"), 1390},
	} {
		if got := effectiveMTU(c.server, c.path, c.ep); got != c.want {
			t.Errorf("%s: effectiveMTU(%d,%d,%v) = %d, want %d", c.name, c.server, c.path, c.ep, got, c.want)
		}
	}
}

func TestTunnelMTU(t *testing.T) {
	old := pathMTUFunc
	defer func() { pathMTUFunc = old }()
	pathMTUFunc = func(netip.AddrPort) int { return 1450 }
	if got := tunnelMTU(0, "192.0.2.1:51820"); got != 1390 {
		t.Errorf("default server MTU over 1450 path = %d, want 1390", got)
	}
	if got := tunnelMTU(1300, "192.0.2.1:51820"); got != 1300 {
		t.Errorf("server 1300 = %d, want 1300", got)
	}
	if got := tunnelMTU(1420, "not an endpoint"); got != 1420 {
		t.Errorf("unparsable endpoint = %d, want 1420", got)
	}
}

func TestLocalLinkMTULoopback(t *testing.T) {
	if got := localLinkMTU(netip.MustParseAddrPort("127.0.0.1:9")); got <= 0 {
		t.Skipf("loopback MTU not readable here: %d", got)
	}
}
