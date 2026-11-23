package wgtun

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestClampMTU(t *testing.T) {
	for in, want := range map[int]int{0: 1420, 1: 576, 575: 576, 576: 576, 1280: 1280, 9000: 9000, 9001: 9000, 1 << 30: 9000, -5: 576} {
		if got := clampMTU(in); got != want {
			t.Errorf("clampMTU(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestRenderUAPIRefusesWhatDoesNotParse(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	srv, _ := wgtypes.GeneratePrivateKey()
	ok := Config{PrivateKey: priv, ServerPublicKey: srv.PublicKey(), Endpoint: "192.0.2.1:51820", AllowedIPs: []string{"10.0.0.0/8", "fd00::/8"}, Keepalive: 25}
	got, err := renderUAPI(ok)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"endpoint=192.0.2.1:51820\n", "allowed_ip=10.0.0.0/8\n", "allowed_ip=fd00::/8\n", "persistent_keepalive_interval=25\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, bad := range []Config{
		{PrivateKey: priv, ServerPublicKey: srv.PublicKey(), Endpoint: "192.0.2.1:51820\nallowed_ip=0.0.0.0/0", AllowedIPs: ok.AllowedIPs},
		{PrivateKey: priv, ServerPublicKey: srv.PublicKey(), Endpoint: "vpn.example.org:51820", AllowedIPs: ok.AllowedIPs},
		{PrivateKey: priv, ServerPublicKey: srv.PublicKey(), Endpoint: ok.Endpoint, AllowedIPs: []string{"10.0.0.1"}},
		{PrivateKey: priv, ServerPublicKey: srv.PublicKey(), Endpoint: ok.Endpoint, AllowedIPs: []string{"10.0.0.0/8\n"}},
	} {
		if s, err := renderUAPI(bad); err == nil {
			t.Errorf("accepted %+v:\n%s", bad, s)
		}
		if s := uapiConfig(bad); !strings.HasPrefix(s, "invalid=") || strings.Contains(s, "allowed_ip") {
			t.Errorf("uapiConfig rendered a refused configuration:\n%s", s)
		}
	}
	if _, _, err := renderRoutes(srv.PublicKey(), []string{"10.0.0.0/8\npublic_key=00"}); err == nil {
		t.Error("renderRoutes accepted an injected line")
	}
	if p, ips, err := renderRoutes(srv.PublicKey(), []string{"10.1.2.3/8"}); err != nil || ips[0] != "10.1.2.3/8" || !strings.Contains(p, "allowed_ip=10.1.2.3/8\n") {
		t.Errorf("renderRoutes: %q %v %v", p, ips, err)
	}
}
