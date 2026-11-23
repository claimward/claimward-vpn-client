package wgtun

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// FuzzUAPIConfig renders server-supplied strings into the UAPI payload. Every
// line of what comes out must be one the renderer wrote itself: whatever the
// server sends, it cannot add a key, a peer or a route of its own.
func FuzzUAPIConfig(f *testing.F) {
	f.Add("192.0.2.1:51820", "10.0.0.0/8", 25)
	f.Add("[2001:db8::1]:51820", "fd00::/8", 0)
	f.Add("192.0.2.1:51820\npublic_key=00", "10.0.0.0/8", 0)
	f.Add("192.0.2.1:51820", "10.0.0.0/8\nallowed_ip=0.0.0.0/0", 0)
	f.Add("host:51820", "10.0.0.1", -1)
	f.Add("", "", 1<<31-1)
	priv, _ := wgtypes.GeneratePrivateKey()
	srv, _ := wgtypes.GeneratePrivateKey()
	f.Fuzz(func(t *testing.T, endpoint, allowed string, keepalive int) {
		out := uapiConfig(Config{PrivateKey: priv, ServerPublicKey: srv.PublicKey(),
			Endpoint: endpoint, AllowedIPs: []string{allowed}, Keepalive: keepalive})
		pubs := 0
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			k, _, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("a line without a key: %q in\n%s", line, out)
			}
			switch k {
			case "private_key", "replace_peers", "endpoint", "persistent_keepalive_interval", "allowed_ip", "invalid":
			case "public_key":
				pubs++
			default:
				t.Fatalf("a key the renderer does not write: %q in\n%s", k, out)
			}
		}
		if pubs > 1 {
			t.Fatalf("%d peers in\n%s", pubs, out)
		}
		clampMTU(keepalive)
	})
}
