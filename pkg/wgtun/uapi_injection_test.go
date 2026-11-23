package wgtun

import (
	"encoding/hex"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Audit 2026-11-23, finding 3: the endpoint and allowed IPs come from the
// server's enroll answer and route pushes and are written into the UAPI
// payload verbatim. A newline in one of them is a UAPI line of the server's
// choosing: here it adds a second peer, with a key the client never saw,
// that receives every address (0.0.0.0/0) -- and no OS route ever names it.
func TestUAPIRefusesInjectedLines(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	srv, _ := wgtypes.GeneratePrivateKey()
	evil, _ := wgtypes.GeneratePrivateKey()
	evilPub := evil.PublicKey()
	evilHex := hex.EncodeToString(evilPub[:])

	cfg := Config{
		PrivateKey:      priv,
		ServerPublicKey: srv.PublicKey(),
		Endpoint:        "192.0.2.1:51820",
		AllowedIPs:      []string{"10.0.0.0/8\npublic_key=" + evilHex + "\nendpoint=198.51.100.7:51820\nallowed_ip=0.0.0.0/0"},
	}

	tdev := tuntest.NewChannelTUN()
	dev := device.NewDevice(tdev.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	setErr := dev.IpcSet(uapiConfig(cfg))
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if setErr == nil && strings.Contains(got, "public_key="+evilHex) {
		t.Fatalf("a server-supplied allowed IP added a peer of its own:\n%s", got)
	}
}
