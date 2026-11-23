package wgtun

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testTunnel(t *testing.T) *Tunnel {
	t.Helper()
	priv, _ := wgtypes.GeneratePrivateKey()
	srv, _ := wgtypes.GeneratePrivateKey()
	dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	return &Tunnel{dev: dev, cfg: Config{PrivateKey: priv, ServerPublicKey: srv.PublicKey()}}
}

func TestUpdateRoutesRefusesWhatDoesNotParse(t *testing.T) {
	tn := testTunnel(t)
	err := tn.UpdateRoutes([]string{"10.0.0.0/8\npublic_key=" + strings.Repeat("0", 64)})
	if err == nil {
		t.Fatal("an injected allowed IP was applied")
	}
	if got, _ := tn.dev.IpcGet(); strings.Contains(got, "public_key="+strings.Repeat("0", 64)) {
		t.Fatalf("the injected peer exists:\n%s", got)
	}
}

func TestUpdateRoutesReportsADeviceRefusal(t *testing.T) {
	tn := testTunnel(t)
	tn.dev.Close()
	if err := tn.UpdateRoutes(nil); err == nil {
		t.Fatal("UpdateRoutes on a closed device reported success")
	}
}

func TestUpIsRefusedBeforeTheDeviceExistsOnABadConfig(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	srv, _ := wgtypes.GeneratePrivateKey()
	_, err := Up(Config{PrivateKey: priv, ServerPublicKey: srv.PublicKey(), Endpoint: "x\ny", AllowedIPs: []string{"10.0.0.0/8"}})
	if err == nil || !strings.Contains(err.Error(), "invalid tunnel configuration") {
		t.Fatalf("Up with a bad endpoint: %v", err)
	}
}
