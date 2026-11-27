package wgtun

import (
	"slices"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Info reads a real wireguard-go device -- on an in-memory tun, so without
// privileges and on every OS -- and finds what was configured, with no
// traffic and no handshake yet.
func TestInfoOfARealDevice(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		PrivateKey: priv, ServerPublicKey: peer.PublicKey(), Endpoint: "127.0.0.1:51999",
		AllowedIPs: []string{"10.2.0.0/16", "192.168.5.9/24"}, DNS: []string{"10.2.0.53"}, MTU: 1380,
	}
	tdev := tuntest.NewChannelTUN()
	dev := device.NewDevice(tdev.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	if err := dev.IpcSet(uapiConfig(cfg)); err != nil {
		t.Fatal(err)
	}
	tun := &Tunnel{dev: dev, tun: tdev.TUN(), name: "test0", cfg: cfg}

	in, err := tun.Info()
	if err != nil {
		t.Fatal(err)
	}
	if in.Endpoint != "127.0.0.1:51999" || in.MTU != 1380 || !slices.Equal(in.DNS, []string{"10.2.0.53"}) {
		t.Errorf("info %+v", in)
	}
	if !slices.Equal(in.AllowedIPs, []string{"10.2.0.0/16", "192.168.5.0/24"}) && !slices.Equal(in.AllowedIPs, []string{"192.168.5.0/24", "10.2.0.0/16"}) {
		t.Errorf("allowed ips %v", in.AllowedIPs)
	}
	if in.RxBytes != 0 || in.TxBytes != 0 || !in.LastHandshake.IsZero() {
		t.Errorf("traffic before any: %+v", in)
	}
}
