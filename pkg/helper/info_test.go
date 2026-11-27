package helper

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/helperclient"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/wgtun"
)

// infoTunnel is a tunnel that reports a live state, as *wgtun.Tunnel does.
type infoTunnel struct {
	fakeTunnel
	in  wgtun.Info
	err error
}

func (f *infoTunnel) Info() (wgtun.Info, error) { return f.in, f.err }

// The status carries what the device reports, and a tunnel whose device
// cannot be read -- or that has no Info -- is still reported from its
// configuration.
func TestStatusCarriesTheTunnelsFacts(t *testing.T) {
	v := newVPNServer(t)
	c, s, _ := helperFor(t, v.URL+"/")
	hs := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	tun := &infoTunnel{in: wgtun.Info{
		Endpoint: "198.51.100.1:51820", AllowedIPs: []string{"10.9.0.0/16"}, DNS: []string{"10.9.0.53"}, MTU: 1380,
		RxBytes: 42, TxBytes: 7, LastHandshake: hs,
	}}
	s.up = func(wgtun.Config) (Tunnel, error) { return tun, nil }
	if _, err := c.Connect(hproto.ConnectSpec{ServerURL: v.URL, Bearer: "tok", PrivateKey: key(t), DeviceName: "laptop"}); err != nil {
		t.Fatal(err)
	}
	got := statusOf(t, c)
	if got.Endpoint != "198.51.100.1:51820" || !slices.Equal(got.AllowedIPs, []string{"10.9.0.0/16"}) ||
		!slices.Equal(got.DNS, []string{"10.9.0.53"}) || got.MTU != 1380 || got.RxBytes != 42 || got.TxBytes != 7 ||
		got.LastHandshake == nil || !got.LastHandshake.Equal(hs) {
		t.Errorf("status %+v", got)
	}

	// No handshake yet: absent, not the epoch.
	tun.in.LastHandshake = time.Time{}
	if got := statusOf(t, c); got.LastHandshake != nil {
		t.Errorf("handshake %v before there was one", got.LastHandshake)
	}

	// The device cannot be read: what was configured is reported.
	tun.err = errors.New("device gone")
	got = statusOf(t, c)
	if got.Endpoint != "vpn.example.org:51820" || !slices.Equal(got.AllowedIPs, []string{"10.2.0.0/16"}) || got.Interface != "utun9" {
		t.Errorf("fallback status %+v", got)
	}
}

// A tunnel with no Info is reported from its configuration, counters at zero.
func TestStatusOfATunnelWithoutInfo(t *testing.T) {
	v := newVPNServer(t)
	c, _, _ := helperFor(t, v.URL+"/")
	if _, err := c.Connect(hproto.ConnectSpec{ServerURL: v.URL, Bearer: "tok", PrivateKey: key(t), DeviceName: "laptop"}); err != nil {
		t.Fatal(err)
	}
	got := statusOf(t, c)
	if got.Endpoint != "vpn.example.org:51820" || got.RxBytes != 0 || got.TxBytes != 0 || got.LastHandshake != nil {
		t.Errorf("status %+v", got)
	}
}

// What the status says never includes a key: the JSON on the socket is
// searched for the private key the app handed over.
func TestStatusLeaksNoKey(t *testing.T) {
	v := newVPNServer(t)
	c, s, _ := helperFor(t, v.URL+"/")
	priv := key(t)
	if _, err := c.Connect(hproto.ConnectSpec{ServerURL: v.URL, Bearer: "tok-secret", PrivateKey: priv, DeviceName: "laptop"}); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(s.status())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{priv, "tok-secret"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("the status contains %q", secret[:4]+"...")
		}
	}
}

func statusOf(t *testing.T, c *helperclient.Client) hproto.Tunnel {
	t.Helper()
	r, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Tunnels) != 1 {
		t.Fatalf("tunnels %+v", r.Tunnels)
	}
	return r.Tunnels[0]
}
