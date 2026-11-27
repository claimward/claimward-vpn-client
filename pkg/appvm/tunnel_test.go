package appvm

import (
	"reflect"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/appcore"
)

// A connected server's tunnel reaches the State, both as the selected tunnel
// and on its row, with every fact the detail panel shows.
func TestStateCarriesTheTunnelsFacts(t *testing.T) {
	hs := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	h := newHarness(t, status(true, appcore.ServerStatus{
		LoggedIn: true, Connected: true, Interface: "cw-0123456789", AssignedIP: "10.80.0.7/32",
		Endpoint: "203.0.113.7:51820", AllowedIPs: []string{"10.2.0.0/16", "fd00::/64"},
		DNS: []string{"10.2.0.53"}, MTU: 1380, RxBytes: 98765, TxBytes: 1234, LastHandshake: &hs,
	}))
	h.Refresh()
	s := h.State()
	want := &TunnelInfo{
		Interface: "cw-0123456789", Address: "10.80.0.7/32", Endpoint: "203.0.113.7:51820",
		AllowedIPs: []string{"10.2.0.0/16", "fd00::/64"}, DNS: []string{"10.2.0.53"}, MTU: 1380,
		RxBytes: 98765, TxBytes: 1234, LastHandshake: &hs,
	}
	if !reflect.DeepEqual(s.Tunnel, want) {
		t.Errorf("State.Tunnel = %+v, want %+v", s.Tunnel, want)
	}
	if len(s.Servers) != 1 || !reflect.DeepEqual(s.Servers[0].Tunnel, want) {
		t.Errorf("row tunnel = %+v", s.Servers)
	}
}

// Without a tunnel there is no TunnelInfo, and no empty one to mistake for it.
func TestStateHasNoTunnelWhenDisconnected(t *testing.T) {
	h := newHarness(t, signedIn)
	h.Refresh()
	s := h.State()
	if s.Tunnel != nil || s.Servers[0].Tunnel != nil {
		t.Errorf("tunnel while disconnected: %+v / %+v", s.Tunnel, s.Servers[0].Tunnel)
	}
}

// A tunnel's slices are the State's own: a view that sorts them does not
// change what the model holds.
func TestTunnelInfoIsACopy(t *testing.T) {
	src := appcore.ServerStatus{Connected: true, AllowedIPs: []string{"b", "a"}, DNS: []string{"d"}}
	in := tunnelInfo(src)
	in.AllowedIPs[0], in.DNS[0] = "x", "x"
	if src.AllowedIPs[0] != "b" || src.DNS[0] != "d" {
		t.Errorf("shared with the status: %+v", src)
	}
}
