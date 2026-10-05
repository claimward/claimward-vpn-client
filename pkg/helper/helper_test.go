package helper

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/helperclient"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/routeclient"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
	"github.com/claimward/claimward-vpn-client/pkg/wgtun"
)

// vpnServer is a claimward-vpn-server as far as the helper sees one.
type vpnServer struct {
	*httptest.Server
	mu     sync.Mutex
	enroll []protocol.EnrollRequest
}

func newVPNServer(t *testing.T) *vpnServer {
	t.Helper()
	v := &vpnServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathEnroll, func(w http.ResponseWriter, r *http.Request) {
		var req protocol.EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)
		v.mu.Lock()
		v.enroll = append(v.enroll, req)
		v.mu.Unlock()
		pair, _ := wgkey.Generate()
		json.NewEncoder(w).Encode(protocol.EnrollResponse{AssignedIP: "10.80.0.7/32", ServerPublicKey: pair.Public.String(),
			Endpoint: "vpn.example.org:51820", AllowedIPs: []string{"10.2.0.0/16"}, GRPCEndpoint: "vpn.example.org:8444"})
	})
	mux.HandleFunc("GET "+protocol.PathTenants, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]protocol.TenantInfo{{ID: "chem", Name: "Chemistry"}, {ID: "hpc", Name: "HPC"}})
	})
	v.Server = httptest.NewServer(mux)
	t.Cleanup(v.Close)
	return v
}

type fakeTunnel struct {
	mu     sync.Mutex
	closed bool
	routes []string
}

func (f *fakeTunnel) Name() string { return "utun9" }
func (f *fakeTunnel) UpdateRoutes(r []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = r
	return nil
}
func (f *fakeTunnel) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// helperFor runs a helper allowed to talk to the given servers, on a socket
// in a temporary directory, with tunnels and route watches faked.
func helperFor(t *testing.T, servers ...string) (*helperclient.Client, *Server, *[]wgtun.Config) {
	t.Helper()
	s := New(Config{Servers: servers}, "linux", "app-test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	var ups []wgtun.Config
	s.up = func(c wgtun.Config) (Tunnel, error) { ups = append(ups, c); return &fakeTunnel{}, nil }
	s.watch = func(ctx context.Context, ep, bearer, pub string, on func(routeclient.Update)) error {
		on(routeclient.Update{AllowedIPs: []string{"10.9.0.0/16"}, Serial: 2})
		<-ctx.Done()
		return nil
	}
	dir, err := os.MkdirTemp("", "cwh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); s.Shutdown() })
	go s.Serve(ln)
	return helperclient.New(sock), s, &ups
}

func key(t *testing.T) string {
	t.Helper()
	p, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return p.Private.String()
}

// The helper enrolls with a server its configuration names, for the tenant
// chosen, and brings the tunnel up from what that server answered.
func TestTheHelperConnectsToItsServer(t *testing.T) {
	v := newVPNServer(t)
	c, _, ups := helperFor(t, v.URL+"/")
	resp, err := c.Connect(hproto.ConnectSpec{ServerURL: v.URL, Bearer: "tok", PrivateKey: key(t), DeviceName: "laptop", Tenant: "hpc"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Connected || resp.AssignedIP != "10.80.0.7/32" || resp.Tenant != "hpc" {
		t.Errorf("connect: %+v", resp)
	}
	if len(v.enroll) != 1 || v.enroll[0].Tenant != "hpc" || v.enroll[0].Device.OS != "linux" || v.enroll[0].Device.Platform != "app-test" {
		t.Errorf("the server was asked %+v", v.enroll)
	}
	if len(*ups) != 1 || (*ups)[0].AllowedIPs[0] != "10.2.0.0/16" {
		t.Errorf("the tunnel was brought up with %+v", *ups)
	}
	st, err := c.Status()
	if err != nil || !st.Connected || st.Tenant != "hpc" || st.Interface != "utun9" {
		t.Errorf("status: %+v %v", st, err)
	}
	if _, err := c.Down(); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Status(); st.Connected {
		t.Error("still connected after down")
	}
	ts, err := c.Tenants(v.URL, "tok")
	if err != nil || len(ts.Tenants) != 2 || ts.Tenants[1].ID != "hpc" {
		t.Errorf("tenants: %+v %v", ts, err)
	}
}

// ⛔ Any process on the socket can ask. A server the configuration does not
// name is never contacted -- it would answer with routes for every packet
// of the machine -- and no request carries a tunnel configuration.
func TestTheHelperRefusesWhatItWasNotConfiguredFor(t *testing.T) {
	trusted, rogue := newVPNServer(t), newVPNServer(t)
	c, _, ups := helperFor(t, trusted.URL)
	if _, err := c.Connect(hproto.ConnectSpec{ServerURL: rogue.URL, Bearer: "tok", PrivateKey: key(t)}); err == nil || !strings.Contains(err.Error(), "not one this helper is configured for") {
		t.Errorf("a rogue server: %v", err)
	}
	if _, err := c.Tenants(rogue.URL, "tok"); err == nil {
		t.Error("a rogue server was asked for tenants")
	}
	if len(rogue.enroll) != 0 || len(*ups) != 0 {
		t.Errorf("the rogue server was contacted (%d) or a tunnel came up (%d)", len(rogue.enroll), len(*ups))
	}
	// The actions that took a tunnel configuration are gone.
	for _, action := range []string{"up", "update-routes"} {
		conn, err := net.Dial("unix", c.SocketPath)
		if err != nil {
			t.Fatal(err)
		}
		json.NewEncoder(conn).Encode(map[string]any{"action": action, "tunnel": map[string]any{"allowed_ips": []string{"0.0.0.0/0"}}})
		var resp hproto.Response
		json.NewDecoder(conn).Decode(&resp)
		conn.Close()
		if resp.OK || !strings.Contains(resp.Error, "unknown action") {
			t.Errorf("%s: %+v", action, resp)
		}
	}
	if _, err := c.Connect(hproto.ConnectSpec{ServerURL: trusted.URL, PrivateKey: key(t)}); err == nil {
		t.Error("a connect with no bearer")
	}
	if _, err := c.Connect(hproto.ConnectSpec{ServerURL: trusted.URL, Bearer: "tok", PrivateKey: "nope"}); err == nil {
		t.Error("a connect with a broken key")
	}
}

// Pushed routes reach the live tunnel.
func TestPushedRoutesReachTheTunnel(t *testing.T) {
	v := newVPNServer(t)
	_, s, _ := helperFor(t, v.URL)
	var tun *fakeTunnel
	s.up = func(c wgtun.Config) (Tunnel, error) { tun = &fakeTunnel{}; return tun, nil }
	if r := s.connect(&hproto.ConnectSpec{ServerURL: v.URL, Bearer: "tok", PrivateKey: key(t)}); !r.OK {
		t.Fatal(r.Error)
	}
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		tun.mu.Lock()
		got := tun.routes
		tun.mu.Unlock()
		if len(got) == 1 && got[0] == "10.9.0.0/16" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("routes %v", got)
		}
	}
	s.Shutdown()
	if !tun.closed {
		t.Error("shutdown left the tunnel up")
	}
}
