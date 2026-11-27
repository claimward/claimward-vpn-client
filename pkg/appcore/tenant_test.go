package appcore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/exclusive"
	"github.com/claimward/claimward-vpn-client/pkg/helper"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/routeclient"
	"github.com/claimward/claimward-vpn-client/pkg/tokenstore"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
	"github.com/claimward/claimward-vpn-client/pkg/wgtun"
)

// worldMu guards what a world's servers were asked.
var worldMu sync.Mutex

type nopTunnel struct{}

func (nopTunnel) Name() string                { return "utun9" }
func (nopTunnel) UpdateRoutes([]string) error { return nil }
func (nopTunnel) Close() error                { return nil }

// provID is the identity provider every test server lists.
const provID = "uni"

// vpnServer is a claimward-vpn-server: its discovery document, and tenants
// for a person in two of them.
type vpnServer struct {
	*httptest.Server
	exclusive atomic.Bool
}

func newVPNServer(t *testing.T, name string, solo bool, asked *[]string) *vpnServer {
	t.Helper()
	v := &vpnServer{}
	v.exclusive.Store(solo)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+protocol.PathWellKnownConfiguration, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		json.NewEncoder(w).Encode(protocol.Configuration{Version: 2, ServerName: name, Exclusive: v.exclusive.Load(),
			Providers: []protocol.Provider{{ID: provID, Kind: protocol.KindOIDC, Name: "Uni", OIDCIssuer: "https://login.example.org", OIDCClientID: "claimward"}}})
	})
	mux.HandleFunc("GET "+protocol.PathTenants, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]protocol.TenantInfo{{ID: "chem", Name: "Chemistry"}, {ID: "hpc", Name: "HPC"}})
	})
	mux.HandleFunc("POST "+protocol.PathEnroll, func(w http.ResponseWriter, r *http.Request) {
		var req protocol.EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)
		worldMu.Lock()
		*asked = append(*asked, name+" enroll "+req.Tenant)
		worldMu.Unlock()
		if req.Tenant == "" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "tenant_required", "message": "choose one of: chem, hpc"})
			return
		}
		pair, _ := wgkey.Generate()
		json.NewEncoder(w).Encode(protocol.EnrollResponse{AssignedIP: "10.80.0.7/32", ServerPublicKey: pair.Public.String(), Endpoint: "vpn.example.org:51820", AllowedIPs: []string{"10.2.0.0/16"}})
	})
	mux.HandleFunc("POST "+protocol.PathHeartbeat, func(w http.ResponseWriter, r *http.Request) {
		worldMu.Lock()
		*asked = append(*asked, "heartbeat "+r.Header.Get("Authorization"))
		worldMu.Unlock()
		json.NewEncoder(w).Encode(protocol.HeartbeatResponse{LeaseExpiresAt: time.Now().Add(time.Hour)})
	})
	mux.HandleFunc("POST "+protocol.PathDeregister, func(w http.ResponseWriter, r *http.Request) {
		worldMu.Lock()
		*asked = append(*asked, "deregister")
		worldMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	v.Server = httptest.NewServer(mux)
	t.Cleanup(v.Close)
	return v
}

// worldOf is servers, a helper allowed to reach them, and a Core that added
// each and is signed in at each -- with the sessions in a configuration
// directory of the test's own.
func worldOf(t *testing.T, servers ...*vpnServer) *Core {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AppData", filepath.Join(home, "AppData"))

	var urls []string
	var entries []ServerEntry
	for _, s := range servers {
		urls = append(urls, s.URL)
		entries = append(entries, ServerEntry{URL: s.URL, Provider: provID})
	}
	h := helper.New(helper.Config{Servers: urls}, "linux", "app-test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.UseTunnels(func(wgtun.Config) (helper.Tunnel, error) { return nopTunnel{}, nil })
	h.UseRouteWatch(func(context.Context, string, string, string, string, func(routeclient.Update)) error { return nil })
	dir, err := os.MkdirTemp("", "cwa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); h.Shutdown() })
	go h.Serve(ln)

	for _, s := range servers {
		pair, _ := wgkey.Generate()
		if err := tokenstore.Save(tokenstore.Key(s.URL, provID), &tokenstore.Session{Provider: provID, Bearer: "a.b.c", WGPrivateKey: pair.Private.String()}); err != nil {
			t.Fatal(err)
		}
	}
	return New(&Config{Servers: entries, SocketPath: sock})
}

// world is one server where the person is in two tenants.
func world(t *testing.T) (*Core, *[]string, string) {
	t.Helper()
	var asked []string
	v := newVPNServer(t, "Test", false, &asked)
	return worldOf(t, v), &asked, v.URL
}

func only(t *testing.T, c *Core, url string) ServerStatus {
	t.Helper()
	for _, s := range c.Status().Servers {
		if s.URL == url {
			return s
		}
	}
	t.Fatalf("no server %s in the status", url)
	return ServerStatus{}
}

// A person in two tenants is asked to choose, chooses, and connects to the
// one chosen; the choice holds for the session.
func TestAPersonChoosesTheirTenant(t *testing.T) {
	c, asked, url := world(t)
	ctx := context.Background()
	if err := c.Connect(ctx, url); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("connecting with no tenant chosen: %v", err)
	}
	st := only(t, c, url)
	if !st.TenantRequired || len(st.Tenants) != 2 || st.Tenants[1].Name != "HPC" {
		t.Fatalf("the status offers %+v (required %v)", st.Tenants, st.TenantRequired)
	}
	if err := c.SetTenant(url, "physics"); err == nil {
		t.Error("a tenant nobody offered was chosen")
	}
	if err := c.SetTenant(url, "hpc"); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(ctx, url); err != nil {
		t.Fatal(err)
	}
	st = only(t, c, url)
	if !st.Connected || st.Tenant != "hpc" || st.TenantRequired || st.Name != "Test" {
		t.Errorf("after choosing: %+v", st)
	}
	if got := *asked; len(got) != 2 || got[0] != "Test enroll " || got[1] != "Test enroll hpc" {
		t.Errorf("the server was asked for %q", got)
	}
	// The choice is the session's: a new sign-in forgets it.
	if sess, _ := tokenstore.Load(tokenstore.Key(url, provID)); sess.Tenant != "hpc" {
		t.Errorf("the session keeps %q", sess.Tenant)
	}
	if err := c.Disconnect(ctx, url); err != nil {
		t.Fatal(err)
	}
	if err := c.Logout(ctx, url); err != nil {
		t.Fatal(err)
	}
	if st := only(t, c, url); st.LoggedIn || len(st.Tenants) != 0 {
		t.Errorf("after logout: %+v", st)
	}
}

// Tenants can be asked for before connecting, to offer the choice up front.
func TestTenantsCanBeListedFirst(t *testing.T) {
	c, _, url := world(t)
	ts, err := c.Tenants(context.Background(), url)
	if err != nil || len(ts) != 2 {
		t.Fatalf("%v %v", ts, err)
	}
	if err := c.SetTenant(url, "chem"); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(context.Background(), url); err != nil {
		t.Fatal(err)
	}
}

func TestNotSignedIn(t *testing.T) {
	c, _, url := world(t)
	tokenstore.Clear(tokenstore.Key(url, provID))
	if err := c.Connect(context.Background(), url); err == nil {
		t.Error("connected without a session")
	}
	if _, err := c.Tenants(context.Background(), url); err == nil {
		t.Error("listed tenants without a session")
	}
	if err := c.SetTenant(url, ""); err == nil {
		t.Error("chose a tenant without a session")
	}
}

// An app that restarts while the tunnel is up still shows the address: it is
// the helper's to report, not only the memory of the Core that connected.
func TestTheAddressSurvivesAnAppRestart(t *testing.T) {
	c, _, url := world(t)
	if _, err := c.Tenants(context.Background(), url); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTenant(url, "hpc"); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(context.Background(), url); err != nil {
		t.Fatal(err)
	}
	restarted := New(&Config{Servers: c.Config().Servers, SocketPath: c.Config().SocketPath})
	st := only(t, restarted, url)
	if !st.Connected || st.AssignedIP != "10.80.0.7/32" || st.Interface != "utun9" || st.Name != "Test" {
		t.Fatalf("after a restart: %+v", st)
	}
}

// The tunnel's facts the helper reports reach the server's status, apart from
// the address: its interface, the peer's endpoint and the routes.
func TestTheStatusCarriesTheTunnelsFacts(t *testing.T) {
	c, _, url := world(t)
	if _, err := c.Tenants(context.Background(), url); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTenant(url, "hpc"); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(context.Background(), url); err != nil {
		t.Fatal(err)
	}
	st := only(t, c, url)
	if st.Interface != "utun9" || st.AssignedIP != "10.80.0.7/32" || st.Endpoint != "vpn.example.org:51820" ||
		len(st.AllowedIPs) == 0 || st.AllowedIPs[0] != "10.2.0.0/16" {
		t.Errorf("status %+v", st)
	}
	if err := c.Disconnect(context.Background(), url); err != nil {
		t.Fatal(err)
	}
	if st := only(t, c, url); st.Endpoint != "" || st.AllowedIPs != nil || st.RxBytes != 0 || st.LastHandshake != nil {
		t.Errorf("facts of a tunnel that is down: %+v", st)
	}
}

// A server that is not one the person added is not asked about.
func TestAnUnknownServerIsRefused(t *testing.T) {
	c, _, _ := world(t)
	ctx := context.Background()
	for _, f := range []func() error{
		func() error { return c.Connect(ctx, "https://elsewhere.example.org") },
		func() error { return c.Login(ctx, "https://elsewhere.example.org", "") },
		func() error { _, err := c.Tenants(ctx, "https://elsewhere.example.org"); return err },
		func() error { return c.Disconnect(ctx, "https://elsewhere.example.org") },
		func() error { return c.SetTenant("https://elsewhere.example.org", "") },
	} {
		if err := f(); !errors.Is(err, ErrUnknownServer) {
			t.Errorf("an unknown server: %v", err)
		}
	}
}

func TestTwoServersAreConnectedAtOnce(t *testing.T) {
	var asked []string
	a, b := newVPNServer(t, "Campus", false, &asked), newVPNServer(t, "Lab", false, &asked)
	c := worldOf(t, a, b)
	ctx := context.Background()
	for _, v := range []*vpnServer{a, b} {
		if _, err := c.Tenants(ctx, v.URL); err != nil {
			t.Fatal(err)
		}
		if err := c.SetTenant(v.URL, "hpc"); err != nil {
			t.Fatal(err)
		}
		if err := c.Connect(ctx, v.URL); err != nil {
			t.Fatal(err)
		}
	}
	if !only(t, c, a.URL).Connected || !only(t, c, b.URL).Connected {
		t.Fatalf("%+v", c.Status().Servers)
	}
	if err := c.Disconnect(ctx, a.URL); err != nil {
		t.Fatal(err)
	}
	if only(t, c, a.URL).Connected || !only(t, c, b.URL).Connected {
		t.Fatalf("after disconnecting the first: %+v", c.Status().Servers)
	}
	if err := c.DisconnectAll(ctx); err != nil {
		t.Fatal(err)
	}
	if only(t, c, b.URL).Connected {
		t.Error("still connected after DisconnectAll")
	}
}

// ⛔ An exclusive server is refused while another is connected, and another is
// refused while an exclusive one is: the error names the server in the way,
// and the refused server is never asked to enroll.
func TestExclusivityIsRefusedInBothDirections(t *testing.T) {
	for _, tc := range []struct {
		name      string
		firstSolo bool
	}{
		{"an exclusive server beside another", false},
		{"another beside an exclusive one", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asked []string
			first := newVPNServer(t, "Campus", tc.firstSolo, &asked)
			second := newVPNServer(t, "Lab", !tc.firstSolo, &asked)
			c := worldOf(t, first, second)
			ctx := context.Background()
			for _, v := range []*vpnServer{first, second} {
				if _, err := c.Tenants(ctx, v.URL); err != nil {
					t.Fatal(err)
				}
				if err := c.SetTenant(v.URL, "hpc"); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Connect(ctx, first.URL); err != nil {
				t.Fatal(err)
			}
			err := c.Connect(ctx, second.URL)
			var xerr *exclusive.Error
			if !errors.As(err, &xerr) || xerr.BlockedBy() != "Campus" {
				t.Fatalf("the second server: %v", err)
			}
			worldMu.Lock()
			for _, a := range asked {
				if a == "Lab enroll hpc" {
					t.Errorf("the refused server was asked to enroll: %q", asked)
				}
			}
			worldMu.Unlock()
			if only(t, c, second.URL).Connected {
				t.Error("the refused server is connected")
			}
			// The app refused it itself: the helper was never asked.
			if l := logOf(c); strings.Contains(l, "enrolling at "+second.URL) || !strings.Contains(l, "connect refused") {
				t.Errorf("the app's own check did not refuse it:\n%s", l)
			}
			// Once the first is down, the second is welcome.
			if err := c.Disconnect(ctx, first.URL); err != nil {
				t.Fatal(err)
			}
			if err := c.Connect(ctx, second.URL); err != nil {
				t.Fatalf("after disconnecting: %v", err)
			}
		})
	}
}

// ⛔ The app's own check is not the only one: a server that became exclusive
// after the app read its document is refused by the helper, which reads the
// document itself, and the app reports it the same way.
func TestTheHelperRefusesWhatTheAppDidNotKnow(t *testing.T) {
	var asked []string
	a, b := newVPNServer(t, "Campus", false, &asked), newVPNServer(t, "Lab", false, &asked)
	c := worldOf(t, a, b)
	ctx := context.Background()
	for _, v := range []*vpnServer{a, b} {
		if _, err := c.Tenants(ctx, v.URL); err != nil {
			t.Fatal(err)
		}
		if err := c.SetTenant(v.URL, "hpc"); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Connect(ctx, a.URL); err != nil {
		t.Fatal(err)
	}
	b.exclusive.Store(true) // the app holds the old document for max-age
	err := c.Connect(ctx, b.URL)
	var xerr *exclusive.Error
	if !errors.As(err, &xerr) || xerr.BlockedBy() != "Campus" {
		t.Fatalf("the helper's refusal: %v", err)
	}
	if l := logOf(c); !strings.Contains(l, "enrolling at "+b.URL) || !strings.Contains(l, "connect refused") || strings.Contains(l, "connect FAILED") {
		t.Errorf("the helper's refusal is not reported as one:\n%s", l)
	}
}
