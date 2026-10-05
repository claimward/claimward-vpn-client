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
	"sync"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/helper"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/routeclient"
	"github.com/claimward/claimward-vpn-client/pkg/tokenstore"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
	"github.com/claimward/claimward-vpn-client/pkg/wgtun"
)

// worldMu guards what a world's server was asked.
var worldMu sync.Mutex

type nopTunnel struct{}

func (nopTunnel) Name() string                { return "utun9" }
func (nopTunnel) UpdateRoutes([]string) error { return nil }
func (nopTunnel) Close() error                { return nil }

// world is a claimward-vpn-server where the person is in two tenants, a
// helper allowed to reach it, and a Core signed in -- with the session in a
// configuration directory of the test's own.
func world(t *testing.T) (*Core, *[]string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AppData", filepath.Join(home, "AppData"))

	mu := &worldMu
	var asked []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+protocol.PathTenants, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]protocol.TenantInfo{{ID: "chem", Name: "Chemistry"}, {ID: "hpc", Name: "HPC"}})
	})
	mux.HandleFunc("POST "+protocol.PathEnroll, func(w http.ResponseWriter, r *http.Request) {
		var req protocol.EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		asked = append(asked, req.Tenant)
		mu.Unlock()
		if req.Tenant == "" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "tenant_required", "message": "choose one of: chem, hpc"})
			return
		}
		pair, _ := wgkey.Generate()
		json.NewEncoder(w).Encode(protocol.EnrollResponse{AssignedIP: "10.80.0.7/32", ServerPublicKey: pair.Public.String(), Endpoint: "vpn.example.org:51820", AllowedIPs: []string{"10.2.0.0/16"}})
	})
	mux.HandleFunc("POST "+protocol.PathHeartbeat, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, "heartbeat "+r.Header.Get("Authorization"))
		mu.Unlock()
		json.NewEncoder(w).Encode(protocol.HeartbeatResponse{LeaseExpiresAt: time.Now().Add(time.Hour)})
	})
	mux.HandleFunc("POST "+protocol.PathDeregister, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, "deregister")
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	vpn := httptest.NewServer(mux)
	t.Cleanup(vpn.Close)

	h := helper.New(helper.Config{Servers: []string{vpn.URL}}, "linux", "app-test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.UseTunnels(func(wgtun.Config) (helper.Tunnel, error) { return nopTunnel{}, nil })
	h.UseRouteWatch(func(context.Context, string, string, string, func(routeclient.Update)) error { return nil })
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

	pair, _ := wgkey.Generate()
	if err := tokenstore.Save(&tokenstore.Session{Provider: "oidc", Bearer: "a.b.c", WGPrivateKey: pair.Private.String()}); err != nil {
		t.Fatal(err)
	}
	return New(&Config{ServerURL: vpn.URL, Provider: "oidc", OIDCIssuer: "https://login.example.org", OIDCClientID: "claimward", SocketPath: sock}), &asked
}

// A person in two tenants is asked to choose, chooses, and connects to the
// one chosen; the choice holds for the session.
func TestAPersonChoosesTheirTenant(t *testing.T) {
	c, asked := world(t)
	ctx := context.Background()
	if err := c.Connect(ctx); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("connecting with no tenant chosen: %v", err)
	}
	st := c.Status()
	if !st.TenantRequired || len(st.Tenants) != 2 || st.Tenants[1].Name != "HPC" {
		t.Fatalf("the status offers %+v (required %v)", st.Tenants, st.TenantRequired)
	}
	if err := c.SetTenant("physics"); err == nil {
		t.Error("a tenant nobody offered was chosen")
	}
	if err := c.SetTenant("hpc"); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	st = c.Status()
	if !st.Connected || st.Tenant != "hpc" || st.TenantRequired {
		t.Errorf("after choosing: %+v", st)
	}
	if got := *asked; len(got) != 2 || got[0] != "" || got[1] != "hpc" {
		t.Errorf("the server was asked for %q", got)
	}
	// The choice is the session's: a new sign-in forgets it.
	if sess, _ := tokenstore.Load(); sess.Tenant != "hpc" {
		t.Errorf("the session keeps %q", sess.Tenant)
	}
	if err := c.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); st.LoggedIn || len(st.Tenants) != 0 {
		t.Errorf("after logout: %+v", st)
	}
}

// Tenants can be asked for before connecting, to offer the choice up front.
func TestTenantsCanBeListedFirst(t *testing.T) {
	c, _ := world(t)
	ts, err := c.Tenants(context.Background())
	if err != nil || len(ts) != 2 {
		t.Fatalf("%v %v", ts, err)
	}
	if err := c.SetTenant("chem"); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNotSignedIn(t *testing.T) {
	c, _ := world(t)
	tokenstore.Clear()
	if err := c.Connect(context.Background()); err == nil {
		t.Error("connected without a session")
	}
	if _, err := c.Tenants(context.Background()); err == nil {
		t.Error("listed tenants without a session")
	}
	if err := c.SetTenant(""); err == nil {
		t.Error("chose a tenant without a session")
	}
}

// An app that restarts while the tunnel is up still shows the address: it is
// the helper's to report, not only the memory of the Core that connected.
func TestTheAddressSurvivesAnAppRestart(t *testing.T) {
	c, _ := world(t)
	if _, err := c.Tenants(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTenant("hpc"); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted := New(&Config{ServerURL: c.Config().ServerURL, Provider: "oidc", OIDCIssuer: "https://login.example.org",
		OIDCClientID: "claimward", SocketPath: c.Config().SocketPath})
	st := restarted.Status()
	if !st.Connected || st.AssignedIP != "10.80.0.7/32" || st.Interface != "utun9" {
		t.Fatalf("after a restart: connected %v address %q interface %q", st.Connected, st.AssignedIP, st.Interface)
	}
}
