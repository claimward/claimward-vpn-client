package appcore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/tokenstore"
)

func confHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AppData", filepath.Join(home, "AppData"))
	t.Setenv("CLAIMWARD_HELPER_SOCKET", "")
	return home
}

func writeConf(t *testing.T, body string) {
	t.Helper()
	p := ConfigPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// seedLegacy leaves the session file v0.9 wrote, which the store migrates the
// first time it reads.
func seedLegacy(t *testing.T, s tokenstore.Session) {
	t.Helper()
	p, err := tokenstore.Path()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRefusesACleartextServer(t *testing.T) {
	c := Config{Servers: []ServerEntry{{URL: "http://vpn.example.org"}}}
	if err := c.Validate(); err == nil {
		t.Fatal("an http:// server was accepted")
	}
	c.Servers[0].URL = "https://vpn.example.org"
	if err := c.Validate(); err != nil {
		t.Fatalf("an https:// server was refused: %v", err)
	}
}

func TestValidateRefusesWhatIsNotCanonicalTwiceOrBadlyNamed(t *testing.T) {
	for name, c := range map[string]Config{
		"not canonical": {Servers: []ServerEntry{{URL: "https://VPN.example.org/"}}},
		"twice":         {Servers: []ServerEntry{{URL: "https://vpn.example.org"}, {URL: "https://vpn.example.org"}}},
		"bad provider":  {Servers: []ServerEntry{{URL: "https://vpn.example.org", Provider: "a b"}}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (&Config{}).Validate(); err != nil {
		t.Errorf("no server at all: %v", err)
	}
}

func TestTheConfigurationRoundTripsAndTheSocketComesFromTheEnvironment(t *testing.T) {
	confHome(t)
	in := &Config{Servers: []ServerEntry{{URL: "https://a.example.org", Provider: "uni"}, {URL: "https://b.example.org"}}}
	if err := SaveConfig(in); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(ConfigPath()); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	t.Setenv("CLAIMWARD_HELPER_SOCKET", "/run/real.sock")
	out, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Servers) != 2 || out.Servers[0] != in.Servers[0] || out.Servers[1] != in.Servers[1] || out.SocketPath != "/run/real.sock" {
		t.Errorf("%+v", out)
	}
}

func TestAConfigurationOfAnUnknownVersionIsRefused(t *testing.T) {
	confHome(t)
	writeConf(t, `{"version":3,"servers":[]}`)
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "version 3") {
		t.Errorf("%v", err)
	}
}

// The single-server configuration of v0.9 becomes one entry, once; the
// session signed in under it follows, and the old file is not read again.
func TestTheOldConfigurationIsMigratedOnce(t *testing.T) {
	confHome(t)
	restore := tokenstore.UseMemory()
	defer restore()
	// The session v0.9 kept: one, with no server in its key.
	seedLegacy(t, tokenstore.Session{Provider: "oidc", Bearer: "a.b.c", WGPrivateKey: "k"})
	writeConf(t, `{"server_url":"https://VPN.example.org:443/","provider":"oidc","oidc_issuer":"https://login.example.org","oidc_client_id":"claimward","socket_path":"/run/h.sock"}`)
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	want := ServerEntry{URL: "https://vpn.example.org", Provider: "oidc"}
	if len(c.Servers) != 1 || c.Servers[0] != want || c.SocketPath != "/run/h.sock" {
		t.Fatalf("%+v", c)
	}
	if sess, _ := tokenstore.Load(tokenstore.Key(want.URL, "oidc")); sess == nil || sess.Bearer != "a.b.c" {
		t.Errorf("the session did not follow: %+v", sess)
	}
	data, _ := os.ReadFile(ConfigPath())
	if !strings.Contains(string(data), `"version": 2`) || strings.Contains(string(data), "oidc_issuer") {
		t.Errorf("the migrated file: %s", data)
	}
	again, err := LoadConfig()
	if err != nil || len(again.Servers) != 1 || again.Servers[0] != want {
		t.Errorf("second load: %+v %v", again, err)
	}
}

func TestAnOldConfigurationWithABadServerIsDroppedAndItsSessionForgotten(t *testing.T) {
	confHome(t)
	restore := tokenstore.UseMemory()
	defer restore()
	seedLegacy(t, tokenstore.Session{Bearer: "x", WGPrivateKey: "k"})
	writeConf(t, `{"server_url":"http://vpn.example.org","provider":"github"}`)
	c, err := LoadConfig()
	if err != nil || len(c.Servers) != 0 {
		t.Fatalf("%+v %v", c, err)
	}
	if ok, _ := tokenstore.AdoptLegacy(tokenstore.Key("https://vpn.example.org", "github")); ok {
		t.Error("the old session of a refused server was kept")
	}
}

// AddServer takes a URL and nothing else: the document tells the rest.
func TestAddServerReadsTheDocument(t *testing.T) {
	confHome(t)
	var asked []string
	v := newVPNServer(t, "Campus", false, &asked)
	c := New(&Config{})
	ctx := context.Background()
	e, err := c.AddServer(ctx, v.URL+"/")
	if err != nil || e.URL != v.URL || e.Provider != provID {
		t.Fatalf("%+v %v", e, err)
	}
	if again, err := c.AddServer(ctx, v.URL); err != nil || again != e || len(c.Config().Servers) != 1 {
		t.Errorf("adding twice: %+v %v", c.Config().Servers, err)
	}
	st := only(t, c, v.URL)
	if st.Name != "Campus" || len(st.Providers) != 1 || st.Provider != provID || st.DiscoveryError != "" {
		t.Errorf("%+v", st)
	}
	if got, _ := LoadConfig(); len(got.Servers) != 1 {
		t.Errorf("not saved: %+v", got)
	}
}

func TestAddServerRefusesWhatIsNotAClaimwardServer(t *testing.T) {
	confHome(t)
	other := httptest.NewServer(http.NotFoundHandler())
	defer other.Close()
	c := New(&Config{})
	for _, u := range []string{other.URL, "http://vpn.example.org", "not a url", ""} {
		if _, err := c.AddServer(context.Background(), u); err == nil {
			t.Errorf("%q was added", u)
		}
	}
	if len(c.Config().Servers) != 0 {
		t.Errorf("%+v", c.Config().Servers)
	}
}

func TestRemoveServerForgetsItsSessions(t *testing.T) {
	c, _, url := world(t)
	if err := c.RemoveServer(context.Background(), url); err != nil {
		t.Fatal(err)
	}
	if len(c.Config().Servers) != 0 {
		t.Error("still listed")
	}
	if sess, _ := tokenstore.Load(tokenstore.Key(url, provID)); sess != nil {
		t.Error("its session was kept")
	}
	if err := c.RemoveServer(context.Background(), url); !errors.Is(err, ErrUnknownServer) {
		t.Errorf("%v", err)
	}
}

// With several providers, signing in needs the chosen one.
func TestSeveralProvidersNeedAChoice(t *testing.T) {
	confHome(t)
	doc := protocol.Configuration{Version: 2, ServerName: "Many", Providers: []protocol.Provider{
		{ID: "gh", Kind: protocol.KindGitHub, Name: "GitHub", GitHubClientID: "x"},
		{ID: "uni", Kind: protocol.KindOIDC, Name: "Uni", OIDCIssuer: "https://login.example.org", OIDCClientID: "c"},
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	c := New(&Config{})
	ctx := context.Background()
	e, err := c.AddServer(ctx, srv.URL)
	if err != nil || e.Provider != "" {
		t.Fatalf("%+v %v", e, err)
	}
	if err := c.Login(ctx, srv.URL, ""); !errors.Is(err, ErrProviderRequired) {
		t.Fatalf("no choice: %v", err)
	}
	if err := c.SetProvider(ctx, srv.URL, "nobody"); err == nil {
		t.Error("a provider the server does not list was chosen")
	}
	if err := c.SetProvider(ctx, srv.URL, "uni"); err != nil {
		t.Fatal(err)
	}
	if got := c.Config().Servers[0].Provider; got != "uni" {
		t.Errorf("chosen %q", got)
	}
	if st := only(t, c, srv.URL); st.Provider != "uni" || len(st.Providers) != 2 {
		t.Errorf("%+v", st)
	}
}

// A session written under the kind of provider, as the migration does, moves
// to the provider's id once the server's document names it.
func TestAMigratedSessionMovesToTheProvidersId(t *testing.T) {
	var asked []string
	v := newVPNServer(t, "Campus", false, &asked)
	c := worldOf(t, v)
	// worldOf signed in under provID; pretend the entry still holds the kind.
	sess, _ := tokenstore.Load(tokenstore.Key(v.URL, provID))
	if err := tokenstore.Save(tokenstore.Key(v.URL, protocol.KindOIDC), sess); err != nil {
		t.Fatal(err)
	}
	tokenstore.Clear(tokenstore.Key(v.URL, provID))
	c.cfg.Servers[0].Provider = protocol.KindOIDC
	if _, err := c.Tenants(context.Background(), v.URL); err != nil {
		t.Fatal(err)
	}
	if got, _ := tokenstore.Load(tokenstore.Key(v.URL, provID)); got == nil {
		t.Error("the session did not move")
	}
	if old, _ := tokenstore.Load(tokenstore.Key(v.URL, protocol.KindOIDC)); old != nil {
		t.Error("the old key was kept")
	}
	if got := c.Config().Servers[0].Provider; got != provID {
		t.Errorf("entry %q", got)
	}
}
