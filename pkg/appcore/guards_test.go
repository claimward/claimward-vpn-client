package appcore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/auth"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/tokenstore"
)

// logOf is the connection log as one string.
func logOf(c *Core) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.log, "\n")
}

// noConfigDir makes the configuration directory, so the secret store's legacy
// file and the configuration file, unreachable: a write to either fails, a read
// from the in-memory store still works.
func noConfigDir(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", "")
}

// serving is a server with a document of its own making.
func serving(t *testing.T, doc protocol.Configuration, logo []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+protocol.PathWellKnownConfiguration, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("GET "+protocol.PathWellKnownLogo, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write(logo)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func TestAServerNameThatIsNotAURLIsNotTakenForAnUnknownServer(t *testing.T) {
	c, _, _ := world(t)
	err := c.SetTenant("http://vpn.example.org", "")
	if err == nil || errors.Is(err, ErrUnknownServer) {
		t.Fatalf("SetTenant = %v, want the URL's own refusal", err)
	}
}

func TestChosenFollowsTheDocument(t *testing.T) {
	one := &protocol.Configuration{Providers: []protocol.Provider{{ID: "a", Kind: "oidc"}}}
	two := &protocol.Configuration{Providers: []protocol.Provider{{ID: "a", Kind: "oidc"}, {ID: "b", Kind: "oidc"}}}
	if got := chosen(ServerEntry{}, one).ID; got != "a" {
		t.Errorf("the only provider: %q", got)
	}
	if got := chosen(ServerEntry{}, two).ID; got != "" {
		t.Errorf("two providers and no choice: %q", got)
	}
	if got := chosen(ServerEntry{Provider: "b"}, two).ID; got != "b" {
		t.Errorf("the entry's own choice: %q", got)
	}
	if got := chosen(ServerEntry{Provider: "oidc"}, two).ID; got != "" {
		t.Errorf("a kind two providers share: %q", got)
	}
	if got := chosen(ServerEntry{Provider: "oidc"}, one).ID; got != "a" {
		t.Errorf("a kind one provider has: %q", got)
	}
}

func TestACleartextServerIsRefusedBeforeAnyRequest(t *testing.T) {
	confHome(t)
	c := New(&Config{})
	_, err := c.AddServer(context.Background(), "http://vpn.example.org")
	if err == nil || strings.Contains(err.Error(), "not a Claimward server") {
		t.Fatalf("AddServer = %v, want the URL's own refusal", err)
	}
}

func TestAServerThatCannotBeSavedIsNotAdded(t *testing.T) {
	confHome(t)
	var asked []string
	v := newVPNServer(t, "Campus", false, &asked)
	c := New(&Config{})
	boom := errors.New("disk full")
	c.save = func(*Config) error { return boom }
	if _, err := c.AddServer(context.Background(), v.URL); !errors.Is(err, boom) {
		t.Fatalf("AddServer = %v", err)
	}
	if n := len(c.Config().Servers); n != 0 {
		t.Fatalf("%d servers kept", n)
	}
}

func TestAServerWhoseSessionsCannotBeForgottenStaysListed(t *testing.T) {
	c, _, url := world(t)
	noConfigDir(t)
	if err := c.RemoveServer(context.Background(), url); err == nil {
		t.Fatal("removed with its sessions still in the store")
	}
	if n := len(c.Config().Servers); n != 1 {
		t.Fatalf("%d servers listed", n)
	}
}

func TestDiscoverNamesAnUnknownServer(t *testing.T) {
	c, _, _ := world(t)
	doc, err := c.Discover(context.Background(), "https://elsewhere.example.org")
	if !errors.Is(err, ErrUnknownServer) || doc != nil {
		t.Fatalf("Discover = %v, %v", doc, err)
	}
}

func TestAServerThatAnswersNoMoreIsAnError(t *testing.T) {
	var asked []string
	v := newVPNServer(t, "Campus", false, &asked)
	c := worldOf(t, v)
	c.disc.Forget(v.URL)
	v.Close()
	ctx := context.Background()
	if err := c.SetProvider(ctx, v.URL, provID); err == nil {
		t.Error("SetProvider: no error")
	}
	err := c.Login(ctx, v.URL, "")
	if err == nil || !strings.HasPrefix(err.Error(), v.URL+": ") {
		t.Errorf("Login = %v", err)
	}
}

func TestAServerWithNoProviderCannotBeSignedInTo(t *testing.T) {
	confHome(t)
	s := serving(t, protocol.Configuration{Version: 2, ServerName: "Bare"}, nil)
	c := New(&Config{Servers: []ServerEntry{{URL: s.URL}}})
	err := c.Login(context.Background(), s.URL, "")
	if err == nil || errors.Is(err, ErrProviderRequired) || !strings.Contains(err.Error(), "no identity provider") {
		t.Fatalf("Login = %v", err)
	}
}

func TestAProviderThatCannotBeBuiltStopsTheSignIn(t *testing.T) {
	c, _, url := world(t)
	boom := errors.New("no such provider")
	c.newAuth = func(auth.Config) (auth.Provider, error) { return nil, boom }
	if err := c.Login(context.Background(), url, ""); !errors.Is(err, boom) {
		t.Errorf("Login = %v", err)
	}
	if err := c.Connect(context.Background(), url); !errors.Is(err, boom) {
		t.Errorf("Connect = %v", err)
	}
}

func TestARegisteredKeyThatCannotBeKeptStopsTheConnection(t *testing.T) {
	c, _, url := world(t)
	c.newAuth = func(auth.Config) (auth.Provider, error) { return &registrar{}, nil }
	noConfigDir(t)
	if _, err := c.Tenants(context.Background(), url); err == nil {
		t.Fatal("went on with a session that could not be saved")
	}
}

func TestATenantIsNotChosenForNoProvider(t *testing.T) {
	confHome(t)
	var asked []string
	v := newVPNServer(t, "Campus", false, &asked)
	c := New(&Config{Servers: []ServerEntry{{URL: v.URL}}}) // no document read, no provider
	key := tokenstore.Key(v.URL, "")
	if err := tokenstore.Save(key, &tokenstore.Session{Bearer: "a.b.c", Tenant: "keep"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTenant(v.URL, ""); err == nil {
		t.Fatal("a tenant was chosen with no provider")
	}
	if s, _ := tokenstore.Load(key); s == nil || s.Tenant != "keep" {
		t.Fatalf("the session was touched: %+v", s)
	}
}

func TestATenantThatCannotBeSavedIsAnError(t *testing.T) {
	c, _, url := world(t)
	noConfigDir(t)
	if err := c.SetTenant(url, ""); err == nil {
		t.Fatal("the choice was not saved, yet no error")
	}
}

// A loop already running is not replaced: its stop function stays.
func TestOneRenewalLoopPerServer(t *testing.T) {
	c, _, url := world(t)
	stopped := false
	c.mu.Lock()
	c.st(url).stopRenew = func() { stopped = true }
	c.mu.Unlock()
	c.startRenewing(url)
	c.mu.Lock()
	stop := c.st(url).stopRenew
	c.mu.Unlock()
	stop()
	if !stopped {
		t.Fatal("a second loop replaced the first")
	}
}

func TestLogoutNamesAnUnknownServer(t *testing.T) {
	c, _, _ := world(t)
	if err := c.Logout(context.Background(), "https://elsewhere.example.org"); !errors.Is(err, ErrUnknownServer) {
		t.Fatalf("Logout = %v", err)
	}
}

func TestLogoFailuresAreLoggedAndNeverFatal(t *testing.T) {
	confHome(t)
	ctx := context.Background()
	prov := []protocol.Provider{{ID: provID, Kind: protocol.KindOIDC, Name: "Uni", OIDCIssuer: "https://login.example.org", OIDCClientID: "c"}}

	// Not a server the person added: nobody is asked, nothing is logged.
	c := New(&Config{})
	if b := c.Logo(ctx, "https://elsewhere.example.org"); b != nil || logOf(c) != "" {
		t.Errorf("unknown server: %q, log %q", b, logOf(c))
	}

	// A server with no logo: nil, and no complaint.
	bare := serving(t, protocol.Configuration{Version: 2, ServerName: "Bare", Providers: prov}, nil)
	c = New(&Config{Servers: []ServerEntry{{URL: bare.URL}}})
	if b := c.Logo(ctx, bare.URL); b != nil || logOf(c) != "" {
		t.Errorf("no logo: %q, log %q", b, logOf(c))
	}

	// A logo that does not match its digest: nil, and the reason in the log.
	wrong := strings.Repeat("0", 64)
	bad := serving(t, protocol.Configuration{Version: 2, ServerName: "Bad", Providers: prov,
		Logo: &protocol.Logo{Path: protocol.PathWellKnownLogo, SHA256: wrong}},
		[]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`))
	c = New(&Config{Servers: []ServerEntry{{URL: bad.URL}}})
	if b := c.Logo(ctx, bad.URL); b != nil || !strings.Contains(logOf(c), "logo of "+bad.URL) {
		t.Errorf("bad digest: %q, log %q", b, logOf(c))
	}

	// A server that does not answer: nil, and the reason in the log.
	gone := serving(t, protocol.Configuration{Version: 2, ServerName: "Gone", Providers: prov}, nil)
	url := gone.URL
	gone.Close()
	c = New(&Config{Servers: []ServerEntry{{URL: url}}})
	if b := c.Logo(ctx, url); b != nil || !strings.Contains(logOf(c), "logo of "+url) {
		t.Errorf("no answer: %q, log %q", b, logOf(c))
	}
}
