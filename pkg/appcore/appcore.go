// Package appcore is a Claimward app's business logic, shared by the macOS,
// Linux and Windows apps and independent of how each draws its window and
// tray: the servers the person added, sign-in at each, the tenant chosen, and
// driving the privileged helper (pkg/helper) to bring a tunnel up and down.
//
// The person types only a server's URL (AddServer). The server's name, its
// identity providers, whether it is exclusive and its logo come from its own
// discovery document (pkg/discovery). Several servers may be connected at
// once, except that an exclusive server is connected alone (pkg/exclusive):
// Connect refuses with an *exclusive.Error naming the blocking server, and the
// helper refuses too, since it does not trust the app.
//
// A server is reached only through the helper. On macOS "Local Network"
// privacy blocks an unprivileged app from a server on the LAN, and the
// helper, as root, is exempt; the other platforms follow the same path so
// that the three apps behave alike.
package appcore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/auth"
	"github.com/claimward/claimward-vpn-client/pkg/discovery"
	"github.com/claimward/claimward-vpn-client/pkg/exclusive"
	"github.com/claimward/claimward-vpn-client/pkg/helperclient"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/secureurl"
	"github.com/claimward/claimward-vpn-client/pkg/tokenstore"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
)

// ErrTenantRequired is a connection the server refused because the person
// belongs to several tenants and none was chosen: the server's Tenants in
// Status list them, and SetTenant chooses.
var ErrTenantRequired = errors.New("choose a tenant: you belong to several")

// ErrProviderRequired is a sign-in at a server that lists several identity
// providers when none was chosen: ServerStatus.Providers lists them, and
// SetProvider (or the providerID of Login) chooses.
var ErrProviderRequired = errors.New("choose an identity provider: the server offers several")

// ErrUnknownServer is a call naming a server the person has not added.
var ErrUnknownServer = errors.New("not a server you added")

// serverState is what Core keeps about one server besides the configuration.
type serverState struct {
	tenants        []hproto.Tenant
	tenantRequired bool
	devURI         string
	devCode        string
	assigned       string
	// stopRenew ends the loop that brings the helper fresh bearers.
	stopRenew context.CancelFunc
}

// Core is the app's stateful service.
type Core struct {
	mu     sync.Mutex
	cfg    *Config
	helper *helperclient.Client
	disc   *discovery.Client
	state  map[string]*serverState
	// log is a capped ring of timestamped connection-process lines.
	log []string
	// renewAfter is how long after a renewal the app brings the next
	// bearer, from what the lease has left (renewDelay).
	renewAfter func(remaining time.Duration) time.Duration
	// save persists the configuration (SaveConfig; replaced by tests).
	save func(*Config) error
}

// renewDelay brings a fresh bearer at 40% of what the lease has left: before
// the helper would renew on its own (at half), with the bearer it holds,
// which may have expired since. Never sooner than 20 s nor later than 8 min,
// which is before the helper's own ceiling (10 min).
func renewDelay(remaining time.Duration) time.Duration {
	return min(max(remaining*2/5, 20*time.Second), 8*time.Minute)
}

// logf appends a timestamped line to the connection log shown in the UI.
// Must NOT be called while holding c.mu.
func (c *Core) logf(format string, args ...any) {
	line := time.Now().Format("15:04:05") + "  " + fmt.Sprintf(format, args...)
	c.mu.Lock()
	c.log = append(c.log, line)
	if len(c.log) > 200 {
		c.log = c.log[len(c.log)-200:]
	}
	c.mu.Unlock()
}

// New builds a Core from config.
func New(cfg *Config) *Core {
	return &Core{
		cfg:        cfg,
		helper:     helperclient.New(cfg.SocketPath),
		disc:       discovery.New(nil),
		state:      map[string]*serverState{},
		renewAfter: renewDelay,
		save:       SaveConfig,
	}
}

// UseDiscovery replaces the discovery client (tests).
func (c *Core) UseDiscovery(d *discovery.Client) {
	c.mu.Lock()
	c.disc = d
	c.mu.Unlock()
}

// st returns the server's state. Caller holds c.mu.
func (c *Core) st(url string) *serverState {
	s := c.state[url]
	if s == nil {
		s = &serverState{}
		c.state[url] = s
	}
	return s
}

// entry finds a server the person added, by any spelling of its URL.
func (c *Core) entry(server string) (ServerEntry, error) {
	canon, err := secureurl.Canonical(server)
	if err != nil {
		return ServerEntry{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.cfg.Servers {
		if e.URL == canon {
			return e, nil
		}
	}
	return ServerEntry{}, ErrUnknownServer
}

// Config returns a copy of the current configuration.
func (c *Core) Config() Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := *c.cfg
	out.Servers = append([]ServerEntry(nil), c.cfg.Servers...)
	return out
}

// persist writes the configuration. Caller holds c.mu.
func (c *Core) persist() error { return c.save(c.cfg) }

// ServerStatus is one server in Status.
type ServerStatus struct {
	URL string `json:"url"`
	// Name, Providers and Exclusive come from the server's discovery document
	// as last read; DiscoveryError says why there is none.
	Name           string              `json:"name,omitempty"`
	Providers      []protocol.Provider `json:"providers,omitempty"`
	Exclusive      bool                `json:"exclusive,omitempty"`
	DiscoveryError string              `json:"discovery_error,omitempty"`
	HasLogo        bool                `json:"has_logo,omitempty"`
	// Provider is the id of the identity provider chosen ("" = none yet).
	Provider  string `json:"provider,omitempty"`
	LoggedIn  bool   `json:"logged_in"`
	Email     string `json:"email,omitempty"`
	Connected bool   `json:"connected"`

	Interface  string `json:"interface,omitempty"`
	AssignedIP string `json:"assigned_ip,omitempty"`
	// Tenant is the one chosen for this session ("" = the server's choice
	// for a person in one), and Tenants those last offered.
	Tenant  string          `json:"tenant,omitempty"`
	Tenants []hproto.Tenant `json:"tenants,omitempty"`
	// TenantRequired: the last connection was refused until one is chosen.
	TenantRequired bool `json:"tenant_required,omitempty"`
	// Device-code prompt, set while a device-flow sign-in is in progress.
	DeviceVerificationURI string `json:"device_verification_uri,omitempty"`
	DeviceUserCode        string `json:"device_user_code,omitempty"`
	// LastError is why the helper last dropped this server's tunnel.
	LastError string `json:"last_error,omitempty"`
}

// Status is a snapshot for the UI and tray. It never touches the network
// beyond the helper's socket: a server's document is the one last read.
type Status struct {
	ConfigOK        bool           `json:"config_ok"`
	ConfigError     string         `json:"config_error,omitempty"`
	HelperInstalled bool           `json:"helper_installed"`
	Servers         []ServerStatus `json:"servers"`
	// Log is the connection-process log (most recent lines).
	Log []string `json:"log,omitempty"`
}

// Status returns the current state.
func (c *Core) Status() Status {
	cfg := c.Config()
	c.mu.Lock()
	helper, disc := c.helper, c.disc
	c.mu.Unlock()
	out := Status{Servers: []ServerStatus{}}
	if err := cfg.Validate(); err != nil {
		out.ConfigError = err.Error()
	} else {
		out.ConfigOK = true
	}
	tunnels := map[string]hproto.Tunnel{}
	lastErrs := map[string]string{}
	out.HelperInstalled = helper.Available()
	if out.HelperInstalled {
		if r, err := helper.Status(); err == nil {
			for _, t := range r.Tunnels {
				tunnels[t.ServerURL] = t
			}
			lastErrs = r.LastErrors
		}
	}
	var renew []string
	for _, e := range cfg.Servers {
		s := ServerStatus{URL: e.URL, Provider: e.Provider}
		if doc, ok := disc.Cached(e.URL); ok {
			s.Name, s.Providers, s.Exclusive, s.HasLogo = doc.ServerName, doc.Providers, doc.Exclusive, doc.Logo != nil
			s.Provider = chosen(e, doc).ID
		} else {
			s.DiscoveryError = "not read yet"
		}
		if sess, _ := tokenstore.Load(tokenstore.Key(e.URL, s.Provider)); sess != nil && sess.Bearer != "" {
			s.LoggedIn = true
			s.Email = nameFromToken(sess.Bearer)
			s.Tenant = sess.Tenant
		}
		if t, ok := tunnels[e.URL]; ok {
			s.Connected, s.Interface, s.AssignedIP = true, t.Interface, t.AssignedIP
			if t.Tenant != "" {
				s.Tenant = t.Tenant
			}
			if s.Name == "" {
				s.Name, s.Exclusive = t.ServerName, t.Exclusive
			}
		}
		s.LastError = lastErrs[e.URL]
		c.mu.Lock()
		ss := c.st(e.URL)
		if s.Connected && s.AssignedIP == "" {
			s.AssignedIP = ss.assigned
		}
		s.Tenants = append([]hproto.Tenant(nil), ss.tenants...)
		s.TenantRequired = ss.tenantRequired
		s.DeviceVerificationURI, s.DeviceUserCode = ss.devURI, ss.devCode
		if s.Connected && s.LoggedIn && ss.stopRenew == nil {
			// A tunnel this Core did not bring up -- the app restarted under
			// it -- still needs fresh bearers.
			renew = append(renew, e.URL)
		}
		c.mu.Unlock()
		out.Servers = append(out.Servers, s)
	}
	for _, url := range renew {
		c.startRenewing(url)
	}
	c.mu.Lock()
	if n := len(c.log); n > 0 {
		out.Log = append([]string(nil), c.log...)
	}
	c.mu.Unlock()
	return out
}

// chosen is the provider an entry signs in with, from the server's document:
// the entry's own choice when the document lists it; else the one whose kind
// is the entry's (a configuration written before servers named their providers
// held a kind); else the only provider. Zero when there is none to pick.
func chosen(e ServerEntry, doc *protocol.Configuration) protocol.Provider {
	for _, p := range doc.Providers {
		if e.Provider != "" && p.ID == e.Provider {
			return p
		}
	}
	if e.Provider != "" {
		var m []protocol.Provider
		for _, p := range doc.Providers {
			if p.Kind == e.Provider {
				m = append(m, p)
			}
		}
		if len(m) == 1 {
			return m[0]
		}
		return protocol.Provider{}
	}
	if len(doc.Providers) == 1 {
		return doc.Providers[0]
	}
	return protocol.Provider{}
}

func authConfig(p protocol.Provider) auth.Config {
	return auth.Config{
		Provider:       p.Kind,
		GitHubClientID: p.GitHubClientID,
		OIDCIssuer:     p.OIDCIssuer,
		OIDCClientID:   p.OIDCClientID,
	}
}

// AddServer adds a server by its URL, the only thing the person types. The
// server must answer with a discovery document; if it does not, nothing is
// added. Adding a server already added changes nothing.
func (c *Core) AddServer(ctx context.Context, rawURL string) (ServerEntry, error) {
	canon, err := secureurl.Canonical(rawURL)
	if err != nil {
		return ServerEntry{}, err
	}
	if e, err := c.entry(canon); err == nil {
		return e, nil
	}
	c.mu.Lock()
	disc := c.disc
	c.mu.Unlock()
	doc, err := disc.Get(ctx, canon)
	if err != nil {
		c.logf("add %s FAILED: %v", canon, err)
		return ServerEntry{}, fmt.Errorf("%s is not a Claimward server: %w", canon, err)
	}
	e := ServerEntry{URL: canon}
	if len(doc.Providers) == 1 {
		e.Provider = doc.Providers[0].ID
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg.Servers = append(c.cfg.Servers, e)
	if err := c.persist(); err != nil {
		c.cfg.Servers = c.cfg.Servers[:len(c.cfg.Servers)-1]
		return ServerEntry{}, err
	}
	c.logf2("added %s (%s)", canon, doc.ServerName)
	return e, nil
}

// logf2 is logf for a caller already holding c.mu.
func (c *Core) logf2(format string, args ...any) {
	c.log = append(c.log, time.Now().Format("15:04:05")+"  "+fmt.Sprintf(format, args...))
	if len(c.log) > 200 {
		c.log = c.log[len(c.log)-200:]
	}
}

// RemoveServer disconnects from a server, forgets its sessions (every
// provider) and drops it from the configuration.
func (c *Core) RemoveServer(ctx context.Context, server string) error {
	e, err := c.entry(server)
	if err != nil {
		return err
	}
	_ = c.Disconnect(ctx, e.URL)
	if err := tokenstore.ClearServer(e.URL); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.cfg.Servers[:0:0]
	for _, s := range c.cfg.Servers {
		if s.URL != e.URL {
			kept = append(kept, s)
		}
	}
	c.cfg.Servers = kept
	delete(c.state, e.URL)
	c.disc.Forget(e.URL)
	return c.persist()
}

// Discover reads the server's discovery document again, ignoring the cache.
func (c *Core) Discover(ctx context.Context, server string) (*protocol.Configuration, error) {
	e, err := c.entry(server)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	disc := c.disc
	c.mu.Unlock()
	doc, err := disc.Refresh(ctx, e.URL)
	if err != nil {
		c.logf("discovery of %s FAILED: %v", e.URL, err)
	}
	return doc, err
}

// SetProvider chooses the identity provider for a server, by its id in the
// server's document.
func (c *Core) SetProvider(ctx context.Context, server, id string) error {
	e, err := c.entry(server)
	if err != nil {
		return err
	}
	c.mu.Lock()
	disc := c.disc
	c.mu.Unlock()
	doc, err := disc.Get(ctx, e.URL)
	if err != nil {
		return err
	}
	found := false
	for _, p := range doc.Providers {
		found = found || p.ID == id
	}
	if !found {
		return fmt.Errorf("%q is not an identity provider of %s", id, e.URL)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.cfg.Servers {
		if c.cfg.Servers[i].URL == e.URL {
			c.cfg.Servers[i].Provider = id
		}
	}
	return c.persist()
}

// resolve reads the server's document and settles which provider signs in.
// providerID overrides the entry's choice ("" = the entry's, or the only
// one) and, when it is one the server lists, becomes the entry's.
func (c *Core) resolve(ctx context.Context, server, providerID string) (ServerEntry, *protocol.Configuration, protocol.Provider, error) {
	e, err := c.entry(server)
	if err != nil {
		return e, nil, protocol.Provider{}, err
	}
	c.mu.Lock()
	disc := c.disc
	c.mu.Unlock()
	doc, err := disc.Get(ctx, e.URL)
	if err != nil {
		return e, nil, protocol.Provider{}, fmt.Errorf("%s: %w", e.URL, err)
	}
	if providerID != "" {
		e.Provider = providerID
	}
	p := chosen(e, doc)
	if p.ID == "" {
		if len(doc.Providers) == 0 {
			return e, doc, p, errors.New("the server offers no identity provider")
		}
		return e, doc, p, ErrProviderRequired
	}
	if p.ID != e.Provider || providerID != "" {
		// Remember the choice, and a session written under the kind of
		// provider (a migrated one) moves to the provider's id.
		c.mu.Lock()
		old := ""
		for i := range c.cfg.Servers {
			if c.cfg.Servers[i].URL == e.URL {
				old = c.cfg.Servers[i].Provider
				c.cfg.Servers[i].Provider = p.ID
			}
		}
		_ = c.persist()
		c.mu.Unlock()
		if old != "" && old != p.ID {
			if sess, _ := tokenstore.Load(tokenstore.Key(e.URL, old)); sess != nil {
				if tokenstore.Save(tokenstore.Key(e.URL, p.ID), sess) == nil {
					_ = tokenstore.Clear(tokenstore.Key(e.URL, old))
				}
			}
		}
	}
	e.Provider = p.ID
	return e, doc, p, nil
}

// Login runs the interactive provider flow at a server and persists the
// session. providerID is the identity provider to use ("" = the one chosen,
// or the server's only one; ErrProviderRequired when it lists several and
// none was chosen). A device-flow prompt is exposed via Status while the
// person completes it. A new sign-in forgets the previous session's tenant.
func (c *Core) Login(ctx context.Context, server, providerID string) error {
	e, _, p, err := c.resolve(ctx, server, providerID)
	if err != nil {
		return err
	}
	provider, err := auth.New(authConfig(p))
	if err != nil {
		return err
	}
	onPrompt := func(d auth.DevicePrompt) {
		c.mu.Lock()
		s := c.st(e.URL)
		s.devURI, s.devCode = d.VerificationURI, d.UserCode
		c.mu.Unlock()
	}
	defer func() {
		c.mu.Lock()
		s := c.st(e.URL)
		s.devURI, s.devCode = "", ""
		c.mu.Unlock()
	}()
	c.logf("sign-in at %s via %s…", e.URL, p.Name)
	tok, err := provider.Login(ctx, onPrompt)
	if err != nil {
		c.logf("sign-in FAILED: %v", err)
		return err
	}
	c.logf("signed in at %s", e.URL)
	key := tokenstore.Key(e.URL, p.ID)
	sess, _ := tokenstore.Load(key)
	if sess == nil {
		sess = &tokenstore.Session{}
	}
	sess.Provider = p.ID
	sess.Bearer = tok.Value
	sess.BearerKind = string(tok.Kind)
	sess.RefreshToken = tok.Refresh
	sess.Expiry = tok.Expiry
	sess.Tenant = ""
	if sess.WGPrivateKey == "" {
		pair, kerr := wgkey.Generate()
		if kerr != nil {
			return kerr
		}
		sess.WGPrivateKey = pair.Private.String()
	}
	c.mu.Lock()
	s := c.st(e.URL)
	s.tenants, s.tenantRequired = nil, false
	c.mu.Unlock()
	return tokenstore.Save(key, sess)
}

// session loads the signed-in session at a server and the bearer to show it.
func (c *Core) session(ctx context.Context, server string) (ServerEntry, *tokenstore.Session, string, error) {
	e, _, p, err := c.resolve(ctx, server, "")
	if err != nil {
		return e, nil, "", err
	}
	key := tokenstore.Key(e.URL, p.ID)
	sess, err := tokenstore.Load(key)
	if err != nil {
		return e, nil, "", err
	}
	if sess == nil || sess.Bearer == "" {
		return e, nil, "", errors.New("not signed in")
	}
	if _, err := wgkey.ParsePrivate(sess.WGPrivateKey); err != nil {
		return e, nil, "", fmt.Errorf("device key invalid, sign in again: %w", err)
	}
	provider, err := auth.New(authConfig(p))
	if err != nil {
		return e, nil, "", err
	}
	host, _ := os.Hostname()
	bearer, changed, err := bearerFor(ctx, provider, sess, host)
	if err != nil {
		return e, nil, "", err
	}
	if changed {
		if err := tokenstore.Save(key, sess); err != nil {
			return e, nil, "", err
		}
	}
	return e, sess, bearer, nil
}

// Tenants asks a server, through the helper, which tenants the person may
// connect to, and keeps them for Status.
func (c *Core) Tenants(ctx context.Context, server string) ([]hproto.Tenant, error) {
	e, _, bearer, err := c.session(ctx, server)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	helper := c.helper
	c.mu.Unlock()
	resp, err := helper.Tenants(e.URL, e.Provider, bearer)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.st(e.URL).tenants = append([]hproto.Tenant(nil), resp.Tenants...)
	c.mu.Unlock()
	return resp.Tenants, nil
}

// SetTenant chooses the tenant for this session at a server. It must be one
// the server offered; the next Connect uses it.
func (c *Core) SetTenant(server, id string) error {
	e, err := c.entry(server)
	if err != nil {
		return err
	}
	c.mu.Lock()
	offered := append([]hproto.Tenant(nil), c.st(e.URL).tenants...)
	c.mu.Unlock()
	if id != "" {
		ok := false
		for _, t := range offered {
			ok = ok || t.ID == id
		}
		if !ok {
			return fmt.Errorf("%q is not a tenant you were offered", id)
		}
	}
	// The provider is the one resolved last (Status or Login), never fetched
	// here: SetTenant does not use the network.
	provider := e.Provider
	if doc, ok := c.discClient().Cached(e.URL); ok {
		provider = chosen(e, doc).ID
	}
	if provider == "" {
		return errors.New("not signed in")
	}
	key := tokenstore.Key(e.URL, provider)
	sess, err := tokenstore.Load(key)
	if err != nil {
		return err
	}
	if sess == nil {
		return errors.New("not signed in")
	}
	sess.Tenant = id
	if err := tokenstore.Save(key, sess); err != nil {
		return err
	}
	c.mu.Lock()
	c.st(e.URL).tenantRequired = false
	c.mu.Unlock()
	return nil
}

func (c *Core) discClient() *discovery.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disc
}

// connectedMembers are the servers the helper holds a tunnel to.
func connectedMembers(r *hproto.Response) []exclusive.Member {
	var out []exclusive.Member
	for _, t := range r.Tunnels {
		out = append(out, exclusive.Member{URL: t.ServerURL, Name: t.ServerName, Exclusive: t.Exclusive})
	}
	return out
}

// Connect asks the helper to enroll at a server into the session's tenant,
// bring a tunnel up and watch routes. Other servers stay connected, unless
// one of them or this one is exclusive: then the answer is an
// *exclusive.Error naming the server in the way. A person in several tenants
// who has chosen none gets ErrTenantRequired, with the tenants in Status.
func (c *Core) Connect(ctx context.Context, server string) error {
	e, sess, bearer, err := c.session(ctx, server)
	if err != nil {
		c.logf("connect: %v", err)
		return err
	}
	doc, _ := c.discClient().Cached(e.URL)
	c.mu.Lock()
	helper := c.helper
	c.mu.Unlock()
	if r, serr := helper.Status(); serr == nil && doc != nil {
		if xerr := exclusive.Check(exclusive.Member{URL: e.URL, Name: doc.ServerName, Exclusive: doc.Exclusive}, connectedMembers(r)); xerr != nil {
			c.logf("connect refused: %v", xerr)
			return xerr
		}
	}
	host, _ := os.Hostname()
	c.logf("connect: enrolling at %s (tenant %q) and bringing up the tunnel…", e.URL, sess.Tenant)
	hresp, err := helper.Connect(hproto.ConnectSpec{ServerURL: e.URL, Provider: e.Provider, Bearer: bearer, PrivateKey: sess.WGPrivateKey, DeviceName: host, Tenant: sess.Tenant})
	if err != nil {
		var xerr *exclusive.Error
		if errors.As(err, &xerr) {
			c.logf("connect refused: %v", xerr)
			return xerr
		}
		if strings.Contains(err.Error(), "tenant_required") {
			c.logf("connect: you belong to several tenants; choose one")
			if _, terr := c.Tenants(ctx, e.URL); terr != nil {
				c.logf("listing tenants FAILED: %v", terr)
			}
			c.mu.Lock()
			c.st(e.URL).tenantRequired = true
			c.mu.Unlock()
			return ErrTenantRequired
		}
		c.logf("connect FAILED: %v", err)
		return err
	}
	var tun hproto.Tunnel
	for _, t := range hresp.Tunnels {
		if t.ServerURL == e.URL {
			tun = t
		}
	}
	c.mu.Lock()
	s := c.st(e.URL)
	s.assigned = tun.AssignedIP
	s.tenantRequired = false
	if s.stopRenew != nil {
		s.stopRenew()
		s.stopRenew = nil
	}
	c.mu.Unlock()
	c.logf("connected to %s: interface=%s ip=%s tenant=%s", e.URL, tun.Interface, tun.AssignedIP, tun.Tenant)
	c.startRenewing(e.URL)
	return nil
}

// startRenewing starts a server's renewal loop unless one runs.
func (c *Core) startRenewing(server string) {
	rctx, stop := context.WithCancel(context.Background())
	c.mu.Lock()
	s := c.st(server)
	if s.stopRenew != nil {
		c.mu.Unlock()
		stop()
		return
	}
	s.stopRenew = stop
	c.mu.Unlock()
	go c.keepRenewing(rctx, server)
}

// keepRenewing brings the helper a fresh bearer before each renewal of a
// server's lease is due, for as long as its tunnel is up. The helper renews on
// its own too, with the bearer it last had: enough for a long-lived one
// (GitHub), not for a go-authn access token, which expires in minutes and
// which only the app, holding the refresh token, can replace.
func (c *Core) keepRenewing(ctx context.Context, server string) {
	defer func() {
		// A loop that ended on its own (not stopped: a newer one may hold
		// stopRenew) lets the next Status start another.
		c.mu.Lock()
		if ctx.Err() == nil {
			c.st(server).stopRenew = nil
		}
		c.mu.Unlock()
	}()
	for {
		c.mu.Lock()
		helper := c.helper
		c.mu.Unlock()
		r, err := helper.Status()
		if err != nil {
			c.logf("renewal: %v", err)
			return
		}
		var tun *hproto.Tunnel
		for i := range r.Tunnels {
			if r.Tunnels[i].ServerURL == server {
				tun = &r.Tunnels[i]
			}
		}
		if tun == nil {
			if msg := r.LastErrors[server]; msg != "" {
				c.logf("disconnected from %s: %s", server, msg)
			}
			c.mu.Lock()
			c.st(server).assigned = ""
			c.mu.Unlock()
			return
		}
		remaining := 2 * time.Hour
		if tun.LeaseExpiresAt != nil {
			remaining = time.Until(*tun.LeaseExpiresAt)
		}
		timer := time.NewTimer(c.renewAfter(remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		e, _, bearer, err := c.session(ctx, server)
		if err != nil {
			// The helper keeps the bearer it has, and retries with it.
			c.logf("renewal: no fresh sign-in: %v", err)
			continue
		}
		if rr, err := helper.Renew(e.URL, e.Provider, bearer); err != nil {
			c.logf("renewal FAILED: %v", err)
		} else {
			for _, t := range rr.Tunnels {
				if t.ServerURL == e.URL && t.LeaseExpiresAt != nil {
					c.logf("lease at %s renewed until %s", e.URL, t.LeaseExpiresAt.Local().Format("15:04:05"))
				}
			}
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// Disconnect tears a server's tunnel down; the helper gives the address back
// to the server (deregisters) rather than leave it held until the lease ends.
func (c *Core) Disconnect(_ context.Context, server string) error {
	e, err := c.entry(server)
	if err != nil {
		return err
	}
	c.logf("disconnecting from %s…", e.URL)
	c.mu.Lock()
	helper := c.helper
	s := c.st(e.URL)
	if s.stopRenew != nil {
		s.stopRenew()
		s.stopRenew = nil
	}
	c.mu.Unlock()
	_, derr := helper.Down(e.URL)
	c.mu.Lock()
	c.st(e.URL).assigned = ""
	c.mu.Unlock()
	return derr
}

// DisconnectAll tears every tunnel down.
func (c *Core) DisconnectAll(_ context.Context) error {
	c.logf("disconnecting from every server…")
	c.mu.Lock()
	helper := c.helper
	for _, s := range c.state {
		if s.stopRenew != nil {
			s.stopRenew()
			s.stopRenew = nil
		}
		s.assigned = ""
	}
	c.mu.Unlock()
	_, err := helper.DownAll()
	return err
}

// Logout disconnects from a server and clears the local session there.
func (c *Core) Logout(ctx context.Context, server string) error {
	e, err := c.entry(server)
	if err != nil {
		return err
	}
	_ = c.Disconnect(ctx, e.URL)
	c.mu.Lock()
	s := c.st(e.URL)
	s.tenants, s.tenantRequired = nil, false
	c.mu.Unlock()
	return tokenstore.ClearServer(e.URL)
}

// Logo is the server's logo (an SVG already validated: same origin, digest
// checked, sanitized, size capped), or nil: a server without one, or one whose
// logo failed a check. A failure is logged and never an error.
func (c *Core) Logo(ctx context.Context, server string) []byte {
	e, err := c.entry(server)
	if err != nil {
		return nil
	}
	disc := c.discClient()
	doc, err := disc.Get(ctx, e.URL)
	if err != nil || doc.Logo == nil {
		return nil
	}
	b, err := disc.Logo(ctx, e.URL, doc)
	if err != nil {
		c.logf("logo of %s: %v", e.URL, err)
		return nil
	}
	return b
}

// nameFromToken is the person's address or name from a JWT, unverified --
// for display only: "email" (an ID token) or "preferred_username" (a
// go-authn access token, which carries no address).
func nameFromToken(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email    string `json:"email"`
		Username string `json:"preferred_username"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	if claims.Email != "" {
		return claims.Email
	}
	return claims.Username
}

// bearerFor is the credential to enroll with. For most providers it is the
// session's own. A provider that keeps the devices' WireGuard keys itself
// (go-authn, auth.KeyRegistrar) has the device's PUBLIC key registered first,
// and the token for the server is the one that registration returns; the
// session's refresh token is then replaced, since the provider rotates them,
// and changed says the session must be saved.
func bearerFor(ctx context.Context, provider auth.Provider, sess *tokenstore.Session, device string) (bearer string, changed bool, err error) {
	reg, ok := provider.(auth.KeyRegistrar)
	if !ok {
		return sess.Bearer, false, nil
	}
	pair, err := wgkey.ParsePrivate(sess.WGPrivateKey)
	if err != nil {
		return "", false, fmt.Errorf("device key invalid, sign in again: %w", err)
	}
	tok, err := reg.RegisterKey(ctx, &auth.Token{Value: sess.Bearer, Kind: auth.Kind(sess.BearerKind), Expiry: sess.Expiry, Refresh: sess.RefreshToken}, pair.Public.String(), device)
	if err != nil {
		return "", false, err
	}
	sess.RefreshToken = tok.Refresh
	return tok.Value, true, nil
}
