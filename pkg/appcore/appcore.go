// Package appcore is a Claimward app's business logic, shared by the macOS,
// Linux and Windows apps and independent of how each draws its window and
// tray: sign-in, the tenant chosen for the session, and driving the
// privileged helper (pkg/helper) to bring the tunnel up and down.
//
// The server is reached only through the helper. On macOS "Local Network"
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
	"github.com/claimward/claimward-vpn-client/pkg/helperclient"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/tokenstore"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
)

// ErrTenantRequired is a connection the server refused because the person
// belongs to several tenants and none was chosen: Status().Tenants lists
// them, and SetTenant chooses.
var ErrTenantRequired = errors.New("choose a tenant: you belong to several")

// Core is the app's stateful service.
type Core struct {
	mu     sync.Mutex
	cfg    *Config
	helper *helperclient.Client

	connected bool
	iface     string
	assigned  string
	// tenants are those last offered by the server, for the choice.
	tenants        []hproto.Tenant
	tenantRequired bool
	// pending device-code prompt, surfaced via Status.
	devURI  string
	devCode string
	// log is a capped ring of timestamped connection-process lines.
	log []string

	// stopRenew ends the loop that brings the helper fresh bearers.
	stopRenew context.CancelFunc
	// renewAfter is how long after a renewal the app brings the next
	// bearer, from what the lease has left (renewDelay).
	renewAfter func(remaining time.Duration) time.Duration
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
	return &Core{cfg: cfg, helper: helperclient.New(cfg.SocketPath), renewAfter: renewDelay}
}

// deps is a consistent snapshot of the config and helper client.
func (c *Core) deps() (Config, *helperclient.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return *c.cfg, c.helper
}

// Config returns the current configuration.
func (c *Core) Config() Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return *c.cfg
}

// UpdateConfig persists a new configuration and applies it live.
func (c *Core) UpdateConfig(in Config) error {
	if in.Provider == "" {
		in.Provider = "github"
	}
	if err := SaveConfig(&in); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = &in
	c.helper = helperclient.New(in.SocketPath)
	c.tenants, c.tenantRequired = nil, false
	return nil
}

// Status is a snapshot for the UI and tray.
type Status struct {
	ConfigOK        bool   `json:"config_ok"`
	ConfigError     string `json:"config_error,omitempty"`
	Provider        string `json:"provider,omitempty"`
	LoggedIn        bool   `json:"logged_in"`
	Email           string `json:"email,omitempty"`
	HelperInstalled bool   `json:"helper_installed"`
	Connected       bool   `json:"connected"`
	Interface       string `json:"interface,omitempty"`
	AssignedIP      string `json:"assigned_ip,omitempty"`
	ServerURL       string `json:"server_url,omitempty"`
	// Tenant is the one chosen for this session ("" = the server's choice
	// for a person in one), and Tenants those last offered.
	Tenant  string          `json:"tenant,omitempty"`
	Tenants []hproto.Tenant `json:"tenants,omitempty"`
	// TenantRequired: the last connection was refused until one is chosen.
	TenantRequired bool `json:"tenant_required,omitempty"`
	// Device-code prompt, set while a device-flow sign-in is in progress.
	DeviceVerificationURI string `json:"device_verification_uri,omitempty"`
	DeviceUserCode        string `json:"device_user_code,omitempty"`
	// Log is the connection-process log (most recent lines).
	Log []string `json:"log,omitempty"`
}

// Status returns the current state.
func (c *Core) Status() Status {
	cfg, helper := c.deps()
	st := Status{ServerURL: cfg.ServerURL, Provider: cfg.Provider}
	if err := cfg.Validate(); err != nil {
		st.ConfigError = err.Error()
	} else {
		st.ConfigOK = true
	}
	if sess, _ := tokenstore.Load(); sess != nil && sess.Bearer != "" {
		st.LoggedIn = true
		st.Email = nameFromToken(sess.Bearer)
		st.Tenant = sess.Tenant
	}
	st.HelperInstalled = helper.Available()
	if st.HelperInstalled {
		if hresp, err := helper.Status(); err == nil {
			st.Connected = hresp.Connected
			st.Interface = hresp.Interface
			if hresp.Connected {
				// The helper knows the address it was given; this Core knows
				// it only if it made the connection itself, which an app
				// restarted under a running tunnel did not.
				st.AssignedIP = hresp.AssignedIP
			}
			if hresp.Connected && hresp.Tenant != "" {
				st.Tenant = hresp.Tenant
			}
		}
	}
	c.mu.Lock()
	if st.Connected && st.AssignedIP == "" {
		st.AssignedIP = c.assigned
	}
	if st.Connected && st.LoggedIn && c.stopRenew == nil {
		// A tunnel this Core did not bring up -- the app restarted under it
		// -- still needs fresh bearers.
		rctx, stop := context.WithCancel(context.Background())
		c.stopRenew = stop
		go c.keepRenewing(rctx)
	}
	st.Tenants = append([]hproto.Tenant(nil), c.tenants...)
	st.TenantRequired = c.tenantRequired
	st.DeviceVerificationURI = c.devURI
	st.DeviceUserCode = c.devCode
	if n := len(c.log); n > 0 {
		st.Log = append([]string(nil), c.log...)
	}
	c.mu.Unlock()
	return st
}

func authConfig(cfg Config) auth.Config {
	return auth.Config{
		Provider:       cfg.Provider,
		GitHubClientID: cfg.GitHubClientID,
		OIDCIssuer:     cfg.OIDCIssuer,
		OIDCClientID:   cfg.OIDCClientID,
	}
}

// Login runs the interactive provider flow and persists the session. A
// device-flow prompt is exposed via Status while the person completes it.
// A new sign-in forgets the previous session's tenant.
func (c *Core) Login(ctx context.Context) error {
	cfg, _ := c.deps()
	if err := cfg.Validate(); err != nil {
		return err
	}
	provider, err := auth.New(authConfig(cfg))
	if err != nil {
		return err
	}
	onPrompt := func(p auth.DevicePrompt) {
		c.mu.Lock()
		c.devURI, c.devCode = p.VerificationURI, p.UserCode
		c.mu.Unlock()
	}
	defer func() {
		c.mu.Lock()
		c.devURI, c.devCode = "", ""
		c.mu.Unlock()
	}()
	c.logf("sign-in via %s…", provider.Name())
	tok, err := provider.Login(ctx, onPrompt)
	if err != nil {
		c.logf("sign-in FAILED: %v", err)
		return err
	}
	c.logf("signed in")
	sess, _ := tokenstore.Load()
	if sess == nil {
		sess = &tokenstore.Session{}
	}
	sess.Provider = provider.Name()
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
	c.tenants, c.tenantRequired = nil, false
	c.mu.Unlock()
	return tokenstore.Save(sess)
}

// session loads the signed-in session and the bearer to show the server.
func (c *Core) session(ctx context.Context, cfg Config) (*tokenstore.Session, string, error) {
	sess, err := tokenstore.Load()
	if err != nil {
		return nil, "", err
	}
	if sess == nil || sess.Bearer == "" {
		return nil, "", errors.New("not signed in")
	}
	if _, err := wgkey.ParsePrivate(sess.WGPrivateKey); err != nil {
		return nil, "", fmt.Errorf("device key invalid, sign in again: %w", err)
	}
	provider, err := auth.New(authConfig(cfg))
	if err != nil {
		return nil, "", err
	}
	host, _ := os.Hostname()
	bearer, changed, err := bearerFor(ctx, provider, sess, host)
	if err != nil {
		return nil, "", err
	}
	if changed {
		if err := tokenstore.Save(sess); err != nil {
			return nil, "", err
		}
	}
	return sess, bearer, nil
}

// Tenants asks the server, through the helper, which tenants the person may
// connect to, and keeps them for Status.
func (c *Core) Tenants(ctx context.Context) ([]hproto.Tenant, error) {
	cfg, helper := c.deps()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	_, bearer, err := c.session(ctx, cfg)
	if err != nil {
		return nil, err
	}
	resp, err := helper.Tenants(cfg.ServerURL, bearer)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.tenants = append([]hproto.Tenant(nil), resp.Tenants...)
	c.mu.Unlock()
	return resp.Tenants, nil
}

// SetTenant chooses the tenant for this session. It must be one the server
// offered; the next Connect uses it.
func (c *Core) SetTenant(id string) error {
	c.mu.Lock()
	offered := append([]hproto.Tenant(nil), c.tenants...)
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
	sess, err := tokenstore.Load()
	if err != nil {
		return err
	}
	if sess == nil {
		return errors.New("not signed in")
	}
	sess.Tenant = id
	if err := tokenstore.Save(sess); err != nil {
		return err
	}
	c.mu.Lock()
	c.tenantRequired = false
	c.mu.Unlock()
	return nil
}

// Connect asks the helper to enroll into the session's tenant, bring the
// tunnel up and watch routes. A person in several tenants who has chosen
// none gets ErrTenantRequired, with the tenants in Status.
func (c *Core) Connect(ctx context.Context) error {
	cfg, helper := c.deps()
	if err := cfg.Validate(); err != nil {
		return err
	}
	sess, bearer, err := c.session(ctx, cfg)
	if err != nil {
		c.logf("connect: %v", err)
		return err
	}
	host, _ := os.Hostname()
	c.logf("connect: enrolling at %s (tenant %q) and bringing up the tunnel…", cfg.ServerURL, sess.Tenant)
	hresp, err := helper.Connect(hproto.ConnectSpec{ServerURL: cfg.ServerURL, Bearer: bearer, PrivateKey: sess.WGPrivateKey, DeviceName: host, Tenant: sess.Tenant})
	if err != nil {
		if strings.Contains(err.Error(), "tenant_required") {
			c.logf("connect: you belong to several tenants; choose one")
			if _, terr := c.Tenants(ctx); terr != nil {
				c.logf("listing tenants FAILED: %v", terr)
			}
			c.mu.Lock()
			c.tenantRequired = true
			c.mu.Unlock()
			return ErrTenantRequired
		}
		c.logf("connect FAILED: %v", err)
		return err
	}
	rctx, stop := context.WithCancel(context.Background())
	c.mu.Lock()
	c.connected, c.iface, c.assigned = true, hresp.Interface, hresp.AssignedIP
	c.tenantRequired = false
	if c.stopRenew != nil {
		c.stopRenew()
	}
	c.stopRenew = stop
	c.mu.Unlock()
	c.logf("connected: interface=%s ip=%s tenant=%s", hresp.Interface, hresp.AssignedIP, hresp.Tenant)
	go c.keepRenewing(rctx)
	return nil
}

// keepRenewing brings the helper a fresh bearer before each renewal of the
// lease is due, for as long as the tunnel is up. The helper renews on its own
// too, with the bearer it last had: enough for a long-lived one (GitHub),
// not for a go-authn access token, which expires in minutes and which only
// the app, holding the refresh token, can replace.
func (c *Core) keepRenewing(ctx context.Context) {
	defer func() {
		// A loop that ended on its own (not stopped: a newer one may hold
		// stopRenew) lets the next Status start another.
		c.mu.Lock()
		if ctx.Err() == nil {
			c.stopRenew = nil
		}
		c.mu.Unlock()
	}()
	for {
		_, helper := c.deps()
		st, err := helper.Status()
		if err != nil {
			c.logf("renewal: %v", err)
			return
		}
		if !st.Connected {
			if st.LastError != "" {
				c.logf("disconnected: %s", st.LastError)
			}
			c.mu.Lock()
			c.connected, c.iface, c.assigned = false, "", ""
			c.mu.Unlock()
			return
		}
		remaining := 2 * time.Hour
		if st.LeaseExpiresAt != nil {
			remaining = time.Until(*st.LeaseExpiresAt)
		}
		timer := time.NewTimer(c.renewAfter(remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		cfg, helper := c.deps()
		_, bearer, err := c.session(ctx, cfg)
		if err != nil {
			// The helper keeps the bearer it has, and retries with it.
			c.logf("renewal: no fresh sign-in: %v", err)
			continue
		}
		if r, err := helper.Renew(bearer); err != nil {
			c.logf("renewal FAILED: %v", err)
		} else if r.LeaseExpiresAt != nil {
			c.logf("lease renewed until %s", r.LeaseExpiresAt.Local().Format("15:04:05"))
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// Disconnect tears the tunnel down; the helper gives the address back to the
// server (deregisters) rather than leave it held until the lease ends.
func (c *Core) Disconnect(_ context.Context) error {
	c.logf("disconnecting…")
	_, helper := c.deps()
	c.mu.Lock()
	if c.stopRenew != nil {
		c.stopRenew()
		c.stopRenew = nil
	}
	c.mu.Unlock()
	_, derr := helper.Down()
	c.mu.Lock()
	c.connected, c.iface, c.assigned = false, "", ""
	c.mu.Unlock()
	return derr
}

// Logout disconnects and clears the local session.
func (c *Core) Logout(ctx context.Context) error {
	_ = c.Disconnect(ctx)
	c.mu.Lock()
	c.tenants, c.tenantRequired = nil, false
	c.mu.Unlock()
	return tokenstore.Clear()
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
