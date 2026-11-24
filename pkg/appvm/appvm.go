// Package appvm is the Claimward apps' view model: what every window and tray
// shows, and what each button does, with no UI toolkit in it. The Linux and
// Windows apps bind a State to their widgets; the macOS app serves it to its
// web view as JSON.
//
// The business logic is not here: it is appcore.Core, reached through the
// Service interface so a test can stand in for the helper, the identity
// provider and the server.
//
// A Model is safe for concurrent use. Every change publishes a State
// snapshot to the subscribers, in order, on whichever goroutine made the
// change (a command, the poller, a finished action). A subscriber must not
// block and must not call a Model method: a UI hands the snapshot to its own
// thread and returns. Commands do nothing when State.Can says they cannot
// run, so a stale button press is harmless.
package appvm

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/appcore"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
)

// Service is what the view model needs from appcore.Core, which satisfies it.
type Service interface {
	Status() appcore.Status
	Config() appcore.Config
	UpdateConfig(appcore.Config) error
	Login(ctx context.Context) error
	Tenants(ctx context.Context) ([]hproto.Tenant, error)
	SetTenant(id string) error
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
	Logout(ctx context.Context) error
}

var _ Service = (*appcore.Core)(nil)

// Screen is what the window shows.
type Screen int

// The screens.
const (
	ScreenLoading      Screen = iota // before the first status arrives
	ScreenUnconfigured               // the app configuration is incomplete
	ScreenMain                       // status, actions, log
	ScreenSettings                   // the configuration form
)

// Slot is what shows under the status.
type Slot int

// The slots.
const (
	SlotNone         Slot = iota // nothing: signed out
	SlotSignIn                   // a sign-in is running: the device-flow prompt
	SlotTenants                  // the tenants offered, to choose from
	SlotChooseTenant             // signed in, no tenant list yet: offer to fetch it
)

// Actions is which buttons are on offer.
type Actions int

// The action sets.
const (
	ActionsSignedOut    Actions = iota // Sign in
	ActionsDisconnected                // Connect, Sign out
	ActionsConnected                   // Disconnect, Sign out
)

// Provider is an identity provider the settings form offers.
type Provider struct{ ID, Label string }

// Providers are offered in this order.
var Providers = []Provider{
	{"github", "GitHub (device flow)"},
	{"oidc", "OIDC (browser)"},
	{"go-authn", "go-authn (device flow)"},
}

// ProviderIndex is the position of provider id in Providers (0 if unknown).
func ProviderIndex(id string) int {
	for i, p := range Providers {
		if p.ID == id {
			return i
		}
	}
	return 0
}

// UsesIssuer reports whether provider id is configured with an OIDC issuer
// and client ID rather than a GitHub client ID.
func UsesIssuer(id string) bool { return id != "github" && id != "" }

// TenantOption is one row of the tenant choice. The first row always has an
// empty ID: no tenant chosen, which lets the server use the person's only one.
type TenantOption struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Form is the settings form.
type Form struct {
	ServerURL      string `json:"server_url"`
	Provider       string `json:"provider"`
	GitHubClientID string `json:"github_client_id"`
	OIDCIssuer     string `json:"oidc_issuer"`
	OIDCClientID   string `json:"oidc_client_id"`
}

// Can says which commands may run now.
type Can struct {
	SignIn         bool `json:"sign_in"`
	CancelSignIn   bool `json:"cancel_sign_in"`
	OpenSignInPage bool `json:"open_sign_in_page"`
	ChooseTenant   bool `json:"choose_tenant"`
	Connect        bool `json:"connect"`
	Disconnect     bool `json:"disconnect"`
	SignOut        bool `json:"sign_out"`
	OpenSettings   bool `json:"open_settings"`
	SaveSettings   bool `json:"save_settings"`
	CloseSettings  bool `json:"close_settings"`
}

// State is everything a view shows, as plain values.
type State struct {
	Screen   Screen  `json:"screen"`
	Headline string  `json:"headline"` // "Connected", "Signed out", ...
	Account  string  `json:"account"`  // "Signed in as ..."
	Address  string  `json:"address"`  // assigned address and interface
	Tenant   string  `json:"tenant"`   // the session's tenant
	Helper   string  `json:"helper"`   // whether the privileged helper answers
	Server   string  `json:"server"`   // the configured server
	Problem  string  `json:"problem"`  // why the configuration is incomplete
	Busy     string  `json:"busy"`     // what is in progress, or ""
	Error    string  `json:"error"`    // the last action's failure or notice, or ""
	Slot     Slot    `json:"slot"`
	Actions  Actions `json:"actions"`
	TrayText string  `json:"tray_text"` // the tray menu's status line

	Connected bool `json:"connected"`
	LoggedIn  bool `json:"logged_in"`

	// The device-flow prompt of a sign-in in progress.
	SigningIn  bool   `json:"signing_in"`
	SignInURL  string `json:"sign_in_url"`
	SignInCode string `json:"sign_in_code"`
	SignInHint string `json:"sign_in_hint"`

	TenantOptions []TenantOption `json:"tenant_options"`
	TenantIndex   int            `json:"tenant_index"`
	TenantLocked  bool           `json:"tenant_locked"` // no change while connected or busy

	// Log is the connection log, oldest first.
	Log []string `json:"log"`

	SettingsError string `json:"settings_error"`
	ConfigPath    string `json:"config_path"`

	Can Can `json:"can"`
}

// Options configures a Model.
type Options struct {
	// Open shows a URL in the person's browser (application.OpenURL).
	Open func(url string) error
	// Interval is how often the status is polled (default 2s), and
	// FastInterval how often while an action runs (default 500ms), so a
	// device-flow code appears without a two-second wait.
	Interval, FastInterval time.Duration
	// ConfigPath is what State.ConfigPath says.
	ConfigPath string
}

// Model is the view model.
type Model struct {
	svc  Service
	open func(string) error

	interval, fastInterval time.Duration
	fast                   atomic.Bool
	ctx                    context.Context
	stop                   context.CancelFunc
	wg                     sync.WaitGroup

	notifyMu sync.Mutex // orders publications
	subs     map[int]func(State)
	nextSub  int

	mu           sync.Mutex // guards everything below
	st           appcore.Status
	haveStatus   bool
	settingsOpen bool
	signingIn    bool
	busy         string
	err          string
	settingsErr  string
	configPath   string
	cancel       context.CancelFunc
}

// New builds a Model. Call Start to begin polling.
func New(svc Service, o Options) *Model {
	if o.Interval <= 0 {
		o.Interval = 2 * time.Second
	}
	if o.FastInterval <= 0 {
		o.FastInterval = 500 * time.Millisecond
	}
	if o.Open == nil {
		o.Open = func(string) error { return errors.New("no browser to open") }
	}
	ctx, stop := context.WithCancel(context.Background())
	return &Model{
		svc: svc, open: o.Open, configPath: o.ConfigPath,
		interval: o.Interval, fastInterval: o.FastInterval,
		ctx: ctx, stop: stop, subs: map[int]func(State){},
	}
}

// Subscribe calls fn with every new State, in order, and returns what ends
// the subscription. See the package comment for what fn may do.
func (m *Model) Subscribe(fn func(State)) (cancel func()) {
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	id := m.nextSub
	m.nextSub++
	m.subs[id] = fn
	return func() {
		m.notifyMu.Lock()
		defer m.notifyMu.Unlock()
		delete(m.subs, id)
	}
}

// State is the current state.
func (m *Model) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshot()
}

// publish hands the current State to the subscribers.
func (m *Model) publish() {
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	s := m.State()
	for _, fn := range m.subs {
		fn(s)
	}
}

// Start polls the status until Stop. The first poll is immediate.
func (m *Model) Start() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for {
			m.Refresh()
			wait := m.interval
			if m.fast.Load() {
				wait = m.fastInterval
			}
			select {
			case <-m.ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}()
}

// Stop ends the polling and cancels the action in progress.
func (m *Model) Stop() { m.stop() }

// Wait blocks until the poller and every action have finished and published
// their results.
func (m *Model) Wait() { m.wg.Wait() }

// Refresh reads the status on the calling goroutine and applies it.
func (m *Model) Refresh() { m.Apply(m.svc.Status()) }

// Apply shows a status.
func (m *Model) Apply(st appcore.Status) {
	m.mu.Lock()
	m.st, m.haveStatus = st, true
	m.mu.Unlock()
	m.publish()
}

// canLocked says which commands may run. The caller holds m.mu.
func (m *Model) canLocked() Can {
	st := m.st
	idle := m.busy == ""
	settings := m.settingsOpen
	return Can{
		SignIn:         idle && st.ConfigOK && !st.LoggedIn,
		CancelSignIn:   m.signingIn,
		OpenSignInPage: st.DeviceVerificationURI != "",
		ChooseTenant:   idle && st.LoggedIn && st.HelperInstalled,
		Connect:        idle && st.LoggedIn && st.HelperInstalled && !st.Connected,
		Disconnect:     idle && st.Connected,
		SignOut:        idle && st.LoggedIn,
		OpenSettings:   idle && !settings,
		SaveSettings:   idle && settings,
		CloseSettings:  idle && settings,
	}
}

// run starts a slow action if ok allows it: pre runs at once under the lock,
// work runs on a goroutine of its own with a context CancelSignIn (or Stop)
// ends, and done (under the lock, after the status that follows the action
// has been applied) handles its outcome.
func (m *Model) run(ok func(Can) bool, busy string, pre func(), work func(context.Context) error, done func(error)) {
	m.mu.Lock()
	if !ok(m.canLocked()) {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.cancel = cancel
	m.err = ""
	m.busy = busy
	m.fast.Store(true)
	if pre != nil {
		pre()
	}
	m.wg.Add(1)
	m.mu.Unlock()
	m.publish()
	go func() {
		defer m.wg.Done()
		err := work(ctx)
		st := m.svc.Status()
		m.mu.Lock()
		cancel()
		m.cancel = nil
		m.fast.Store(false)
		m.busy = ""
		m.st, m.haveStatus = st, true
		done(err)
		m.mu.Unlock()
		m.publish()
	}()
}

// SignIn starts the sign-in, whose device-flow prompt appears in State.
func (m *Model) SignIn() {
	m.run(func(c Can) bool { return c.SignIn }, "Signing in…",
		func() { m.signingIn = true },
		m.svc.Login,
		func(err error) {
			m.signingIn = false
			switch {
			case errors.Is(err, context.Canceled):
				m.err = "Sign-in cancelled."
			case err != nil:
				m.err = "Sign-in failed: " + err.Error()
			}
		})
}

// CancelSignIn gives up a sign-in that waits for the person.
func (m *Model) CancelSignIn() {
	m.mu.Lock()
	cancel := m.cancel
	ok := m.signingIn && cancel != nil
	m.mu.Unlock()
	if ok {
		cancel()
	}
}

// OpenSignInPage opens the device-flow page in the browser. Only an http or
// https URL is opened: it came from the identity provider through the
// network, and a URL handed to the system can as well name a program.
func (m *Model) OpenSignInPage() {
	m.mu.Lock()
	raw := m.st.DeviceVerificationURI
	if raw == "" {
		m.mu.Unlock()
		return
	}
	m.err = ""
	if u, err := url.Parse(raw); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		m.err = fmt.Sprintf("Not opening %q: the sign-in page must be an http(s) URL. Open it yourself if you trust it.", raw)
	} else if err := m.open(u.String()); err != nil {
		m.err = "Could not open the browser: " + err.Error() + ". Open " + u.String() + " yourself."
	}
	m.mu.Unlock()
	m.publish()
}

// ChooseTenant asks the server which tenants the person may join; they then
// appear in State.TenantOptions.
func (m *Model) ChooseTenant() {
	var n int
	m.run(func(c Can) bool { return c.ChooseTenant }, "Asking the server for your tenants…", nil,
		func(ctx context.Context) error {
			ts, err := m.svc.Tenants(ctx)
			n = len(ts)
			return err
		},
		func(err error) {
			switch {
			case err != nil:
				m.err = "Listing tenants failed: " + err.Error()
			case n == 0:
				m.err = "The server lists no tenant for you."
			case n == 1:
				m.err = "You belong to one tenant: there is nothing to choose."
			}
		})
}

// Connect brings the tunnel up.
func (m *Model) Connect() {
	m.run(func(c Can) bool { return c.Connect }, "Connecting…", nil, m.svc.Connect,
		func(err error) {
			switch {
			case errors.Is(err, appcore.ErrTenantRequired):
				m.err = "You belong to several tenants: choose one, then connect again."
			case err != nil:
				m.err = "Connection failed: " + err.Error()
			}
		})
}

// Disconnect takes the tunnel down.
func (m *Model) Disconnect() {
	m.run(func(c Can) bool { return c.Disconnect }, "Disconnecting…", nil, m.svc.Disconnect,
		func(err error) {
			if err != nil {
				m.err = "Disconnecting failed: " + err.Error()
			}
		})
}

// SignOut forgets the session.
func (m *Model) SignOut() {
	m.run(func(c Can) bool { return c.SignOut }, "Signing out…", nil, m.svc.Logout,
		func(err error) {
			if err != nil {
				m.err = "Signing out failed: " + err.Error()
			}
		})
}

// SelectTenant chooses the row i of State.TenantOptions for the session. It
// writes to the session at once, a small local file, so that no status poll
// can come back in between with the previous choice. A choice refused (the
// tunnel is up, or an action runs) or failed leaves State as it was, with
// the failure in State.Error.
func (m *Model) SelectTenant(i int) {
	m.mu.Lock()
	opts := m.optionsLocked()
	if m.st.Connected || m.busy != "" || i < 0 || i >= len(opts) || opts[i].ID == m.st.Tenant {
		m.mu.Unlock()
		m.publish() // a view that moved its selection is put back
		return
	}
	id := opts[i].ID
	m.mu.Unlock()
	err := m.svc.SetTenant(id)
	m.mu.Lock()
	if err != nil {
		m.err = "Choosing the tenant failed: " + err.Error()
	} else {
		m.err = ""
		m.st.Tenant = id
	}
	m.mu.Unlock()
	m.publish()
}

// OpenSettings shows the settings form and returns what to fill it with.
func (m *Model) OpenSettings() (Form, bool) {
	c := m.svc.Config()
	m.mu.Lock()
	if !m.canLocked().OpenSettings {
		m.mu.Unlock()
		return Form{}, false
	}
	m.settingsOpen = true
	m.settingsErr = ""
	m.mu.Unlock()
	m.publish()
	return Form{
		ServerURL: c.ServerURL, Provider: Providers[ProviderIndex(c.Provider)].ID,
		GitHubClientID: c.GitHubClientID, OIDCIssuer: c.OIDCIssuer, OIDCClientID: c.OIDCClientID,
	}, true
}

// SaveSettings saves the form. An incomplete configuration is saved all the
// same, since the person may be filling it in over two sittings, and
// State.Error says what it lacks; a server URL that is no http(s) URL is
// refused.
func (m *Model) SaveSettings(f Form) {
	c := m.svc.Config()
	c.ServerURL = strings.TrimSpace(f.ServerURL)
	c.Provider = Providers[ProviderIndex(f.Provider)].ID
	c.GitHubClientID = strings.TrimSpace(f.GitHubClientID)
	c.OIDCIssuer = strings.TrimSpace(f.OIDCIssuer)
	c.OIDCClientID = strings.TrimSpace(f.OIDCClientID)
	if c.ServerURL != "" {
		if u, err := url.Parse(c.ServerURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			m.mu.Lock()
			ok := m.canLocked().SaveSettings
			if ok {
				m.settingsErr = "The server URL must be an http(s) URL, such as https://vpn.example.org."
			}
			m.mu.Unlock()
			m.publish()
			return
		}
	}
	m.run(func(c Can) bool { return c.SaveSettings }, "Saving the configuration…",
		func() { m.settingsErr = "" },
		func(context.Context) error { return m.svc.UpdateConfig(c) },
		func(err error) {
			if err != nil {
				m.settingsErr = "Saving failed: " + err.Error()
				return
			}
			m.settingsOpen = false
			if err := c.Validate(); err != nil {
				m.err = "Saved, but not complete: " + err.Error()
			}
		})
}

// CloseSettings leaves the settings form without saving.
func (m *Model) CloseSettings() {
	m.mu.Lock()
	ok := m.canLocked().CloseSettings
	if ok {
		m.settingsOpen = false
		m.settingsErr = ""
	}
	m.mu.Unlock()
	if ok {
		m.publish()
	}
}

func (m *Model) optionsLocked() []TenantOption {
	first := "No tenant chosen"
	if m.st.TenantRequired {
		first = "Choose a tenant…"
	}
	opts := []TenantOption{{Label: first}}
	for _, t := range m.st.Tenants {
		opts = append(opts, TenantOption{ID: t.ID, Label: tenantName(t)})
	}
	return opts
}

// snapshot builds the State. The caller holds m.mu.
func (m *Model) snapshot() State {
	st := m.st
	s := State{
		Server: st.ServerURL, Problem: st.ConfigError, Busy: m.busy, Error: m.err,
		Connected: st.Connected, LoggedIn: st.LoggedIn,
		SigningIn: m.signingIn, SignInURL: st.DeviceVerificationURI, SignInCode: st.DeviceUserCode,
		SettingsError: m.settingsErr, ConfigPath: m.configPath,
		TenantLocked: st.Connected || m.busy != "",
		Can:          m.canLocked(),
		Log:          append([]string(nil), st.Log...),
	}
	switch {
	case m.settingsOpen:
		s.Screen = ScreenSettings
	case !m.haveStatus:
		s.Screen = ScreenLoading
	case !st.ConfigOK:
		s.Screen = ScreenUnconfigured
	default:
		s.Screen = ScreenMain
	}

	switch {
	case !m.haveStatus:
		s.Headline, s.TrayText = "Starting…", "Claimward: starting…"
	case !st.ConfigOK:
		s.Headline, s.TrayText = "Not configured", "Claimward: not configured"
	case st.Connected:
		s.Headline, s.TrayText = "Connected", "Claimward: connected"
		if st.AssignedIP != "" {
			s.TrayText += " (" + st.AssignedIP + ")"
		}
	case st.LoggedIn:
		s.Headline = "Disconnected"
		s.TrayText = "Claimward: disconnected"
		if !st.HelperInstalled {
			s.TrayText = "Claimward: helper not running"
		}
	default:
		s.Headline, s.TrayText = "Signed out", "Claimward: signed out"
	}
	switch {
	case !st.LoggedIn:
		s.Account = "Not signed in"
	case st.Email != "":
		s.Account = "Signed in as " + st.Email
	default:
		s.Account = "Signed in"
	}
	if st.Connected {
		addr := st.AssignedIP
		if addr == "" {
			addr = "address unknown"
		}
		iface := st.Interface
		if iface == "" {
			iface = "—"
		}
		s.Address = addr + " on " + iface
	} else {
		s.Address = "Not connected"
	}
	if st.HelperInstalled {
		s.Helper = "Privileged helper: running"
	} else {
		s.Helper = "Privileged helper: not running (see the README)"
	}

	switch {
	case !st.LoggedIn:
		s.Actions = ActionsSignedOut
	case st.Connected:
		s.Actions = ActionsConnected
	default:
		s.Actions = ActionsDisconnected
	}

	switch {
	case st.DeviceUserCode != "":
		s.SignInHint = "Open the sign-in page, then enter this code:"
	case st.DeviceVerificationURI != "":
		s.SignInHint = "Complete the sign-in in your browser."
	case m.signingIn:
		s.SignInHint = "Waiting for the identity provider…"
	}
	switch {
	case m.signingIn || st.DeviceVerificationURI != "":
		s.Slot = SlotSignIn
	case !st.LoggedIn:
		s.Slot = SlotNone
	case len(st.Tenants) > 0 || st.TenantRequired:
		s.Slot = SlotTenants
	default:
		s.Slot = SlotChooseTenant
	}

	s.TenantOptions = m.optionsLocked()
	for i, o := range s.TenantOptions {
		if o.ID == st.Tenant {
			s.TenantIndex = i
			break
		}
	}
	switch {
	case !st.LoggedIn:
	case st.Tenant == "" && st.TenantRequired:
		s.Tenant = "Tenant: none chosen"
	case st.Tenant == "":
		s.Tenant = "Tenant: the server's choice"
	default:
		s.Tenant = "Tenant: " + tenantLabel(st.Tenant, st.Tenants)
	}
	return s
}

func tenantLabel(id string, offered []hproto.Tenant) string {
	for _, t := range offered {
		if t.ID == id {
			return tenantName(t)
		}
	}
	return id
}

func tenantName(t hproto.Tenant) string {
	if t.Name == "" || t.Name == t.ID {
		return t.ID
	}
	return t.Name + " (" + t.ID + ")"
}

// LogDelta compares the log a view shows with the log of a new State. When
// next continues shown (the log is a ring that drops its oldest lines, which
// is not a continuation) it returns the lines to append and true; otherwise
// the lines to show instead of shown, and false.
func LogDelta(shown, next []string) (lines []string, appended bool) {
	if len(next) < len(shown) {
		return next, false
	}
	for i := range shown {
		if shown[i] != next[i] {
			return next, false
		}
	}
	return next[len(shown):], true
}
