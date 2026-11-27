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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/appcore"
	"github.com/claimward/claimward-vpn-client/pkg/exclusive"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
)

// Service is what the view model needs from appcore.Core, which satisfies it.
// Every command but Status names the server it is about, by URL.
type Service interface {
	Status() appcore.Status
	AddServer(ctx context.Context, rawURL string) (appcore.ServerEntry, error)
	RemoveServer(ctx context.Context, server string) error
	SetProvider(ctx context.Context, server, id string) error
	Login(ctx context.Context, server, providerID string) error
	Tenants(ctx context.Context, server string) ([]hproto.Tenant, error)
	SetTenant(server, id string) error
	Connect(ctx context.Context, server string) error
	Disconnect(ctx context.Context, server string) error
	Logout(ctx context.Context, server string) error
	Logo(ctx context.Context, server string) []byte
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

// ProviderOption is one row of the identity-provider choice, as the server's
// discovery document lists them.
type ProviderOption struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// ServerRow is one server in the list.
type ServerRow struct {
	URL       string `json:"url"`
	Name      string `json:"name"` // the server's own name, or its URL
	Exclusive bool   `json:"exclusive"`
	LoggedIn  bool   `json:"logged_in"`
	Connected bool   `json:"connected"`
	Selected  bool   `json:"selected"`
	// Tunnel is the row's live tunnel, nil while it is not connected.
	Tunnel *TunnelInfo `json:"tunnel"`
}

// TunnelInfo is one live tunnel's facts, for a WireGuard-style detail panel:
// the Interface section (Interface, Address, DNS, MTU) and the Peer section
// (Endpoint, AllowedIPs, LastHandshake, RxBytes, TxBytes). Every field is
// read-only and may be empty: a view hides what is.
type TunnelInfo struct {
	Interface  string   `json:"interface"`
	Address    string   `json:"address"` // the assigned address alone, in CIDR form
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
	DNS        []string `json:"dns"`
	MTU        int      `json:"mtu"`
	RxBytes    uint64   `json:"rx_bytes"`
	TxBytes    uint64   `json:"tx_bytes"`
	// LastHandshake is nil until the peer has completed one.
	LastHandshake *time.Time `json:"last_handshake"`
}

// tunnelInfo is the server's tunnel, nil when it has none.
func tunnelInfo(s appcore.ServerStatus) *TunnelInfo {
	if !s.Connected {
		return nil
	}
	return &TunnelInfo{
		Interface: s.Interface, Address: s.AssignedIP, Endpoint: s.Endpoint,
		AllowedIPs: append([]string{}, s.AllowedIPs...), DNS: append([]string{}, s.DNS...), MTU: s.MTU,
		RxBytes: s.RxBytes, TxBytes: s.TxBytes, LastHandshake: s.LastHandshake,
	}
}

// TenantOption is one row of the tenant choice. The first row always has an
// empty ID: no tenant chosen, which lets the server use the person's only one.
type TenantOption struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Form is the settings form: the person types a server's URL and nothing
// else; the server's own document says the rest.
type Form struct {
	ServerURL string `json:"server_url"`
}

// Can says which commands may run now.
type Can struct {
	SignIn         bool `json:"sign_in"`
	ChooseProvider bool `json:"choose_provider"`
	RemoveServer   bool `json:"remove_server"`
	SelectServer   bool `json:"select_server"`
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
	Screen   Screen `json:"screen"`
	Headline string `json:"headline"` // "Connected", "Signed out", ...
	Account  string `json:"account"`  // "Signed in as ..."
	Address  string `json:"address"`  // assigned address and interface
	// Tunnel is the selected server's live tunnel, nil while it is not
	// connected: the same value as its ServerRow's.
	Tunnel   *TunnelInfo `json:"tunnel"`
	Tenant   string      `json:"tenant"`  // the session's tenant
	Helper   string      `json:"helper"`  // whether the privileged helper answers
	Server   string      `json:"server"`  // the selected server's URL
	Problem  string      `json:"problem"` // why the configuration is incomplete
	Busy     string      `json:"busy"`    // what is in progress, or ""
	Error    string      `json:"error"`   // the last action's failure or notice, or ""
	Slot     Slot        `json:"slot"`
	Actions  Actions     `json:"actions"`
	TrayText string      `json:"tray_text"` // the tray menu's status line

	Connected bool `json:"connected"`
	LoggedIn  bool `json:"logged_in"`

	// The device-flow prompt of a sign-in in progress.
	SigningIn  bool   `json:"signing_in"`
	SignInURL  string `json:"sign_in_url"`
	SignInCode string `json:"sign_in_code"`
	SignInHint string `json:"sign_in_hint"`

	// ServerName is the selected server's own name (its URL until its
	// document has been read), and Servers every server added, in order.
	ServerName  string      `json:"server_name"`
	Servers     []ServerRow `json:"servers"`
	ServerIndex int         `json:"server_index"`
	// Exclusive: the selected server refuses to share the machine with any
	// other. HasLogo: Logo returns its picture.
	Exclusive bool `json:"exclusive"`
	HasLogo   bool `json:"has_logo"`
	// ProviderOptions are the identity providers the selected server lists;
	// NeedsProvider says several are listed and none is chosen yet.
	ProviderOptions []ProviderOption `json:"provider_options"`
	ProviderIndex   int              `json:"provider_index"`
	NeedsProvider   bool             `json:"needs_provider"`

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
	evsubs   map[int]func(Event)
	nextSub  int

	mu           sync.Mutex // guards everything below
	st           appcore.Status
	sel          string // the selected server's URL; "" = the first
	haveStatus   bool
	settingsOpen bool
	signingIn    bool
	busy         string
	err          string
	settingsErr  string
	configPath   string
	cancel       context.CancelFunc
	userDown     bool    // the person's own Disconnect or SignOut runs
	pending      []Event // events noted, not yet published
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
		ctx: ctx, stop: stop, subs: map[int]func(State){}, evsubs: map[int]func(Event){},
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

// EventKind says what happened.
type EventKind int

// The events.
const (
	// EventDropped: the tunnel went down without the person asking.
	EventDropped EventKind = iota + 1
	// EventSessionExpired: the session ended without the person signing out.
	EventSessionExpired
)

// Event is something worth telling the person who is not looking at the
// window: an app turns it into a tray notification, and a click on that
// notification into bringing the window forward. Events are published on
// transitions only, never once per poll.
type Event struct {
	Kind        EventKind `json:"kind"`
	Title, Body string
}

// SubscribeEvents calls fn with every Event, in order, under the same
// contract as Subscribe, and returns what ends the subscription.
func (m *Model) SubscribeEvents(fn func(Event)) (cancel func()) {
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	id := m.nextSub
	m.nextSub++
	m.evsubs[id] = fn
	return func() {
		m.notifyMu.Lock()
		defer m.notifyMu.Unlock()
		delete(m.evsubs, id)
	}
}

// setStatusLocked records a status and notes the event its change makes. The
// caller holds m.mu. A tunnel or session that ends while the person's own
// Disconnect or SignOut runs is not an event.
func (m *Model) setStatusLocked(st appcore.Status) {
	prev, had := m.st, m.haveStatus
	m.st, m.haveStatus = st, true
	if !had || m.userDown {
		return
	}
	for _, p := range prev.Servers {
		for _, s := range st.Servers {
			if s.URL != p.URL {
				continue
			}
			who := rowName(s)
			switch {
			case p.LoggedIn && !s.LoggedIn:
				m.pending = append(m.pending, Event{Kind: EventSessionExpired,
					Title: "Claimward: signed out of " + who, Body: "Your session expired. Sign in again to connect."})
			case p.Connected && !s.Connected:
				m.pending = append(m.pending, Event{Kind: EventDropped,
					Title: "Claimward: disconnected from " + who, Body: "The VPN connection dropped. Open Claimward to connect again."})
			}
		}
	}
}

// rowName is what a server is called: its own name, else its URL.
func rowName(s appcore.ServerStatus) string {
	if s.Name != "" {
		return s.Name
	}
	return s.URL
}

// curLocked is the selected server, or the first if none is selected or the
// selected one is gone; ok is false when no server was added. The caller
// holds m.mu.
func (m *Model) curLocked() (appcore.ServerStatus, bool) {
	for _, s := range m.st.Servers {
		if s.URL == m.sel {
			return s, true
		}
	}
	if len(m.st.Servers) > 0 {
		return m.st.Servers[0], true
	}
	return appcore.ServerStatus{}, false
}

// needsProvider: the server lists several identity providers and none is
// chosen, so signing in needs the person's choice.
func needsProvider(s appcore.ServerStatus) bool {
	return len(s.Providers) > 1 && s.Provider == ""
}

// publish hands the current State, then the events it brought, to the
// subscribers.
func (m *Model) publish() {
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	m.mu.Lock()
	s := m.snapshot()
	events := m.pending
	m.pending = nil
	m.mu.Unlock()
	for _, fn := range m.subs {
		fn(s)
	}
	for _, e := range events {
		for _, fn := range m.evsubs {
			fn(e)
		}
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
	m.setStatusLocked(st)
	m.mu.Unlock()
	m.publish()
}

// canLocked says which commands may run. The caller holds m.mu.
func (m *Model) canLocked() Can {
	st := m.st
	cur, have := m.curLocked()
	idle := m.busy == ""
	settings := m.settingsOpen
	return Can{
		SignIn:         idle && have && st.ConfigOK && !cur.LoggedIn && !needsProvider(cur),
		ChooseProvider: idle && have && !cur.LoggedIn && len(cur.Providers) > 1,
		RemoveServer:   idle && have,
		SelectServer:   idle && len(st.Servers) > 1,
		CancelSignIn:   m.signingIn,
		OpenSignInPage: cur.DeviceVerificationURI != "",
		ChooseTenant:   idle && cur.LoggedIn && st.HelperInstalled,
		Connect:        idle && cur.LoggedIn && st.HelperInstalled && !cur.Connected,
		Disconnect:     idle && cur.Connected,
		SignOut:        idle && cur.LoggedIn,
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
		m.setStatusLocked(st)
		m.userDown = false
		done(err)
		m.mu.Unlock()
		m.publish()
	}()
}

// SignIn starts the sign-in, whose device-flow prompt appears in State.
func (m *Model) SignIn() {
	server := m.curURL()
	m.run(func(c Can) bool { return c.SignIn }, "Signing in…",
		func() { m.signingIn = true },
		func(ctx context.Context) error { return m.svc.Login(ctx, server, "") },
		func(err error) {
			m.signingIn = false
			switch {
			case errors.Is(err, context.Canceled):
				m.err = "Sign-in cancelled."
			case errors.Is(err, appcore.ErrProviderRequired):
				m.err = "Choose an identity provider, then sign in."
			case err != nil:
				m.err = "Sign-in failed: " + err.Error()
			}
		})
}

// curURL is the selected server's URL ("" when none was added).
func (m *Model) curURL() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, _ := m.curLocked()
	return cur.URL
}

// SelectServer makes the row i of State.Servers the server the window shows
// and the commands are about. Other servers are left as they are: a tunnel
// stays up when another is selected.
func (m *Model) SelectServer(i int) {
	m.mu.Lock()
	if m.canLocked().SelectServer && i >= 0 && i < len(m.st.Servers) {
		m.sel = m.st.Servers[i].URL
	}
	m.mu.Unlock()
	m.publish()
}

// SelectProvider chooses the row i of State.ProviderOptions as the selected
// server's identity provider, for the sign-ins that follow.
func (m *Model) SelectProvider(i int) {
	server := m.curURL()
	var id string
	m.mu.Lock()
	cur, _ := m.curLocked()
	if i >= 0 && i < len(cur.Providers) {
		id = cur.Providers[i].ID
	}
	m.mu.Unlock()
	if id == "" {
		m.publish()
		return
	}
	m.run(func(c Can) bool { return c.ChooseProvider }, "Choosing the identity provider…", nil,
		func(ctx context.Context) error { return m.svc.SetProvider(ctx, server, id) },
		func(err error) {
			if err != nil {
				m.err = "Choosing the identity provider failed: " + err.Error()
			}
		})
}

// Logo is the selected server's logo, an SVG document the library has
// already checked (same origin, digest, sanitised, size capped), or nil.
func (m *Model) Logo() []byte {
	return m.svc.Logo(m.ctx, m.curURL())
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
	cur, _ := m.curLocked()
	raw := cur.DeviceVerificationURI
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
	server := m.curURL()
	m.run(func(c Can) bool { return c.ChooseTenant }, "Asking the server for your tenants…", nil,
		func(ctx context.Context) error {
			ts, err := m.svc.Tenants(ctx, server)
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
	server := m.curURL()
	m.run(func(c Can) bool { return c.Connect }, "Connecting…", nil,
		func(ctx context.Context) error { return m.svc.Connect(ctx, server) },
		func(err error) {
			var xerr *exclusive.Error
			switch {
			case errors.Is(err, appcore.ErrTenantRequired):
				m.err = "You belong to several tenants: choose one, then connect again."
			case errors.As(err, &xerr):
				// The refusal names the server in the way.
				m.err = "Not connected: " + xerr.Error()
			case err != nil:
				m.err = "Connection failed: " + err.Error()
			}
		})
}

// Disconnect takes the selected server's tunnel down; the others stay up.
func (m *Model) Disconnect() {
	server := m.curURL()
	m.run(func(c Can) bool { return c.Disconnect }, "Disconnecting…", func() { m.userDown = true },
		func(ctx context.Context) error { return m.svc.Disconnect(ctx, server) },
		func(err error) {
			if err != nil {
				m.err = "Disconnecting failed: " + err.Error()
			}
		})
}

// SignOut forgets the session at the selected server.
func (m *Model) SignOut() {
	server := m.curURL()
	m.run(func(c Can) bool { return c.SignOut }, "Signing out…", func() { m.userDown = true },
		func(ctx context.Context) error { return m.svc.Logout(ctx, server) },
		func(err error) {
			if err != nil {
				m.err = "Signing out failed: " + err.Error()
			}
		})
}

// RemoveServer takes the selected server out of the list: its tunnel is
// brought down and its sessions forgotten.
func (m *Model) RemoveServer() {
	server := m.curURL()
	m.run(func(c Can) bool { return c.RemoveServer }, "Removing the server…", func() { m.userDown = true },
		func(ctx context.Context) error { return m.svc.RemoveServer(ctx, server) },
		func(err error) {
			if err != nil {
				m.err = "Removing the server failed: " + err.Error()
			} else if m.sel == server {
				m.sel = ""
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
	cur, _ := m.curLocked()
	id, found := "", false
	for j, o := range m.optionsLocked() {
		if j == i {
			id, found = o.ID, true
		}
	}
	if !found || cur.Connected || m.busy != "" || id == cur.Tenant {
		m.mu.Unlock()
		m.publish() // a view that moved its selection is put back
		return
	}
	m.mu.Unlock()
	err := m.svc.SetTenant(cur.URL, id)
	m.mu.Lock()
	if err != nil {
		m.err = "Choosing the tenant failed: " + err.Error()
	} else {
		m.err = ""
		for k := range m.st.Servers {
			if m.st.Servers[k].URL == cur.URL {
				m.st.Servers[k].Tenant = id
			}
		}
	}
	m.mu.Unlock()
	m.publish()
}

// OpenSettings shows the settings form and returns what to fill it with.
func (m *Model) OpenSettings() (Form, bool) {
	m.mu.Lock()
	if !m.canLocked().OpenSettings {
		m.mu.Unlock()
		return Form{}, false
	}
	m.settingsOpen = true
	m.settingsErr = ""
	m.mu.Unlock()
	m.publish()
	return Form{}, true
}

// SaveSettings adds the server whose URL the form holds and selects it. The
// server must answer with its discovery document: a URL that is no server's
// is refused, with the reason in State.SettingsError, and the form stays
// open. A URL that is no https URL (http only for a loopback address) is
// refused before the network is asked.
func (m *Model) SaveSettings(f Form) {
	raw := strings.TrimSpace(f.ServerURL)
	if u, err := url.Parse(raw); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		m.mu.Lock()
		ok := m.canLocked().SaveSettings
		if ok {
			m.settingsErr = "The server URL must be an https URL, such as https://vpn.example.org."
		}
		m.mu.Unlock()
		m.publish()
		return
	}
	var added appcore.ServerEntry
	m.run(func(c Can) bool { return c.SaveSettings }, "Reading the server's configuration…",
		func() { m.settingsErr = "" },
		func(ctx context.Context) (err error) {
			added, err = m.svc.AddServer(ctx, raw)
			return err
		},
		func(err error) {
			if err != nil {
				m.settingsErr = "Adding the server failed: " + err.Error()
				return
			}
			m.settingsOpen = false
			m.sel = added.URL
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
	cur, _ := m.curLocked()
	first := "No tenant chosen"
	if cur.TenantRequired {
		first = "Choose a tenant…"
	}
	opts := []TenantOption{{Label: first}}
	for _, t := range cur.Tenants {
		opts = append(opts, TenantOption{ID: t.ID, Label: tenantName(t)})
	}
	return opts
}

// snapshot builds the State. The caller holds m.mu.
func (m *Model) snapshot() State {
	g := m.st
	st, have := m.curLocked()
	// No server added is the one way the configuration is incomplete now.
	configured := g.ConfigOK && have
	problem := g.ConfigError
	if g.ConfigOK && !have {
		problem = "No server yet: add one by typing its URL."
	}
	s := State{
		Server: st.URL, ServerName: rowName(st), Problem: problem, Busy: m.busy, Error: m.err,
		Connected: st.Connected, LoggedIn: st.LoggedIn, Exclusive: st.Exclusive, HasLogo: st.HasLogo,
		SigningIn: m.signingIn, SignInURL: st.DeviceVerificationURI, SignInCode: st.DeviceUserCode,
		SettingsError: m.settingsErr, ConfigPath: m.configPath,
		TenantLocked:  st.Connected || m.busy != "",
		Can:           m.canLocked(),
		Log:           append([]string(nil), g.Log...),
		NeedsProvider: needsProvider(st),
		Servers:       []ServerRow{},
	}
	for i, r := range g.Servers {
		row := ServerRow{URL: r.URL, Name: rowName(r), Exclusive: r.Exclusive, LoggedIn: r.LoggedIn, Connected: r.Connected, Selected: r.URL == st.URL, Tunnel: tunnelInfo(r)}
		if row.Selected {
			s.Tunnel = row.Tunnel
			s.ServerIndex = i
		}
		s.Servers = append(s.Servers, row)
	}
	s.ProviderOptions = []ProviderOption{}
	for i, p := range st.Providers {
		s.ProviderOptions = append(s.ProviderOptions, ProviderOption{ID: p.ID, Label: p.Name})
		if p.ID == st.Provider {
			s.ProviderIndex = i
		}
	}
	switch {
	case m.settingsOpen:
		s.Screen = ScreenSettings
	case !m.haveStatus:
		s.Screen = ScreenLoading
	case !configured:
		s.Screen = ScreenUnconfigured
	default:
		s.Screen = ScreenMain
	}

	switch {
	case !m.haveStatus:
		s.Headline, s.TrayText = "Starting…", "Claimward: starting…"
	case !configured:
		s.Headline, s.TrayText = "Not configured", "Claimward: not configured"
	case st.Connected:
		s.Headline, s.TrayText = "Connected", "Claimward: connected"
		if st.AssignedIP != "" {
			s.TrayText += " (" + st.AssignedIP + ")"
		}
		if n := connectedCount(g); n > 1 {
			s.TrayText = fmt.Sprintf("Claimward: connected to %d servers", n)
		}
	case st.LoggedIn:
		s.Headline = "Disconnected"
		s.TrayText = "Claimward: disconnected"
		if !g.HelperInstalled {
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
	if g.HelperInstalled {
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

func connectedCount(g appcore.Status) int {
	n := 0
	for _, r := range g.Servers {
		if r.Connected {
			n++
		}
	}
	return n
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
	if !slices.Equal(shown, next[:min(len(shown), len(next))]) {
		return next, false
	}
	return next[min(len(shown), len(next)):], true
}
