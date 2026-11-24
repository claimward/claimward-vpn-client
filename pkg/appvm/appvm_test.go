package appvm

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/appcore"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
)

// fake is a Service whose slow calls wait for the test.
type fake struct {
	mu      sync.Mutex
	st      appcore.Status
	cfg     appcore.Config
	tenants []hproto.Tenant

	loginErr, connectErr, disconnectErr, logoutErr, tenantsErr, setTenantErr, updateErr error
	// gate, when set, is waited for by every slow call.
	gate  chan struct{}
	calls []string
}

func (f *fake) rec(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }
func (f *fake) wait(ctx context.Context) error {
	if f.gate == nil {
		return nil
	}
	select {
	case <-f.gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (f *fake) Status() appcore.Status       { f.mu.Lock(); defer f.mu.Unlock(); return f.st }
func (f *fake) set(fn func(*appcore.Status)) { f.mu.Lock(); fn(&f.st); f.mu.Unlock() }
func (f *fake) Config() appcore.Config       { return f.cfg }
func (f *fake) UpdateConfig(c appcore.Config) error {
	f.rec("update")
	if f.updateErr == nil {
		f.cfg = c
	}
	return f.updateErr
}
func (f *fake) Login(ctx context.Context) error {
	f.rec("login")
	if err := f.wait(ctx); err != nil {
		return err
	}
	return f.loginErr
}
func (f *fake) Tenants(ctx context.Context) ([]hproto.Tenant, error) {
	f.rec("tenants")
	return f.tenants, f.tenantsErr
}
func (f *fake) SetTenant(id string) error { f.rec("settenant:" + id); return f.setTenantErr }
func (f *fake) Connect(ctx context.Context) error {
	f.rec("connect")
	return f.connectErr
}
func (f *fake) Disconnect(ctx context.Context) error { f.rec("disconnect"); return f.disconnectErr }
func (f *fake) Logout(ctx context.Context) error     { f.rec("logout"); return f.logoutErr }

// harness collects every published state.
type harness struct {
	*Model
	f      *fake
	mu     sync.Mutex
	states []State
	opened []string
	openEr error
}

func newHarness(t *testing.T, st appcore.Status) *harness {
	t.Helper()
	h := &harness{f: &fake{st: st}}
	h.Model = New(h.f, Options{
		Open:       func(u string) error { h.opened = append(h.opened, u); return h.openEr },
		Interval:   5 * time.Millisecond,
		ConfigPath: "/cfg.json",
	})
	h.Subscribe(func(s State) { h.mu.Lock(); h.states = append(h.states, s); h.mu.Unlock() })
	t.Cleanup(func() { h.Stop(); h.Wait() })
	return h
}

// settle waits for the running action, which publishes last.
func (h *harness) settle(t *testing.T) State {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for h.State().Busy != "" {
		if time.Now().After(deadline) {
			t.Fatal("action never finished")
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan struct{})
	go func() { h.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("an action is still running: one that should have been refused?")
	}
	return h.State()
}

var (
	signedOut = appcore.Status{ConfigOK: true, HelperInstalled: true, ServerURL: "https://vpn.example.org"}
	signedIn  = appcore.Status{ConfigOK: true, HelperInstalled: true, LoggedIn: true, Email: "a@b.c", ServerURL: "https://vpn.example.org"}
	up        = appcore.Status{ConfigOK: true, HelperInstalled: true, LoggedIn: true, Connected: true, AssignedIP: "10.0.0.2", Interface: "wg0"}
)

func TestDefaultsAndLoading(t *testing.T) {
	m := New(&fake{}, Options{})
	if m.interval != 2*time.Second || m.fastInterval != 500*time.Millisecond {
		t.Fatal("intervals")
	}
	s := m.State()
	if s.Screen != ScreenLoading || s.Headline != "Starting…" || s.TrayText != "Claimward: starting…" {
		t.Fatalf("%+v", s)
	}
	m.OpenSignInPage() // nothing to open: no panic, no change
	m.mu.Lock()
	m.st.DeviceVerificationURI = "https://x.example/d"
	m.mu.Unlock()
	m.OpenSignInPage()
	if got := m.State().Error; got != "Could not open the browser: no browser to open. Open https://x.example/d yourself." {
		t.Fatal(got)
	}
}

func TestHeadlinesAndTexts(t *testing.T) {
	cases := []struct {
		name string
		st   appcore.Status
		want State
	}{
		{"unconfigured", appcore.Status{ConfigError: "no server"},
			State{Screen: ScreenUnconfigured, Headline: "Not configured", TrayText: "Claimward: not configured", Problem: "no server",
				Account: "Not signed in", Address: "Not connected", Actions: ActionsSignedOut, Slot: SlotNone}},
		{"signed out", signedOut,
			State{Screen: ScreenMain, Headline: "Signed out", TrayText: "Claimward: signed out", Server: "https://vpn.example.org",
				Account: "Not signed in", Address: "Not connected", Actions: ActionsSignedOut, Slot: SlotNone}},
		{"up", up,
			State{Screen: ScreenMain, Headline: "Connected", TrayText: "Claimward: connected (10.0.0.2)", Account: "Signed in",
				Address: "10.0.0.2 on wg0", Actions: ActionsConnected, Slot: SlotChooseTenant, Connected: true, LoggedIn: true,
				Tenant: "Tenant: the server's choice", TenantLocked: true}},
	}
	for _, c := range cases {
		h := newHarness(t, c.st)
		h.Refresh()
		got := h.State()
		got.Can, c.want.Can = Can{}, Can{}
		got.Helper, c.want.Helper = "", ""
		got.TenantOptions, c.want.TenantOptions = nil, nil
		got.ConfigPath = ""
		if c.name == "unconfigured" || c.name == "signed out" {
			got.TenantLocked = false
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
	// Variants.
	h := newHarness(t, appcore.Status{ConfigOK: true, Connected: true, LoggedIn: true, Email: "e@x"})
	h.Refresh()
	s := h.State()
	if s.Address != "address unknown on —" || s.TrayText != "Claimward: connected" || s.Account != "Signed in as e@x" ||
		s.Helper != "Privileged helper: not running (see the README)" {
		t.Fatalf("%+v", s)
	}
	h.f.set(func(s *appcore.Status) { *s = appcore.Status{ConfigOK: true, LoggedIn: true} })
	h.Refresh()
	if s := h.State(); s.TrayText != "Claimward: helper not running" || s.Headline != "Disconnected" {
		t.Fatalf("%+v", s)
	}
	h.f.set(func(s *appcore.Status) { s.HelperInstalled = true })
	h.Refresh()
	if s := h.State(); s.TrayText != "Claimward: disconnected" || s.Helper != "Privileged helper: running" ||
		s.Actions != ActionsDisconnected {
		t.Fatalf("%+v", s)
	}
}

func TestSignInFlow(t *testing.T) {
	h := newHarness(t, signedOut)
	h.f.gate = make(chan struct{})
	h.Refresh()
	h.SignIn()
	s := h.State()
	if s.Busy != "Signing in…" || !s.SigningIn || s.Slot != SlotSignIn || !s.Can.CancelSignIn || s.Can.SignIn ||
		s.SignInHint != "Waiting for the identity provider…" {
		t.Fatalf("%+v", s)
	}
	h.SignIn() // already running: ignored
	h.f.set(func(s *appcore.Status) {
		s.DeviceVerificationURI, s.DeviceUserCode = "https://idp.example/device", "ABCD-1234"
	})
	h.Refresh()
	s = h.State()
	if s.SignInHint != "Open the sign-in page, then enter this code:" || s.SignInCode != "ABCD-1234" || !s.Can.OpenSignInPage {
		t.Fatalf("%+v", s)
	}
	h.f.set(func(s *appcore.Status) { s.DeviceUserCode = "" })
	h.Refresh()
	if h.State().SignInHint != "Complete the sign-in in your browser." {
		t.Fatal(h.State().SignInHint)
	}
	h.OpenSignInPage()
	if !reflect.DeepEqual(h.opened, []string{"https://idp.example/device"}) || h.State().Error != "" {
		t.Fatal(h.opened, h.State().Error)
	}
	h.CancelSignIn()
	s = h.settle(t)
	if s.Error != "Sign-in cancelled." || s.SigningIn {
		t.Fatalf("%+v", s)
	}
	h.CancelSignIn() // nothing to cancel
}

func TestSignInFailureAndSuccess(t *testing.T) {
	h := newHarness(t, signedOut)
	h.Refresh()
	h.f.loginErr = errors.New("denied")
	h.SignIn()
	if s := h.settle(t); s.Error != "Sign-in failed: denied" {
		t.Fatalf("%+v", s)
	}
	h.f.loginErr = nil
	h.f.set(func(s *appcore.Status) { s.LoggedIn = true })
	h.Refresh()
	h.SignIn() // signed in now: refused
	if s := h.settle(t); s.Error != "Sign-in failed: denied" || s.Slot != SlotChooseTenant {
		t.Fatalf("%+v", s)
	}
}

func TestOpenSignInPageRefusals(t *testing.T) {
	h := newHarness(t, signedOut)
	for _, bad := range []string{"file:///etc/passwd", "javascript:alert(1)", "https://", "ht tp://%zz", "calc.exe"} {
		h.f.set(func(s *appcore.Status) { s.DeviceVerificationURI = bad })
		h.Refresh()
		h.OpenSignInPage()
		if !strings.HasPrefix(h.State().Error, "Not opening ") {
			t.Errorf("%q: %q", bad, h.State().Error)
		}
	}
	if len(h.opened) != 0 {
		t.Fatal(h.opened)
	}
	h.f.set(func(s *appcore.Status) { s.DeviceVerificationURI = "http://localhost:5556/device" })
	h.Refresh()
	h.openEr = errors.New("no xdg-open")
	h.OpenSignInPage()
	if !strings.HasPrefix(h.State().Error, "Could not open the browser: no xdg-open") {
		t.Fatal(h.State().Error)
	}
}

func TestConnectDisconnectSignOut(t *testing.T) {
	h := newHarness(t, signedIn)
	h.Refresh()
	h.Disconnect() // not connected: ignored
	h.Connect()
	h.settle(t)
	h.f.connectErr = appcore.ErrTenantRequired
	h.Connect()
	if s := h.settle(t); s.Error != "You belong to several tenants: choose one, then connect again." {
		t.Fatal(s.Error)
	}
	h.f.connectErr = errors.New("boom")
	h.Connect()
	if s := h.settle(t); s.Error != "Connection failed: boom" {
		t.Fatal(s.Error)
	}
	h.f.set(func(s *appcore.Status) { s.Connected = true })
	h.Refresh()
	h.Connect() // connected: ignored
	h.f.disconnectErr = errors.New("stuck")
	h.Disconnect()
	if s := h.settle(t); s.Error != "Disconnecting failed: stuck" {
		t.Fatal(s.Error)
	}
	h.f.disconnectErr = nil
	h.Disconnect()
	h.settle(t)
	h.f.logoutErr = errors.New("locked")
	h.SignOut()
	if s := h.settle(t); s.Error != "Signing out failed: locked" {
		t.Fatal(s.Error)
	}
	h.f.logoutErr = nil
	h.SignOut()
	if s := h.settle(t); s.Error != "" {
		t.Fatal(s.Error)
	}
	want := []string{"connect", "connect", "connect", "disconnect", "disconnect", "logout", "logout"}
	if !reflect.DeepEqual(h.f.log(), want) {
		t.Fatalf("%v", h.f.log())
	}
}

func TestTenants(t *testing.T) {
	h := newHarness(t, signedIn)
	h.Refresh()
	for _, c := range []struct {
		ts   []hproto.Tenant
		err  error
		want string
	}{
		{nil, nil, "The server lists no tenant for you."},
		{[]hproto.Tenant{{ID: "a"}}, nil, "You belong to one tenant: there is nothing to choose."},
		{[]hproto.Tenant{{ID: "a"}, {ID: "b"}}, nil, ""},
		{nil, errors.New("down"), "Listing tenants failed: down"},
	} {
		h.f.tenants, h.f.tenantsErr = c.ts, c.err
		h.ChooseTenant()
		if s := h.settle(t); s.Error != c.want {
			t.Errorf("%v: %q", c.ts, s.Error)
		}
	}

	h.f.set(func(s *appcore.Status) {
		s.Tenants = []hproto.Tenant{{ID: "acme", Name: "Acme"}, {ID: "x", Name: "x"}, {ID: "y"}}
		s.TenantRequired = true
	})
	h.Refresh()
	s := h.State()
	want := []TenantOption{{Label: "Choose a tenant…"}, {ID: "acme", Label: "Acme (acme)"}, {ID: "x", Label: "x"}, {ID: "y", Label: "y"}}
	if !reflect.DeepEqual(s.TenantOptions, want) || s.TenantIndex != 0 || s.Slot != SlotTenants || s.Tenant != "Tenant: none chosen" {
		t.Fatalf("%+v", s)
	}
	h.SelectTenant(1)
	s = h.State()
	if s.TenantIndex != 1 || s.Tenant != "Tenant: Acme (acme)" || s.Error != "" || h.f.log()[len(h.f.log())-1] != "settenant:acme" {
		t.Fatalf("%+v", s)
	}
	n := len(h.f.log())
	h.SelectTenant(1)  // already chosen
	h.SelectTenant(9)  // out of range
	h.SelectTenant(-1) // out of range
	if len(h.f.log()) != n {
		t.Fatal("no call expected")
	}
	h.f.setTenantErr = errors.New("disk")
	h.SelectTenant(2)
	s = h.State()
	if s.TenantIndex != 1 || s.Error != "Choosing the tenant failed: disk" {
		t.Fatalf("%+v", s)
	}
	// Locked while connected.
	h.f.setTenantErr = nil
	h.f.set(func(s *appcore.Status) { s.Connected, s.Tenant = true, "acme" })
	h.Refresh()
	n = len(h.f.log())
	h.SelectTenant(2)
	if len(h.f.log()) != n || !h.State().TenantLocked {
		t.Fatal("locked")
	}
	// An unlisted tenant, and a server choice.
	h.f.set(func(s *appcore.Status) { s.Connected, s.Tenant, s.TenantRequired = false, "gone", false })
	h.Refresh()
	if s := h.State(); s.Tenant != "Tenant: gone" || s.TenantIndex != 0 || s.TenantOptions[0].Label != "No tenant chosen" {
		t.Fatalf("%+v", s)
	}
}

func TestSettings(t *testing.T) {
	h := newHarness(t, appcore.Status{ConfigError: "no server"})
	h.f.cfg = appcore.Config{ServerURL: "https://vpn", Provider: "go-authn", OIDCIssuer: "https://i", OIDCClientID: "c", GitHubClientID: "g"}
	h.Refresh()
	h.SaveSettings(Form{}) // not open: ignored
	h.CloseSettings()      // not open: ignored
	if len(h.f.log()) != 0 {
		t.Fatal(h.f.log())
	}
	f, ok := h.OpenSettings()
	if !ok || f.Provider != "go-authn" || f.ServerURL != "https://vpn" || f.GitHubClientID != "g" || f.OIDCIssuer != "https://i" || f.OIDCClientID != "c" {
		t.Fatalf("%+v %v", f, ok)
	}
	if s := h.State(); s.Screen != ScreenSettings || s.Can.OpenSettings || !s.Can.SaveSettings || s.ConfigPath != "/cfg.json" {
		t.Fatalf("%+v", s)
	}
	if _, ok := h.OpenSettings(); ok {
		t.Fatal("already open")
	}
	// A status arriving does not leave the form.
	h.Refresh()
	if h.State().Screen != ScreenSettings {
		t.Fatal("left the form")
	}
	h.SaveSettings(Form{ServerURL: "ftp://x"})
	if s := h.State(); !strings.HasPrefix(s.SettingsError, "The server URL must be an http(s) URL") || s.Screen != ScreenSettings {
		t.Fatalf("%+v", s)
	}
	h.f.updateErr = errors.New("read-only")
	h.SaveSettings(Form{ServerURL: " https://vpn.example.org ", Provider: "nonsense"})
	if s := h.settle(t); s.SettingsError != "Saving failed: read-only" || s.Screen != ScreenSettings {
		t.Fatalf("%+v", s)
	}
	h.f.updateErr = nil
	h.SaveSettings(Form{ServerURL: "https://vpn.example.org", Provider: "github"})
	s := h.settle(t)
	if s.SettingsError != "" || s.Screen != ScreenUnconfigured || !strings.HasPrefix(s.Error, "Saved, but not complete: ") {
		t.Fatalf("%+v", s)
	}
	if h.f.cfg.ServerURL != "https://vpn.example.org" || h.f.cfg.Provider != "github" {
		t.Fatalf("%+v", h.f.cfg)
	}
	// Complete, and an empty server URL is let through to the validation.
	h.OpenSettings()
	h.SaveSettings(Form{ServerURL: "https://vpn.example.org", Provider: "github", GitHubClientID: "Iv1.abc"})
	h.f.set(func(s *appcore.Status) { *s = signedOut })
	if s := h.settle(t); s.Error != "" {
		t.Fatalf("%+v", s)
	}
	h.Refresh()
	h.OpenSettings()
	h.SaveSettings(Form{})
	h.settle(t)
	h.OpenSettings()
	h.SettingsErrorForTest("x")
	h.CloseSettings()
	if s := h.State(); s.Screen != ScreenMain || s.SettingsError != "" {
		t.Fatalf("%+v", s)
	}
	// While busy the form refuses a bad URL silently.
	h.f.gate = make(chan struct{})
	h.SignIn()
	h.SaveSettings(Form{ServerURL: "ftp://x"})
	if h.State().SettingsError != "" {
		t.Fatal("busy")
	}
	close(h.f.gate)
	h.settle(t)
}

// SettingsErrorForTest sets a settings error, to see CloseSettings clear it.
func (m *Model) SettingsErrorForTest(s string) { m.mu.Lock(); m.settingsErr = s; m.mu.Unlock() }

func TestProviders(t *testing.T) {
	if ProviderIndex("oidc") != 1 || ProviderIndex("nope") != 0 || ProviderIndex("go-authn") != 2 {
		t.Fatal("index")
	}
	if UsesIssuer("github") || UsesIssuer("") || !UsesIssuer("oidc") || !UsesIssuer("go-authn") {
		t.Fatal("issuer")
	}
}

func TestPollingAndSubscribe(t *testing.T) {
	h := newHarness(t, signedIn)
	var n int
	var mu sync.Mutex
	cancel := h.Subscribe(func(State) { mu.Lock(); n++; mu.Unlock() })
	h.Start()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		k := n
		mu.Unlock()
		if k >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no polling")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	h.f.gate = make(chan struct{})
	h.SignOut() // a fast poll while an action runs
	h.Stop()
	h.Wait()
	mu.Lock()
	k := n
	mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if n != k {
		t.Fatal("still notified after cancel")
	}
}

func TestFastPolling(t *testing.T) {
	f := &fake{st: signedOut, gate: make(chan struct{})}
	m := New(f, Options{Interval: time.Hour, FastInterval: time.Millisecond})
	m.Refresh()
	m.SignIn() // an action runs: the poller goes fast
	var mu sync.Mutex
	n := 0
	m.Subscribe(func(State) { mu.Lock(); n++; mu.Unlock() })
	m.Start()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		k := n
		mu.Unlock()
		if k >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no fast polling")
		}
		time.Sleep(time.Millisecond)
	}
	close(f.gate)
	m.Stop()
	m.Wait()
}

func TestLogDelta(t *testing.T) {
	cases := []struct {
		shown, next, lines []string
		appended           bool
	}{
		{nil, nil, nil, true},
		{[]string{"a"}, []string{"a"}, nil, true},
		{[]string{"a"}, []string{"a", "b"}, []string{"b"}, true},
		{[]string{"a", "b"}, []string{"b", "c"}, []string{"b", "c"}, false},
		{[]string{"a", "b"}, []string{"a"}, []string{"a"}, false},
	}
	for _, c := range cases {
		lines, ok := LogDelta(c.shown, c.next)
		if len(lines) != len(c.lines) || ok != c.appended {
			t.Errorf("%v -> %v: %v %v", c.shown, c.next, lines, ok)
		}
	}
}

func TestLogInState(t *testing.T) {
	h := newHarness(t, appcore.Status{ConfigOK: true, Log: []string{"1", "2"}})
	h.Refresh()
	s := h.State()
	s.Log[0] = "mutated"
	if h.State().Log[0] != "1" {
		t.Fatal("State shares its log with the Model")
	}
}

func collectEvents(m *Model) (get func() []Event, cancel func()) {
	var mu sync.Mutex
	var evs []Event
	cancel = m.SubscribeEvents(func(e Event) { mu.Lock(); evs = append(evs, e); mu.Unlock() })
	return func() []Event { mu.Lock(); defer mu.Unlock(); return append([]Event(nil), evs...) }, cancel
}

func TestEventsOnTransitionsOnly(t *testing.T) {
	h := newHarness(t, up)
	get, cancel := collectEvents(h.Model)
	h.Refresh() // the first status is no transition
	h.Refresh()
	if len(get()) != 0 {
		t.Fatal(get())
	}
	h.f.set(func(s *appcore.Status) { s.Connected = false })
	for range 10 {
		h.Refresh()
	}
	if ev := get(); len(ev) != 1 || ev[0].Kind != EventDropped || ev[0].Title == "" || ev[0].Body == "" {
		t.Fatalf("10 polls in the dropped state: %+v", ev)
	}
	// Up again, then the session expires under a running tunnel.
	h.f.set(func(s *appcore.Status) { s.Connected = true })
	h.Refresh()
	h.f.set(func(s *appcore.Status) { s.Connected, s.LoggedIn = false, false })
	for range 3 {
		h.Refresh()
	}
	if ev := get(); len(ev) != 2 || ev[1].Kind != EventSessionExpired {
		t.Fatalf("%+v", ev)
	}
	cancel()
	h.f.set(func(s *appcore.Status) { *s = up })
	h.Refresh()
	h.f.set(func(s *appcore.Status) { s.Connected = false })
	h.Refresh()
	if len(get()) != 2 {
		t.Fatal("notified after cancel")
	}
}

func TestOwnDisconnectAndSignOutAreNoEvents(t *testing.T) {
	h := newHarness(t, up)
	h.Refresh()
	get, _ := collectEvents(h.Model)
	h.f.disconnectErr = nil
	h.f.set(func(s *appcore.Status) {}) // the fake keeps reporting up: the tunnel is not really down
	h.Disconnect()
	h.settle(t)
	// The status the action ends with says down: the person asked for it.
	h.f.gate = make(chan struct{})
	h.Apply(up)
	h.f.set(func(s *appcore.Status) { s.Connected = false })
	h.Disconnect()
	h.settle(t)
	h.Apply(up)
	h.f.set(func(s *appcore.Status) { s.Connected, s.LoggedIn = false, false })
	h.SignOut()
	h.settle(t)
	if len(get()) != 0 {
		t.Fatalf("%+v", get())
	}
	// The flag does not outlive the action.
	h.Apply(up)
	h.Apply(signedOut)
	if ev := get(); len(ev) != 1 || ev[0].Kind != EventSessionExpired {
		t.Fatalf("%+v", ev)
	}
}

func TestRefusedCommandsDoNothing(t *testing.T) {
	h := newHarness(t, signedOut)
	h.Refresh()
	h.Connect()
	h.Disconnect()
	h.SignOut()
	h.ChooseTenant()
	h.OpenSignInPage()
	if len(h.f.log()) != 0 || h.State().Busy != "" || h.State().Error != "" || len(h.opened) != 0 {
		t.Fatalf("%v %+v", h.f.log(), h.State())
	}
	// A tenant choice while an action runs, and one that moves nothing.
	h.f.st = signedIn
	h.f.st.Tenants = []hproto.Tenant{{ID: "a"}, {ID: "b"}}
	h.f.gate = make(chan struct{})
	h.Apply(appcore.Status{ConfigOK: true, HelperInstalled: true})
	h.SignIn()
	for len(h.f.log()) == 0 { // Login is under way, waiting for the gate
		time.Sleep(time.Millisecond)
	}
	before := h.State()
	h.SelectTenant(1)
	if after := h.State(); !reflect.DeepEqual(before, after) || len(h.f.log()) != 1 {
		t.Fatalf("%v", h.f.log())
	}
	close(h.f.gate)
	h.settle(t)
	h.Apply(h.f.st)
	h.SelectTenant(0) // already the chosen row
	h.SelectTenant(1)
	h.SelectTenant(len(h.State().TenantOptions))
	if got := h.f.log()[len(h.f.log())-1]; got != "settenant:a" {
		t.Fatal(got)
	}
	n := len(h.f.log())
	h.SelectTenant(-1)
	if len(h.f.log()) != n {
		t.Fatal("negative row")
	}
}

func (f *fake) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}
