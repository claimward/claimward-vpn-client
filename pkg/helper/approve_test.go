package helper

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/helperclient"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

// consent stands in for the operating system: it records what it was asked
// and answers as told.
type consent struct {
	mu    sync.Mutex
	asked []Approval
	yes   bool
}

func (c *consent) Authorize(_ context.Context, a Approval) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.asked = append(c.asked, a)
	if !c.yes {
		return ErrDenied
	}
	return nil
}

func (c *consent) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.asked)
}

// docName makes the helper's discovery answer with a document of that name.
func docName(s *Server, name *string) {
	s.UseDiscovery(func(context.Context, string) (*protocol.Configuration, error) {
		return &protocol.Configuration{Version: 2, ServerName: *name,
			Providers: []protocol.Provider{{ID: "uni", Kind: protocol.KindOIDC, OIDCIssuer: "https://i", OIDCClientID: "c"}}}, nil
	})
}

func connect(t *testing.T, c *helperclient.Client, url string) error {
	t.Helper()
	_, err := c.Connect(hproto.ConnectSpec{ServerURL: url, Bearer: "tok", PrivateKey: key(t), DeviceName: "laptop"})
	return err
}

// ⛔ A server nobody approved is refused with a typed error, and approving it
// without the system's consent changes nothing.
func TestAnUnapprovedServerIsRefusedUntilTheSystemConsents(t *testing.T) {
	v := newVPNServer(t)
	c, s, ups := helperFor(t)
	sys := &consent{}
	s.UseAuthorizer(sys)
	name := "Chemistry"
	docName(s, &name)

	var na *helperclient.NotApprovedError
	if err := connect(t, c, v.URL); !errors.As(err, &na) || na.Changed {
		t.Fatalf("an unapproved server: %v", err)
	}
	if _, err := c.Tenants(v.URL, "", "tok"); !errors.As(err, &na) {
		t.Errorf("tenants of an unapproved server: %v", err)
	}
	// The app's own claim is nothing: whatever it sends, the system decides.
	if _, err := c.Approve(v.URL, []byte("I am an administrator")); !errors.Is(err, helperclient.ErrApprovalDenied) {
		t.Fatalf("approve without consent: %v", err)
	}
	if sys.count() != 1 || sys.asked[0].Name != name || sys.asked[0].Elevated || string(sys.asked[0].Credential) != "I am an administrator" {
		t.Errorf("the system was asked %+v", sys.asked)
	}
	if err := connect(t, c, v.URL); !errors.As(err, &na) {
		t.Errorf("still unapproved: %v", err)
	}
	if len(v.enroll) != 0 || len(*ups) != 0 {
		t.Errorf("an unapproved server was enrolled with (%d) or a tunnel came up (%d)", len(v.enroll), len(*ups))
	}
	if got, _ := c.Approved(); len(got.Approved) != 0 {
		t.Errorf("approved: %+v", got.Approved)
	}
}

// With the system's consent the server is accepted, remembered in the file
// (read by a helper that starts later), and listed; the admin's servers are
// listed too and cannot be revoked.
func TestAnApprovedServerIsRememberedAndCanBeRevoked(t *testing.T) {
	v, admin := newVPNServer(t), newVPNServer(t)
	c, s, _ := helperFor(t, admin.URL)
	sys := &consent{yes: true}
	s.UseAuthorizer(sys)
	name := "Chemistry"
	docName(s, &name)

	resp, err := c.Approve(v.URL, nil)
	if err != nil || len(resp.Approved) != 2 {
		t.Fatalf("approve: %+v %v", resp, err)
	}
	if err := connect(t, c, v.URL); err != nil {
		t.Fatalf("connect after approval: %v", err)
	}
	later := &approvals{path: s.approvals.path}
	if e, ok, err := later.lookup(strings.TrimSuffix(v.URL, "/")); err != nil || !ok || e.Name != name || e.Identity == "" {
		t.Errorf("the file does not hold the approval: %+v %v %v", e, ok, err)
	}
	var admins, user int
	got, _ := c.Approved()
	for _, a := range got.Approved {
		if a.Admin {
			admins++
		} else {
			user++
		}
	}
	if admins != 1 || user != 1 {
		t.Errorf("listing: %+v", got.Approved)
	}
	// The administrator's server needs no consent, and is not revocable.
	before := sys.count()
	if _, err := c.Approve(admin.URL, nil); err != nil || sys.count() != before {
		t.Errorf("approving an admin server asked the system (%d) or failed: %v", sys.count()-before, err)
	}
	if _, err := c.Revoke(admin.URL); err == nil || !strings.Contains(err.Error(), "administrator") {
		t.Errorf("revoking an admin server: %v", err)
	}

	// Revocation drops the tunnel and the trust.
	if st, _ := c.Status(); len(st.Tunnels) != 1 {
		t.Fatalf("not connected: %+v", st)
	}
	if _, err := c.Revoke(v.URL); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Status(); len(st.Tunnels) != 0 {
		t.Error("the tunnel outlived the revocation")
	}
	var na *helperclient.NotApprovedError
	if err := connect(t, c, v.URL); !errors.As(err, &na) {
		t.Errorf("a revoked server: %v", err)
	}
	if _, ok, _ := later.lookup(strings.TrimSuffix(v.URL, "/")); ok {
		t.Error("the file still holds a revoked server")
	}
}

// A server that changes who it is after it was approved is no longer the
// one that was: it is refused until approved again.
func TestAServerThatChangesIsNotTheOneApproved(t *testing.T) {
	v := newVPNServer(t)
	c, s, _ := helperFor(t)
	sys := &consent{yes: true}
	s.UseAuthorizer(sys)
	name := "Chemistry"
	docName(s, &name)
	if _, err := c.Approve(v.URL, nil); err != nil {
		t.Fatal(err)
	}
	name = "Totally the same server"
	var na *helperclient.NotApprovedError
	if err := connect(t, c, v.URL); !errors.As(err, &na) || !na.Changed {
		t.Fatalf("a changed server: %v", err)
	}
	if _, err := c.Tenants(v.URL, "", "tok"); !errors.As(err, &na) || !na.Changed {
		t.Errorf("tenants of a changed server: %v", err)
	}
	if _, err := c.Approve(v.URL, nil); err != nil {
		t.Fatal(err)
	}
	if err := connect(t, c, v.URL); err != nil {
		t.Errorf("after approving again: %v", err)
	}
}

// One prompt at a time: while the person has not answered, a second request
// is refused, not queued.
func TestOnlyOneApprovalWaitsAtATime(t *testing.T) {
	v := newVPNServer(t)
	c, s, _ := helperFor(t)
	asking, release := make(chan struct{}), make(chan struct{})
	s.UseAuthorizer(AuthorizerFunc(func(context.Context, Approval) error {
		close(asking)
		<-release
		return nil
	}))
	name := "Chemistry"
	docName(s, &name)
	done := make(chan error, 1)
	go func() { _, err := c.Approve(v.URL, nil); done <- err }()
	<-asking
	if _, err := c.Approve(v.URL, nil); !errors.Is(err, helperclient.ErrApprovalDenied) || !strings.Contains(err.Error(), "already waiting") {
		t.Errorf("a second approval: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Errorf("the first approval: %v", err)
	}
}

// Without an Authorizer (a platform that has none) nothing is approved.
func TestNoAuthorizerNoApproval(t *testing.T) {
	v := newVPNServer(t)
	c, s, _ := helperFor(t)
	s.UseAuthorizer(nil)
	if _, err := c.Approve(v.URL, nil); !errors.Is(err, helperclient.ErrApprovalDenied) {
		t.Errorf("approve with no authorizer: %v", err)
	}
}

// The identity is what the person approved -- the name and the identity
// providers -- and not what an operator changes in passing.
func TestIdentity(t *testing.T) {
	a := &protocol.Configuration{ServerName: "X", Exclusive: false, Providers: []protocol.Provider{
		{ID: "b", Kind: protocol.KindOIDC, Name: "B", OIDCIssuer: "https://b", OIDCClientID: "1"},
		{ID: "a", Kind: protocol.KindOIDC, Name: "A", OIDCIssuer: "https://a", OIDCClientID: "2"},
	}}
	b := &protocol.Configuration{ServerName: "X", Exclusive: true, Providers: []protocol.Provider{
		{ID: "a", Kind: protocol.KindOIDC, Name: "Renamed", OIDCIssuer: "https://a", OIDCClientID: "2"},
		{ID: "b", Kind: protocol.KindOIDC, Name: "B", OIDCIssuer: "https://b", OIDCClientID: "1"},
	}}
	if Identity(a) != Identity(b) {
		t.Error("order, exclusivity or a display name changed the identity")
	}
	for name, mutate := range map[string]func(*protocol.Configuration){
		"name":      func(c *protocol.Configuration) { c.ServerName = "Y" },
		"issuer":    func(c *protocol.Configuration) { c.Providers[0].OIDCIssuer = "https://evil" },
		"client id": func(c *protocol.Configuration) { c.Providers[1].OIDCClientID = "9" },
		"provider":  func(c *protocol.Configuration) { c.Providers = c.Providers[:1] },
	} {
		c := &protocol.Configuration{ServerName: b.ServerName, Providers: append([]protocol.Provider(nil), b.Providers...)}
		mutate(c)
		if Identity(c) == Identity(b) {
			t.Errorf("a changed %s kept the identity", name)
		}
	}
}

// The elevated socket admits SYSTEM and the Administrators and nobody else.
func TestTheElevatedSocketNamesNoGroup(t *testing.T) {
	d := elevatedSocketSDDL()
	if strings.Count(d, "(A;") != 2 || !strings.Contains(d, ";;;SY)") || !strings.Contains(d, ";;;BA)") || strings.Contains(d, "S-1-") {
		t.Errorf("the elevated socket's descriptor: %s", d)
	}
}

// Tenants of an administrator's server: no bearer is refused before anyone is
// asked, and a server that does not answer is an error, not an empty list.
func TestTenantsOfAnAdminServer(t *testing.T) {
	v := newVPNServer(t)
	dead := newVPNServer(t)
	dead.Close()
	c, _, _ := helperFor(t, v.URL, dead.URL)
	if _, err := c.Tenants(v.URL, "", ""); err == nil {
		t.Error("tenants with no bearer")
	}
	if ts, err := c.Tenants(v.URL, "", "tok"); err != nil || len(ts.Tenants) != 2 {
		t.Errorf("tenants: %+v %v", ts, err)
	}
	if _, err := c.Tenants(dead.URL, "", "tok"); err == nil {
		t.Error("tenants of a server that is down")
	}
}

// The elevated socket is the client's to name; where a platform has none, it
// says so.
func TestApproveElevatedUsesTheSocketItIsGiven(t *testing.T) {
	v := newVPNServer(t)
	c, s, _ := helperFor(t)
	s.UseAuthorizer(AuthorizerFunc(func(_ context.Context, a Approval) error {
		if a.Elevated {
			return nil
		}
		return ErrDenied
	}))
	name := "Chemistry"
	docName(s, &name)
	// Through the ordinary socket the approval is not elevated: refused.
	if _, err := c.Approve(v.URL, nil); !errors.Is(err, helperclient.ErrApprovalDenied) {
		t.Fatalf("ordinary socket: %v", err)
	}
	// Through the socket the client names, served as elevated: accepted.
	dir, err := os.MkdirTemp("", "cwe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "e.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go s.ServeElevated(ln)
	c.ElevatedSocketPath = ln.Addr().String()
	if _, err := c.ApproveElevated(v.URL); err != nil {
		t.Errorf("elevated socket: %v", err)
	}
	if hproto.DefaultElevatedSocketPath == "" {
		c.ElevatedSocketPath = ""
		if _, err := c.ApproveElevated(v.URL); err == nil || !strings.Contains(err.Error(), "no elevated socket") {
			t.Errorf("no elevated socket: %v", err)
		}
	}
}
