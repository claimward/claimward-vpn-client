package helper

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

// Who connected a tunnel is read from the operating system's credentials of
// the connection (a fake source here, the real one in peer_real_test.go),
// never from the request: these tests pin who sees and who may act on what.

var (
	alice = Peer{ID: "uid:1001"}
	bob   = Peer{ID: "uid:1002"}
	admin = Peer{ID: "uid:0", Admin: true}
)

func urls(r hproto.Response) []string {
	var out []string
	for _, t := range r.Tunnels {
		out = append(out, t.ServerURL)
	}
	return out
}

// twoUsers connects a's server as alice and b's as bob.
func twoUsers(t *testing.T) (s *Server, a, b *leaseServer) {
	t.Helper()
	a, b = newLeaseServer(t), newLeaseServer(t)
	s, _ = leasedHelper(t, a.URL, b.URL)
	describe(s, map[string]*protocol.Configuration{a.URL: plain("A"), b.URL: plain("B")})
	for _, c := range []struct {
		p Peer
		v *leaseServer
	}{{alice, a}, {bob, b}} {
		spec, _ := connectSpec(t, c.v.URL)
		if r := s.connectAs(c.p, spec); !r.OK {
			t.Fatal(r.Error)
		}
	}
	return s, a, b
}

func TestStatusShowsACallerOnlyItsOwnTunnels(t *testing.T) {
	s, a, b := twoUsers(t)
	if got := urls(s.statusFor(alice)); len(got) != 1 || got[0] != a.URL {
		t.Errorf("alice sees %v, want only %s", got, a.URL)
	}
	if got := urls(s.statusFor(bob)); len(got) != 1 || got[0] != b.URL {
		t.Errorf("bob sees %v, want only %s", got, b.URL)
	}
	// A third user, and one nobody identified, see nothing.
	for _, p := range []Peer{{ID: "uid:1003"}, {}} {
		if r := s.statusFor(p); !r.OK || len(r.Tunnels) != 0 {
			t.Errorf("%+v sees %+v", p, r.Tunnels)
		}
	}
}

// The rule, explicit: root (or an administrator) sees every tunnel.
func TestAdminSeesEveryTunnel(t *testing.T) {
	s, a, b := twoUsers(t)
	got := urls(s.statusFor(admin))
	if len(got) != 2 || !(got[0] == a.URL || got[1] == a.URL) || !(got[0] == b.URL || got[1] == b.URL) {
		t.Errorf("admin sees %v, want both %s and %s", got, a.URL, b.URL)
	}
}

func TestStatusLastErrorsAreTheCallersOwn(t *testing.T) {
	s, a, b := twoUsers(t)
	s.mu.Lock()
	s.setErrLocked(a.URL, alice.ID, "alice's trouble")
	s.setErrLocked(b.URL, bob.ID, "bob's trouble")
	s.mu.Unlock()
	if e := s.statusFor(alice).LastErrors; len(e) != 1 || e[a.URL] != "alice's trouble" {
		t.Errorf("alice sees errors %v", e)
	}
	if e := s.statusFor(admin).LastErrors; len(e) != 2 {
		t.Errorf("admin sees errors %v", e)
	}
}

func TestDisconnectOfAnotherUsersTunnelIsRefused(t *testing.T) {
	s, a, b := twoUsers(t)
	r := s.downAs(bob, &hproto.ConnectSpec{ServerURL: a.URL})
	if r.OK || r.ErrorCode != hproto.ErrNotOwner {
		t.Fatalf("bob took down alice's tunnel: %+v", r)
	}
	if n := a.count(func(v *leaseServer) int { return len(v.deregisters) }); n != 0 {
		t.Errorf("alice's lease was given back %d times", n)
	}
	if got := urls(s.statusFor(alice)); len(got) != 1 {
		t.Errorf("alice's tunnel is gone: %v", got)
	}
	// "Everything" is the caller's own everything.
	if r := s.downAs(bob, nil); !r.OK || len(r.Tunnels) != 0 {
		t.Errorf("bob down all: %+v", r)
	}
	if got := urls(s.statusFor(alice)); len(got) != 1 || got[0] != a.URL {
		t.Errorf("alice's tunnel after bob's down-all: %v", got)
	}
	if got := urls(s.statusFor(admin)); len(got) != 1 {
		t.Errorf("only alice's should remain: %v", got)
	}
	_ = b
	// Her own, she may.
	if r := s.downAs(alice, &hproto.ConnectSpec{ServerURL: a.URL}); !r.OK || len(r.Tunnels) != 0 {
		t.Errorf("alice down: %+v", r)
	}
}

func TestAdminMayTakeDownAnyTunnel(t *testing.T) {
	s, a, _ := twoUsers(t)
	if r := s.downAs(admin, &hproto.ConnectSpec{ServerURL: a.URL}); !r.OK || len(r.Tunnels) != 2-1 {
		t.Fatalf("admin down: %+v", r)
	}
	if r := s.downAs(admin, nil); !r.OK || len(r.Tunnels) != 0 {
		t.Fatalf("admin down all: %+v", r)
	}
}

func TestAnotherUsersTunnelIsNotRenewedReplacedOrRevoked(t *testing.T) {
	s, a, _ := twoUsers(t)
	if r := s.renewAs(bob, &hproto.ConnectSpec{ServerURL: a.URL, Bearer: "bobs"}); r.OK || r.ErrorCode != hproto.ErrNotOwner {
		t.Errorf("renew: %+v", r)
	}
	// Connecting to the server alice holds would replace her tunnel.
	spec, _ := connectSpec(t, a.URL)
	if r := s.connectAs(bob, spec); r.OK || r.ErrorCode != hproto.ErrNotOwner {
		t.Errorf("connect over alice's tunnel: %+v", r)
	}
	if r := s.revokeAs(bob, &hproto.ConnectSpec{ServerURL: a.URL}); r.OK || r.ErrorCode != hproto.ErrNotOwner {
		t.Errorf("revoke: %+v", r)
	}
	if got := urls(s.statusFor(alice)); len(got) != 1 {
		t.Errorf("alice's tunnel did not survive: %v", got)
	}
	// Her own renewal works; an administrator may replace hers.
	if r := s.renewAs(alice, &hproto.ConnectSpec{ServerURL: a.URL, Bearer: "hers"}); r.ErrorCode == hproto.ErrNotOwner {
		t.Errorf("alice renewing her own: %+v", r)
	}
	spec, _ = connectSpec(t, a.URL)
	if r := s.connectAs(admin, spec); !r.OK {
		t.Errorf("admin connect over alice's: %+v", r)
	}
	if got := urls(s.statusFor(alice)); len(got) != 0 {
		t.Errorf("the tunnel an administrator replaced is still alice's: %v", got)
	}
}

// A refused connect asks the server nothing: no enrollment is made and then
// given back.
func TestRefusedConnectOverAnotherUsersTunnelAsksTheServerNothing(t *testing.T) {
	s, a, _ := twoUsers(t)
	before := a.count(func(v *leaseServer) int { return len(v.enrolled) })
	spec, _ := connectSpec(t, a.URL)
	if r := s.connectAs(bob, spec); r.ErrorCode != hproto.ErrNotOwner {
		t.Fatalf("%+v", r)
	}
	if n := a.count(func(v *leaseServer) int { return len(v.enrolled) }); n != before {
		t.Errorf("the server was asked to enroll %d more time(s)", n-before)
	}
	if n := a.count(func(v *leaseServer) int { return len(v.deregisters) }); n != 0 {
		t.Errorf("%d deregistration(s)", n)
	}
}

// Another user may connect to the server while this one's enrollment is in
// flight: the check is made again under the lock, and the enrollment just
// made is given back.
func TestAConnectRacedByAnotherUsersIsRefusedAndGivenBack(t *testing.T) {
	a := newLeaseServer(t)
	s, _ := leasedHelper(t, a.URL)
	describe(s, map[string]*protocol.Configuration{a.URL: plain("A")})
	a.set(func(v *leaseServer) {
		v.onEnroll = func() {
			v.set(func(v *leaseServer) { v.onEnroll = nil })
			spec, _ := connectSpec(t, a.URL)
			if r := s.connectAs(alice, spec); !r.OK {
				t.Error(r.Error)
			}
		}
	})
	spec, _ := connectSpec(t, a.URL)
	if r := s.connectAs(bob, spec); r.OK || r.ErrorCode != hproto.ErrNotOwner {
		t.Fatalf("bob: %+v", r)
	}
	if got := urls(s.statusFor(alice)); len(got) != 1 {
		t.Errorf("alice lost her tunnel: %v", got)
	}
	if n := a.count(func(v *leaseServer) int { return len(v.deregisters) }); n != 1 {
		t.Errorf("%d deregistrations, want bob's enrollment given back", n)
	}
}

// The wire: the caller is the credentials source's answer for THAT connection,
// and no field of the request can say otherwise.
func TestStatusOverTheSocketIsFilteredByTheConnectionsCredentials(t *testing.T) {
	s, a, b := twoUsers(t)
	byUID := map[string]Peer{"alice": alice, "bob": bob, "root": admin}
	ask := func(who string) hproto.Response {
		client, server := net.Pipe()
		defer client.Close()
		s.UsePeerCredentials(func(net.Conn) (Peer, error) { return byUID[who], nil })
		go s.handle(server, false)
		// A request that names an owner is just a request: unknown fields do
		// not exist for the decoder.
		if _, err := client.Write([]byte(`{"action":"status","owner":"uid:0","admin":true}`)); err != nil {
			t.Fatal(err)
		}
		var r hproto.Response
		if err := json.NewDecoder(client).Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if got := urls(ask("alice")); len(got) != 1 || got[0] != a.URL {
		t.Errorf("alice: %v", got)
	}
	if got := urls(ask("bob")); len(got) != 1 || got[0] != b.URL {
		t.Errorf("bob: %v", got)
	}
	if got := urls(ask("root")); len(got) != 2 {
		t.Errorf("root: %v", got)
	}
}

// Fail closed: a caller the system cannot identify is refused for every
// action, with a code that names the reason, whether the source says so with an
// error or answers with no identity. It never joins a pool of such callers.
func TestACallerTheSystemCannotIdentifyIsRefused(t *testing.T) {
	sources := map[string]PeerSource{
		"error":       func(net.Conn) (Peer, error) { return Peer{}, net.ErrClosed },
		"no identity": func(net.Conn) (Peer, error) { return Peer{}, nil },
		"admin flag but no identity": func(net.Conn) (Peer, error) {
			return Peer{Admin: true}, nil
		},
	}
	for name, src := range sources {
		for _, action := range []string{"connect", "down", "status"} {
			s, _, _ := twoUsers(t)
			client, server := net.Pipe()
			s.UsePeerCredentials(src)
			go s.handle(server, false)
			_, _ = client.Write([]byte(`{"action":"` + action + `"}`))
			var r hproto.Response
			if err := json.NewDecoder(client).Decode(&r); err != nil {
				t.Fatal(err)
			}
			client.Close()
			if r.OK || len(r.Tunnels) != 0 || r.ErrorCode != hproto.ErrCallerUnidentified ||
				!strings.Contains(r.Error, "cannot identify") {
				t.Errorf("%s / %s: %+v", name, action, r)
			}
			if got := urls(s.statusFor(admin)); len(got) != 2 {
				t.Errorf("%s / %s changed the tunnels: %v", name, action, got)
			}
		}
	}
}

// Every caller of the elevated socket is an administrator (its ACL admits
// nothing else), whatever the credentials source says.
func TestElevatedSocketCallersAreAdmins(t *testing.T) {
	s, _, _ := twoUsers(t)
	client, server := net.Pipe()
	defer client.Close()
	s.UsePeerCredentials(func(net.Conn) (Peer, error) { return Peer{ID: "S-1-5-21-1"}, nil })
	go s.handle(server, true)
	_, _ = client.Write([]byte(`{"action":"status"}`))
	var r hproto.Response
	if err := json.NewDecoder(client).Decode(&r); err != nil {
		t.Fatal(err)
	}
	if len(r.Tunnels) != 2 {
		t.Errorf("%+v", r.Tunnels)
	}
}
