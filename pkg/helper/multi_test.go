package helper

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/routeclient"
	"github.com/claimward/claimward-vpn-client/pkg/secureurl"
)

func isUp(s *Server) bool { return len(s.status().Tunnels) > 0 }

// describe makes the helper's discovery answer from a table keyed by server
// URL; a server not in it fails to answer.
func describe(s *Server, docs map[string]*protocol.Configuration) {
	s.UseDiscovery(func(_ context.Context, server string) (*protocol.Configuration, error) {
		if d, ok := docs[server]; ok {
			return d, nil
		}
		return nil, errors.New("no document")
	})
}

func plain(name string) *protocol.Configuration {
	return &protocol.Configuration{Version: 2, ServerName: name}
}

func solo(name string) *protocol.Configuration {
	return &protocol.Configuration{Version: 2, ServerName: name, Exclusive: true}
}

func TestTwoPlainServersAreConnectedAtOnce(t *testing.T) {
	a, b := newLeaseServer(t), newLeaseServer(t)
	s, tuns := leasedHelper(t, a.URL, b.URL)
	describe(s, map[string]*protocol.Configuration{a.URL: plain("A"), b.URL: plain("B")})
	for _, v := range []*leaseServer{a, b} {
		spec, _ := connectSpec(t, v.URL)
		if r := s.connect(spec); !r.OK {
			t.Fatal(r.Error)
		}
	}
	st := s.status()
	if len(st.Tunnels) != 2 || len(tuns()) != 2 {
		t.Fatalf("tunnels %+v, brought up %d", st.Tunnels, len(tuns()))
	}
	if st.Tunnels[0].ServerName == st.Tunnels[1].ServerName {
		t.Errorf("both tunnels are the same server: %+v", st.Tunnels)
	}
	// Taking one down leaves the other, and gives back only its lease.
	if r := s.down(&hproto.ConnectSpec{ServerURL: a.URL}); !r.OK || len(r.Tunnels) != 1 || r.Tunnels[0].ServerURL != b.URL {
		t.Fatalf("down a: %+v", r)
	}
	if n := a.count(func(v *leaseServer) int { return len(v.deregisters) }); n != 1 {
		t.Errorf("a: %d deregistrations", n)
	}
	if n := b.count(func(v *leaseServer) int { return len(v.deregisters) }); n != 0 {
		t.Errorf("b: %d deregistrations", n)
	}
	if r := s.down(nil); !r.OK || len(r.Tunnels) != 0 {
		t.Fatalf("down all: %+v", r)
	}
	if n := b.count(func(v *leaseServer) int { return len(v.deregisters) }); n != 1 {
		t.Errorf("b: %d deregistrations", n)
	}
}

// ⛔ The helper does not trust the app about exclusivity: it reads the
// server's own document, and refuses before asking the server anything.
func TestAnExclusiveServerIsRefusedWhileAnotherIsConnected(t *testing.T) {
	plainSrv, soloSrv := newLeaseServer(t), newLeaseServer(t)
	s, tuns := leasedHelper(t, plainSrv.URL, soloSrv.URL)
	describe(s, map[string]*protocol.Configuration{plainSrv.URL: plain("Campus"), soloSrv.URL: solo("Lab")})
	spec, _ := connectSpec(t, plainSrv.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	spec, _ = connectSpec(t, soloSrv.URL)
	r := s.connect(spec)
	if r.OK || r.ErrorCode != hproto.ErrExclusive || r.BlockedBy != "Campus" {
		t.Fatalf("exclusive beside another: %+v", r)
	}
	if n := soloSrv.count(func(v *leaseServer) int { return len(v.enrolled) }); n != 0 {
		t.Errorf("the exclusive server was asked to enroll (%d)", n)
	}
	if len(tuns()) != 1 || len(s.status().Tunnels) != 1 {
		t.Errorf("a tunnel was brought up for the refused server")
	}
}

func TestAnotherServerIsRefusedWhileAnExclusiveOneIsConnected(t *testing.T) {
	plainSrv, soloSrv := newLeaseServer(t), newLeaseServer(t)
	s, tuns := leasedHelper(t, plainSrv.URL, soloSrv.URL)
	describe(s, map[string]*protocol.Configuration{plainSrv.URL: plain("Campus"), soloSrv.URL: solo("Lab")})
	spec, _ := connectSpec(t, soloSrv.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	spec, _ = connectSpec(t, plainSrv.URL)
	r := s.connect(spec)
	if r.OK || r.ErrorCode != hproto.ErrExclusive || r.BlockedBy != "Lab" {
		t.Fatalf("beside an exclusive: %+v", r)
	}
	if n := plainSrv.count(func(v *leaseServer) int { return len(v.enrolled) }); n != 0 {
		t.Errorf("the refused server was asked to enroll (%d)", n)
	}
	if len(tuns()) != 1 {
		t.Errorf("%d tunnels", len(tuns()))
	}
	// Once the exclusive one is down, the other is welcome.
	s.down(nil)
	spec, _ = connectSpec(t, plainSrv.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
}

func TestAnExclusiveServerAloneIsFine(t *testing.T) {
	soloSrv := newLeaseServer(t)
	s, _ := leasedHelper(t, soloSrv.URL)
	describe(s, map[string]*protocol.Configuration{soloSrv.URL: solo("Lab")})
	spec, _ := connectSpec(t, soloSrv.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	// Connecting it again is a reconnection, not a second server.
	if r := s.connect(spec); !r.OK || len(r.Tunnels) != 1 || !r.Tunnels[0].Exclusive {
		t.Fatalf("reconnect: %+v", r)
	}
}

// The helper cannot tell whether a server is exclusive without its document,
// so without it nothing is connected.
func TestTheHelperFailsClosedWithoutTheDiscoveryDocument(t *testing.T) {
	v := newLeaseServer(t)
	s, tuns := leasedHelper(t, v.URL)
	describe(s, nil)
	spec, _ := connectSpec(t, v.URL)
	r := s.connect(spec)
	if r.OK || r.ErrorCode != hproto.ErrDiscovery {
		t.Fatalf("no document: %+v", r)
	}
	if n := v.count(func(v *leaseServer) int { return len(v.enrolled) }); n != 0 || len(tuns()) != 0 {
		t.Errorf("enrolled %d, tunnels %d", n, len(tuns()))
	}
}

// The renewal loop re-enrolls a forgotten device of an exclusive server
// without asking the rule again: it is still the only one.
func TestAReEnrollmentOfAnExclusiveServerIsNotRefused(t *testing.T) {
	v := newLeaseServer(t)
	s, tuns := leasedHelper(t, v.URL)
	describe(s, map[string]*protocol.Configuration{v.URL: solo("Lab")})
	v.set(func(v *leaseServer) { v.forget = true })
	spec, _ := connectSpec(t, v.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	eventually(t, "the tunnel brought up again", func() bool { return isUp(s) && len(tuns()) == 2 })
	if st := s.status(); !st.Tunnels[0].Exclusive || len(st.LastErrors) != 0 {
		t.Errorf("status %+v", st)
	}
}

func TestOnlyTheNamedServersTunnelIsRenewedAndStopped(t *testing.T) {
	a, b := newLeaseServer(t), newLeaseServer(t)
	s, _ := leasedHelper(t, a.URL, b.URL)
	describe(s, map[string]*protocol.Configuration{a.URL: plain("A"), b.URL: plain("B")})
	for _, v := range []*leaseServer{a, b} {
		spec, _ := connectSpec(t, v.URL)
		if r := s.connect(spec); !r.OK {
			t.Fatal(r.Error)
		}
	}
	if r := s.renewNow(&hproto.ConnectSpec{ServerURL: "https://elsewhere.example", Bearer: "x"}); r.OK || r.Error != "not connected" {
		t.Errorf("renew of an unknown server: %+v", r)
	}
	// Unlisted servers cannot be taken "down" into a lookup of anything.
	if r := s.down(&hproto.ConnectSpec{ServerURL: "https://elsewhere.example"}); !r.OK || len(r.Tunnels) != 2 {
		t.Errorf("down of an unknown server: %+v", r)
	}
}

func TestTheProviderReachesTheRouteWatch(t *testing.T) {
	v := newVPNServer(t)
	_, s, _ := helperFor(t, v.URL)
	var mu sync.Mutex
	var got string
	done := make(chan struct{}, 1)
	s.watch = func(ctx context.Context, ep, bearer, provider, pub string, on func(routeclient.Update)) error {
		mu.Lock()
		got = provider
		mu.Unlock()
		done <- struct{}{}
		<-ctx.Done()
		return nil
	}
	spec := &hproto.ConnectSpec{ServerURL: v.URL, Provider: "github", Bearer: "tok", PrivateKey: key(t)}
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	if got != "github" {
		t.Errorf("provider %q", got)
	}
	s.Shutdown()
}

func TestAnInvalidProviderIdIsRefused(t *testing.T) {
	v := newVPNServer(t)
	_, s, ups := helperFor(t, v.URL)
	spec := &hproto.ConnectSpec{ServerURL: v.URL, Provider: "a b\r\nX: y", Bearer: "tok", PrivateKey: key(t)}
	if r := s.connect(spec); r.OK || len(*ups) != 0 || r.Error != "invalid provider id" {
		t.Fatalf("%+v", r)
	}
}

// A server URL that is no safe one is refused for what it is, not as a server
// the helper merely does not know.
func TestAnUnsafeServerURLIsRefusedAsSuch(t *testing.T) {
	v := newVPNServer(t)
	_, s, ups := helperFor(t, v.URL)
	spec := &hproto.ConnectSpec{ServerURL: "http://vpn.example.org", Bearer: "tok", PrivateKey: key(t)}
	if r := s.connect(spec); r.OK || len(*ups) != 0 || !strings.Contains(r.Error, "must be https") {
		t.Fatalf("%+v", r)
	}
}

// An answerless resolver is no document: the helper still fails closed.
func TestAResolverThatAnswersNothingFailsClosed(t *testing.T) {
	v := newLeaseServer(t)
	s, tuns := leasedHelper(t, v.URL)
	s.UseDiscovery(func(context.Context, string) (*protocol.Configuration, error) { return nil, nil })
	spec, _ := connectSpec(t, v.URL)
	if r := s.connect(spec); r.OK || r.ErrorCode != hproto.ErrDiscovery || len(tuns()) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestABadServerURLIsRefusedByRenewAndDown(t *testing.T) {
	v := newLeaseServer(t)
	s, _ := leasedHelper(t, v.URL)
	spec, _ := connectSpec(t, v.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	if r := s.renewNow(&hproto.ConnectSpec{ServerURL: "::not a url", Bearer: "x"}); r.OK || !strings.HasPrefix(r.Error, "server: ") {
		t.Errorf("renew: %+v", r)
	}
	if r := s.down(&hproto.ConnectSpec{ServerURL: "::not a url"}); r.OK || !strings.HasPrefix(r.Error, "server: ") || isUp(s) == false {
		t.Errorf("down: %+v", r)
	}
}

// A session that is no longer its server's live one cannot take the live
// tunnel down.
func TestAStaleSessionDoesNotDropTheLiveTunnel(t *testing.T) {
	v := newLeaseServer(t)
	s, _ := leasedHelper(t, v.URL)
	spec, _ := connectSpec(t, v.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	server, _ := secureurl.Canonical(v.URL)
	s.drop(&session{server: server}, "a stale renewal gave up")
	if st := s.status(); len(st.Tunnels) != 1 || len(st.LastErrors) != 0 {
		t.Fatalf("%+v", st)
	}
}

// ⛔ The check made before the enrollment can be outrun by another connection
// made while the server answers: the one made after it refuses, gives the
// enrollment back, and brings nothing up.
func TestAConnectionMadeMeanwhileIsNotOutrunByAnExclusiveOne(t *testing.T) {
	plainSrv, soloSrv := newLeaseServer(t), newLeaseServer(t)
	s, tuns := leasedHelper(t, plainSrv.URL, soloSrv.URL)
	describe(s, map[string]*protocol.Configuration{plainSrv.URL: plain("Campus"), soloSrv.URL: solo("Lab")})
	soloSrv.set(func(v *leaseServer) {
		v.onEnroll = func() {
			spec, _ := connectSpec(t, plainSrv.URL)
			if r := s.connect(spec); !r.OK {
				t.Error(r.Error)
			}
		}
	})
	spec, _ := connectSpec(t, soloSrv.URL)
	r := s.connect(spec)
	if r.OK || r.ErrorCode != hproto.ErrExclusive || r.BlockedBy != "Campus" {
		t.Fatalf("%+v", r)
	}
	if len(tuns()) != 1 || len(s.status().Tunnels) != 1 {
		t.Errorf("tunnels %d", len(tuns()))
	}
	if n := soloSrv.count(func(v *leaseServer) int { return len(v.deregisters) }); n != 1 {
		t.Errorf("the enrollment was not given back (%d)", n)
	}
}
