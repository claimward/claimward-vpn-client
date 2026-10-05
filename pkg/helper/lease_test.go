package helper

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
	"github.com/claimward/claimward-vpn-client/pkg/wgtun"
)

// leaseServer is a claimward-vpn-server that keeps leases: it answers a
// heartbeat with whatever status the test sets, and records what it was
// asked.
type leaseServer struct {
	*httptest.Server
	mu          sync.Mutex
	enrolled    []string // public keys
	heartbeats  []string // "bearer key"
	deregisters []string // "bearer key"
	// answer is the heartbeat's status for a bearer (200 when unset), and
	// code its error code.
	answer map[string]int
	code   string
	// forget makes the next heartbeat a 404, as after a server restart.
	forget bool
	// failEnroll refuses enrollments.
	failEnroll bool
}

func newLeaseServer(t *testing.T) *leaseServer {
	t.Helper()
	v := &leaseServer{answer: map[string]int{}}
	bearer := func(r *http.Request) string { return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") }
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathEnroll, func(w http.ResponseWriter, r *http.Request) {
		var req protocol.EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)
		v.mu.Lock()
		fail := v.failEnroll
		if !fail {
			v.enrolled = append(v.enrolled, req.PublicKey)
		}
		v.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: "invalid_token", Message: "expired"})
			return
		}
		pair, _ := wgkey.Generate()
		json.NewEncoder(w).Encode(protocol.EnrollResponse{AssignedIP: "10.80.0.7/32", ServerPublicKey: pair.Public.String(),
			Endpoint: "vpn.example.org:51820", AllowedIPs: []string{"10.2.0.0/16"}, LeaseExpiresAt: time.Now().Add(time.Hour)})
	})
	mux.HandleFunc("POST "+protocol.PathHeartbeat, func(w http.ResponseWriter, r *http.Request) {
		var req protocol.HeartbeatRequest
		json.NewDecoder(r.Body).Decode(&req)
		b := bearer(r)
		v.mu.Lock()
		v.heartbeats = append(v.heartbeats, b+" "+req.PublicKey)
		status, code := v.answer[b], v.code
		if v.forget {
			v.forget, status, code = false, http.StatusNotFound, "not_enrolled"
		}
		v.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: code})
			return
		}
		json.NewEncoder(w).Encode(protocol.HeartbeatResponse{LeaseExpiresAt: time.Now().Add(time.Hour)})
	})
	mux.HandleFunc("POST "+protocol.PathDeregister, func(w http.ResponseWriter, r *http.Request) {
		var req protocol.DeregisterRequest
		json.NewDecoder(r.Body).Decode(&req)
		v.mu.Lock()
		v.deregisters = append(v.deregisters, bearer(r)+" "+req.PublicKey)
		v.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	v.Server = httptest.NewServer(mux)
	t.Cleanup(v.Close)
	return v
}

func (v *leaseServer) set(f func(v *leaseServer)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	f(v)
}

func (v *leaseServer) count(of func(v *leaseServer) int) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return of(v)
}

// eventually waits for cond, briefly.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); !cond(); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
	}
}

// leasedHelper is a helper on its own, renewing every few milliseconds.
func leasedHelper(t *testing.T, servers ...string) (*Server, func() []*fakeTunnel) {
	t.Helper()
	s := New(Config{Servers: servers}, "linux", "app-test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	var mu sync.Mutex
	var tuns []*fakeTunnel
	s.up = func(wgtun.Config) (Tunnel, error) {
		mu.Lock()
		defer mu.Unlock()
		f := &fakeTunnel{}
		tuns = append(tuns, f)
		return f, nil
	}
	s.renewAfter = func(time.Duration) time.Duration { return 5 * time.Millisecond }
	s.retryAfter = 5 * time.Millisecond
	t.Cleanup(s.Shutdown)
	return s, func() []*fakeTunnel {
		mu.Lock()
		defer mu.Unlock()
		return append([]*fakeTunnel(nil), tuns...)
	}
}

func (f *fakeTunnel) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func connectSpec(t *testing.T, server string) (*hproto.ConnectSpec, string) {
	t.Helper()
	pair, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return &hproto.ConnectSpec{ServerURL: server, Bearer: "tok", PrivateKey: pair.Private.String(), Tenant: "hpc"}, pair.Public.String()
}

// ⛔ The server removes a peer whose lease ends (LEASE_TTL). Before this,
// nothing renewed it: a device connected for a day lost its peer while the
// tunnel stayed up, with nobody at the other end.
func TestTheHelperRenewsTheLease(t *testing.T) {
	v := newLeaseServer(t)
	s, _ := leasedHelper(t, v.URL)
	spec, pub := connectSpec(t, v.URL)
	r := s.connect(spec)
	if !r.OK || r.LeaseExpiresAt == nil {
		t.Fatalf("connect: %+v", r)
	}
	eventually(t, "two renewals", func() bool { return v.count(func(v *leaseServer) int { return len(v.heartbeats) }) >= 2 })
	v.set(func(v *leaseServer) {
		if v.heartbeats[0] != "tok "+pub {
			t.Errorf("renewed %q, want the enrolled key with the session's bearer", v.heartbeats[0])
		}
	})
	if st := s.status(); !st.Connected || st.LastError != "" {
		t.Errorf("status: %+v", st)
	}
}

// A server that forgot the device -- restarted, or the lease ran out -- is
// enrolled with again, same key and tenant, and the tunnel follows.
func TestAForgottenDeviceEnrollsAgain(t *testing.T) {
	v := newLeaseServer(t)
	s, tuns := leasedHelper(t, v.URL)
	v.set(func(v *leaseServer) { v.forget = true })
	spec, pub := connectSpec(t, v.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	eventually(t, "a second enrollment", func() bool { return v.count(func(v *leaseServer) int { return len(v.enrolled) }) == 2 })
	eventually(t, "the tunnel brought up again", func() bool { return s.status().Connected && len(tuns()) == 2 })
	v.set(func(v *leaseServer) {
		if v.enrolled[1] != pub {
			t.Errorf("enrolled again with %s, want %s", v.enrolled[1], pub)
		}
		if len(v.deregisters) != 0 {
			t.Errorf("a re-enrollment of the same key deregistered it: %v", v.deregisters)
		}
	})
	if !tuns()[0].isClosed() {
		t.Error("the first tunnel was left up")
	}
}

// A device the server forgot and will not take back leads nowhere: down.
func TestAForgottenDeviceThatCannotEnrollIsTakenDown(t *testing.T) {
	v := newLeaseServer(t)
	s, tuns := leasedHelper(t, v.URL)
	spec, _ := connectSpec(t, v.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	v.set(func(v *leaseServer) { v.forget, v.failEnroll = true, true })
	eventually(t, "down", func() bool { return !s.status().Connected })
	if st := s.status(); !strings.Contains(st.LastError, "re-enrollment failed") || !strings.Contains(st.LastError, "invalid_token") {
		t.Errorf("last error %q", st.LastError)
	}
	if !tuns()[0].isClosed() {
		t.Error("the tunnel was left up")
	}
}

// Access withdrawn -- out of the tenant, key registration taken back -- is
// not retried: the tunnel goes down and says why.
func TestWithdrawnAccessTakesTheTunnelDown(t *testing.T) {
	v := newLeaseServer(t)
	s, tuns := leasedHelper(t, v.URL)
	spec, _ := connectSpec(t, v.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	v.set(func(v *leaseServer) { v.answer["tok"], v.code = http.StatusForbidden, "not_a_member" })
	eventually(t, "down", func() bool { return !s.status().Connected })
	if st := s.status(); !strings.Contains(st.LastError, "not_a_member") {
		t.Errorf("last error %q", st.LastError)
	}
	if !tuns()[0].isClosed() {
		t.Error("the tunnel was left up")
	}
}

// A bearer the server no longer takes (a go-authn access token expires in
// minutes) is retried, not acted on, until the app brings a fresh one --
// which the helper then renews with, and keeps renewing with.
func TestAnExpiredBearerWaitsForAFreshOne(t *testing.T) {
	v := newLeaseServer(t)
	s, _ := leasedHelper(t, v.URL)
	spec, pub := connectSpec(t, v.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	v.set(func(v *leaseServer) { v.answer["tok"], v.code = http.StatusUnauthorized, "invalid_token" })
	eventually(t, "a failed renewal", func() bool { return strings.Contains(s.status().LastError, "invalid_token") })
	if !s.status().Connected {
		t.Fatal("an expired bearer took the tunnel down")
	}
	r := s.renewNow(&hproto.ConnectSpec{Bearer: "fresh"})
	if !r.OK || r.LastError != "" || r.LeaseExpiresAt == nil {
		t.Fatalf("renew: %+v", r)
	}
	before := v.count(func(v *leaseServer) int { return len(v.heartbeats) })
	eventually(t, "renewals with the fresh bearer", func() bool {
		return v.count(func(v *leaseServer) int { return len(v.heartbeats) }) > before+1
	})
	v.set(func(v *leaseServer) {
		if last := v.heartbeats[len(v.heartbeats)-1]; last != "fresh "+pub {
			t.Errorf("renewed with %q", last)
		}
	})
	// A renewal the server refuses outright says so to the app.
	v.set(func(v *leaseServer) { v.answer["fresh"] = http.StatusUnauthorized })
	if r := s.renewNow(&hproto.ConnectSpec{Bearer: "fresh"}); r.OK || !strings.Contains(r.Error, "invalid_token") {
		t.Errorf("a refused renewal: %+v", r)
	}
}

// Renew acts only on the helper's own enrollment: it names no server or key.
func TestRenewNeedsALiveTunnelAndABearer(t *testing.T) {
	v := newLeaseServer(t)
	s, _ := leasedHelper(t, v.URL)
	if r := s.renewNow(&hproto.ConnectSpec{Bearer: "tok"}); r.OK || r.Error != "not connected" {
		t.Errorf("renew while down: %+v", r)
	}
	if r := s.renewNow(nil); r.OK {
		t.Errorf("renew without a bearer: %+v", r)
	}
	if n := v.count(func(v *leaseServer) int { return len(v.heartbeats) }); n != 0 {
		t.Errorf("%d heartbeats while down", n)
	}
	// Through the socket, a renew taken back by the server says why.
	spec, _ := connectSpec(t, v.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	v.set(func(v *leaseServer) { v.answer["tok"], v.code = http.StatusForbidden, "key_not_registered" })
	if r := s.renewNow(&hproto.ConnectSpec{Bearer: "tok"}); r.OK || r.Connected || !strings.Contains(r.Error, "key_not_registered") {
		t.Errorf("renew refused: %+v", r)
	}
}

// Disconnecting gives the address back, rather than hold it for a day.
func TestDownDeregisters(t *testing.T) {
	v := newLeaseServer(t)
	s, _ := leasedHelper(t, v.URL)
	s.renewAfter = func(time.Duration) time.Duration { return time.Hour }
	spec, pub := connectSpec(t, v.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	if r := s.down(); !r.OK {
		t.Fatal(r.Error)
	}
	v.set(func(v *leaseServer) {
		if len(v.deregisters) != 1 || v.deregisters[0] != "tok "+pub {
			t.Errorf("deregistered %v", v.deregisters)
		}
	})
	// Down again: nothing to give back.
	s.down()
	if n := v.count(func(v *leaseServer) int { return len(v.deregisters) }); n != 1 {
		t.Errorf("%d deregistrations", n)
	}
}

// Connecting elsewhere gives back the previous enrollment; connecting again
// with the same key to the same server does not, since that is this one.
func TestReconnectingGivesBackOnlyAnotherEnrollment(t *testing.T) {
	a, b := newLeaseServer(t), newLeaseServer(t)
	s, _ := leasedHelper(t, a.URL, b.URL)
	s.renewAfter = func(time.Duration) time.Duration { return time.Hour }
	spec, pub := connectSpec(t, a.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	other := *spec
	other.ServerURL = b.URL
	if r := s.connect(&other); !r.OK {
		t.Fatal(r.Error)
	}
	eventually(t, "a gives the old enrollment back", func() bool { return a.count(func(v *leaseServer) int { return len(v.deregisters) }) == 1 })
	a.set(func(v *leaseServer) {
		if v.deregisters[0] != "tok "+pub {
			t.Errorf("deregistered %v", v.deregisters)
		}
	})
}

// A re-enrollment that finds the session gone or replaced acts on nothing:
// it gives back what it enrolled -- except when the live session is that
// very key at that very server, which a racing re-enrollment just made.
func TestASupersededReEnrollmentGivesWay(t *testing.T) {
	v := newLeaseServer(t)
	s, tuns := leasedHelper(t, v.URL)
	s.renewAfter = func(time.Duration) time.Duration { return time.Hour }
	spec, _ := connectSpec(t, v.URL)
	if r := s.connect(spec); !r.OK {
		t.Fatal(r.Error)
	}
	stale := s.status()
	s.mu.Lock()
	gen := s.sess.gen
	s.mu.Unlock()

	// Raced by a re-enrollment of the same key: the live tunnel stays.
	s.mu.Lock()
	s.gen++ // as if another session had taken over
	s.sess.gen = s.gen
	s.mu.Unlock()
	if r := s.enroll(spec, gen); r.Error != superseded {
		t.Fatalf("stale re-enrollment: %+v", r)
	}
	if n := v.count(func(v *leaseServer) int { return len(v.deregisters) }); n != 0 {
		t.Errorf("the live key was deregistered (%d)", n)
	}
	if st := s.status(); !st.Connected || st.AssignedIP != stale.AssignedIP || len(tuns()) != 1 {
		t.Errorf("the live tunnel was touched: %+v, %d tunnels", st, len(tuns()))
	}

	// Disconnected meanwhile: what it enrolled is given back.
	s.down()
	if r := s.enroll(spec, gen); r.Error != superseded {
		t.Fatalf("re-enrollment after down: %+v", r)
	}
	if n := v.count(func(v *leaseServer) int { return len(v.deregisters) }); n != 2 {
		t.Errorf("%d deregistrations, want the down's and the stale enrollment's", n)
	}
	if s.status().Connected {
		t.Error("a stale re-enrollment brought the tunnel back after a disconnect")
	}
}

// A transient failure is retried well before the lease ends, and a server
// that gives no lease is renewed at the longest interval.
func TestRenewalTiming(t *testing.T) {
	for _, c := range []struct{ left, want time.Duration }{
		{24 * time.Hour, 10 * time.Minute},
		{16 * time.Minute, 8 * time.Minute},
		{10 * time.Second, 30 * time.Second},
		{-time.Minute, 30 * time.Second},
	} {
		if got := renewDelay(c.left); got != c.want {
			t.Errorf("renewDelay(%v) = %v, want %v", c.left, got, c.want)
		}
	}
	v := newLeaseServer(t)
	s, _ := leasedHelper(t, v.URL)
	var asked []time.Duration
	var mu sync.Mutex
	s.renewAfter = func(d time.Duration) time.Duration {
		mu.Lock()
		asked = append(asked, d)
		mu.Unlock()
		return time.Hour
	}
	sess := &session{wake: make(chan struct{}, 1)}
	s.setLeaseLocked(sess, time.Time{})
	if len(asked) != 1 || asked[0] != 2*time.Hour {
		t.Errorf("no lease: asked %v", asked)
	}
	// The wake is not blocked by one already pending.
	s.setLeaseLocked(sess, time.Now().Add(time.Minute))
	if len(sess.wake) != 1 {
		t.Error("no wake pending")
	}
}
