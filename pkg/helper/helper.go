// Package helper is the privileged side of a Claimward app: the process that
// runs as root (or SYSTEM), owns the tunnels, and does the server comms --
// shared by the macOS, Linux and Windows apps, each of which only supplies a
// main that listens.
//
// ⛔ Anybody who can reach the helper's socket can make it act, so what it
// will do is bounded by ITS OWN configuration, not by what it is asked:
//
//   - It enrolls only with a server its configuration names. A helper that
//     took the server from the request would let any local process point it
//     at a server of its own, which answers with routes for 0.0.0.0/0 and a
//     peer of its choosing: every packet of the machine, sent there.
//   - It takes no tunnel configuration from the request at all; the tunnel
//     is what that server answered.
//   - It holds one tunnel per server, and applies the exclusivity rule
//     (pkg/exclusive) itself, from the discovery document it fetched: it does
//     not take the app's word for whether a server is exclusive.
//   - Its socket is 0660, for root and one group (listen_unix.go); the
//     previous helper's was 0666.
package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/client"
	"github.com/claimward/claimward-vpn-client/pkg/discovery"
	"github.com/claimward/claimward-vpn-client/pkg/exclusive"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/routeclient"
	"github.com/claimward/claimward-vpn-client/pkg/secureurl"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
	"github.com/claimward/claimward-vpn-client/pkg/wgtun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config is the helper's own configuration, read from a file only an
// administrator can write.
type Config struct {
	// Servers are claimward-vpn-server base URLs the administrator approves
	// in advance: the helper enrolls with them without asking anybody. Any
	// other server needs the system's consent first (ActionApprove). May be
	// empty.
	Servers []string `json:"servers,omitempty"`
	// Approvals is the file the approved servers are kept in. Empty:
	// DefaultApprovalsPath.
	Approvals string `json:"approvals,omitempty"`
	// Group may use the socket beside root (unix). Empty: the platform's
	// default (DefaultGroup).
	Group string `json:"group,omitempty"`
	// Socket is where to listen. Empty: hproto.DefaultSocketPath.
	Socket string `json:"socket,omitempty"`
}

// LoadConfig reads the configuration and refuses one an unprivileged user
// could have written (checkOwner, per platform).
func LoadConfig(path string) (*Config, error) {
	if err := checkOwner(path); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, s := range c.Servers {
		if err := secureurl.Check(s); err != nil {
			return nil, fmt.Errorf("%s: server %q: %w", path, s, err)
		}
	}
	if c.Group == "" {
		c.Group = DefaultGroup
	}
	if c.Socket == "" {
		c.Socket = hproto.DefaultSocketPath
	}
	if c.Approvals == "" {
		c.Approvals = DefaultApprovalsPath
	}
	return &c, nil
}

// Tunnel is a running tunnel (*wgtun.Tunnel).
type Tunnel interface {
	Name() string
	UpdateRoutes(allowedIPs []string) error
	Close() error
}

// Server answers the app.
type Server struct {
	cfg           Config
	os, platform  string
	log           *slog.Logger
	up            func(wgtun.Config) (Tunnel, error)
	watch         func(ctx context.Context, endpoint, bearer, provider, publicKey string, onUpdate func(routeclient.Update)) error
	discover      func(ctx context.Context, server string) (*protocol.Configuration, error)
	enrollTimeout time.Duration
	// renewAfter is how long after a renewal the next one is due, from the
	// time the lease has left (renewDelay).
	renewAfter func(remaining time.Duration) time.Duration
	// retryAfter is how long to wait after a renewal that did not reach the
	// server, or reached it broken.
	retryAfter time.Duration

	approvals *approvals
	authz     Authorizer
	// approving is held while the system's consent is being asked for: one
	// prompt at a time, so a process cannot flood the person with them.
	approving sync.Mutex

	mu sync.Mutex
	// sessions are the enrollments behind the live tunnels, by canonical
	// server URL; a server with no tunnel has none.
	sessions map[string]*session
	// gen counts the sessions: a renewal whose session is no longer the
	// server's live one acts on nothing.
	gen uint64
	// lastErrs is, per server, why its tunnel was last lost or its renewal
	// last failed.
	lastErrs map[string]string
}

// superseded is a re-enrollment that found a newer session, or none.
const superseded = "superseded"

// session is one enrollment and the tunnel brought up from it.
type session struct {
	gen    uint64
	server string
	// member is the server as discovery described it when it was connected.
	member   exclusive.Member
	spec     hproto.ConnectSpec // Bearer is replaced by ActionRenew
	pub      wgtypes.Key
	tun      Tunnel
	assigned string
	lease    time.Time
	// renewBy is when the renewal is due; wake tells the loop it moved.
	renewBy time.Time
	wake    chan struct{}
	cancel  context.CancelFunc // the renewal loop and the route watch
}

// renewDelay renews at half of what the lease has left -- so a renewal
// that fails has the other half to be retried in -- and never sooner than
// 30 s nor later than 10 min. The ceiling is how long a device stays cut off
// after the server restarts: the server removes the peers it no longer
// knows, and the device learns it at its next renewal (404) and enrolls
// again.
func renewDelay(remaining time.Duration) time.Duration {
	return min(max(remaining/2, 30*time.Second), maxRenewDelay)
}

const maxRenewDelay = 10 * time.Minute

// RenewDelay is when the helper renews a lease with remaining left: for an
// app that must bring a fresh bearer before then.
func RenewDelay(remaining time.Duration) time.Duration { return renewDelay(remaining) }

// New is a helper for the platform os ("darwin", "linux", "windows") and app
// ("app-osx", ...), as the server's admin sees the device.
func New(cfg Config, os, platform string, log *slog.Logger) *Server {
	disc := discovery.New(nil)
	if cfg.Approvals == "" {
		cfg.Approvals = DefaultApprovalsPath
	}
	return &Server{
		cfg: cfg, os: os, platform: platform, log: log,
		approvals: &approvals{path: cfg.Approvals, verify: checkOwner},
		authz:     DefaultAuthorizer(),
		up: func(c wgtun.Config) (Tunnel, error) {
			t, err := wgtun.Up(c)
			if err != nil {
				return nil, err
			}
			return t, nil
		},
		watch:         routeclient.Watch,
		discover:      disc.Get,
		enrollTimeout: 30 * time.Second,
		renewAfter:    renewDelay,
		retryAfter:    time.Minute,
		sessions:      map[string]*session{},
		lastErrs:      map[string]string{},
	}
}

// UseTunnels replaces how a tunnel is brought up (wgtun.Up by default): for
// tests, and for a platform that brings tunnels up another way.
func (s *Server) UseTunnels(up func(wgtun.Config) (Tunnel, error)) { s.up = up }

// UseRouteWatch replaces how route pushes are watched (routeclient.Watch by
// default).
func (s *Server) UseRouteWatch(w func(ctx context.Context, endpoint, bearer, provider, publicKey string, onUpdate func(routeclient.Update)) error) {
	s.watch = w
}

// UseDiscovery replaces how a server's discovery document is read
// (discovery.Client.Get by default): for tests.
func (s *Server) UseDiscovery(d func(ctx context.Context, server string) (*protocol.Configuration, error)) {
	s.discover = d
}

// UseAuthorizer replaces how the system's consent to a server is obtained
// (DefaultAuthorizer by default): for tests, and for a platform that obtains
// it another way.
func (s *Server) UseAuthorizer(a Authorizer) { s.authz = a }

// Serve answers connections until ln is closed.
func (s *Server) Serve(ln net.Listener) error { return s.serve(ln, false) }

// ServeElevated answers connections on a listener the operating system opens
// to elevated processes alone (Windows: ListenElevated). A connection on it
// is the consent ActionApprove asks for, and the DefaultAuthorizer there
// accepts nothing else.
func (s *Server) ServeElevated(ln net.Listener) error { return s.serve(ln, true) }

func (s *Server) serve(ln net.Listener, elevated bool) error {
	sem := make(chan struct{}, maxConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				s.handle(conn, elevated)
			}()
		default:
			// Too many open at once: refuse rather than queue (audit 2026-11-23).
			conn.Close()
		}
	}
}

const (
	// maxRequestBytes bounds what one request on the socket may carry: a
	// request is a bearer, a key and a few names.
	maxRequestBytes = 64 << 10
	// maxConns bounds the connections served at once.
	maxConns = 32
)

func (s *Server) handle(conn net.Conn, elevated bool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	var req hproto.Request
	if err := json.NewDecoder(io.LimitReader(conn, maxRequestBytes)).Decode(&req); err != nil {
		reply(conn, hproto.Response{Error: "bad request: " + err.Error()})
		return
	}
	switch req.Action {
	case hproto.ActionConnect:
		reply(conn, s.connect(req.Connect))
	case hproto.ActionTenants:
		reply(conn, s.tenants(req.Connect))
	case hproto.ActionRenew:
		reply(conn, s.renewNow(req.Connect))
	case hproto.ActionDown:
		reply(conn, s.down(req.Connect))
	case hproto.ActionStatus:
		reply(conn, s.status())
	case hproto.ActionApprove:
		// Asking the person takes as long as the person does.
		_ = conn.SetDeadline(time.Now().Add(approveTimeout + 30*time.Second))
		reply(conn, s.approve(conn, elevated, req.Connect))
	case hproto.ActionRevoke:
		reply(conn, s.revoke(req.Connect))
	case hproto.ActionApproved:
		reply(conn, s.approvedList())
	default:
		reply(conn, hproto.Response{Error: "unknown action: " + req.Action})
	}
}

// adminServer says whether the administrator's configuration names server (a
// canonical URL).
func (s *Server) adminServer(server string) bool {
	for _, u := range s.cfg.Servers {
		if c, err := secureurl.Canonical(u); err == nil && c == server {
			return true
		}
	}
	return false
}

// How much of a server's identity trust reads.
const (
	// trustFresh reads the discovery document and returns it: a connection.
	trustFresh = iota
	// trustApproved reads it only for a server that was approved, to check
	// that it is still the one that was.
	trustApproved
	// trustListed reads nothing: the renewal of a connection that was checked.
	trustListed
)

// trust is the canonical URL of the server rawURL names, and its discovery
// document when it was read, if the helper may deal with the server: the
// administrator named it, or it was approved and is still what was approved.
// Otherwise the response to give instead.
func (s *Server) trust(ctx context.Context, rawURL string, mode int) (string, *protocol.Configuration, *hproto.Response) {
	server, err := secureurl.Canonical(rawURL)
	if err != nil {
		return "", nil, &hproto.Response{Error: fmt.Sprintf("server %q: %v", rawURL, err)}
	}
	var entry approvedEntry
	admin := s.adminServer(server)
	if !admin {
		e, ok, err := s.approvals.lookup(server)
		if err != nil { // fail closed
			return "", nil, &hproto.Response{Error: "approved servers: " + err.Error()}
		}
		if !ok {
			return "", nil, &hproto.Response{ErrorCode: hproto.ErrNotApproved,
				Error: fmt.Sprintf("server %q is not approved: it needs the system's authorization first (approve)", rawURL)}
		}
		entry = e
	}
	if mode == trustListed || (mode == trustApproved && admin) {
		return server, nil, nil
	}
	cfg, err := s.discover(ctx, server)
	if err == nil && cfg == nil {
		err = errors.New("empty answer")
	}
	if err != nil {
		// Fail closed: without the document the helper can tell neither
		// whether the server is exclusive nor whether it is the one approved.
		return "", nil, &hproto.Response{Error: "discovery: " + err.Error(), ErrorCode: hproto.ErrDiscovery}
	}
	if !admin && Identity(cfg) != entry.Identity {
		return "", nil, &hproto.Response{ErrorCode: hproto.ErrIdentityChanged,
			Error: fmt.Sprintf("server %q no longer says what it said when it was approved (its name or identity providers changed): approve it again", rawURL)}
	}
	return server, cfg, nil
}

// checkSpec refuses a connect spec with no bearer or a bad provider.
func checkSpec(spec *hproto.ConnectSpec) error {
	if spec == nil || spec.Bearer == "" {
		return errors.New("missing connect spec")
	}
	if spec.Provider != "" && !protocol.ValidProviderID(spec.Provider) {
		return errors.New("invalid provider id")
	}
	return nil
}

func (s *Server) tenants(spec *hproto.ConnectSpec) hproto.Response {
	if err := checkSpec(spec); err != nil {
		return hproto.Response{Error: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.enrollTimeout)
	defer cancel()
	server, _, fail := s.trust(ctx, spec.ServerURL, trustApproved)
	if fail != nil {
		return *fail
	}
	ts, err := client.New(server).WithProvider(spec.Provider).Tenants(ctx, spec.Bearer)
	if err != nil {
		return hproto.Response{Error: "tenants: " + err.Error()}
	}
	out := hproto.Response{OK: true}
	for _, t := range ts {
		out.Tenants = append(out.Tenants, hproto.Tenant{ID: t.ID, Name: t.Name})
	}
	return out
}

func (s *Server) connect(spec *hproto.ConnectSpec) hproto.Response {
	return s.enroll(spec, 0, nil)
}

// membersLocked are the servers with a live tunnel.
func (s *Server) membersLocked() []exclusive.Member {
	out := make([]exclusive.Member, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess.member)
	}
	return out
}

// refusal is the response to a connection the exclusivity rule refuses.
func refusal(err *exclusive.Error) hproto.Response {
	return hproto.Response{Error: err.Error(), ErrorCode: hproto.ErrExclusive, BlockedBy: err.BlockedBy()}
}

// enroll enrolls with the server spec names, brings the tunnel up from its
// answer and starts renewing the lease. A non-zero gen is a re-enrollment
// by that session's renewal loop (member is then the session's own), which
// gives way to anything that happened since (a disconnect, another connect).
// A first connection (gen 0) reads the server's discovery document and is
// refused if the server, or one already connected, is exclusive.
func (s *Server) enroll(spec *hproto.ConnectSpec, gen uint64, member *exclusive.Member) hproto.Response {
	if err := checkSpec(spec); err != nil {
		return hproto.Response{Error: err.Error()}
	}
	pair, err := wgkey.ParsePrivate(spec.PrivateKey)
	if err != nil {
		return hproto.Response{Error: "private key: " + err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.enrollTimeout)
	defer cancel()

	mode := trustFresh
	if member != nil {
		mode = trustListed
	}
	server, doc, fail := s.trust(ctx, spec.ServerURL, mode)
	if fail != nil {
		return *fail
	}

	if member == nil {
		member = &exclusive.Member{URL: server, Name: doc.ServerName, Exclusive: doc.Exclusive}
		s.mu.Lock()
		err = exclusive.Check(*member, s.membersLocked())
		s.mu.Unlock()
		if ex := (*exclusive.Error)(nil); errors.As(err, &ex) {
			return refusal(ex) // before anything is asked of the server
		}
	}

	c := client.New(server).WithProvider(spec.Provider)
	resp, err := c.Enroll(ctx, spec.Bearer, pair.Public, protocol.DeviceInfo{
		Name: spec.DeviceName, OS: s.os, Platform: s.platform,
	}, spec.Tenant)
	if err != nil {
		return hproto.Response{Error: "enroll: " + err.Error()}
	}
	cfg, err := client.TunnelConfig(resp, pair.Private)
	if err != nil {
		return hproto.Response{Error: err.Error()}
	}

	s.mu.Lock()
	cur := s.sessions[server]
	if gen != 0 && (cur == nil || cur.gen != gen) {
		// Disconnected, or connected again, while this re-enrolled. The
		// enrollment just made is given back -- unless the live session is
		// that same key at that same server, which another re-enrollment
		// raced this one to: giving it back would cut the live tunnel.
		s.mu.Unlock()
		if cur == nil || cur.pub != pair.Public {
			s.deregister(&session{server: server, spec: *spec, pub: pair.Public})
		}
		return hproto.Response{Error: superseded}
	}
	if gen == 0 {
		// The authoritative check: another connection may have been made
		// since the first one.
		if err := exclusive.Check(*member, s.membersLocked()); err != nil {
			s.mu.Unlock()
			s.deregister(&session{server: server, spec: *spec, pub: pair.Public})
			var ex *exclusive.Error
			if errors.As(err, &ex) {
				return refusal(ex)
			}
			return hproto.Response{Error: err.Error()}
		}
	}
	old := s.stopLocked(server)
	if old != nil && old.pub != pair.Public {
		// The previous enrollment is somebody else's lease now: give it back.
		go s.deregister(old)
	}
	tun, err := s.up(cfg)
	if err != nil {
		s.lastErrs[server] = err.Error()
		s.mu.Unlock()
		return hproto.Response{Error: err.Error()}
	}
	s.gen++
	sctx, scancel := context.WithCancel(context.Background())
	sess := &session{
		gen: s.gen, server: server, member: *member, spec: *spec, pub: pair.Public,
		tun: tun, assigned: resp.AssignedIP, wake: make(chan struct{}, 1), cancel: scancel,
	}
	s.setLeaseLocked(sess, resp.LeaseExpiresAt)
	s.sessions[server] = sess
	delete(s.lastErrs, server)
	s.mu.Unlock()

	go s.renewLoop(sctx, sess)
	if resp.GRPCEndpoint != "" {
		go s.watchRoutes(sctx, sess, resp.GRPCEndpoint)
	}
	s.log.Info("connected", "server", server, "interface", tun.Name(), "assigned", resp.AssignedIP, "tenant", spec.Tenant, "routes", resp.AllowedIPs, "lease", resp.LeaseExpiresAt)
	return s.status()
}

func (s *Server) watchRoutes(ctx context.Context, sess *session, endpoint string) {
	s.mu.Lock()
	bearer := sess.spec.Bearer
	s.mu.Unlock()
	err := s.watch(ctx, endpoint, bearer, sess.spec.Provider, sess.pub.String(), func(u routeclient.Update) {
		if ctx.Err() != nil {
			return // the tunnel is going down
		}
		if e := sess.tun.UpdateRoutes(u.AllowedIPs); e != nil {
			s.log.Error("apply pushed routes", "server", sess.server, "err", e)
		} else {
			s.log.Info("routes updated", "server", sess.server, "serial", u.Serial, "allowed_ips", u.AllowedIPs)
		}
	})
	if err != nil && ctx.Err() == nil {
		s.log.Warn("route watch ended", "server", sess.server, "err", err)
	}
}

// setLeaseLocked records the lease the server gave and when to renew it. A
// server that gave none is renewed at the longest interval.
func (s *Server) setLeaseLocked(sess *session, lease time.Time) {
	sess.lease = lease
	remaining := time.Hour * 2
	if !lease.IsZero() {
		remaining = time.Until(lease)
	}
	sess.renewBy = time.Now().Add(s.renewAfter(remaining))
	select {
	case sess.wake <- struct{}{}:
	default:
	}
}

// renewLoop keeps the server's lease on the peer. Without it the server
// removes the peer when the lease ends (LEASE_TTL, 24 h by default) and the
// tunnel stays up with nobody at the other end.
//
// It renews with the last bearer it was given. An app that holds a
// refreshable sign-in hands it fresher ones (ActionRenew); a bearer the
// server no longer accepts (401) is retried, since the app may yet bring a
// new one, until the lease is gone.
func (s *Server) renewLoop(ctx context.Context, sess *session) {
	for {
		s.mu.Lock()
		wait := time.Until(sess.renewBy)
		s.mu.Unlock()
		timer := time.NewTimer(max(wait, 0))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-sess.wake:
			timer.Stop()
			continue
		case <-timer.C:
		}
		if !s.renew(ctx, sess) {
			return
		}
	}
}

// renew renews sess's lease once, and says whether its loop goes on.
func (s *Server) renew(ctx context.Context, sess *session) bool {
	s.mu.Lock()
	bearer := sess.spec.Bearer
	s.mu.Unlock()
	hctx, cancel := context.WithTimeout(ctx, s.enrollTimeout)
	resp, err := client.New(sess.server).WithProvider(sess.spec.Provider).Heartbeat(hctx, bearer, sess.pub)
	cancel()
	if ctx.Err() != nil {
		return false
	}
	var se *client.ServerError
	switch {
	case err == nil:
		s.mu.Lock()
		s.setLeaseLocked(sess, resp.LeaseExpiresAt)
		if s.sessions[sess.server] == sess {
			delete(s.lastErrs, sess.server)
		}
		s.mu.Unlock()
		s.log.Info("lease renewed", "server", sess.server, "until", resp.LeaseExpiresAt)
		return true

	case errors.As(err, &se) && se.Status == http.StatusNotFound:
		// The server no longer knows the peer: its lease ran out, or the
		// server restarted (it keeps leases in memory). Enroll again, with
		// the same key and tenant; failing that the tunnel leads nowhere.
		s.log.Warn("the server forgot this device; enrolling again", "server", sess.server, "err", err)
		s.mu.Lock()
		spec := sess.spec
		member := sess.member
		s.mu.Unlock()
		if r := s.enroll(&spec, sess.gen, &member); !r.OK && r.Error != superseded {
			s.drop(sess, "re-enrollment failed: "+r.Error)
		}
		return false

	case errors.As(err, &se) && se.Status == http.StatusForbidden:
		// Access withdrawn: removed from the tenant, key registration
		// taken back. Not something a retry changes.
		s.drop(sess, "the server refused to renew: "+err.Error())
		return false

	default:
		// Unreachable, a 5xx, or a bearer that expired (401): retry, sooner
		// than the lease ends.
		s.mu.Lock()
		s.lastErrs[sess.server] = "renewal failed: " + err.Error()
		left := time.Until(sess.lease)
		if sess.lease.IsZero() {
			left = s.retryAfter * 2
		}
		sess.renewBy = time.Now().Add(min(s.retryAfter, max(left/2, time.Second)))
		s.mu.Unlock()
		s.log.Warn("lease renewal failed; retrying", "server", sess.server, "err", err)
		return true
	}
}

// drop takes sess's tunnel down, if it is still its server's live one,
// because the server no longer carries it.
func (s *Server) drop(sess *session, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[sess.server] != sess {
		return
	}
	s.stopLocked(sess.server)
	s.lastErrs[sess.server] = why
	s.log.Error("tunnel taken down", "server", sess.server, "why", why)
}

// renewNow is ActionRenew: a fresh bearer for the live session of the server
// spec names, and a renewal with it now.
func (s *Server) renewNow(spec *hproto.ConnectSpec) hproto.Response {
	if spec == nil || spec.Bearer == "" {
		return hproto.Response{Error: "missing bearer"}
	}
	server, err := secureurl.Canonical(spec.ServerURL)
	if err != nil {
		return hproto.Response{Error: "server: " + err.Error()}
	}
	s.mu.Lock()
	sess := s.sessions[server]
	if sess == nil {
		s.mu.Unlock()
		return hproto.Response{Error: "not connected"}
	}
	sess.spec.Bearer = spec.Bearer
	s.mu.Unlock()
	s.renew(context.Background(), sess)
	// Whatever renew did -- renewed, retried, re-enrolled, dropped -- the
	// status says where that left the tunnel, and LastErrors why not.
	st := s.status()
	if e := st.LastErrors[server]; e != "" {
		st.OK, st.Error = false, e
	}
	return st
}

// down is ActionDown: one server's tunnel, or all of them when none is named.
func (s *Server) down(spec *hproto.ConnectSpec) hproto.Response {
	var olds []*session
	s.mu.Lock()
	if spec == nil || spec.ServerURL == "" {
		for _, server := range slices.Sorted(maps.Keys(s.sessions)) {
			olds = append(olds, s.stopLocked(server))
		}
		clear(s.lastErrs)
	} else {
		server, err := secureurl.Canonical(spec.ServerURL)
		if err != nil {
			s.mu.Unlock()
			return hproto.Response{Error: "server: " + err.Error()}
		}
		if old := s.stopLocked(server); old != nil {
			olds = append(olds, old)
		}
		delete(s.lastErrs, server)
	}
	s.mu.Unlock()
	for _, old := range olds {
		s.deregister(old)
	}
	return s.status()
}

// deregister gives the peer's address back to the server, rather than leave
// it held until the lease ends. Best effort: a server that cannot be told
// reaps the peer when the lease runs out.
func (s *Server) deregister(sess *session) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.New(sess.server).WithProvider(sess.spec.Provider).Deregister(ctx, sess.spec.Bearer, sess.pub); err != nil {
		s.log.Warn("deregister", "server", sess.server, "err", err)
	}
}

// stopLocked takes a server's tunnel down and returns the session it belonged
// to (nil when it had none).
func (s *Server) stopLocked(server string) *session {
	old := s.sessions[server]
	if old == nil {
		return nil
	}
	old.cancel()
	_ = old.tun.Close()
	delete(s.sessions, server)
	s.log.Info("tunnel down", "server", server)
	return old
}

func (s *Server) status() hproto.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := hproto.Response{OK: true}
	for _, server := range slices.Sorted(maps.Keys(s.sessions)) {
		sess := s.sessions[server]
		t := hproto.Tunnel{
			ServerURL: server, ServerName: sess.member.Name, Exclusive: sess.member.Exclusive,
			Interface: sess.tun.Name(), AssignedIP: sess.assigned, Tenant: sess.spec.Tenant,
		}
		if !sess.lease.IsZero() {
			lease := sess.lease
			t.LeaseExpiresAt = &lease
		}
		resp.Tunnels = append(resp.Tunnels, t)
	}
	if len(s.lastErrs) > 0 {
		resp.LastErrors = maps.Clone(s.lastErrs)
	}
	return resp
}

// Shutdown takes the tunnels down, for a helper that is stopping. It does not
// deregister: a helper restarted by its service manager finds the server
// still holding the lease, and a stopped machine's lease runs out.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for server := range maps.Clone(s.sessions) {
		s.stopLocked(server)
	}
}

func reply(conn net.Conn, resp hproto.Response) { _ = json.NewEncoder(conn).Encode(resp) }
