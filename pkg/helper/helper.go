// Package helper is the privileged side of a Claimward app: the process that
// runs as root (or SYSTEM), owns the tunnel, and does the server comms --
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
//   - Its socket is 0660, for root and one group (listen_unix.go); the
//     previous helper's was 0666.
package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/client"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/routeclient"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
	"github.com/claimward/claimward-vpn-client/pkg/wgtun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config is the helper's own configuration, read from a file only an
// administrator can write.
type Config struct {
	// Servers are the claimward-vpn-server base URLs the helper may enroll
	// with. Required: a helper that trusts no server connects nowhere.
	Servers []string `json:"servers"`
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
	if len(c.Servers) == 0 {
		return nil, fmt.Errorf("%s: no servers: the helper must be told which claimward-vpn-server it may connect to", path)
	}
	if c.Group == "" {
		c.Group = DefaultGroup
	}
	if c.Socket == "" {
		c.Socket = hproto.DefaultSocketPath
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
	watch         func(ctx context.Context, endpoint, bearer, publicKey string, onUpdate func(routeclient.Update)) error
	enrollTimeout time.Duration
	// renewAfter is how long after a renewal the next one is due, from the
	// time the lease has left (renewDelay).
	renewAfter func(remaining time.Duration) time.Duration
	// retryAfter is how long to wait after a renewal that did not reach the
	// server, or reached it broken.
	retryAfter time.Duration

	mu sync.Mutex
	// sess is the enrollment behind the live tunnel; nil when down.
	sess *session
	// gen counts the sessions: a renewal that finds a newer one acts on
	// nothing.
	gen     uint64
	lastErr string
}

// superseded is a re-enrollment that found a newer session, or none.
const superseded = "superseded"

// session is one enrollment and the tunnel brought up from it.
type session struct {
	gen      uint64
	server   string
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
// 30 s nor later than an hour.
func renewDelay(remaining time.Duration) time.Duration {
	return min(max(remaining/2, 30*time.Second), time.Hour)
}

// New is a helper for the platform os ("darwin", "linux", "windows") and app
// ("app-osx", ...), as the server's admin sees the device.
func New(cfg Config, os, platform string, log *slog.Logger) *Server {
	return &Server{
		cfg: cfg, os: os, platform: platform, log: log,
		up: func(c wgtun.Config) (Tunnel, error) {
			t, err := wgtun.Up(c)
			if err != nil {
				return nil, err
			}
			return t, nil
		},
		watch:         routeclient.Watch,
		enrollTimeout: 30 * time.Second,
		renewAfter:    renewDelay,
		retryAfter:    time.Minute,
	}
}

// UseTunnels replaces how a tunnel is brought up (wgtun.Up by default): for
// tests, and for a platform that brings tunnels up another way.
func (s *Server) UseTunnels(up func(wgtun.Config) (Tunnel, error)) { s.up = up }

// UseRouteWatch replaces how route pushes are watched (routeclient.Watch by
// default).
func (s *Server) UseRouteWatch(w func(ctx context.Context, endpoint, bearer, publicKey string, onUpdate func(routeclient.Update)) error) {
	s.watch = w
}

// Serve answers connections until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	var req hproto.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
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
		reply(conn, s.down())
	case hproto.ActionStatus:
		reply(conn, s.status())
	default:
		reply(conn, hproto.Response{Error: "unknown action: " + req.Action})
	}
}

// allowed is the server URL as configured, if spec names one.
func (s *Server) allowed(spec *hproto.ConnectSpec) (string, error) {
	if spec == nil || spec.Bearer == "" {
		return "", errors.New("missing connect spec")
	}
	want := strings.TrimRight(spec.ServerURL, "/")
	for _, u := range s.cfg.Servers {
		if strings.TrimRight(u, "/") == want {
			return u, nil
		}
	}
	return "", fmt.Errorf("server %q is not one this helper is configured for", spec.ServerURL)
}

func (s *Server) tenants(spec *hproto.ConnectSpec) hproto.Response {
	server, err := s.allowed(spec)
	if err != nil {
		return hproto.Response{Error: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.enrollTimeout)
	defer cancel()
	ts, err := client.New(server).Tenants(ctx, spec.Bearer)
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
	return s.enroll(spec, 0)
}

// enroll enrolls with the server spec names, brings the tunnel up from its
// answer and starts renewing the lease. A non-zero gen is a re-enrollment
// by that session's renewal loop, which gives way to anything that happened
// since (a disconnect, another connect).
func (s *Server) enroll(spec *hproto.ConnectSpec, gen uint64) hproto.Response {
	server, err := s.allowed(spec)
	if err != nil {
		return hproto.Response{Error: err.Error()}
	}
	pair, err := wgkey.ParsePrivate(spec.PrivateKey)
	if err != nil {
		return hproto.Response{Error: "private key: " + err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.enrollTimeout)
	defer cancel()
	resp, err := client.New(server).Enroll(ctx, spec.Bearer, pair.Public, protocol.DeviceInfo{
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
	if gen != 0 && s.gen != gen {
		// Disconnected, or connected again, while this re-enrolled. The
		// enrollment just made is given back -- unless the live session is
		// that same key at that same server, which another re-enrollment
		// raced this one to: giving it back would cut the live tunnel.
		cur := s.sess
		s.mu.Unlock()
		if cur == nil || cur.server != server || cur.pub != pair.Public {
			s.deregister(&session{server: server, spec: *spec, pub: pair.Public})
		}
		return hproto.Response{Error: superseded}
	}
	old := s.stopLocked()
	if old != nil && (old.server != server || old.pub != pair.Public) {
		// The previous enrollment is somebody else's lease now: give it back.
		go s.deregister(old)
	}
	tun, err := s.up(cfg)
	if err != nil {
		s.lastErr = err.Error()
		s.mu.Unlock()
		return hproto.Response{Error: err.Error()}
	}
	s.gen++
	sctx, scancel := context.WithCancel(context.Background())
	sess := &session{
		gen: s.gen, server: server, spec: *spec, pub: pair.Public,
		tun: tun, assigned: resp.AssignedIP, wake: make(chan struct{}, 1), cancel: scancel,
	}
	s.setLeaseLocked(sess, resp.LeaseExpiresAt)
	s.sess, s.lastErr = sess, ""
	s.mu.Unlock()

	go s.renewLoop(sctx, sess)
	if resp.GRPCEndpoint != "" {
		go s.watchRoutes(sctx, sess, resp.GRPCEndpoint)
	}
	s.log.Info("connected", "interface", tun.Name(), "assigned", resp.AssignedIP, "tenant", spec.Tenant, "routes", resp.AllowedIPs, "lease", resp.LeaseExpiresAt)
	return s.status()
}

func (s *Server) watchRoutes(ctx context.Context, sess *session, endpoint string) {
	s.mu.Lock()
	bearer := sess.spec.Bearer
	s.mu.Unlock()
	err := s.watch(ctx, endpoint, bearer, sess.pub.String(), func(u routeclient.Update) {
		if ctx.Err() != nil {
			return // the tunnel is going down
		}
		if e := sess.tun.UpdateRoutes(u.AllowedIPs); e != nil {
			s.log.Error("apply pushed routes", "err", e)
		} else {
			s.log.Info("routes updated", "serial", u.Serial, "allowed_ips", u.AllowedIPs)
		}
	})
	if err != nil && ctx.Err() == nil {
		s.log.Warn("route watch ended", "err", err)
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
	resp, err := client.New(sess.server).Heartbeat(hctx, bearer, sess.pub)
	cancel()
	if ctx.Err() != nil {
		return false
	}
	var se *client.ServerError
	switch {
	case err == nil:
		s.mu.Lock()
		s.setLeaseLocked(sess, resp.LeaseExpiresAt)
		if s.sess == sess {
			s.lastErr = ""
		}
		s.mu.Unlock()
		s.log.Info("lease renewed", "until", resp.LeaseExpiresAt)
		return true

	case errors.As(err, &se) && se.Status == http.StatusNotFound:
		// The server no longer knows the peer: its lease ran out, or the
		// server restarted (it keeps leases in memory). Enroll again, with
		// the same key and tenant; failing that the tunnel leads nowhere.
		s.log.Warn("the server forgot this device; enrolling again", "err", err)
		s.mu.Lock()
		spec := sess.spec
		s.mu.Unlock()
		if r := s.enroll(&spec, sess.gen); !r.OK && r.Error != superseded {
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
		s.lastErr = "renewal failed: " + err.Error()
		left := time.Until(sess.lease)
		if sess.lease.IsZero() {
			left = s.retryAfter * 2
		}
		sess.renewBy = time.Now().Add(min(s.retryAfter, max(left/2, time.Second)))
		s.mu.Unlock()
		s.log.Warn("lease renewal failed; retrying", "err", err)
		return true
	}
}

// drop takes sess's tunnel down, if it is still the live one, because the
// server no longer carries it.
func (s *Server) drop(sess *session, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess != sess {
		return
	}
	s.stopLocked()
	s.lastErr = why
	s.log.Error("tunnel taken down", "why", why)
}

// renewNow is ActionRenew: a fresh bearer for the live session, and a
// renewal with it now.
func (s *Server) renewNow(spec *hproto.ConnectSpec) hproto.Response {
	if spec == nil || spec.Bearer == "" {
		return hproto.Response{Error: "missing bearer"}
	}
	s.mu.Lock()
	sess := s.sess
	if sess == nil {
		s.mu.Unlock()
		return hproto.Response{Error: "not connected"}
	}
	sess.spec.Bearer = spec.Bearer
	s.mu.Unlock()
	s.renew(context.Background(), sess)
	// Whatever renew did -- renewed, retried, re-enrolled, dropped -- the
	// status says where that left the tunnel, and LastError why not.
	st := s.status()
	if st.LastError != "" {
		st.OK, st.Error = false, st.LastError
	}
	return st
}

func (s *Server) down() hproto.Response {
	s.mu.Lock()
	old := s.stopLocked()
	s.lastErr = ""
	s.mu.Unlock()
	if old != nil {
		s.deregister(old)
	}
	return hproto.Response{OK: true}
}

// deregister gives the peer's address back to the server, rather than leave
// it held until the lease ends. Best effort: a server that cannot be told
// reaps the peer when the lease runs out.
func (s *Server) deregister(sess *session) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.New(sess.server).Deregister(ctx, sess.spec.Bearer, sess.pub); err != nil {
		s.log.Warn("deregister", "err", err)
	}
}

// stopLocked takes the tunnel down and returns the session it belonged to.
func (s *Server) stopLocked() *session {
	old := s.sess
	if old == nil {
		return nil
	}
	old.cancel()
	_ = old.tun.Close()
	s.sess = nil
	s.gen++
	s.log.Info("tunnel down")
	return old
}

func (s *Server) status() hproto.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := hproto.Response{OK: true, Connected: s.sess != nil, LastError: s.lastErr}
	if sess := s.sess; sess != nil {
		resp.Interface, resp.AssignedIP, resp.Tenant = sess.tun.Name(), sess.assigned, sess.spec.Tenant
		if !sess.lease.IsZero() {
			lease := sess.lease
			resp.LeaseExpiresAt = &lease
		}
	}
	return resp
}

// Shutdown takes the tunnel down, for a helper that is stopping. It does not
// deregister: a helper restarted by its service manager finds the server
// still holding the lease, and a stopped machine's lease runs out.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

func reply(conn net.Conn, resp hproto.Response) { _ = json.NewEncoder(conn).Encode(resp) }
