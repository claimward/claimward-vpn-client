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
	cfg              Config
	os, platform     string
	log              *slog.Logger
	up               func(wgtun.Config) (Tunnel, error)
	watch            func(ctx context.Context, endpoint, bearer, publicKey string, onUpdate func(routeclient.Update)) error
	enrollTimeout    time.Duration
	mu               sync.Mutex
	tun              Tunnel
	assigned, tenant string
	watchCancel      context.CancelFunc
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
	defer s.mu.Unlock()
	s.stopLocked()
	tun, err := s.up(cfg)
	if err != nil {
		return hproto.Response{Error: err.Error()}
	}
	s.tun, s.assigned, s.tenant = tun, resp.AssignedIP, spec.Tenant
	if resp.GRPCEndpoint != "" {
		wctx, wcancel := context.WithCancel(context.Background())
		s.watchCancel = wcancel
		ep, bearer, pub := resp.GRPCEndpoint, spec.Bearer, pair.Public.String()
		go func() {
			err := s.watch(wctx, ep, bearer, pub, func(u routeclient.Update) {
				s.mu.Lock()
				t := s.tun
				s.mu.Unlock()
				if t == nil {
					return
				}
				if e := t.UpdateRoutes(u.AllowedIPs); e != nil {
					s.log.Error("apply pushed routes", "err", e)
				} else {
					s.log.Info("routes updated", "serial", u.Serial, "allowed_ips", u.AllowedIPs)
				}
			})
			if err != nil && wctx.Err() == nil {
				s.log.Warn("route watch ended", "err", err)
			}
		}()
	}
	s.log.Info("connected", "interface", tun.Name(), "assigned", resp.AssignedIP, "tenant", spec.Tenant, "routes", resp.AllowedIPs)
	return hproto.Response{OK: true, Connected: true, Interface: tun.Name(), AssignedIP: resp.AssignedIP, Tenant: spec.Tenant}
}

func (s *Server) down() hproto.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
	return hproto.Response{OK: true}
}

func (s *Server) stopLocked() {
	if s.watchCancel != nil {
		s.watchCancel()
		s.watchCancel = nil
	}
	if s.tun != nil {
		_ = s.tun.Close()
		s.tun, s.assigned, s.tenant = nil, "", ""
		s.log.Info("tunnel down")
	}
}

func (s *Server) status() hproto.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := hproto.Response{OK: true, Connected: s.tun != nil}
	if s.tun != nil {
		resp.Interface, resp.AssignedIP, resp.Tenant = s.tun.Name(), s.assigned, s.tenant
	}
	return resp
}

// Shutdown takes the tunnel down, for a helper that is stopping.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

func reply(conn net.Conn, resp hproto.Response) { _ = json.NewEncoder(conn).Encode(resp) }
