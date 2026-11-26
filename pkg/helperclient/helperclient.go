// Package helperclient is the app's side of the privileged helper's socket.
package helperclient

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/exclusive"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
)

// Client talks to the helper over its socket.
type Client struct {
	SocketPath string
}

// New returns a Client for the given socket path (empty = default).
func New(socketPath string) *Client {
	if socketPath == "" {
		socketPath = hproto.DefaultSocketPath
	}
	return &Client{SocketPath: socketPath}
}

// Connect asks the helper to enroll, bring the server's tunnel up and watch
// routes. A refusal because a server is exclusive is an *exclusive.Error
// (errors.As), naming the server in the way.
func (c *Client) Connect(spec hproto.ConnectSpec) (*hproto.Response, error) {
	return c.call(60*time.Second, hproto.Request{Action: hproto.ActionConnect, Connect: &spec}, spec.ServerURL)
}

// Tenants asks the helper which tenants the bearer may connect to at the
// server, signed in with the provider.
func (c *Client) Tenants(serverURL, provider, bearer string) (*hproto.Response, error) {
	return c.call(30*time.Second, hproto.Request{Action: hproto.ActionTenants,
		Connect: &hproto.ConnectSpec{ServerURL: serverURL, Provider: provider, Bearer: bearer}}, serverURL)
}

// Renew hands the helper a fresh bearer for the tunnel it holds to the
// server, and has it renew that lease with it now.
func (c *Client) Renew(serverURL, provider, bearer string) (*hproto.Response, error) {
	return c.call(45*time.Second, hproto.Request{Action: hproto.ActionRenew,
		Connect: &hproto.ConnectSpec{ServerURL: serverURL, Provider: provider, Bearer: bearer}}, serverURL)
}

// Down tears the server's tunnel down.
func (c *Client) Down(serverURL string) (*hproto.Response, error) {
	return c.call(15*time.Second, hproto.Request{Action: hproto.ActionDown,
		Connect: &hproto.ConnectSpec{ServerURL: serverURL}}, serverURL)
}

// DownAll tears every tunnel down.
func (c *Client) DownAll() (*hproto.Response, error) {
	return c.call(30*time.Second, hproto.Request{Action: hproto.ActionDown}, "")
}

// Status queries the helper's state, briefly: the UI asks it periodically. It
// answers for every server.
func (c *Client) Status() (*hproto.Response, error) {
	return c.call(3*time.Second, hproto.Request{Action: hproto.ActionStatus}, "")
}

// Available reports whether the helper's socket answers.
func (c *Client) Available() bool {
	conn, err := net.DialTimeout("unix", c.SocketPath, 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (c *Client) call(timeout time.Duration, req hproto.Request, server string) (*hproto.Response, error) {
	conn, err := net.DialTimeout("unix", c.SocketPath, timeout)
	if err != nil {
		return nil, fmt.Errorf("helper not reachable at %s (is it installed and running?): %w", c.SocketPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	var resp hproto.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if !resp.OK && resp.Error != "" {
		if resp.ErrorCode == hproto.ErrExclusive {
			return &resp, &exclusive.Error{
				Server:  exclusive.Member{URL: server},
				Blocker: exclusive.Member{Name: resp.BlockedBy},
				Reason:  "helper: " + resp.Error,
			}
		}
		return &resp, fmt.Errorf("helper: %s", resp.Error)
	}
	return &resp, nil
}
