// Package helperclient is the app's side of the privileged helper's socket.
package helperclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/exclusive"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
)

// Client talks to the helper over its socket.
type Client struct {
	SocketPath string
	// ElevatedSocketPath is the approval socket (Windows); empty = default.
	ElevatedSocketPath string
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

// NotApprovedError is a refusal because the helper does not trust the server
// yet (Changed false) or no longer (Changed true: the server's discovery
// identity is not the one that was approved). The app answers it with
// Approve and tries again.
type NotApprovedError struct {
	Server  string
	Changed bool
	Message string
}

func (e *NotApprovedError) Error() string { return "helper: " + e.Message }

// ErrApprovalDenied is Approve's refusal: the system's consent was not given.
var ErrApprovalDenied = errors.New("approval denied")

// approveTimeout covers the person's answer to the system's prompt.
const approveTimeout = 4 * time.Minute

// Approve asks the helper to trust the server. The helper obtains the
// system's consent itself; authorization is only what the platform's
// mechanism needs from the app (macOS: the external form from
// macauth.Obtain; elsewhere nil -- Linux is asked through polkit, and
// Windows through ApproveElevated).
func (c *Client) Approve(serverURL string, authorization []byte) (*hproto.Response, error) {
	return c.callOn(c.SocketPath, approveTimeout, hproto.Request{Action: hproto.ActionApprove,
		Connect: &hproto.ConnectSpec{ServerURL: serverURL, Authorization: authorization}}, serverURL)
}

// ApproveElevated is Approve on the helper's elevated socket (Windows), which
// only an elevated process may open.
func (c *Client) ApproveElevated(serverURL string) (*hproto.Response, error) {
	path := c.ElevatedSocketPath
	if path == "" {
		path = hproto.DefaultElevatedSocketPath
	}
	if path == "" {
		return nil, errors.New("this platform has no elevated socket")
	}
	return c.callOn(path, approveTimeout, hproto.Request{Action: hproto.ActionApprove,
		Connect: &hproto.ConnectSpec{ServerURL: serverURL}}, serverURL)
}

// Revoke makes the helper forget an approved server and take its tunnel down.
func (c *Client) Revoke(serverURL string) (*hproto.Response, error) {
	return c.call(15*time.Second, hproto.Request{Action: hproto.ActionRevoke,
		Connect: &hproto.ConnectSpec{ServerURL: serverURL}}, serverURL)
}

// Approved lists the servers the helper trusts (resp.Approved).
func (c *Client) Approved() (*hproto.Response, error) {
	return c.call(5*time.Second, hproto.Request{Action: hproto.ActionApproved}, "")
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
	return c.callOn(c.SocketPath, timeout, req, server)
}

func (c *Client) callOn(path string, timeout time.Duration, req hproto.Request, server string) (*hproto.Response, error) {
	conn, err := net.DialTimeout("unix", path, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("helper not reachable at %s (is it installed and running?): %w", path, err)
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
		switch resp.ErrorCode {
		case hproto.ErrNotApproved, hproto.ErrIdentityChanged:
			return &resp, &NotApprovedError{Server: server, Changed: resp.ErrorCode == hproto.ErrIdentityChanged, Message: resp.Error}
		case hproto.ErrApprovalDenied:
			return &resp, fmt.Errorf("%w: %s", ErrApprovalDenied, resp.Error)
		}
		return &resp, fmt.Errorf("helper: %s", resp.Error)
	}
	return &resp, nil
}
