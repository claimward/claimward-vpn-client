package helperclient

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/exclusive"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
)

// fakeHelper answers every request with resp, on a socket of its own.
func fakeHelper(t *testing.T, resp hproto.Response) *Client {
	t.Helper()
	// A short path: an AF_UNIX socket's is limited (104 bytes on macOS).
	dir, err := os.MkdirTemp("", "hcl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var req hproto.Request
			_ = json.NewDecoder(c).Decode(&req)
			_ = json.NewEncoder(c).Encode(resp)
			c.Close()
		}
	}()
	return &Client{SocketPath: path, ElevatedSocketPath: path}
}

// Every helper refusal, on every path, is a typed error carrying the helper's
// error_code: a caller uses errors.As and the code, never the message, which
// here is worded as no caller could have matched it.
func TestEveryPathSurfacesTheRefusalCode(t *testing.T) {
	paths := map[string]func(c *Client) error{
		"connect":          func(c *Client) error { _, err := c.Connect(hproto.ConnectSpec{ServerURL: "https://a"}); return err },
		"tenants":          func(c *Client) error { _, err := c.Tenants("https://a", "p", "b"); return err },
		"renew":            func(c *Client) error { _, err := c.Renew("https://a", "p", "b"); return err },
		"disconnect":       func(c *Client) error { _, err := c.Down("https://a"); return err },
		"disconnect all":   func(c *Client) error { _, err := c.DownAll(); return err },
		"status":           func(c *Client) error { _, err := c.Status(); return err },
		"revoke":           func(c *Client) error { _, err := c.Revoke("https://a"); return err },
		"approve":          func(c *Client) error { _, err := c.Approve("https://a", nil); return err },
		"approve elevated": func(c *Client) error { _, err := c.ApproveElevated("https://a"); return err },
		"approved":         func(c *Client) error { _, err := c.Approved(); return err },
	}
	for _, code := range []string{hproto.ErrNotOwner, hproto.ErrCallerUnidentified} {
		for _, msg := range []string{"original wording", "something else entirely, reworded"} {
			c := fakeHelper(t, hproto.Response{Error: msg, ErrorCode: code})
			for name, call := range paths {
				err := call(c)
				var r *RefusalError
				if !errors.As(err, &r) {
					t.Errorf("%s / %s: %T %v is not a *RefusalError", name, code, err, err)
					continue
				}
				if r.Code != code || r.Message != msg {
					t.Errorf("%s: code %q message %q, want %q %q", name, r.Code, r.Message, code, msg)
				}
				if got := CodeOf(err); got != code {
					t.Errorf("%s: CodeOf = %q, want %q", name, got, code)
				}
				if err.Error() != "helper: "+msg {
					t.Errorf("%s: text %q changed", name, err.Error())
				}
			}
		}
	}
}

// The more specific types keep their identity, and CodeOf sees through them.
func TestSpecificRefusalsKeepTheirTypeAndCode(t *testing.T) {
	c := fakeHelper(t, hproto.Response{Error: "x", ErrorCode: hproto.ErrNotApproved})
	_, err := c.Connect(hproto.ConnectSpec{ServerURL: "https://a"})
	var na *NotApprovedError
	if !errors.As(err, &na) || na.Changed || CodeOf(err) != hproto.ErrNotApproved {
		t.Errorf("not approved: %T %v code %q", err, err, CodeOf(err))
	}
	c = fakeHelper(t, hproto.Response{Error: "x", ErrorCode: hproto.ErrIdentityChanged})
	_, err = c.Connect(hproto.ConnectSpec{ServerURL: "https://a"})
	if !errors.As(err, &na) || !na.Changed || CodeOf(err) != hproto.ErrIdentityChanged {
		t.Errorf("identity changed: %T %v code %q", err, err, CodeOf(err))
	}
	c = fakeHelper(t, hproto.Response{Error: "x", ErrorCode: hproto.ErrExclusive, BlockedBy: "other"})
	_, err = c.Connect(hproto.ConnectSpec{ServerURL: "https://a"})
	var ex *exclusive.Error
	if !errors.As(err, &ex) || CodeOf(err) != hproto.ErrExclusive {
		t.Errorf("exclusive: %T %v code %q", err, err, CodeOf(err))
	}
	c = fakeHelper(t, hproto.Response{Error: "no", ErrorCode: hproto.ErrApprovalDenied})
	_, err = c.Approve("https://a", nil)
	if !errors.Is(err, ErrApprovalDenied) || CodeOf(err) != hproto.ErrApprovalDenied {
		t.Errorf("approval denied: %T %v code %q", err, err, CodeOf(err))
	}
}

// A refusal from a helper that gives no code is still a typed error, with an
// empty code; failures that are not refusals have none.
func TestNoCodeAndNotARefusal(t *testing.T) {
	c := fakeHelper(t, hproto.Response{Error: "old helper"})
	_, err := c.Status()
	var r *RefusalError
	if !errors.As(err, &r) || r.Code != "" || CodeOf(err) != "" {
		t.Errorf("%T %v", err, err)
	}
	if _, err := (&Client{SocketPath: filepath.Join(t.TempDir(), "none.sock")}).Status(); err == nil || CodeOf(err) != "" {
		t.Errorf("an unreachable helper: %v code %q", err, CodeOf(err))
	}
	if CodeOf(nil) != "" {
		t.Error("CodeOf(nil)")
	}
}
