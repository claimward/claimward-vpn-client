package helperclient

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// The wording of each failure that is not a refusal, and of ErrApprovalDenied's.
func TestTransportFailuresAndWording(t *testing.T) {
	c := fakeHelper(t, hproto.Response{Error: "why", ErrorCode: hproto.ErrApprovalDenied})
	_, err := c.Approve("https://a", nil)
	if err == nil || err.Error() != "approval denied: why" {
		t.Errorf("approval denied text: %v", err)
	}
	// A helper that hangs up without answering.
	dir, derr := os.MkdirTemp("", "hcl")
	if derr != nil {
		t.Fatal(derr)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "h.sock")
	ln, lerr := net.Listen("unix", path)
	if lerr != nil {
		t.Fatal(lerr)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	if _, err := (&Client{SocketPath: path}).Status(); err == nil || CodeOf(err) != "" {
		t.Errorf("a helper that hung up: %v", err)
	}
	if _, err := (&Client{SocketPath: filepath.Join(dir, "none.sock")}).Status(); err == nil {
		t.Error("an unreachable helper answered")
	}
	// No elevated socket on this platform: an error, not a connection to "".
	if hproto.DefaultElevatedSocketPath == "" {
		if _, err := (&Client{SocketPath: path}).ApproveElevated("https://a"); err == nil || err.Error() != "this platform has no elevated socket" {
			t.Errorf("elevated: %v", err)
		}
	}
}

func TestAvailableAndUnreachable(t *testing.T) {
	c := fakeHelper(t, hproto.Response{OK: true})
	if !c.Available() {
		t.Error("a listening helper is not available")
	}
	dir, derr := os.MkdirTemp("", "hcl")
	if derr != nil {
		t.Fatal(derr)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	gone := &Client{SocketPath: filepath.Join(dir, "x")}
	if gone.Available() {
		t.Error("a missing socket is available")
	}
	_, err := gone.Status()
	if err == nil || !strings.Contains(err.Error(), "helper not reachable") {
		t.Errorf("unreachable: %v", err)
	}
	// Windows reports a refused connection, not a missing file.
	if err != nil && runtime.GOOS != "windows" && !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unreachable is not ErrNotExist: %v", err)
	}
}

// A helper that hangs up before reading a request larger than the socket's
// buffer: the failure is the sending, and is said so.
func TestASendThatFailsIsReportedAsSuch(t *testing.T) {
	dir, derr := os.MkdirTemp("", "hcl")
	if derr != nil {
		t.Fatal(derr)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "h.sock")
	ln, lerr := net.Listen("unix", path)
	if lerr != nil {
		t.Fatal(lerr)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, err := (&Client{SocketPath: path}).Connect(hproto.ConnectSpec{ServerURL: "https://a", Bearer: strings.Repeat("x", 8<<20)})
	// Windows lets the send complete and fails on the read instead.
	if err == nil || !(strings.Contains(err.Error(), "send request") || (runtime.GOOS == "windows" && strings.Contains(err.Error(), "read response"))) {
		t.Errorf("%v", err)
	}
}
