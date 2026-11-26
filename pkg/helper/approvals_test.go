package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/helperclient"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

// rawRequest sends a request as the app's client never would.
func rawRequest(t *testing.T, c *helperclient.Client, req any) hproto.Response {
	t.Helper()
	conn, err := net.Dial("unix", c.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	json.NewEncoder(conn).Encode(req)
	var resp hproto.Response
	json.NewDecoder(conn).Decode(&resp)
	return resp
}

func storeIn(t *testing.T) *approvals {
	t.Helper()
	return &approvals{path: filepath.Join(t.TempDir(), "sub", "approved.json")}
}

func TestTheApprovalsFileRoundTrips(t *testing.T) {
	a := storeIn(t)
	if es, err := a.list(); err != nil || len(es) != 0 {
		t.Fatalf("an absent file: %v %v", es, err)
	}
	if ok, err := a.remove("https://x"); ok || err != nil {
		t.Errorf("removing from nothing: %v %v", ok, err)
	}
	if _, err := os.Stat(a.path); err == nil {
		t.Error("removing a server that was not there wrote a file")
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := a.add(approvedEntry{URL: "https://x", Identity: "1", ApprovedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := a.add(approvedEntry{URL: "https://x", Identity: "2", ApprovedAt: now}); err != nil { // replaces
		t.Fatal(err)
	}
	if err := a.add(approvedEntry{URL: "https://y", Identity: "3", ApprovedAt: now}); err != nil {
		t.Fatal(err)
	}
	e, ok, err := a.lookup("https://x")
	if err != nil || !ok || e.Identity != "2" {
		t.Errorf("lookup: %+v %v %v", e, ok, err)
	}
	if _, ok, _ := a.lookup("https://z"); ok {
		t.Error("a server nobody approved was found")
	}
	if ok, err := a.remove("https://z"); ok || err != nil {
		t.Errorf("removing an unknown server: %v %v", ok, err)
	}
	if ok, err := a.remove("https://x"); !ok || err != nil {
		t.Errorf("remove: %v %v", ok, err)
	}
	if es, _ := a.list(); len(es) != 1 || es[0].URL != "https://y" {
		t.Errorf("after remove: %+v", es)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(a.path), ".approved-*"))
	if len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

// ⛔ A file that cannot be trusted is never read as "nobody approved" or as
// "everybody": every use of it fails.
func TestAnApprovalsFileThatCannotBeReadFailsClosed(t *testing.T) {
	a := storeIn(t)
	os.MkdirAll(filepath.Dir(a.path), 0o755)
	for name, body := range map[string]string{
		"corrupt":   `{"servers": [`,
		"oversized": strings.Repeat(" ", maxApprovalsBytes+10) + `{"version":1}`,
	} {
		if err := os.WriteFile(a.path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := a.lookup("https://x"); err == nil {
			t.Errorf("%s: lookup", name)
		}
		if _, err := a.list(); err == nil {
			t.Errorf("%s: list", name)
		}
		if err := a.add(approvedEntry{URL: "https://x"}); err == nil {
			t.Errorf("%s: add", name)
		}
		if _, err := a.remove("https://x"); err == nil {
			t.Errorf("%s: remove", name)
		}
	}
	// The ownership check decides before the file is opened: an absent file is
	// empty, any other refusal is an error.
	os.Remove(a.path)
	a.verify = func(string) error { return os.ErrNotExist }
	if es, err := a.list(); err != nil || len(es) != 0 {
		t.Errorf("verify says absent: %v %v", es, err)
	}
	a.verify = func(string) error { return errors.New("owned by somebody") }
	if _, err := a.list(); err == nil || !strings.Contains(err.Error(), "owned by somebody") {
		t.Errorf("verify refuses: %v", err)
	}
	// A file that exists but cannot be opened.
	a.verify = nil
	if os.Getuid() != 0 {
		if err := os.WriteFile(a.path, []byte(`{}`), 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := a.list(); err == nil {
			t.Error("an unreadable file was read")
		}
	}
}

// A file that cannot be written fails the operation, and leaves nothing
// behind.
func TestAnApprovalsFileThatCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	os.WriteFile(blocker, nil, 0o600)
	// The directory cannot be made: its parent is a file.
	if err := (&approvals{path: filepath.Join(blocker, "x", "approved.json")}).add(approvedEntry{URL: "https://x"}); err == nil {
		t.Error("add under a file")
	}
	// The rename fails: the target is a directory.
	target := filepath.Join(dir, "approved.json")
	os.MkdirAll(filepath.Join(target, "held"), 0o755)
	a := &approvals{path: target}
	if err := a.add(approvedEntry{URL: "https://x"}); err == nil {
		t.Error("add over a directory")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".approved-*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
	// The temporary file cannot be created: the directory is not writable.
	if os.Getuid() != 0 {
		ro := filepath.Join(dir, "ro")
		os.Mkdir(ro, 0o500)
		if err := (&approvals{path: filepath.Join(ro, "approved.json")}).add(approvedEntry{URL: "https://x"}); err == nil {
			t.Error("add in a read-only directory")
		}
	}
}

// What the helper answers when the file is damaged or cannot be written, as
// the app sees it.
func TestApprovalOverAFileThatFails(t *testing.T) {
	v := newVPNServer(t)
	c, s, _ := helperFor(t)
	sys := &consent{yes: true}
	s.UseAuthorizer(sys)
	name := "Chemistry"
	docName(s, &name)

	// Cannot be remembered: the person's yes is not turned into a trust.
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, nil, 0o600)
	s.approvals.path = filepath.Join(blocker, "approved.json")
	_, err := c.Approve(v.URL, nil)
	if err == nil || errors.Is(err, helperclient.ErrApprovalDenied) || !strings.Contains(err.Error(), "remember the approval") {
		t.Errorf("approve with an unwritable file: %v", err)
	}
	var na *helperclient.NotApprovedError
	if err := connect(t, c, v.URL); err == nil {
		t.Error("connect with an unreadable file")
	}

	// Damaged: everything that reads it fails, and says so.
	s.approvals.path = filepath.Join(t.TempDir(), "approved.json")
	os.WriteFile(s.approvals.path, []byte("{"), 0o600)
	if _, err := c.Approved(); err == nil || !strings.Contains(err.Error(), "approved servers") {
		t.Errorf("listing from a damaged file: %v", err)
	}
	if _, err := c.Revoke(v.URL); err == nil || !strings.Contains(err.Error(), "forget the approval") {
		t.Errorf("revoking from a damaged file: %v", err)
	}
	if err := connect(t, c, v.URL); err == nil || errors.As(err, &na) {
		t.Errorf("connect with a damaged file: %v", err)
	}
}

// Requests that name no server, or a bad one, are refused before anything is
// asked of the system or the server.
func TestApprovalRequestsAreChecked(t *testing.T) {
	c, s, _ := helperFor(t)
	sys := &consent{yes: true}
	s.UseAuthorizer(sys)
	for _, bad := range []string{"", "http://vpn.example.org", "not a url"} {
		if _, err := c.Approve(bad, nil); err == nil {
			t.Errorf("approve %q", bad)
		}
		if _, err := c.Revoke(bad); err == nil {
			t.Errorf("revoke %q", bad)
		}
	}
	// A request with no connect member at all.
	for _, action := range []string{"approve", "revoke"} {
		if resp := rawRequest(t, c, map[string]any{"action": action}); resp.OK || !strings.Contains(resp.Error, "missing server") {
			t.Errorf("%s with nothing: %+v", action, resp)
		}
	}
	// And a tenants request with no bearer is refused before anyone is asked.
	if _, err := c.Tenants("https://vpn.example.org", "", ""); err == nil {
		t.Error("tenants with no bearer")
	}
	if sys.count() != 0 {
		t.Errorf("the system was asked %d times for requests that were refused", sys.count())
	}
}

// A server that does not answer cannot be approved: there is nothing to show
// the person, and no identity to remember.
func TestAServerThatDoesNotAnswerIsNotApproved(t *testing.T) {
	v := newVPNServer(t)
	c, s, _ := helperFor(t)
	sys := &consent{yes: true}
	s.UseAuthorizer(sys)
	s.UseDiscovery(func(_ context.Context, _ string) (*protocol.Configuration, error) { return nil, errors.New("no route") })
	if _, err := c.Approve(v.URL, nil); err == nil || !strings.Contains(err.Error(), "discovery") {
		t.Errorf("approve: %v", err)
	}
	s.UseDiscovery(func(_ context.Context, _ string) (*protocol.Configuration, error) { return nil, nil })
	if _, err := c.Approve(v.URL, nil); err == nil || !strings.Contains(err.Error(), "discovery") {
		t.Errorf("approve with an empty answer: %v", err)
	}
	if sys.count() != 0 {
		t.Error("the system was asked about a server that could not be read")
	}
}

func TestAnApprovalsPathThatIsADirectoryIsAnError(t *testing.T) {
	a := &approvals{path: t.TempDir()}
	if _, err := a.list(); err == nil {
		t.Error("a directory was read as an approvals file")
	}
}

func TestSaveFailuresAreReported(t *testing.T) {
	dir := t.TempDir()
	// Temp file cannot be created: a parent that is a regular file.
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	a := &approvals{path: filepath.Join(file, "approved.json")}
	if err := a.saveLocked(approvalsFile{Version: 1}); err == nil {
		t.Error("write under a regular file succeeded")
	}
	// Rename cannot replace a non-empty directory.
	d := filepath.Join(dir, "d")
	if err := os.MkdirAll(filepath.Join(d, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	b := &approvals{path: d}
	if err := b.saveLocked(approvalsFile{Version: 1}); err == nil {
		t.Error("rename over a directory succeeded")
	}
	if _, err := os.Stat(d + ".tmp"); err == nil {
		t.Error("temp file left behind")
	}
}
