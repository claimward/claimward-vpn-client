package helper

// Server approval. The helper runs as root, and a server it enrolls with
// chooses the routes and the peer of the machine's tunnel: a hostile server
// is every packet of the machine, sent there. The helper therefore takes a
// server from the app only if
//
//   - the administrator's configuration names it (Config.Servers), or
//   - it was approved before, and still says what it said then, or
//   - it is approved now: the SYSTEM vouches that a person with the authority
//     to do so consented (an Authorizer), asked by the helper, not claimed by
//     the app.
//
// Approved servers are kept in a file only root (SYSTEM) can write.

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

// Approval is one request for the system's consent to trust a server.
type Approval struct {
	// Server is the canonical URL, and Name what its discovery document calls
	// it: both are shown to the person where the platform allows.
	Server, Name string
	// Peer is the app's connection to the helper, which an Authorizer may
	// read the credentials of (the process behind it).
	Peer net.Conn
	// Elevated: the request came in on the helper's elevated socket
	// (Windows), which the operating system's ACL opens to elevated processes
	// alone.
	Elevated bool
	// Credential is what the app obtained from the system for this approval
	// (macOS: an AuthorizationExternalForm). It is evidence for the system to
	// judge, never a decision.
	Credential []byte
}

// ErrDenied is what an Authorizer returns when the person (or the platform)
// refused; any other error is the consent being unavailable. Both refuse.
var ErrDenied = errors.New("the system's authorization was not granted")

// An Authorizer obtains the system's consent to an Approval, or returns an
// error. It must not return nil unless the operating system said yes.
type Authorizer interface {
	Authorize(ctx context.Context, a Approval) error
}

// AuthorizerFunc adapts a function.
type AuthorizerFunc func(ctx context.Context, a Approval) error

func (f AuthorizerFunc) Authorize(ctx context.Context, a Approval) error { return f(ctx, a) }

// Identity is the SHA-256 (hex) of what makes a server the one that was
// approved: its display name and its identity providers (id, kind, issuer,
// client ids), sorted by id. These decide who the person signs in with and
// where a bearer is sent, and a server that changes them is not the one that
// was approved. Not part of it: whether the server is exclusive, its logo and
// the providers' display names, which an operator changes without changing
// who the server is; and its TLS certificate, which is renewed every few
// weeks and would make approvals expire for nothing (the connection to the
// URL is verified against the web PKI at each use anyway).
func Identity(cfg *protocol.Configuration) string {
	type prov struct {
		ID, Kind, Issuer, ClientID, GitHubClientID string
	}
	doc := struct {
		Name      string
		Providers []prov
	}{Name: cfg.ServerName}
	for _, p := range cfg.Providers {
		doc.Providers = append(doc.Providers, prov{p.ID, p.Kind, p.OIDCIssuer, p.OIDCClientID, p.GitHubClientID})
	}
	slices.SortFunc(doc.Providers, func(a, b prov) int { return cmp.Compare(a.ID, b.ID) })
	b, _ := json.Marshal(doc) // fixed field order: canonical
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// approvedEntry is one line of the approvals file.
type approvedEntry struct {
	URL        string    `json:"url"`
	Identity   string    `json:"identity"`
	Name       string    `json:"name,omitempty"`
	ApprovedAt time.Time `json:"approved_at"`
}

type approvalsFile struct {
	Version int             `json:"version"`
	Servers []approvedEntry `json:"servers"`
}

const maxApprovalsBytes = 1 << 20

// approvals is the file of approved servers. It is read afresh at every use,
// so that an administrator who edits or deletes it is obeyed at once.
type approvals struct {
	path string
	// verify refuses a file somebody other than root could have written; nil
	// in tests that stand in for root.
	verify func(path string) error
	mu     sync.Mutex
}

func (a *approvals) loadLocked() (approvalsFile, error) {
	f := approvalsFile{Version: 1}
	if a.verify != nil {
		if err := a.verify(a.path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return f, nil
			}
			return f, fmt.Errorf("%s: %w", a.path, err)
		}
	}
	b, err := readLimited(a.path)
	if err == nil {
		if err = json.Unmarshal(b, &f); err != nil {
			err = fmt.Errorf("%s: %w", a.path, err)
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		return approvalsFile{Version: 1}, nil
	}
	if err != nil {
		return approvalsFile{Version: 1}, err
	}
	return f, nil
}

// readLimited reads a file of at most maxApprovalsBytes.
func readLimited(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, maxApprovalsBytes+1))
	if err == nil && len(b) > maxApprovalsBytes {
		err = errors.New("approvals file too large")
	}
	return b, err
}

// Lookup is the approved entry for a canonical URL.
func (a *approvals) lookup(server string) (approvedEntry, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := a.loadLocked()
	if err != nil {
		return approvedEntry{}, false, err
	}
	for _, e := range f.Servers {
		if e.URL == server {
			return e, true, nil
		}
	}
	return approvedEntry{}, false, nil
}

func (a *approvals) list() ([]approvedEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := a.loadLocked()
	return f.Servers, err
}

// add records (or replaces) an approval.
func (a *approvals) add(e approvedEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := a.loadLocked()
	if err != nil {
		return err
	}
	f.Servers = slices.DeleteFunc(f.Servers, func(o approvedEntry) bool { return o.URL == e.URL })
	f.Servers = append(f.Servers, e)
	return a.saveLocked(f)
}

// remove forgets a server, and says whether it was there.
func (a *approvals) remove(server string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := a.loadLocked()
	if err != nil {
		return false, err
	}
	n := len(f.Servers)
	f.Servers = slices.DeleteFunc(f.Servers, func(o approvedEntry) bool { return o.URL == server })
	if len(f.Servers) == n {
		return false, nil
	}
	return true, a.saveLocked(f)
}

// saveLocked writes the file whole beside itself and renames it over: a crash
// leaves the old file or the new one. It is created 0600 in the directory of
// the file (root's on Unix; on Windows the protected directory of the socket,
// whose ACL the new file inherits).
func (a *approvals) saveLocked(f approvalsFile) error {
	// A directory that cannot be made shows as the write below failing.
	_ = os.MkdirAll(filepath.Dir(a.path), 0o755)
	b, _ := json.MarshalIndent(f, "", "  ") // plain strings and times: cannot fail
	tmp := a.path + ".tmp"
	err := os.WriteFile(tmp, append(b, '\n'), 0o600)
	if err == nil {
		err = os.Rename(tmp, a.path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
