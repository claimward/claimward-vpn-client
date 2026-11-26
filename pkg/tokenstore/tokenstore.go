// Package tokenstore persists the user's sessions (OIDC tokens and the device's
// WireGuard private key), one per server and identity provider, in the
// platform's secret store, never in clear on disk:
//
//   - macOS: the login Keychain, through /usr/bin/security;
//   - Windows: DPAPI (CryptProtectData), the blob kept in the user's config dir;
//   - Linux: the Secret Service (GNOME Keyring, KWallet), through secret-tool.
//
// The sessions of all servers are one document in the one secret-store entry,
// keyed by Key(canonical server URL, provider id): signing in to a second
// server never touches the first one's session.
//
// A session written by an earlier version (a single session, as a 0600 JSON
// file or as the secret-store entry) is kept as the legacy session until
// AdoptLegacy gives it a key, and the file is deleted. There is no plaintext
// fallback: on a machine with no usable secret store (no Secret Service on a
// headless Linux server, Keychain or DPAPI failing) saving fails with
// ErrNoSecretStore, and no session file is ever written.
package tokenstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Session is everything we keep between runs, for one server and provider.
type Session struct {
	// Provider is the id of the identity provider that issued Bearer (its
	// protocol.Provider.ID in the server's discovery document).
	Provider string `json:"provider,omitempty"`
	// Bearer is the opaque credential sent to the server in the Authorization
	// header (a GitHub access token or an OIDC ID token, depending on Provider).
	Bearer string `json:"bearer"`
	// BearerKind records what Bearer is ("access_token" | "id_token").
	BearerKind   string    `json:"bearer_kind,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry"`
	// WGPrivateKey is the device's stable WireGuard private key (base64). Kept so
	// the device keeps the same public key (and assigned IP) across reconnects.
	WGPrivateKey string `json:"wg_private_key,omitempty"`
	// Tenant is the tenant chosen for this session, for a person who
	// belongs to several. Empty lets the server use the person's only one.
	Tenant string `json:"tenant,omitempty"`
}

// Key is what a session is stored under: the server's canonical URL
// (secureurl.Canonical) and the provider's id. A canonical URL holds no
// space, nor a provider id, so two different pairs never make one key.
func Key(server, provider string) string { return server + " " + provider }

// legacyKey holds a session an earlier version wrote, until AdoptLegacy.
// A real key starts with a URL scheme, never with NUL.
const legacyKey = "\x00legacy"

// ErrNoSecretStore is returned when the platform has no usable secret store to
// hold the session. Its text says what is missing on this platform.
var ErrNoSecretStore = errors.New("tokenstore: no secret store available: " + storeHelp(runtime.GOOS))

// storeHelp names what to install or unlock, per platform.
func storeHelp(goos string) string {
	switch goos {
	case "linux":
		return "the session is never written to disk in clear; install and unlock a Secret Service provider (such as gnome-keyring or KeePassXC) and make sure secret-tool is installed, then sign in again"
	case "darwin":
		return "the session is never written to disk in clear; unlock the login Keychain, then sign in again"
	case "windows":
		return "the session is never written to disk in clear; Windows DPAPI failed for this account, sign in to Windows as the user who runs the app, then sign in again"
	}
	return "the session is never written to disk in clear, and this platform has no supported secret store"
}

// errNotFound is a backend's "nothing stored".
var errNotFound = errors.New("tokenstore: not found")

// backend is one place a session's bytes can live.
type backend interface {
	get() ([]byte, error) // errNotFound when empty
	set([]byte) error
	del() error // a missing entry is not an error
}

// store is the platform's backend; tests replace it.
var store backend = platformBackend()

// mu orders the read-modify-write of the one document in this process.
var mu sync.Mutex

// document is what the backend holds: every session, by Key.
type document struct {
	Version  int                 `json:"version"`
	Sessions map[string]*Session `json:"sessions"`
}

const documentVersion = 2

// Path returns the on-disk location of the legacy plaintext session file.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "claimward", "session.json"), nil
}

// decode reads what the backend held: the document, or the single session an
// earlier version wrote, which becomes the legacy session.
func decode(data []byte) (*document, error) {
	var probe struct {
		Version  int             `json:"version"`
		Sessions json.RawMessage `json:"sessions"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	if probe.Sessions != nil {
		if probe.Version != documentVersion {
			return nil, fmt.Errorf("tokenstore: document version %d is not supported", probe.Version)
		}
		var d document
		if err := json.Unmarshal(data, &d); err != nil {
			return nil, err
		}
		if d.Sessions == nil {
			d.Sessions = map[string]*Session{}
		}
		return &d, nil
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &document{Version: documentVersion, Sessions: map[string]*Session{legacyKey: &s}}, nil
}

// read loads the document; nothing stored is an empty document. A legacy
// plaintext file is migrated into the secret store and removed.
func read() (*document, error) {
	data, err := store.get()
	if errors.Is(err, errNotFound) {
		return migrate()
	}
	if err != nil {
		return nil, err
	}
	return decode(data)
}

// migrate moves a legacy plaintext file into the store, once. The file is read
// here and nowhere else. If the store refuses it, the file is deleted anyway
// (the person signs in again): a plaintext copy is never kept, and never read
// a second time.
func migrate() (*document, error) {
	empty := &document{Version: documentVersion, Sessions: map[string]*Session{}}
	p, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return nil, err
	}
	d, uerr := decode(data)
	var serr error
	if uerr == nil {
		serr = store.set(data)
	}
	if err := removeIfPresent(p); err != nil {
		return nil, err
	}
	if uerr != nil {
		return nil, uerr
	}
	if serr != nil {
		if errors.Is(serr, ErrNoSecretStore) {
			return nil, serr
		}
		return nil, fmt.Errorf("%w: %v", ErrNoSecretStore, serr)
	}
	return d, nil
}

// write stores the document, replacing the earlier one, and removes a legacy
// plaintext file. An empty document deletes the entry.
func write(d *document) error {
	if len(d.Sessions) == 0 {
		if err := store.del(); err != nil { // the legacy file is removed below either way
			return err
		}
		return removeLegacy()
	}
	data, _ := json.Marshal(d) // strings, a time and maps of them: it cannot fail
	if err := store.set(data); err != nil {
		if errors.Is(err, ErrNoSecretStore) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrNoSecretStore, err)
	}
	return removeLegacy()
}

// removeLegacy deletes the plaintext file; a missing file is not an error.
func removeLegacy() error {
	p, err := Path()
	if err != nil {
		return err
	}
	return removeIfPresent(p)
}

// removeIfPresent deletes a file; a missing file is not an error.
func removeIfPresent(p string) error {
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Load reads the session stored under key (see Key). It returns (nil, nil)
// when there is none.
func Load(key string) (*Session, error) {
	mu.Lock()
	defer mu.Unlock()
	d, err := read()
	if err != nil {
		return nil, err
	}
	if s := d.Sessions[key]; s != nil {
		c := *s
		return &c, nil
	}
	return nil, nil
}

// Save stores the session under key, replacing the earlier one there and
// leaving every other server's alone.
func Save(key string, s *Session) error {
	mu.Lock()
	defer mu.Unlock()
	d, err := read()
	if err != nil {
		// A document that cannot be read is not overwritten from a half
		// picture: only a malformed one is replaced, by this session alone.
		if !isMalformed(err) {
			if errors.Is(err, ErrNoSecretStore) {
				return err
			}
			return fmt.Errorf("%w: %v", ErrNoSecretStore, err)
		}
		d = &document{Version: documentVersion, Sessions: map[string]*Session{}}
	}
	c := *s
	d.Sessions[key] = &c
	return write(d)
}

// Clear deletes the session under key (logout). A missing session is not an
// error.
func Clear(key string) error {
	return clearWhere(func(k string) bool { return k == key })
}

// ClearServer deletes every session of a server, whatever the provider: a
// server removed from the configuration leaves no secret behind.
func ClearServer(server string) error {
	return clearWhere(func(k string) bool { return strings.HasPrefix(k, server+" ") })
}

func clearWhere(match func(string) bool) error {
	mu.Lock()
	defer mu.Unlock()
	d, err := read()
	if err != nil {
		if !isMalformed(err) {
			return err
		}
		d = &document{Version: documentVersion, Sessions: map[string]*Session{}}
	}
	for k := range d.Sessions {
		if match(k) {
			delete(d.Sessions, k)
		}
	}
	return write(d)
}

// AdoptLegacy gives the session an earlier version wrote the key it belongs
// under, if there is one and key holds none yet. It reports whether it did.
// A legacy session no key claims is deleted by Discard: it is not kept.
func AdoptLegacy(key string) (bool, error) {
	mu.Lock()
	defer mu.Unlock()
	d, err := read()
	if err != nil {
		return false, err
	}
	s := d.Sessions[legacyKey]
	if s == nil {
		return false, nil
	}
	delete(d.Sessions, legacyKey)
	if d.Sessions[key] != nil {
		return false, write(d)
	}
	d.Sessions[key] = s
	return true, write(d)
}

// DiscardLegacy deletes the session an earlier version wrote.
func DiscardLegacy() error {
	mu.Lock()
	defer mu.Unlock()
	d, err := read()
	if err != nil {
		return err
	}
	if d.Sessions[legacyKey] == nil {
		return nil
	}
	delete(d.Sessions, legacyKey)
	return write(d)
}

// isMalformed says err is a document that does not parse, as opposed to a
// store that cannot be read.
func isMalformed(err error) bool {
	var se *json.SyntaxError
	var ue *json.UnmarshalTypeError
	return errors.As(err, &se) || errors.As(err, &ue)
}

// writeAtomic writes data to p with 0600 permissions, via a rename.
func writeAtomic(p string, data []byte) error {
	os.MkdirAll(filepath.Dir(p), 0o700) // a failure shows as WriteFile's own error
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
