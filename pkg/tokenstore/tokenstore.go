// Package tokenstore persists the user's session (OIDC tokens and the device's
// WireGuard private key) in the platform's secret store, never in clear on
// disk:
//
//   - macOS: the login Keychain, through /usr/bin/security;
//   - Windows: DPAPI (CryptProtectData), the blob kept in the user's config dir;
//   - Linux: the Secret Service (GNOME Keyring, KWallet), through secret-tool.
//
// A session written by an earlier version as a 0600 JSON file is moved into
// the store on first load and the file deleted. On a machine with no secret
// store (a headless Linux server) saving fails with ErrNoSecretStore, unless
// CLAIMWARD_ALLOW_PLAINTEXT_SESSION=1 opts into the old 0600 file.
package tokenstore

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Session is everything we keep between CLI invocations.
type Session struct {
	// Provider is the auth provider that issued Bearer ("github", "oidc", …).
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

// ErrNoSecretStore is returned by Save when the platform has no secret store
// to hold the session and the plaintext opt-in is not set.
var ErrNoSecretStore = errors.New("tokenstore: no secret store available (install a Secret Service such as gnome-keyring, or set CLAIMWARD_ALLOW_PLAINTEXT_SESSION=1 to keep a 0600 file)")

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

// current is the backend in use: the 0600 file when the person opted into it,
// the platform's secret store otherwise.
func current() backend {
	if plaintextAllowed() {
		return fileBackend{}
	}
	return store
}

// Path returns the on-disk location of the legacy plaintext session file.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "claimward", "session.json"), nil
}

// Load reads the session. It returns (nil, nil) when no session exists yet.
// A legacy plaintext file is migrated into the secret store and removed.
func Load() (*Session, error) {
	data, err := current().get()
	if errors.Is(err, errNotFound) {
		return migrate()
	}
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// migrate moves a legacy plaintext file into the store.
func migrate() (*Session, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if plaintextAllowed() {
		return &s, nil // the file is the store: nothing to move
	}
	if err := store.set(data); err != nil {
		return &s, nil // keep the file rather than lose the session
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return &s, nil
}

// Save stores the session, replacing any earlier one, and removes a legacy
// plaintext file.
func Save(s *Session) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := current().set(data); err != nil {
		return err
	}
	if plaintextAllowed() {
		return nil
	}
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Clear deletes the session (logout). A missing session is not an error.
func Clear() error {
	if err := current().del(); err != nil { // the legacy file is removed below either way
		return err
	}
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// fileBackend is the legacy 0600 JSON file: the fallback where the platform
// has no secret store and the person opted in.
type fileBackend struct{}

func (fileBackend) get() ([]byte, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNotFound
	}
	return data, err
}

func (fileBackend) set(data []byte) error {
	p, err := Path()
	if err != nil {
		return err
	}
	return writeAtomic(p, data)
}

func (fileBackend) del() error { return nil } // Clear removes the file

// writeAtomic writes data to p with 0600 permissions, via a rename.
func writeAtomic(p string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// plaintextAllowed reports the opt-in for the 0600 file.
func plaintextAllowed() bool { return os.Getenv("CLAIMWARD_ALLOW_PLAINTEXT_SESSION") == "1" }
