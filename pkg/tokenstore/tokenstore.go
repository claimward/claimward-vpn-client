// Package tokenstore persists the user's session (OIDC tokens and the device's
// WireGuard private key) in the platform's secret store, never in clear on
// disk:
//
//   - macOS: the login Keychain, through /usr/bin/security;
//   - Windows: DPAPI (CryptProtectData), the blob kept in the user's config dir;
//   - Linux: the Secret Service (GNOME Keyring, KWallet), through secret-tool.
//
// A session written by an earlier version as a 0600 JSON file is moved into
// the store on first load and the file deleted. There is no plaintext
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
	data, err := store.get()
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

// migrate moves a legacy plaintext file into the store, once. The file is read
// here and nowhere else. If the store refuses it, the file is deleted anyway
// (the person signs in again): a plaintext copy is never kept, and never read
// a second time.
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
	uerr := json.Unmarshal(data, &s)
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
	return &s, nil
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

// Save stores the session, replacing any earlier one, and removes a legacy
// plaintext file.
func Save(s *Session) error {
	data, _ := json.Marshal(s) // a Session holds only strings and a time: it cannot fail
	if err := store.set(data); err != nil {
		if errors.Is(err, ErrNoSecretStore) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrNoSecretStore, err)
	}
	return removeLegacy()
}

// Clear deletes the session (logout). A missing session is not an error.
func Clear() error {
	if err := store.del(); err != nil { // the legacy file is removed below either way
		return err
	}
	return removeLegacy()
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
