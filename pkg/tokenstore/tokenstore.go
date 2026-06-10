// Package tokenstore persists the user's session (OIDC tokens and the device's
// WireGuard private key) on disk with owner-only permissions.
//
// This is a pragmatic MVP store: a 0600 JSON file under the user's config dir.
// On macOS the platform app is expected to graduate this to the Keychain; the
// API here is intentionally small so that swap is local.
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
	IDToken      string    `json:"id_token"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	// WGPrivateKey is the device's stable WireGuard private key (base64). Kept so
	// the device keeps the same public key (and assigned IP) across reconnects.
	WGPrivateKey string `json:"wg_private_key,omitempty"`
}

// Path returns the on-disk location of the session file.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "claimward", "session.json"), nil
}

// Load reads the session. It returns (nil, nil) when no session exists yet.
func Load() (*Session, error) {
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
	return &s, nil
}

// Save writes the session atomically with 0600 permissions.
func Save(s *Session) error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Clear deletes the session file (logout). Missing file is not an error.
func Clear() error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
