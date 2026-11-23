package tokenstore

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// memKeyring is a keyring in memory.
type memKeyring struct {
	v    string
	has  bool
	fail error
}

func (m *memKeyring) get() (string, error) {
	if !m.has {
		return "", errNotFound
	}
	return m.v, nil
}
func (m *memKeyring) set(v string) error {
	if m.fail != nil {
		return m.fail
	}
	m.v, m.has = v, true
	return nil
}
func (m *memKeyring) del() error { m.v, m.has = "", false; return nil }

// isolate points the config dir at a temp dir and installs b as the backend.
func isolate(t *testing.T, b backend) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AppData", filepath.Join(home, "AppData"))
	t.Setenv("CLAIMWARD_ALLOW_PLAINTEXT_SESSION", "")
	old := store
	store = b
	t.Cleanup(func() { store = old })
	p, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(p)
}

// dirHolds reports whether any file under dir contains the bytes.
func dirHolds(t *testing.T, dir string, secrets ...string) (string, bool) {
	t.Helper()
	var hit string
	var found bool
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // nothing was written
		}
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				hit, found = p, true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hit, found
}

// Audit 2026-11-23, finding 5: the bearer, the refresh token and the
// WireGuard private key were written in clear to a 0600 file. 0600 keeps other
// users out; it does not keep out any process running as the person, nor a
// backup or sync of their configuration directory.
func TestSessionSecretsAreNotStoredInClear(t *testing.T) {
	dir := isolate(t, sealedBackend{kr: &memKeyring{}})
	s := &Session{Bearer: "secret-bearer-audit", RefreshToken: "secret-refresh-audit", WGPrivateKey: "secret-wgkey-audit"}
	if err := Save(s); err != nil {
		t.Fatal(err)
	}
	if p, found := dirHolds(t, dir, s.Bearer, s.RefreshToken, s.WGPrivateKey); found {
		t.Errorf("%s holds a secret in clear", p)
	}
	got, err := Load()
	if err != nil || got == nil || *got != *s {
		t.Fatalf("Load = %+v, %v; want %+v", got, err, s)
	}
}

func TestLoadMigratesTheLegacyPlaintextFile(t *testing.T) {
	kr := &memKeyring{}
	dir := isolate(t, sealedBackend{kr: kr})
	legacy := filepath.Join(dir, "session.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(`{"bearer":"old-bearer-xyz","wg_private_key":"old-key-xyz","tenant":"hpc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil || got == nil || got.Bearer != "old-bearer-xyz" || got.Tenant != "hpc" {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the plaintext file survives the migration: %v", err)
	}
	if p, found := dirHolds(t, dir, "old-bearer-xyz", "old-key-xyz"); found {
		t.Errorf("%s holds a migrated secret in clear", p)
	}
	again, err := Load()
	if err != nil || again == nil || again.Bearer != "old-bearer-xyz" {
		t.Fatalf("second Load = %+v, %v", again, err)
	}
}

func TestSaveRemovesTheLegacyFileAndClearRemovesEverything(t *testing.T) {
	kr := &memKeyring{}
	dir := isolate(t, sealedBackend{kr: kr})
	legacy := filepath.Join(dir, "session.json")
	_ = os.MkdirAll(dir, 0o700)
	if err := os.WriteFile(legacy, []byte(`{"bearer":"old"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Save(&Session{Bearer: "new"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Save left the plaintext file: %v", err)
	}
	if err := Clear(); err != nil {
		t.Fatal(err)
	}
	if kr.has {
		t.Error("Clear left the key in the keyring")
	}
	if s, err := Load(); s != nil || err != nil {
		t.Errorf("Load after Clear = %+v, %v", s, err)
	}
	if err := Clear(); err != nil {
		t.Errorf("a second Clear: %v", err)
	}
}

func TestNoSecretStoreRefusesToSaveAndKeepsTheLegacyFile(t *testing.T) {
	dir := isolate(t, noStore{})
	if err := Save(&Session{Bearer: "b"}); !errors.Is(err, ErrNoSecretStore) {
		t.Fatalf("Save = %v, want ErrNoSecretStore", err)
	}
	if _, found := dirHolds(t, dir, "b"); found {
		t.Error("a refused Save wrote the session")
	}
	_ = os.MkdirAll(dir, 0o700)
	legacy := filepath.Join(dir, "session.json")
	if err := os.WriteFile(legacy, []byte(`{"bearer":"kept"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil || got == nil || got.Bearer != "kept" {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Errorf("the file was removed although nothing took the session: %v", err)
	}
}

func TestPlaintextOptInUsesA0600File(t *testing.T) {
	dir := isolate(t, noStore{})
	t.Setenv("CLAIMWARD_ALLOW_PLAINTEXT_SESSION", "1")
	if err := Save(&Session{Bearer: "plain"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtimeHasUnixModes() && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	got, err := Load()
	if err != nil || got == nil || got.Bearer != "plain" {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	if err := Clear(); err != nil {
		t.Fatal(err)
	}
	if s, _ := Load(); s != nil {
		t.Error("session survives Clear")
	}
}

func TestSealedSessionRefusesTamperingAndALostKey(t *testing.T) {
	kr := &memKeyring{}
	dir := isolate(t, sealedBackend{kr: kr})
	if err := Save(&Session{Bearer: "b"}); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "session.enc")
	blob, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 1
	if err := os.WriteFile(enc, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := Load(); err == nil {
		t.Errorf("a tampered blob loaded: %+v", s)
	}
	if err := os.WriteFile(enc, blob[:3], 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := Load(); err == nil {
		t.Errorf("a truncated blob loaded: %+v", s)
	}
	if err := os.WriteFile(enc, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	kr.del()
	if s, err := Load(); err == nil {
		t.Errorf("a blob loaded without its key: %+v", s)
	}
	kr.v, kr.has = "zz", true
	if s, err := Load(); err == nil {
		t.Errorf("a malformed key loaded a blob: %+v", s)
	}
}

func TestSaveSurfacesAKeyringFailureAsNoSecretStore(t *testing.T) {
	isolate(t, sealedBackend{kr: &memKeyring{fail: errors.New("locked")}})
	if err := Save(&Session{Bearer: "b"}); !errors.Is(err, ErrNoSecretStore) {
		t.Fatalf("Save = %v, want ErrNoSecretStore", err)
	}
}
