package tokenstore

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	if err := Save(testKey, s); err != nil {
		t.Fatal(err)
	}
	if p, found := dirHolds(t, dir, s.Bearer, s.RefreshToken, s.WGPrivateKey); found {
		t.Errorf("%s holds a secret in clear", p)
	}
	got, err := Load(testKey)
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
	if adopted, err := AdoptLegacy(testKey); err != nil || !adopted {
		t.Fatalf("AdoptLegacy = %v, %v", adopted, err)
	}
	got, err := Load(testKey)
	if err != nil || got == nil || got.Bearer != "old-bearer-xyz" || got.Tenant != "hpc" {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the plaintext file survives the migration: %v", err)
	}
	if p, found := dirHolds(t, dir, "old-bearer-xyz", "old-key-xyz"); found {
		t.Errorf("%s holds a migrated secret in clear", p)
	}
	again, err := Load(testKey)
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
	if err := Save(testKey, &Session{Bearer: "new"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Save left the plaintext file: %v", err)
	}
	// The legacy session stays until an owner adopts it or it is discarded.
	if err := DiscardLegacy(); err != nil {
		t.Fatal(err)
	}
	if err := Clear(testKey); err != nil {
		t.Fatal(err)
	}
	if kr.has {
		t.Error("Clear left the key in the keyring")
	}
	if s, err := Load(testKey); s != nil || err != nil {
		t.Errorf("Load after Clear = %+v, %v", s, err)
	}
	if err := Clear(testKey); err != nil {
		t.Errorf("a second Clear: %v", err)
	}
}

// Product decision 2026-11-23: there is no plaintext fallback. With no secret
// store, saving fails and says what to install; nothing is written to disk.
func TestNoSecretStoreRefusesToSaveAndWritesNothing(t *testing.T) {
	dir := isolate(t, noStore{})
	err := Save(testKey, &Session{Bearer: "secret-b", WGPrivateKey: "secret-k"})
	if err == nil || err.Error() != ErrNoSecretStore.Error() {
		t.Fatalf("Save = %v, want exactly ErrNoSecretStore (not wrapped twice)", err)
	}
	if _, found := dirHolds(t, dir, "secret-b", "secret-k"); found {
		t.Error("a refused Save wrote the session")
	}
	if _, err := os.Stat(dir); err == nil {
		t.Errorf("a refused Save created %s", dir)
	}
}

// The message names what is missing, for the platform it runs on.
func TestTheNoStoreErrorIsActionable(t *testing.T) {
	for goos, want := range map[string]string{
		"linux":   "Secret Service provider (such as gnome-keyring or KeePassXC)",
		"darwin":  "unlock the login Keychain",
		"windows": "DPAPI",
		"plan9":   "no supported secret store",
	} {
		if got := storeHelp(goos); !strings.Contains(got, want) || !strings.Contains(got, "never written to disk in clear") {
			t.Errorf("storeHelp(%q) = %q, want %q", goos, got, want)
		}
	}
	if !strings.Contains(ErrNoSecretStore.Error(), "no secret store available") {
		t.Errorf("ErrNoSecretStore = %q", ErrNoSecretStore)
	}
	if strings.Contains(ErrNoSecretStore.Error(), "PLAINTEXT") {
		t.Error("the error still mentions the opt-in")
	}
}

// A backend that fails with its own error still surfaces as ErrNoSecretStore.
func TestAStoreFailureIsReportedAsNoSecretStore(t *testing.T) {
	isolate(t, brokenBackend{err: errors.New("keychain locked")})
	err := Save(testKey, &Session{Bearer: "b"})
	if !errors.Is(err, ErrNoSecretStore) || !strings.Contains(err.Error(), "keychain locked") {
		t.Errorf("Save = %v", err)
	}
}

// The old opt-in variable has no effect any more: no file is written, with or
// without it, and a legacy file is not read back as the session.
func TestTheOptInVariableHasNoEffect(t *testing.T) {
	for _, v := range []string{"", "1", "true"} {
		dir := isolate(t, noStore{})
		t.Setenv("CLAIMWARD_ALLOW_PLAINTEXT_SESSION", v)
		if err := Save(testKey, &Session{Bearer: "plain-secret"}); !errors.Is(err, ErrNoSecretStore) {
			t.Fatalf("value %q: Save = %v, want ErrNoSecretStore", v, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "session.json")); err == nil {
			t.Errorf("value %q: a session.json was written", v)
		}
		if s, err := Load(testKey); s != nil || err != nil {
			t.Errorf("value %q: Load = %+v, %v", v, s, err)
		}
	}
}

// Migration is one attempt. If the store refuses, the plaintext file is
// deleted anyway, never kept and never read a second time, and Load refuses.
func TestAFailedMigrationDeletesTheLegacyFile(t *testing.T) {
	dir := isolate(t, noStore{})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "session.json")
	if err := os.WriteFile(legacy, []byte(`{"bearer":"old-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := Load(testKey); s != nil || err == nil || err.Error() != ErrNoSecretStore.Error() {
		t.Fatalf("Load = %+v, %v, want exactly ErrNoSecretStore", s, err)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the plaintext file was kept: %v", err)
	}
	if s, err := Load(testKey); s != nil || err != nil {
		t.Errorf("second Load = %+v, %v, want nothing", s, err)
	}
}

// A store failing with its own error during migration is reported as no store.
func TestAMigrationFailingWithAStoreErrorIsReported(t *testing.T) {
	dir := isolate(t, brokenBackend{err: errors.New("keychain locked")})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "session.json")
	if err := os.WriteFile(legacy, []byte(`{"bearer":"old"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// brokenBackend.get fails too, so go through migrate directly.
	if s, err := migrate(); s != nil || !errors.Is(err, ErrNoSecretStore) || !strings.Contains(err.Error(), "keychain locked") {
		t.Fatalf("migrate = %+v, %v", s, err)
	}
	if _, err := os.Stat(legacy); err == nil {
		t.Error("the plaintext file was kept")
	}
}

func TestSealedSessionRefusesTamperingAndALostKey(t *testing.T) {
	kr := &memKeyring{}
	dir := isolate(t, sealedBackend{kr: kr})
	if err := Save(testKey, &Session{Bearer: "b"}); err != nil {
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
	if s, err := Load(testKey); err == nil {
		t.Errorf("a tampered blob loaded: %+v", s)
	}
	if err := os.WriteFile(enc, blob[:3], 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := Load(testKey); err == nil {
		t.Errorf("a truncated blob loaded: %+v", s)
	}
	if err := os.WriteFile(enc, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	kr.del()
	if s, err := Load(testKey); err == nil {
		t.Errorf("a blob loaded without its key: %+v", s)
	}
	kr.v, kr.has = "zz", true
	if s, err := Load(testKey); err == nil {
		t.Errorf("a malformed key loaded a blob: %+v", s)
	}
}

func TestSaveSurfacesAKeyringFailureAsNoSecretStore(t *testing.T) {
	isolate(t, sealedBackend{kr: &memKeyring{fail: errors.New("locked")}})
	if err := Save(testKey, &Session{Bearer: "b"}); !errors.Is(err, ErrNoSecretStore) {
		t.Fatalf("Save = %v, want ErrNoSecretStore", err)
	}
}
