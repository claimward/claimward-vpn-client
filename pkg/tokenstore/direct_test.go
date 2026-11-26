package tokenstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The sealed backend called directly, so that each failure is judged on its
// own and not through whatever the layer above would also have reported.
func TestSealedBackendWithoutAConfigDir(t *testing.T) {
	noConfigDir(t)
	b := sealedBackend{kr: &memKeyring{}}
	if _, err := b.get(); err == nil || errors.Is(err, errNotFound) {
		t.Errorf("get = %v, want a config-dir error", err)
	}
	isPathErr(t, "set", b.set([]byte("x")))
	if err := b.set([]byte("x")); errors.Is(err, ErrNoSecretStore) {
		t.Errorf("set = %v, want a config-dir error", err)
	}
	if err := b.del(); err == nil {
		t.Error("del: no error")
	}
}

func TestSealedBackendOverABlockedConfigDir(t *testing.T) {
	blockConfigDir(t)
	b := sealedBackend{kr: &memKeyring{}}
	if _, err := b.get(); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("get = %v, want the read error", err)
	}
	if err := b.del(); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("del = %v, want the remove error", err)
	}
}

func TestSealingKeyValidation(t *testing.T) {
	for _, bad := range []string{"zz", "00ff", ""} {
		b := sealedBackend{kr: &memKeyring{v: bad, has: true}}
		if k, err := b.key(true); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Errorf("key %q = %x, %v; want a malformed-key error", bad, k, err)
		}
	}
	good := strings.Repeat("ab", 32)
	if k, err := (sealedBackend{kr: &memKeyring{v: good, has: true}}).key(false); err != nil || len(k) != 32 {
		t.Errorf("a 32-byte key: %x, %v", k, err)
	}
}

func TestKeyringFailuresKeepTheirOwnMessage(t *testing.T) {
	kr := &failingGet{}
	b := sealedBackend{kr: kr}
	if _, err := b.key(true); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Errorf("key(true) = %v, want the keyring's error", err)
	}
	if _, err := b.key(false); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Errorf("key(false) = %v, want the keyring's error", err)
	}
	if kr.sets != 0 {
		t.Error("a key was minted over a keyring that could not be read")
	}
}

func TestClearReportsABackendFailure(t *testing.T) {
	isolate(t, brokenBackend{err: errors.New("denied")})
	if err := Clear(testKey); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("Clear = %v, want the backend's error", err)
	}
}

// okBackend accepts every write and keeps nothing.
type okBackend struct{}

func (okBackend) get() ([]byte, error) { return nil, errNotFound }
func (okBackend) set([]byte) error     { return nil }
func (okBackend) del() error           { return nil }

func TestMigrateReportsALegacyFileItCannotRemove(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory the user cannot write to")
	}
	dir := isolate(t, okBackend{})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.json"), []byte(`{"bearer":"b"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if s, err := Load(testKey); err == nil {
		t.Errorf("Load = %+v, want the remove error", s)
	}
}
