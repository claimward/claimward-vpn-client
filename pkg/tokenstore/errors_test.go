package tokenstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// brokenBackend answers every call with its fields.
type brokenBackend struct {
	data []byte
	err  error
	// sets counts the calls to set, to see a backend that was not to be used.
	sets *int
}

func (b brokenBackend) get() ([]byte, error) { return b.data, b.err }
func (b brokenBackend) set([]byte) error {
	if b.sets != nil {
		*b.sets++
	}
	return b.err
}
func (b brokenBackend) del() error { return b.err }

// noConfigDir makes os.UserConfigDir fail.
func noConfigDir(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", "")
	if _, err := Path(); err == nil {
		t.Fatal("Path found a config dir with HOME, XDG_CONFIG_HOME and AppData empty")
	}
}

// isPathErr fails the test unless err is the one Path reports: the failure of
// the config dir itself, not a later one it also causes.
func isPathErr(t *testing.T, what string, err error) {
	t.Helper()
	_, want := Path()
	if err == nil || want == nil || !strings.Contains(err.Error(), want.Error()) {
		t.Errorf("%s = %v, want the config-dir error %v", what, err, want)
	}
}

func TestPathReportsAMissingConfigDir(t *testing.T) {
	noConfigDir(t)
	if p, err := Path(); err == nil || p != "" {
		t.Errorf("Path = %q, %v", p, err)
	}
}

func TestNoConfigDirIsReportedEverywhere(t *testing.T) {
	noConfigDir(t)
	old := store
	t.Cleanup(func() { store = old })

	store = sealedBackend{kr: &memKeyring{}}
	if _, err := Load(); err == nil {
		t.Error("sealed Load: no error")
	}
	if err := Save(&Session{Bearer: "b"}); err == nil {
		t.Error("sealed Save: no error")
	}
	if err := Clear(); err == nil {
		t.Error("sealed Clear: no error")
	}

	store = noStore{} // Load falls to the legacy file, whose path cannot be found
	if _, err := Load(); err == nil {
		t.Error("migrate: no error")
	}
}

// blockConfigDir makes the claimward config dir a regular file, so every path
// under it fails with something other than "does not exist".
func blockConfigDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a path under a file reads as missing on Windows")
	}
	dir := isolate(t, noStore{})
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAnUnreadableOrUnwritableConfigDirIsReported(t *testing.T) {
	blockConfigDir(t)
	store = sealedBackend{kr: &memKeyring{}}
	if _, err := Load(); err == nil {
		t.Error("sealed Load: no error") // reading session.enc fails
	}
	if err := Save(&Session{Bearer: "b"}); err == nil {
		t.Error("sealed Save: no error") // MkdirAll fails
	}
	if err := Clear(); err == nil {
		t.Error("sealed Clear: no error") // removing session.enc fails
	}
}

func TestWriteAtomicReportsATempFileItCannotCreate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s")
	if err := os.Mkdir(p+".tmp", 0o700); err != nil { // a directory is in the way
		t.Fatal(err)
	}
	if err := writeAtomic(p, []byte("x")); err == nil {
		t.Error("no error")
	}
}

func TestRemoveIfPresent(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	if err := removeIfPresent(f); err != nil {
		t.Errorf("a missing file: %v", err)
	}
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeIfPresent(f); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f); err == nil {
		t.Error("the file is still there")
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := removeIfPresent(filepath.Join(f, "under")); err == nil {
			t.Error("a path under a file: no error")
		}
	}
}

func TestLoadReportsABackendFailureAndUnparsableData(t *testing.T) {
	isolate(t, brokenBackend{err: errors.New("denied")})
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("Load = %v, want the backend's error", err)
	}
	store = brokenBackend{data: []byte("not json")}
	if _, err := Load(); err == nil {
		t.Error("unparsable stored data loaded")
	}
}

func TestMigrateReportsAnUnparsableLegacyFile(t *testing.T) {
	dir := isolate(t, sealedBackend{kr: &memKeyring{}})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Error("an unparsable legacy file loaded")
	}
}

func TestMigrateReportsAnUnreadableLegacyFile(t *testing.T) {
	dir := blockConfigDir(t)
	_ = dir
	store = sealedBackend{kr: &memKeyring{}}
	// The sealed read fails first on this layout, so go through migrate directly.
	if _, err := migrate(); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("migrate = %v, want the read error", err)
	}
}

func TestAMalformedSealingKeyIsRefused(t *testing.T) {
	for _, bad := range []string{"zz", "00ff", ""} {
		kr := &memKeyring{v: bad, has: true}
		isolate(t, sealedBackend{kr: kr})
		if err := Save(&Session{Bearer: "b"}); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Errorf("key %q: Save = %v, want a malformed-key error", bad, err)
		}
	}
}

func TestAKeyringReadFailureIsNotAMissingKey(t *testing.T) {
	kr := &failingGet{}
	isolate(t, sealedBackend{kr: kr})
	if err := Save(&Session{Bearer: "b"}); err == nil {
		t.Fatal("Save: no error")
	}
	if kr.sets != 0 {
		t.Error("a key was minted over a keyring that could not be read")
	}
	// A session already sealed cannot be opened without the key.
	kr2 := &memKeyring{}
	dir := isolate(t, sealedBackend{kr: kr2})
	if err := Save(&Session{Bearer: "b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "session.enc")); err != nil {
		t.Fatal(err)
	}
	store = sealedBackend{kr: &failingGet{}}
	if _, err := Load(); err == nil || strings.Contains(err.Error(), "log in again") {
		t.Errorf("Load = %v, want the keyring's own error", err)
	}
}

// failingGet is a keyring whose read fails with something other than "empty".
type failingGet struct{ sets int }

func (f *failingGet) get() (string, error) { return "", errors.New("locked") }
func (f *failingGet) set(string) error     { f.sets++; return nil }
func (f *failingGet) del() error           { return nil }
