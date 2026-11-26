package tokenstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testKey is the key the single-session tests store under.
var testKey = Key("https://vpn.example.org", "github")

// useMemory swaps the platform backend for a memory one for the test.
func useMemory(t *testing.T) *memBackend {
	t.Helper()
	old := store
	m := &memBackend{}
	store = m
	t.Cleanup(func() { store = old })
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AppData", t.TempDir())
	return m
}

func TestKeyedSessionsAreIndependent(t *testing.T) {
	useMemory(t)
	a := Key("https://a.example", "github")
	b := Key("https://b.example", "corp")
	if err := Save(a, &Session{Bearer: "A"}); err != nil {
		t.Fatal(err)
	}
	if err := Save(b, &Session{Bearer: "B"}); err != nil {
		t.Fatal(err)
	}
	if s, _ := Load(a); s == nil || s.Bearer != "A" {
		t.Fatalf("a = %+v", s)
	}
	if err := Clear(a); err != nil {
		t.Fatal(err)
	}
	if s, _ := Load(a); s != nil {
		t.Fatal("a survived its Clear")
	}
	if s, _ := Load(b); s == nil || s.Bearer != "B" {
		t.Fatalf("b lost with a: %+v", s)
	}
}

func TestKeyDistinguishesServerAndProvider(t *testing.T) {
	if Key("https://a.example", "x") == Key("https://a.example", "y") {
		t.Fatal("providers share a key")
	}
}

func TestClearServerRemovesEveryProvider(t *testing.T) {
	useMemory(t)
	Save(Key("https://a.example", "one"), &Session{Bearer: "1"})
	Save(Key("https://a.example", "two"), &Session{Bearer: "2"})
	Save(Key("https://a.example.evil", "one"), &Session{Bearer: "3"})
	if err := ClearServer("https://a.example"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"one", "two"} {
		if s, _ := Load(Key("https://a.example", p)); s != nil {
			t.Fatalf("%s survived", p)
		}
	}
	if s, _ := Load(Key("https://a.example.evil", "one")); s == nil {
		t.Fatal("a different server lost its session")
	}
}

func TestClearLastSessionDeletesEntry(t *testing.T) {
	m := useMemory(t)
	Save(testKey, &Session{Bearer: "x"})
	if err := Clear(testKey); err != nil {
		t.Fatal(err)
	}
	if m.data != nil {
		t.Fatal("an empty document stayed in the store")
	}
}

func TestLegacySingleSessionIsAdopted(t *testing.T) {
	m := useMemory(t)
	old, _ := json.Marshal(&Session{Bearer: "old", Provider: "github"})
	m.data = old
	if s, _ := Load(testKey); s != nil {
		t.Fatal("a legacy session answered to a key before it was adopted")
	}
	ok, err := AdoptLegacy(testKey)
	if err != nil || !ok {
		t.Fatalf("AdoptLegacy = %v, %v", ok, err)
	}
	if s, _ := Load(testKey); s == nil || s.Bearer != "old" {
		t.Fatalf("adopted = %+v", s)
	}
	if ok, _ := AdoptLegacy(testKey); ok {
		t.Fatal("adopted twice")
	}
}

func TestAdoptLegacyDoesNotOverwrite(t *testing.T) {
	m := useMemory(t)
	Save(testKey, &Session{Bearer: "new"})
	d, _ := decode(m.data)
	d.Sessions[legacyKey] = &Session{Bearer: "old"}
	m.data, _ = json.Marshal(d)
	if ok, _ := AdoptLegacy(testKey); ok {
		t.Fatal("overwrote a live session")
	}
	if s, _ := Load(testKey); s.Bearer != "new" {
		t.Fatalf("got %q", s.Bearer)
	}
	if err := DiscardLegacy(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscardLegacy(t *testing.T) {
	m := useMemory(t)
	old, _ := json.Marshal(&Session{Bearer: "old"})
	m.data = old
	if err := DiscardLegacy(); err != nil {
		t.Fatal(err)
	}
	if m.data != nil {
		t.Fatal("legacy session kept")
	}
	if err := DiscardLegacy(); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownDocumentVersionRefused(t *testing.T) {
	m := useMemory(t)
	m.data = []byte(`{"version":9,"sessions":{}}`)
	if _, err := Load(testKey); err == nil {
		t.Fatal("a future document was read")
	}
	if err := Save(testKey, &Session{Bearer: "x"}); err == nil {
		t.Fatal("a future document was overwritten")
	}
}

func TestLegacyFileIsMigratedAndRemoved(t *testing.T) {
	useMemory(t)
	p, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(p), 0o700)
	old, _ := json.Marshal(&Session{Bearer: "file"})
	if err := os.WriteFile(p, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := AdoptLegacy(testKey); err != nil || !ok {
		t.Fatalf("AdoptLegacy = %v, %v", ok, err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("the plaintext file stayed")
	}
	if s, _ := Load(testKey); s == nil || s.Bearer != "file" {
		t.Fatalf("got %+v", s)
	}
}
