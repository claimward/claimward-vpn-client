package tokenstore

import (
	"path/filepath"
	"testing"
)

func TestUseMemoryKeepsTheSessionInMemoryOnly(t *testing.T) {
	old := store
	t.Cleanup(func() { store = old })
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AppData", filepath.Join(home, "AppData"))

	restore := UseMemory()
	if s, err := Load(testKey); s != nil || err != nil {
		t.Fatalf("empty Load = %+v, %v", s, err)
	}
	if err := Save(testKey, &Session{Bearer: "mem-secret"}); err != nil {
		t.Fatal(err)
	}
	if s, err := Load(testKey); err != nil || s == nil || s.Bearer != "mem-secret" {
		t.Fatalf("Load = %+v, %v", s, err)
	}
	if _, found := dirHolds(t, home, "mem-secret"); found {
		t.Error("the memory store wrote to disk")
	}
	if err := Clear(testKey); err != nil {
		t.Fatal(err)
	}
	if s, _ := Load(testKey); s != nil {
		t.Error("session survives Clear")
	}
	restore()
	if store != old {
		t.Error("restore did not put the platform store back")
	}
}
