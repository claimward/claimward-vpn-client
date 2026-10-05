//go:build !windows

package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/hproto"
)

// The configuration names the servers, and only root may have written it.
func TestTheConfigurationIsRootsAlone(t *testing.T) {
	old := rootUID
	rootUID = uint32(os.Getuid()) // stand in for root
	t.Cleanup(func() { rootUID = old })
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
		return p
	}
	cfg, err := LoadConfig(write("ok.json", `{"servers": ["https://vpn.example.org"]}`, 0o644))
	if err != nil || cfg.Servers[0] != "https://vpn.example.org" || cfg.Group != DefaultGroup || cfg.Socket != hproto.DefaultSocketPath {
		t.Errorf("a good configuration: %+v %v", cfg, err)
	}
	if _, err := LoadConfig(write("writable.json", `{"servers": ["https://vpn.example.org"]}`, 0o666)); err == nil {
		t.Error("a configuration anybody may write was taken")
	}
	if _, err := LoadConfig(write("none.json", `{"servers": []}`, 0o644)); err == nil {
		t.Error("a configuration naming no server was taken")
	}
	if _, err := LoadConfig(write("bad.json", `{`, 0o644)); err == nil {
		t.Error("a configuration that is not JSON was taken")
	}
	rootUID = old
	if os.Getuid() != 0 {
		if _, err := LoadConfig(filepath.Join(dir, "ok.json")); err == nil {
			t.Error("a configuration a user owns was taken")
		}
	}
}
