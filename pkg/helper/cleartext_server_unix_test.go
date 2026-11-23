//go:build !windows

package helper

import (
	"os"
	"path/filepath"
	"testing"
)

// Audit 2026-11-23, finding 6: the helper sends the person's bearer to every
// server its configuration names, and takes an http:// one. Anybody on the
// path then reads the bearer and answers the enrollment: the endpoint, the
// server key and the routes of the tunnel are theirs. Only https (or a
// loopback address, for development) may be configured.
func TestHelperRefusesACleartextServer(t *testing.T) {
	old := rootUID
	rootUID = uint32(os.Getuid()) // stand in for root
	t.Cleanup(func() { rootUID = old })
	p := filepath.Join(t.TempDir(), "helper.json")
	if err := os.WriteFile(p, []byte(`{"servers": ["http://vpn.example.org"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadConfig(p); err == nil {
		t.Fatalf("a cleartext server was taken: %v", cfg.Servers)
	}
}
