package tokenstore

import (
	"os"
	"path/filepath"
	"testing"
)

// The DPAPI backend, for real: the blob on disk holds no secret in clear and
// opens again for the same user.
func TestDPAPIRoundTrip(t *testing.T) {
	dir := isolate(t, dpapi{})
	s := &Session{Bearer: "dpapi-bearer-secret", RefreshToken: "dpapi-refresh-secret", WGPrivateKey: "dpapi-key-secret"}
	if err := Save(s); err != nil {
		t.Fatal(err)
	}
	if p, found := dirHolds(t, dir, s.Bearer, s.RefreshToken, s.WGPrivateKey); found {
		t.Errorf("%s holds a secret in clear", p)
	}
	if _, err := os.Stat(filepath.Join(dir, "session.dpapi")); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil || got == nil || *got != *s {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	if err := Clear(); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(); got != nil {
		t.Error("session survives Clear")
	}
}
