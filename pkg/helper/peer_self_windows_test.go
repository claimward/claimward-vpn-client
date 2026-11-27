//go:build windows

package helper

import (
	"testing"

	"golang.org/x/sys/windows"
)

// selfPeer is this process's own token: its user SID, and administrator when
// the token is elevated (the CI runner's is) or SYSTEM.
func selfPeer(t *testing.T) Peer {
	t.Helper()
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	return Peer{ID: u.User.Sid.String(), Admin: tok.IsElevated() || u.User.Sid.Equals(system)}
}
