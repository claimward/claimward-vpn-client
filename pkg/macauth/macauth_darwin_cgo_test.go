//go:build darwin && cgo

package macauth

import (
	"errors"
	"os"
	"testing"
)

// The system, not this package, says whether a token is good: a length that is
// not an external form's is refused before the system is asked, and 32 bytes
// the system never issued are refused by it.
func TestVerifyRefusesWhatTheSystemDidNotIssue(t *testing.T) {
	for _, form := range [][]byte{nil, make([]byte, FormLength-1), make([]byte, FormLength+1)} {
		if err := Verify(form); !errors.Is(err, ErrNotAuthorized) {
			t.Errorf("a %d-byte token: %v", len(form), err)
		}
	}
	forged := make([]byte, FormLength)
	for i := range forged {
		forged[i] = byte(i * 7)
	}
	if err := Verify(forged); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("a forged token: %v", err)
	}
}

// Creating the right in the policy database takes root; a person is refused
// (and this does not hang or crash).
func TestEnsureRightNeedsRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root would create the right in this machine's policy database")
	}
	if err := EnsureRight(); err == nil {
		t.Skip("the right already exists on this machine")
	}
}
