package appcore

import (
	"os"
	"testing"
)

// The tests keep the session in the 0600 file: the platform's secret store is
// the person's own Keychain, Credential Store or Secret Service.
func TestMain(m *testing.M) {
	os.Setenv("CLAIMWARD_ALLOW_PLAINTEXT_SESSION", "1")
	os.Exit(m.Run())
}
