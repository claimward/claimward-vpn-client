package appcore

import (
	"os"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/tokenstore"
)

// The tests keep the session in memory: the platform's secret store is the
// person's own Keychain, Credential Store or Secret Service.
func TestMain(m *testing.M) {
	restore := tokenstore.UseMemory()
	code := m.Run()
	restore()
	os.Exit(code)
}
