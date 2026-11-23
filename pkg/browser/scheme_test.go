package browser

import "testing"

// Audit 2026-11-23, finding 7: Open hands any string to the platform opener.
// The URLs it receives come from an identity provider's discovery document
// (oidc.go) or answer (github.go, goauthn.go); a file:, UNC or custom-scheme
// URL there makes `open` / `rundll32 url.dll,FileProtocolHandler` /
// `xdg-open` launch a local file or handler. Only http(s) may be opened.
// (The URL below names a file that does not exist: if the opener is spawned,
// it only prints an error.)
func TestOpenRefusesNonHTTPURLs(t *testing.T) {
	for _, u := range []string{
		"file:///nonexistent-claimward-audit-2026-11-23",
		"-a nonexistent-claimward-audit",
	} {
		if err := Open(u); err == nil {
			t.Errorf("Open(%q) spawned the opener", u)
		}
	}
}
