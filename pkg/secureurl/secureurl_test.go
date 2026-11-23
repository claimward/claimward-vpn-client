package secureurl

import "testing"

func TestCheck(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://vpn.example.org":       true,
		"https://vpn.example.org:8443/": true,
		"http://127.0.0.1:8080":         true,
		"http://localhost:8080":         true,
		"http://[::1]:8080":             true,
		"http://vpn.example.org":        false,
		"http://10.0.0.1":               false,
		"http://127.0.0.1.evil.org":     false,
		"https://user:pw@example.org":   false,
		"ftp://example.org":             false,
		"file:///etc/passwd":            false,
		"vpn.example.org":               false,
		"https://":                      false,
		"":                              false,
		"http://[::1":                   false, // does not parse
	} {
		if err := Check(raw); (err == nil) != ok {
			t.Errorf("Check(%q) = %v, want accepted=%v", raw, err, ok)
		}
	}
}
