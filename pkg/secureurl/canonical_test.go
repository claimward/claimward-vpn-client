package secureurl

import "testing"

func TestCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"https://vpn.example.org":           "https://vpn.example.org",
		"https://VPN.Example.ORG/":          "https://vpn.example.org",
		"HTTPS://vpn.example.org:443":       "https://vpn.example.org",
		"https://vpn.example.org:8443//":    "https://vpn.example.org:8443",
		"https://vpn.example.org/sub/path/": "https://vpn.example.org/sub/path",
		"http://127.0.0.1:8080/":            "http://127.0.0.1:8080",
		"http://localhost:80":               "http://localhost",
		"https://[::1]:443/":                "https://[::1]",
	} {
		got, err := Canonical(in)
		if err != nil || got != want {
			t.Errorf("Canonical(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestCanonicalRefuses(t *testing.T) {
	for _, in := range []string{
		"", "vpn.example.org", "http://vpn.example.org", "ftp://x",
		"https://u:p@vpn.example.org", "https://vpn.example.org/?a=1",
		"https://vpn.example.org/#x", "https://vpn.example.org?", "https://",
	} {
		if got, err := Canonical(in); err == nil {
			t.Errorf("Canonical(%q) = %q, want a refusal", in, got)
		}
	}
}

func TestCanonicalIsStable(t *testing.T) {
	a, _ := Canonical("https://Vpn.Example.org:443/")
	b, err := Canonical(a)
	if err != nil || a != b {
		t.Errorf("not idempotent: %q then %q, %v", a, b, err)
	}
}

func TestOrigin(t *testing.T) {
	got, err := Origin("https://vpn.example.org:8443/sub")
	if err != nil || got != "https://vpn.example.org:8443" {
		t.Errorf("Origin = %q, %v", got, err)
	}
}
