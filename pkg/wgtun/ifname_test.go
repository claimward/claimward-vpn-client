package wgtun

import (
	"strings"
	"testing"
)

func TestLinuxIfNameFitsAndIsDeterministic(t *testing.T) {
	keys := []string{"", "https://vpn.example.org", "https://vpn.example.org/",
		strings.Repeat("https://very-long-host.example.org/", 50), "http://127.0.0.1:8080", "é\n\x00"}
	seen := map[string]string{}
	for _, k := range keys {
		n := linuxIfName(k)
		if len(n) > linuxIfNameMax {
			t.Errorf("%q: %q is %d bytes, IFNAMSIZ-1 is %d", k, n, len(n), linuxIfNameMax)
		}
		if !strings.HasPrefix(n, "cw-") {
			t.Errorf("%q: %q has no cw- prefix", k, n)
		}
		if n != linuxIfName(k) {
			t.Errorf("%q: not deterministic", k)
		}
		if other, dup := seen[n]; dup {
			t.Errorf("%q and %q share %q", k, other, n)
		}
		seen[n] = k
		if strings.ContainsAny(n, "/ \n\x00") {
			t.Errorf("%q: unsafe name %q", k, n)
		}
	}
}

func TestWindowsAdapterName(t *testing.T) {
	a := windowsAdapterName("https://vpn.example.org")
	if !strings.HasPrefix(a, "Claimward vpn.example.org ") {
		t.Errorf("readable part: %q", a)
	}
	if a != windowsAdapterName("https://vpn.example.org") {
		t.Error("not deterministic")
	}
	if a == windowsAdapterName("https://vpn.example.org:8443") {
		t.Error("two keys, one name")
	}
	long := windowsAdapterName("https://" + strings.Repeat("a", 300) + ".org")
	if len(long) > len("Claimward ")+windowsHostMax+1+6 {
		t.Errorf("unbounded name: %d bytes", len(long))
	}
	odd := windowsAdapterName("https://ho\"st;rm.org")
	if strings.ContainsAny(odd, "\";\\/") {
		t.Errorf("unsafe characters survive: %q", odd)
	}
	// No readable part: the name is "Claimward" and the 6 hex, nothing between.
	if got := windowsAdapterName(""); len(got) != len("Claimward ")+6 || strings.Contains(got, "  ") {
		t.Errorf("empty key: %q", got)
	}
}

func TestInterfaceNameIsPerPlatform(t *testing.T) {
	if InterfaceName("https://a") == "" {
		t.Error("empty name")
	}
}
