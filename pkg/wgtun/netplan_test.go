package wgtun

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// What Windows is asked to set is what the server answered, family by
// family, in a stable order.
func TestPlanSplitsByFamilyMasksAndSorts(t *testing.T) {
	p, err := planNetwork(Config{
		Address: "10.80.0.5/32",
		AllowedIPs: []string{
			"10.2.3.4/16", // masked to 10.2.0.0/16
			"10.2.0.0/16", // a duplicate once masked
			"fd00::1/64",
			"10.1.0.0/24",
			"::ffff:192.168.7.0/120", // IPv4-mapped: the IPv4 route 192.168.7.0/24
			"not-a-route",            // skipped, as routeAdd does elsewhere
		},
		DNS: []string{"10.2.0.53", "fd00::53", "::ffff:10.2.0.54"},
		MTU: 1380,
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParsePrefix("10.80.0.5/32"); p.Address != want {
		t.Errorf("address %v, want %v", p.Address, want)
	}
	if want := prefixes("10.1.0.0/24", "10.2.0.0/16", "192.168.7.0/24"); !reflect.DeepEqual(p.Routes4, want) {
		t.Errorf("IPv4 routes %v, want %v", p.Routes4, want)
	}
	if want := prefixes("fd00::/64"); !reflect.DeepEqual(p.Routes6, want) {
		t.Errorf("IPv6 routes %v, want %v", p.Routes6, want)
	}
	if want := addrs("10.2.0.53", "10.2.0.54"); !reflect.DeepEqual(p.DNS4, want) {
		t.Errorf("IPv4 DNS %v, want %v", p.DNS4, want)
	}
	if want := addrs("fd00::53"); !reflect.DeepEqual(p.DNS6, want) {
		t.Errorf("IPv6 DNS %v, want %v", p.DNS6, want)
	}
	if p.Default4 || p.Default6 {
		t.Error("no default route was asked for, yet one is planned")
	}
	if p.MTU != 1380 {
		t.Errorf("MTU %d, want 1380", p.MTU)
	}
}

// A full tunnel pins the metric, per family, so that its default route wins
// over the physical interface's.
func TestPlanNoticesDefaultRoutes(t *testing.T) {
	p, err := planNetwork(Config{Address: "10.80.0.5/32", AllowedIPs: []string{"0.0.0.0/0"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Default4 || p.Default6 {
		t.Errorf("0.0.0.0/0: Default4=%v Default6=%v, want true false", p.Default4, p.Default6)
	}
	p, err = planNetwork(Config{Address: "10.80.0.5/32", AllowedIPs: []string{"::/0", "10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Default4 || !p.Default6 {
		t.Errorf("::/0: Default4=%v Default6=%v, want false true", p.Default4, p.Default6)
	}
}

func TestPlanRefusesWhatCannotBeApplied(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no address":        {AllowedIPs: []string{"10.0.0.0/8"}},
		"a bare address":    {Address: "10.80.0.5"},
		"a malformed DNS":   {Address: "10.80.0.5/32", DNS: []string{"resolver.example.org"}},
		"an address in DNS": {Address: "10.80.0.5/32", DNS: []string{"10.2.0.53/32"}},
	} {
		if _, err := planNetwork(cfg); err == nil {
			t.Errorf("%s: planned", name)
		}
	}
	_, err := planNetwork(Config{Address: "10.80.0.5/32", DNS: []string{"nope"}})
	if err == nil || !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("the error does not name the bad resolver: %v", err)
	}
}

func TestParseRoute(t *testing.T) {
	for in, want := range map[string]string{
		"10.2.3.4/16":         "10.2.0.0/16",
		"0.0.0.0/0":           "0.0.0.0/0",
		"fd00::1/64":          "fd00::/64",
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
	} {
		got, ok := parseRoute(in)
		if !ok || got != netip.MustParsePrefix(want) {
			t.Errorf("parseRoute(%q) = %v %v, want %s", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "10.0.0.0", "10.0.0.0/33", "::ffff:10.0.0.0/64"} {
		if r, ok := parseRoute(in); ok {
			t.Errorf("parseRoute(%q) = %v, want refused", in, r)
		}
	}
}
