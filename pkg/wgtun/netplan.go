package wgtun

import (
	"fmt"
	"net/netip"
	"sort"
)

// netPlan is the interface configuration a Config asks for, worked out
// without touching the system: what wgtun_windows.go hands winipcfg. It is
// kept apart from the Windows calls so that the translation -- the part
// that can be wrong without anybody noticing until a route is missing --
// is tested on every platform, not only on a Windows machine.
type netPlan struct {
	// Address is the client's own address, in CIDR form.
	Address netip.Prefix
	// Routes4 and Routes6 are the AllowedIPs, masked, de-duplicated and
	// sorted, split by family: Windows sets routes one family at a time.
	Routes4, Routes6 []netip.Prefix
	// DNS4 and DNS6 are the resolvers, split the same way.
	DNS4, DNS6 []netip.Addr
	// Default4 and Default6 say a default route goes into the tunnel, in
	// which case the interface metric is pinned to 0 so that it wins over
	// the physical interface's, as WireGuard for Windows does.
	Default4, Default6 bool
	// MTU is the interface MTU to set; 0 leaves the system's.
	MTU int
}

// planNetwork translates a Config. The address must parse: an interface
// with no address cannot carry anything. A malformed route is skipped, as
// on the other platforms (routeAdd); a malformed resolver is an error,
// since silently dropping one sends the names it was for to whichever
// resolver the physical interface has.
func planNetwork(cfg Config) (netPlan, error) {
	var p netPlan
	addr, err := netip.ParsePrefix(cfg.Address)
	if err != nil {
		return p, fmt.Errorf("parse address %q: %w", cfg.Address, err)
	}
	p.Address = addr
	p.MTU = cfg.MTU

	seen := map[netip.Prefix]bool{}
	for _, s := range cfg.AllowedIPs {
		r, ok := parseRoute(s)
		if !ok || seen[r] {
			continue
		}
		seen[r] = true
		if r.Addr().Is4() {
			p.Routes4 = append(p.Routes4, r)
			p.Default4 = p.Default4 || r.Bits() == 0
		} else {
			p.Routes6 = append(p.Routes6, r)
			p.Default6 = p.Default6 || r.Bits() == 0
		}
	}
	sortPrefixes(p.Routes4)
	sortPrefixes(p.Routes6)

	for _, s := range cfg.DNS {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return p, fmt.Errorf("parse DNS server %q: %w", s, err)
		}
		a = a.Unmap()
		if a.Is4() {
			p.DNS4 = append(p.DNS4, a)
		} else {
			p.DNS6 = append(p.DNS6, a)
		}
	}
	return p, nil
}

// parseRoute is an AllowedIPs entry as the route Windows will hold: masked
// (10.2.3.4/16 is the route 10.2.0.0/16) and with an IPv4-mapped IPv6
// address taken as the IPv4 one it maps.
func parseRoute(s string) (netip.Prefix, bool) {
	r, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	if r.Addr().Is4In6() {
		bits := r.Bits() - 96
		if bits < 0 {
			return netip.Prefix{}, false
		}
		r = netip.PrefixFrom(r.Addr().Unmap(), bits)
	}
	return r.Masked(), true
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}
