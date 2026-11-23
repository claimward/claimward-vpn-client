package wgtun

import (
	"net"
	"net/netip"
)

// Underlay overhead of a WireGuard packet: outer IP header + UDP (8) +
// WireGuard data header and tag (32), i.e. 60 over IPv4 and 80 over IPv6.
const (
	overheadV4 = 60
	overheadV6 = 80

	// floorMTU is IPv6's minimum link MTU: the path clamp never goes below
	// it (a server value below it is still honoured, never raised).
	floorMTU = 1280
)

// effectiveMTU is the tunnel MTU to use: the server's value, lowered to what
// the path to the endpoint carries (pathMTU, the MTU of the local link the
// endpoint is reached through, 0 = unknown, minus the underlay overhead of
// the endpoint's address family). It is never above the server's value and
// the path clamp never goes below floorMTU.
func effectiveMTU(server, pathMTU int, endpoint netip.Addr) int {
	if pathMTU <= 0 {
		return server
	}
	over := overheadV4
	if endpoint.Is6() && !endpoint.Is4In6() {
		over = overheadV6
	}
	fit := max(pathMTU-over, floorMTU)
	return min(server, fit)
}

// pathMTUFunc reports the MTU of the local link used to reach addr, 0 when
// it cannot be told. It is a variable so tests can stand in for the network.
var pathMTUFunc = localLinkMTU

// localLinkMTU asks the kernel which source address a UDP socket to addr
// would use (no packet is sent) and returns the MTU of the interface that
// holds it. This reads the same routing decision on macOS, Linux and
// Windows without a platform API.
func localLinkMTU(addr netip.AddrPort) int {
	src, err := sourceAddr(addr)
	if err != nil {
		return 0
	}
	return mtuOfSource(src, systemLinks())
}

// dialUDP is a variable so tests can make the route lookup fail.
var dialUDP = func(raddr *net.UDPAddr) (*net.UDPConn, error) {
	return net.DialUDP("udp", nil, raddr)
}

// sourceAddr is the local address the kernel picks to reach addr.
func sourceAddr(addr netip.AddrPort) (netip.Addr, error) {
	c, err := dialUDP(net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	la, _ := c.LocalAddr().(*net.UDPAddr) // always a *net.UDPAddr for DialUDP
	return la.AddrPort().Addr().Unmap(), nil
}

// link is one interface: its MTU and the prefixes configured on it.
type link struct {
	mtu   int
	addrs []netip.Prefix
}

// systemLinks lists the interfaces. An interface whose addresses cannot be
// read lists none, and an address that does not parse is the zero prefix,
// which matches no source address.
func systemLinks() []link {
	ifs, _ := net.Interfaces()
	out := make([]link, 0, len(ifs))
	for _, ifc := range ifs {
		l := link{mtu: ifc.MTU}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			p, _ := netip.ParsePrefix(a.String())
			l.addrs = append(l.addrs, p)
		}
		out = append(out, l)
	}
	return out
}

// mtuOfSource is the MTU of the link holding src, 0 when none does.
func mtuOfSource(src netip.Addr, links []link) int {
	for _, l := range links {
		for _, p := range l.addrs {
			if p.Addr().Unmap() == src {
				return l.mtu
			}
		}
	}
	return 0
}

// tunnelMTU resolves the MTU for cfg: the server's (default when absent),
// lowered to fit the path to cfg.Endpoint.
func tunnelMTU(serverMTU int, endpoint string) int {
	m := clampMTU(serverMTU)
	ep, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return m
	}
	return effectiveMTU(m, pathMTUFunc(ep), ep.Addr().Unmap())
}
