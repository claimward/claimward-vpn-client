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
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return 0
	}
	defer c.Close()
	la, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0
	}
	src, ok := netip.AddrFromSlice(la.IP)
	if !ok {
		return 0
	}
	src = src.Unmap()
	ifs, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Unmap() == src {
				return ifc.MTU
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
