//go:build windows

package wgtun

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// tunName is the Wintun adapter's name, which is what Windows shows the
// person in its network settings.
//
// The adapter is Wintun's: wireguard-go's tun.CreateTUN loads wintun.dll,
// which must sit beside the executable (https://www.wintun.net, signed by
// WireGuard LLC). It is not bundled here; each app ships it.
const tunName = "Claimward"

// luid is the adapter's interface LUID, what every winipcfg call is keyed on.
func (t *Tunnel) luid() (winipcfg.LUID, error) {
	nt, ok := t.tun.(*tun.NativeTun)
	if !ok {
		return 0, fmt.Errorf("wgtun: %T is not a Wintun adapter", t.tun)
	}
	return winipcfg.LUID(nt.LUID()), nil
}

// configureNetwork gives the Wintun adapter its address, routes, DNS and
// MTU with winipcfg (the IP Helper API, no netsh), the way WireGuard for
// Windows does in tunnel/addressconfig.go. What to set is worked out by
// planNetwork; this only applies it.
func (t *Tunnel) configureNetwork() error {
	plan, err := planNetwork(t.cfg)
	if err != nil {
		return err
	}
	luid, err := t.luid()
	if err != nil {
		return err
	}
	for _, f := range []struct {
		family  winipcfg.AddressFamily
		routes  []netip.Prefix
		dns     []netip.Addr
		isDflt  bool
		hasAddr bool
		nextHop netip.Addr
	}{
		{windows.AF_INET, plan.Routes4, plan.DNS4, plan.Default4, plan.Address.Addr().Is4(), netip.IPv4Unspecified()},
		{windows.AF_INET6, plan.Routes6, plan.DNS6, plan.Default6, plan.Address.Addr().Is6(), netip.IPv6Unspecified()},
	} {
		if len(f.routes) > 0 {
			rs := make([]*winipcfg.RouteData, 0, len(f.routes))
			for _, r := range f.routes {
				rs = append(rs, &winipcfg.RouteData{Destination: r, NextHop: f.nextHop})
			}
			if err := luid.SetRoutesForFamily(f.family, rs); err != nil {
				return fmt.Errorf("set routes: %w", err)
			}
		}
		if f.hasAddr {
			if err := luid.SetIPAddressesForFamily(f.family, []netip.Prefix{plan.Address}); err != nil {
				return fmt.Errorf("set address %s: %w", plan.Address, err)
			}
		}
		if !f.hasAddr && len(f.routes) == 0 {
			continue // nothing of this family goes through the tunnel
		}
		ipif, err := luid.IPInterface(f.family)
		if err != nil {
			return fmt.Errorf("read interface: %w", err)
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		if plan.MTU > 0 {
			ipif.NLMTU = uint32(plan.MTU)
		}
		if f.isDflt {
			ipif.UseAutomaticMetric = false
			ipif.Metric = 0
		}
		if err := ipif.Set(); err != nil {
			return fmt.Errorf("set metric and MTU: %w", err)
		}
		if err := luid.SetDNS(f.family, f.dns, nil); err != nil {
			return fmt.Errorf("set DNS: %w", err)
		}
	}
	return nil
}

// teardownNetwork removes what configureNetwork set. Best-effort: closing
// the device deletes the Wintun adapter, and its addresses and routes with
// it; this only saves them outliving it for a moment.
func (t *Tunnel) teardownNetwork() {
	luid, err := t.luid()
	if err != nil {
		return
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		_ = luid.FlushRoutes(family)
		_ = luid.FlushDNS(family)
		_ = luid.FlushIPAddresses(family)
	}
}

func (t *Tunnel) routeAdd(cidr string) error {
	r, ok := parseRoute(cidr)
	if !ok {
		return nil // skip malformed, as on the other platforms
	}
	luid, err := t.luid()
	if err != nil {
		return err
	}
	if err := luid.AddRoute(r, unspecified(r), 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("add route %s: %w", r, err)
	}
	return nil
}

func (t *Tunnel) routeDel(cidr string) {
	r, ok := parseRoute(cidr)
	if !ok {
		return
	}
	if luid, err := t.luid(); err == nil {
		_ = luid.DeleteRoute(r, unspecified(r))
	}
}

// unspecified is the on-link next hop of r's family: the route goes out of
// the adapter itself, as a point-to-point link has no gateway.
func unspecified(r netip.Prefix) netip.Addr {
	if r.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}
