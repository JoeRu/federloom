// Package netutil holds small, pure network-address helpers shared across
// FederLoom. It has no dependencies on other internal packages.
package netutil

import (
	"fmt"
	"net/netip"
)

// NormalizeIP canonicalises an observed IP string into a reputation key:
//   - IPv4 (or IPv4-mapped IPv6): the bare, unmapped address ("1.2.3.4").
//   - IPv6: masked to ipv6Prefix and returned as an explicit CIDR
//     ("2001:db8:1:2::/64").
//
// Input may already be an IPv6 CIDR (from a peer that normalized): its base is
// re-masked to THIS node's ipv6Prefix. IPv4 in CIDR form (e.g. "0.0.0.0/0") is
// rejected so a malformed/attacker CIDR is dropped by the caller. A wide IPv6
// CIDR ("::/0") collapses to a single /ipv6Prefix key — the re-masking is the
// guard. ipv6Prefix must be 1..128 (callers pass a validated value).
func NormalizeIP(s string, ipv6Prefix int) (string, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		// Maybe an already-CIDR input from a normalizing peer.
		p, perr := netip.ParsePrefix(s)
		if perr != nil {
			return "", fmt.Errorf("netutil: parse %q: %w", s, err)
		}
		base := p.Addr().Unmap()
		if !base.Is6() {
			// IPv4-in-CIDR is malformed on the wire; reject (preserves the
			// CIDR-injection guard).
			return "", fmt.Errorf("netutil: reject IPv4 CIDR %q", s)
		}
		addr = base
	} else {
		addr = addr.Unmap()
	}

	if addr.Is4() {
		return addr.String(), nil
	}
	p, err := addr.Prefix(ipv6Prefix)
	if err != nil {
		return "", fmt.Errorf("netutil: mask %q to /%d: %w", s, ipv6Prefix, err)
	}
	return p.Masked().String(), nil
}

// KeyAddr returns the address to test for a reputation key: the address itself
// for a bare IP, or the base address for a CIDR key. ok is false if s parses as
// neither. Used by never-block/whitelist/API to match a normalized CIDR key.
func KeyAddr(s string) (addr netip.Addr, ok bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}
