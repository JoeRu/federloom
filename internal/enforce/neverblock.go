package enforce

import "net/netip"

// defaultNeverBlock contains CIDRs that must never be blocked (spec §6.2, invariant 3).
var defaultNeverBlock = []string{
	"127.0.0.0/8",    // loopback
	"::1/128",        // IPv6 loopback
	"10.0.0.0/8",     // RFC1918
	"172.16.0.0/12",  // RFC1918
	"192.168.0.0/16", // RFC1918
	"100.64.0.0/10",  // CGNAT (RFC6598)
	"169.254.0.0/16", // link-local
	"224.0.0.0/4",    // multicast
	"fc00::/7",       // IPv6 ULA
	"fe80::/10",      // IPv6 link-local
}

// NeverBlockList is an immutable set of CIDRs that must never be blocked.
type NeverBlockList struct {
	prefixes []netip.Prefix
}

// NewNeverBlockList builds a NeverBlockList from the default RFC1918 ranges plus any
// operator-provided extra CIDRs. Invalid entries in extra are silently skipped.
func NewNeverBlockList(extra []string) *NeverBlockList {
	all := append(defaultNeverBlock, extra...)
	var prefixes []netip.Prefix
	for _, cidr := range all {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return &NeverBlockList{prefixes: prefixes}
}

// Contains returns true if ip is covered by any CIDR in the list.
func (l *NeverBlockList) Contains(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range l.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
