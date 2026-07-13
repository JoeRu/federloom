package enforce

import (
	"net/netip"

	"github.com/JoeRu/federloom/internal/netutil"
)

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
	// Public resolvers — safe default per spec §10; operator-removable by
	// editing this list. Broad provider/CDN ranges are documented in
	// docs/config.md for opt-in via extra_whitelist (spec caveat N).
	"8.8.8.8/32",         // Google DNS
	"8.8.4.4/32",         // Google DNS secondary
	"1.1.1.1/32",         // Cloudflare DNS
	"1.0.0.1/32",         // Cloudflare DNS secondary
	"9.9.9.9/32",         // Quad9
	"149.112.112.112/32", // Quad9 secondary
}

// NeverBlockList is an immutable set of CIDRs that must never be blocked.
type NeverBlockList struct {
	prefixes []netip.Prefix
}

// NewNeverBlockList builds a NeverBlockList from the default RFC1918 ranges plus any
// operator-provided extra CIDRs or bare IPs. Invalid entries in extra are silently skipped.
// Bare IPs are converted to /32 (or /128 for IPv6).
func NewNeverBlockList(extra []string) *NeverBlockList {
	all := append(defaultNeverBlock, extra...)
	var prefixes []netip.Prefix
	for _, cidr := range all {
		// Try to parse as a CIDR prefix first
		prefix, err := netip.ParsePrefix(cidr)
		if err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		// If that fails, try to parse as a bare IP and convert to /32 or /128
		if addr, err := netip.ParseAddr(cidr); err == nil {
			if addr.Is6() {
				prefix, _ = netip.ParsePrefix(addr.String() + "/128")
			} else {
				prefix, _ = netip.ParsePrefix(addr.String() + "/32")
			}
			prefixes = append(prefixes, prefix)
		}
	}
	return &NeverBlockList{prefixes: prefixes}
}

// Contains returns true if ip (a bare address or CIDR key) is covered by any
// CIDR in the list. For a CIDR key, its base address is tested.
func (l *NeverBlockList) Contains(ip string) bool {
	addr, ok := netutil.KeyAddr(ip)
	if !ok {
		return false
	}
	for _, p := range l.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
