package enforce_test

import (
	"testing"

	"github.com/JoeRu/federloom/internal/enforce"
)

func TestNeverBlockRFC1918(t *testing.T) {
	nbl := enforce.NewNeverBlockList(nil)
	for _, ip := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1"} {
		if !nbl.Contains(ip) {
			t.Errorf("expected %s to be neverblock", ip)
		}
	}
}

func TestNeverBlockPublicIP(t *testing.T) {
	nbl := enforce.NewNeverBlockList(nil)
	if nbl.Contains("198.51.100.1") {
		t.Error("198.51.100.1 should not be in neverblock")
	}
}

func TestNeverBlockExtraWhitelist(t *testing.T) {
	nbl := enforce.NewNeverBlockList([]string{"203.0.113.0/24"})
	if !nbl.Contains("203.0.113.5") {
		t.Error("203.0.113.5 should be in extra whitelist")
	}
	if nbl.Contains("203.0.114.1") {
		t.Error("203.0.114.1 should not be in extra whitelist")
	}
}

// TestNeverBlockAcceptsBareIP: a bare (non-CIDR) IP in the extra list is
// honored as an exact /32 (or /128) entry — previously such entries were
// silently skipped, leaving an operator who wrote a bare IP unprotected.
func TestNeverBlockAcceptsBareIP(t *testing.T) {
	nbl := enforce.NewNeverBlockList([]string{"203.0.113.7", "2001:db8::1"})
	if !nbl.Contains("203.0.113.7") {
		t.Error("bare IPv4 203.0.113.7 should be never-blocked (as /32)")
	}
	if nbl.Contains("203.0.113.8") {
		t.Error("bare-IP entry must be exact /32, not a wider range")
	}
	if !nbl.Contains("2001:db8::1") {
		t.Error("bare IPv6 2001:db8::1 should be never-blocked (as /128)")
	}
	if nbl.Contains("2001:db8::2") {
		t.Error("bare IPv6 entry must be exact /128, not wider")
	}
}

// TestNeverBlockAcceptsMappedBareIP: an IPv4-mapped IPv6 literal passed as a
// bare "extra" entry (e.g. from a dual-stack log source) must Unmap() to its
// IPv4 form BEFORE the /32 vs /128 decision. Storing it as a /128 IPv6 prefix
// would never match a real query, since Contains() unmaps the query address
// to plain IPv4 first (netutil.KeyAddr) and netip.Prefix.Contains requires
// matching address families. This would FAIL against the pre-fix code, which
// checked addr.Is6() before unmapping.
func TestNeverBlockAcceptsMappedBareIP(t *testing.T) {
	nbl := enforce.NewNeverBlockList([]string{"::ffff:203.0.113.7"})
	if !nbl.Contains("203.0.113.7") {
		t.Error("::ffff:203.0.113.7 should be never-blocked as 203.0.113.7/32 after Unmap()")
	}
	if nbl.Contains("203.0.113.8") {
		t.Error("mapped bare-IP entry must be exact /32, not a wider range")
	}
}

// TestNeverBlockSkipsZonedAddr: a zoned IPv6 literal (e.g. "2001:db8::1%eth0")
// parses successfully via netip.ParseAddr but cannot form a valid netip.Prefix
// (zones can't live in a prefix). The pre-fix code discarded the ParsePrefix
// error and appended a zero/invalid netip.Prefix, silently corrupting the
// list. The fix must skip the zoned entry entirely (no panic, no match), and
// must not affect other valid entries in the same list. Note: this uses a
// non-link-local address (2001:db8::1) so the assertion isn't confounded by
// the default fe80::/10 link-local never-block entry.
func TestNeverBlockSkipsZonedAddr(t *testing.T) {
	nbl := enforce.NewNeverBlockList([]string{"2001:db8::1%eth0", "203.0.113.9"})
	if nbl.Contains("2001:db8::1") {
		t.Error("zoned entry (2001:db8::1 with zone eth0) must be skipped, not silently matched")
	}
	if !nbl.Contains("203.0.113.9") {
		t.Error("valid sibling entry must still work alongside a skipped zoned entry")
	}
}

func TestNeverBlockIPv6Loopback(t *testing.T) {
	nbl := enforce.NewNeverBlockList(nil)
	if !nbl.Contains("::1") {
		t.Error("::1 should be in neverblock (::1/128 default entry)")
	}
}

func TestNeverBlockIPv4MappedRFC1918(t *testing.T) {
	nbl := enforce.NewNeverBlockList(nil)
	// ::ffff:10.0.0.1 is IPv4-mapped RFC1918 — Unmap() must reveal 10.0.0.1
	if !nbl.Contains("::ffff:10.0.0.1") {
		t.Error("::ffff:10.0.0.1 (IPv4-mapped RFC1918) should be caught by 10.0.0.0/8")
	}
}

func TestNeverBlockCoversPublicResolvers(t *testing.T) {
	nbl := enforce.NewNeverBlockList(nil)
	for _, ip := range []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"} {
		if !nbl.Contains(ip) {
			t.Errorf("public resolver %s must be never-blocked by default", ip)
		}
	}
	// Sanity: an ordinary public IP is still blockable (not in the set).
	if nbl.Contains("203.0.113.5") {
		t.Error("203.0.113.5 must NOT be in the never-block default set")
	}
}

func TestNeverBlockAcceptsCIDRKey(t *testing.T) {
	nbl := enforce.NewNeverBlockList([]string{"2001:db8:1::/48"})
	if !nbl.Contains("2001:db8:1:2::/64") {
		t.Error("/64 whose base is in a whitelisted /48 must be never-blocked")
	}
	if nbl.Contains("2001:db8:9:9::/64") {
		t.Error("/64 outside all never-block ranges must be blockable")
	}
}
