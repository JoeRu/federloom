package enforce_test

import (
	"testing"

	"github.com/JoeRu/swarmguard/internal/enforce"
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
