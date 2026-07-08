package enforce

import "testing"

func TestNftablesIPv6BlocksInV6Set(t *testing.T) {
	var calls [][]string
	s := NewNftables("blocked", "input")
	s.run = captureRun(&calls) // captureRun/hasCall defined in ipset_test.go (same package)

	if err := s.Block("2001:db8:1:2::/64"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	// IPv6 CIDR goes to the v6 set (blocked6), added as an interval element.
	if !hasCall(calls, "nft", "add", "element", "inet", "federloom", "blocked6", "{", "2001:db8:1:2::/64", "}") {
		t.Errorf("IPv6 CIDR must be added to blocked6; calls=%v", calls)
	}
}

func TestNftablesIPv4BlocksInV4Set(t *testing.T) {
	var calls [][]string
	s := NewNftables("blocked", "input")
	s.run = captureRun(&calls)

	if err := s.Block("1.2.3.4"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !hasCall(calls, "nft", "add", "element", "inet", "federloom", "blocked", "{", "1.2.3.4", "}") {
		t.Errorf("IPv4 must be added to the v4 set; calls=%v", calls)
	}
}
