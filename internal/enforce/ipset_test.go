package enforce

import (
	"context"
	"testing"
)

// captureRun records ipset/iptables invocations for assertion.
func captureRun(calls *[][]string) func(ctx context.Context, name string, args ...string) error {
	return func(ctx context.Context, name string, args ...string) error {
		*calls = append(*calls, append([]string{name}, args...))
		return nil
	}
}

func hasCall(calls [][]string, want ...string) bool {
	for _, c := range calls {
		if len(c) != len(want) {
			continue
		}
		match := true
		for i := range c {
			if c[i] != want[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestIpsetIPv6BlocksAsHashNet(t *testing.T) {
	var calls [][]string
	s := NewIpset("federloom", []string{"INPUT"})
	s.run = captureRun(&calls)

	if err := s.Block("2001:db8:1:2::/64"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !hasCall(calls, "ipset", "add", "federloom6", "2001:db8:1:2::/64", "-exist") {
		t.Errorf("IPv6 CIDR must be added to the hash:net set federloom6; calls=%v", calls)
	}
}

func TestIpsetIPv4BlocksBareAddress(t *testing.T) {
	var calls [][]string
	s := NewIpset("federloom", []string{"INPUT"})
	s.run = captureRun(&calls)

	if err := s.Block("1.2.3.4"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !hasCall(calls, "ipset", "add", "federloom", "1.2.3.4", "-exist") {
		t.Errorf("IPv4 must be added to the hash:ip set federloom; calls=%v", calls)
	}
}

func TestIpsetStartCreatesHashNetIPv6Set(t *testing.T) {
	var calls [][]string
	s := NewIpset("federloom", []string{"INPUT"})
	s.run = captureRun(&calls)

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !hasCall(calls, "ipset", "create", "federloom6", "hash:net", "family", "inet6", "-exist") {
		t.Errorf("IPv6 set must be created as hash:net; calls=%v", calls)
	}
	if !hasCall(calls, "ipset", "create", "federloom", "hash:ip", "family", "inet", "-exist") {
		t.Errorf("IPv4 set must stay hash:ip; calls=%v", calls)
	}
}
