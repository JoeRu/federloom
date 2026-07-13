package enforce

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
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
	if !hasCall(calls, "ipset", "create", "federloom6", "hash:net", "family", "inet6", "timeout", "0", "-exist") {
		t.Errorf("IPv6 set must be created as hash:net; calls=%v", calls)
	}
	if !hasCall(calls, "ipset", "create", "federloom", "hash:ip", "family", "inet", "timeout", "0", "-exist") {
		t.Errorf("IPv4 set must stay hash:ip; calls=%v", calls)
	}
}

func TestIpsetStartMigratesHashIpToHashNet(t *testing.T) {
	var calls [][]string
	firstCreateFailed := false
	s := NewIpset("federloom", []string{"INPUT"})
	s.run = func(ctx context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		// Fail the FIRST create of the hash:net IPv6 set to simulate a stale hash:ip set.
		if !firstCreateFailed && name == "ipset" && len(args) >= 2 && args[0] == "create" && args[1] == "federloom6" {
			firstCreateFailed = true
			return fmt.Errorf("set with the same name already exists")
		}
		return nil
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Migration must drop the ip6tables rule for the chain, destroy the stale set, then recreate as hash:net.
	if !hasCall(calls, "ip6tables", "-D", "INPUT", "-m", "set", "--match-set", "federloom6", "src", "-j", "DROP") {
		t.Errorf("migration must delete the ip6tables rule; calls=%v", calls)
	}
	if !hasCall(calls, "ipset", "destroy", "federloom6") {
		t.Errorf("migration must destroy the stale set; calls=%v", calls)
	}
	// After destroy, it recreates as hash:net (this is the SECOND create call).
	recreates := 0
	for _, c := range calls {
		if len(c) >= 5 && c[0] == "ipset" && c[1] == "create" && c[2] == "federloom6" && c[3] == "hash:net" {
			recreates++
		}
	}
	if recreates < 2 {
		t.Errorf("expected two hash:net create attempts (initial + post-destroy recreate); got %d; calls=%v", recreates, calls)
	}
}

func TestIpsetBlockForIssuesTimeout(t *testing.T) {
	var calls [][]string
	s := NewIpset("testset", []string{"INPUT"})
	s.run = func(ctx context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	if err := s.BlockFor("203.0.113.9", 90*time.Second); err != nil {
		t.Fatalf("BlockFor: %v", err)
	}
	// Expect: ipset add testset 203.0.113.9 timeout 90 -exist
	last := calls[len(calls)-1]
	joined := strings.Join(last, " ")
	if !strings.Contains(joined, "add testset 203.0.113.9") || !strings.Contains(joined, "timeout 90") {
		t.Errorf("BlockFor args = %v, want add with 'timeout 90'", last)
	}
}

func TestIpsetStartCreatesWithTimeoutCapability(t *testing.T) {
	var calls [][]string
	s := NewIpset("testset", []string{"INPUT"})
	s.run = func(ctx context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	_ = s.Start(context.Background())
	// The v4 create must include "timeout 0" so per-entry timeouts are allowed.
	found := false
	for _, c := range calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, "create testset hash:ip") && strings.Contains(j, "timeout 0") {
			found = true
		}
	}
	if !found {
		t.Errorf("Start did not create the v4 set with 'timeout 0'; calls=%v", calls)
	}
}

func TestBlockForErrorIsActionable(t *testing.T) {
	s := NewIpset("federloom", []string{"INPUT"})
	// Mock run to return a timeout-support error
	s.run = func(ctx context.Context, name string, args ...string) error {
		if name == "ipset" && len(args) > 0 && args[0] == "add" {
			return fmt.Errorf("set was created without timeout support")
		}
		return nil
	}
	err := s.BlockFor("203.0.113.50", 60*time.Second)
	if err == nil {
		t.Fatal("BlockFor should return an error")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "without timeout support") {
		t.Errorf("error should contain 'without timeout support' hint, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "recreate it or redeploy") {
		t.Errorf("error should contain 'recreate it or redeploy' hint, got: %s", errMsg)
	}
}
