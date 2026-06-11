package enforce

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"
)

// IpsetSink enforces blocks via ipset + iptables. Shells out to /sbin/ipset
// and /sbin/iptables — no CGo, auditable. Requires root.
type IpsetSink struct {
	setName string
	chain   string
}

// NewIpset creates an IpsetSink. setName is the ipset name; chain is the
// iptables chain (DOCKER-USER recommended for Docker environments; INPUT for host-only).
func NewIpset(setName, chain string) *IpsetSink {
	if setName == "" {
		setName = "swarmguard"
	}
	if chain == "" {
		chain = "DOCKER-USER"
	}
	return &IpsetSink{setName: setName, chain: chain}
}

func (s *IpsetSink) Name() string { return "ipset" }

// Start creates the ipset and installs the iptables rule (both idempotent).
// Logs a warning if chain is INPUT, as that misses Docker container traffic.
func (s *IpsetSink) Start(ctx context.Context) error {
	if s.chain == "INPUT" {
		log.Printf("WARN enforce/ipset: chain=INPUT will not block traffic to Docker containers; use chain=DOCKER-USER for Docker environments")
	}

	if err := s.run(ctx, "ipset", "create", s.setName, "hash:ip", "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: create set %q: %w", s.setName, err)
	}

	// Check if rule already exists before inserting.
	check := s.run(ctx, "iptables", "-C", s.chain, "-m", "set", "--match-set", s.setName, "src", "-j", "DROP")
	if check != nil {
		// Rule not present — insert at top.
		if err := s.run(ctx, "iptables", "-I", s.chain, "-m", "set", "--match-set", s.setName, "src", "-j", "DROP"); err != nil {
			return fmt.Errorf("enforce/ipset: install iptables rule: %w", err)
		}
	}
	return nil
}

// Block adds ip to the ipset.
func (s *IpsetSink) Block(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.run(ctx, "ipset", "add", s.setName, ip, "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: block %s: %w", ip, err)
	}
	return nil
}

// Unblock removes ip from the ipset.
func (s *IpsetSink) Unblock(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.run(ctx, "ipset", "del", s.setName, ip, "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: unblock %s: %w", ip, err)
	}
	return nil
}

// Close is a no-op: the set persists across daemon restarts so blocks survive.
func (s *IpsetSink) Close() error { return nil }

func (s *IpsetSink) run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

// Compile-time interface check.
var _ Sink = (*IpsetSink)(nil)
