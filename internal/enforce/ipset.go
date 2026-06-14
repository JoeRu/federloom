package enforce

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
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

// Start creates the ipset sets and installs iptables/ip6tables rules (idempotent).
// Logs a warning if chain is INPUT, as that misses Docker container traffic.
func (s *IpsetSink) Start(ctx context.Context) error {
	if s.chain == "INPUT" {
		log.Printf("WARN enforce/ipset: chain=INPUT will not block traffic to Docker containers; use chain=DOCKER-USER for Docker environments")
	}

	// IPv4 set
	if err := s.run(ctx, "ipset", "create", s.setName, "hash:ip", "family", "inet", "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: create IPv4 set %q: %w", s.setName, err)
	}
	// IPv6 set — best-effort; ip6tables may not be present on all hosts
	if err := s.run(ctx, "ipset", "create", s.setName+"6", "hash:ip", "family", "inet6", "-exist"); err != nil {
		log.Printf("enforce/ipset: IPv6 set creation failed (ip6tables may be unavailable): %v", err)
	}

	// iptables rule (IPv4)
	if s.run(ctx, "iptables", "-C", s.chain, "-m", "set", "--match-set", s.setName, "src", "-j", "DROP") != nil {
		if err := s.run(ctx, "iptables", "-I", s.chain, "-m", "set", "--match-set", s.setName, "src", "-j", "DROP"); err != nil {
			return fmt.Errorf("enforce/ipset: install iptables rule: %w", err)
		}
	}
	// ip6tables rule (IPv6) — best-effort
	if s.run(ctx, "ip6tables", "-C", s.chain, "-m", "set", "--match-set", s.setName+"6", "src", "-j", "DROP") != nil {
		if err := s.run(ctx, "ip6tables", "-I", s.chain, "-m", "set", "--match-set", s.setName+"6", "src", "-j", "DROP"); err != nil {
			log.Printf("enforce/ipset: ip6tables rule installation failed: %v", err)
		}
	}
	return nil
}

// Block adds ip to the appropriate ipset (IPv4 or IPv6).
func (s *IpsetSink) Block(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	set := s.ipSet(ip)
	if err := s.run(ctx, "ipset", "add", set, ip, "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: block %s: %w", ip, err)
	}
	return nil
}

// Unblock removes ip from the appropriate ipset.
func (s *IpsetSink) Unblock(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	set := s.ipSet(ip)
	if err := s.run(ctx, "ipset", "del", set, ip, "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: unblock %s: %w", ip, err)
	}
	return nil
}

func (s *IpsetSink) ipSet(ip string) string {
	if strings.Contains(ip, ":") {
		return s.setName + "6"
	}
	return s.setName
}

// Close is a no-op: the set persists across daemon restarts so blocks survive.
func (s *IpsetSink) Close() error { return nil }

func (s *IpsetSink) run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

// Compile-time interface check.
var _ Sink = (*IpsetSink)(nil)
