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
	chains  []string
}

// NewIpset creates an IpsetSink. setName is the ipset name; chains lists the
// iptables chains to install the drop rule in. Typical values: ["DOCKER-USER"]
// for Docker container traffic, ["INPUT"] for host-only, or both for mixed.
// Defaults to ["DOCKER-USER"] when chains is empty.
func NewIpset(setName string, chains []string) *IpsetSink {
	if setName == "" {
		setName = "federloom"
	}
	if len(chains) == 0 {
		chains = []string{"DOCKER-USER"}
	}
	return &IpsetSink{setName: setName, chains: chains}
}

func (s *IpsetSink) Name() string { return "ipset" }

// Start creates the ipset sets and installs iptables/ip6tables rules (idempotent).
func (s *IpsetSink) Start(ctx context.Context) error {
	// IPv4 set
	if err := s.run(ctx, "ipset", "create", s.setName, "hash:ip", "family", "inet", "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: create IPv4 set %q: %w", s.setName, err)
	}
	// IPv6 set — best-effort; ip6tables may not be present on all hosts
	if err := s.run(ctx, "ipset", "create", s.setName+"6", "hash:ip", "family", "inet6", "-exist"); err != nil {
		log.Printf("enforce/ipset: IPv6 set creation failed (ip6tables may be unavailable): %v", err)
	}

	for _, chain := range s.chains {
		// iptables rule (IPv4)
		if s.run(ctx, "iptables", "-C", chain, "-m", "set", "--match-set", s.setName, "src", "-j", "DROP") != nil {
			if err := s.run(ctx, "iptables", "-I", chain, "-m", "set", "--match-set", s.setName, "src", "-j", "DROP"); err != nil {
				return fmt.Errorf("enforce/ipset: install iptables rule in %s: %w", chain, err)
			}
		}
		// ip6tables rule (IPv6) — best-effort
		if s.run(ctx, "ip6tables", "-C", chain, "-m", "set", "--match-set", s.setName+"6", "src", "-j", "DROP") != nil {
			if err := s.run(ctx, "ip6tables", "-I", chain, "-m", "set", "--match-set", s.setName+"6", "src", "-j", "DROP"); err != nil {
				log.Printf("enforce/ipset: ip6tables rule in %s failed: %v", chain, err)
			}
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
