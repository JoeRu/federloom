package enforce

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// IpsetSink enforces blocks via ipset + iptables. Shells out to /sbin/ipset
// and /sbin/iptables — no CGo, auditable. Requires root.
type IpsetSink struct {
	setName string
	chains  []string
	run     func(ctx context.Context, name string, args ...string) error
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
	s := &IpsetSink{setName: setName, chains: chains}
	s.run = func(ctx context.Context, name string, args ...string) error {
		return exec.CommandContext(ctx, name, args...).Run()
	}
	return s
}

func (s *IpsetSink) Name() string { return "ipset" }

// Start creates the ipset sets and installs iptables/ip6tables rules (idempotent).
func (s *IpsetSink) Start(ctx context.Context) error {
	// IPv4 set
	if err := s.run(ctx, "ipset", "create", s.setName, "hash:ip", "family", "inet", "timeout", "0", "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: create IPv4 set %q: %w", s.setName, err)
	}
	// IPv6 set is hash:net so a whole /64 (or configured prefix) blocks as one
	// entry. Migrate a pre-existing hash:ip set: -exist errors on a type
	// mismatch, which we use as the migration trigger. Best-effort (IPv6 may be
	// unavailable on some hosts).
	set6 := s.setName + "6"
	if err := s.run(ctx, "ipset", "create", set6, "hash:net", "family", "inet6", "timeout", "0", "-exist"); err != nil {
		// Likely a stale hash:ip set from a prior version. Drop referencing
		// ip6tables rules so the set can be destroyed, then recreate as hash:net.
		for _, chain := range s.chains {
			_ = s.run(ctx, "ip6tables", "-D", chain, "-m", "set", "--match-set", set6, "src", "-j", "DROP")
		}
		_ = s.run(ctx, "ipset", "destroy", set6)
		if err2 := s.run(ctx, "ipset", "create", set6, "hash:net", "family", "inet6", "timeout", "0", "-exist"); err2 != nil {
			log.Printf("enforce/ipset: IPv6 hash:net set creation failed (ip6tables may be unavailable): %v", err2)
		}
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

// BlockFor adds ip with a TTL (seconds) after which ipset auto-removes it.
func (s *IpsetSink) BlockFor(ip string, ttl time.Duration) error {
	if ttl <= 0 {
		return s.Block(ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	set := s.ipSet(ip)
	secs := strconv.Itoa(int(ttl.Seconds()))
	if err := s.run(ctx, "ipset", "add", set, ip, "timeout", secs, "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: blockFor %s: %w (if this reports 'without timeout support', the ipset set %q predates the materialise feature — recreate it or redeploy the node)", ip, err, set)
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

// Compile-time interface check.
var _ Sink = (*IpsetSink)(nil)
