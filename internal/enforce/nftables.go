package enforce

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

const nftTable = "federloom"
const nftSetName = "blocked"

// NftablesSink enforces blocks via nftables. Shells out to /sbin/nft. Requires root.
type NftablesSink struct {
	setName string // IPv4 set; IPv6 set is setName+"6"
	hook    string // "input" (host traffic) or "forward" (Docker/routed)
	run     func(ctx context.Context, name string, args ...string) error
}

// NewNftables creates a NftablesSink. hook should be "forward" in Docker environments.
func NewNftables(setName, hook string) *NftablesSink {
	if setName == "" {
		setName = nftSetName
	}
	if hook == "" {
		hook = "input"
	}
	s := &NftablesSink{setName: setName, hook: hook}
	s.run = func(ctx context.Context, name string, args ...string) error {
		return exec.CommandContext(ctx, name, args...).Run()
	}
	return s
}

func (s *NftablesSink) Name() string { return "nftables" }

func (s *NftablesSink) set6() string { return s.setName + "6" }

// nftSet selects the IPv4 or IPv6 set for ip (CIDR or address).
func (s *NftablesSink) nftSet(ip string) string {
	if strings.Contains(ip, ":") {
		return s.set6()
	}
	return s.setName
}

// Start creates the nftables table, both sets (v4 addr + v6 addr interval),
// chain, and drop rules (all idempotent — errors ignored).
func (s *NftablesSink) Start(ctx context.Context) error {
	if s.hook == "input" {
		log.Printf("INFO enforce/nftables: hook=input covers host traffic only; use hook=forward for Docker environments")
	}
	cmds := [][]string{
		{"nft", "add", "table", "inet", nftTable},
		{"nft", "add", "set", "inet", nftTable, s.setName, "{ type ipv4_addr; flags interval; }"},
		{"nft", "add", "set", "inet", nftTable, s.set6(), "{ type ipv6_addr; flags interval; }"},
		{"nft", "add", "chain", "inet", nftTable, s.hook, fmt.Sprintf("{ type filter hook %s priority 0; }", s.hook)},
		{"nft", "add", "rule", "inet", nftTable, s.hook, "ip", "saddr", "@" + s.setName, "drop"},
		{"nft", "add", "rule", "inet", nftTable, s.hook, "ip6", "saddr", "@" + s.set6(), "drop"},
	}
	for _, args := range cmds {
		_ = s.run(ctx, args[0], args[1:]...)
	}
	return nil
}

// Block adds ip (IPv4 address or IPv6 CIDR) to the matching set.
func (s *NftablesSink) Block(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.run(ctx, "nft", "add", "element", "inet", nftTable, s.nftSet(ip), "{", ip, "}"); err != nil {
		return fmt.Errorf("enforce/nftables: block %s: %w", ip, err)
	}
	return nil
}

// Unblock removes ip from the matching set.
func (s *NftablesSink) Unblock(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.run(ctx, "nft", "delete", "element", "inet", nftTable, s.nftSet(ip), "{", ip, "}"); err != nil {
		return fmt.Errorf("enforce/nftables: unblock %s: %w", ip, err)
	}
	return nil
}

// Close is a no-op: the nftables rules persist across daemon restarts.
func (s *NftablesSink) Close() error { return nil }

// Compile-time interface check.
var _ Sink = (*NftablesSink)(nil)
