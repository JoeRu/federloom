package enforce

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"
)

const nftTable = "federloom"
const nftSetName = "blocked"

// NftablesSink enforces blocks via nftables. Shells out to /sbin/nft. Requires root.
type NftablesSink struct {
	setName string
	hook    string // "input" (host traffic) or "forward" (Docker/routed)
}

// NewNftables creates a NftablesSink. hook should be "forward" in Docker environments.
func NewNftables(setName, hook string) *NftablesSink {
	if setName == "" {
		setName = nftSetName
	}
	if hook == "" {
		hook = "input"
	}
	return &NftablesSink{setName: setName, hook: hook}
}

func (s *NftablesSink) Name() string { return "nftables" }

// Start creates the nftables table, set, chain, and drop rule (all idempotent via || true).
func (s *NftablesSink) Start(ctx context.Context) error {
	if s.hook == "input" {
		log.Printf("INFO enforce/nftables: hook=input covers host traffic only; use hook=forward for Docker environments")
	}

	cmds := [][]string{
		{"nft", "add", "table", "inet", nftTable},
		{"nft", "add", "set", "inet", nftTable, s.setName, "{ type ipv4_addr; flags interval; }"},
		{"nft", "add", "chain", "inet", nftTable, s.hook, fmt.Sprintf("{ type filter hook %s priority 0; }", s.hook)},
		{"nft", "add", "rule", "inet", nftTable, s.hook, "ip", "saddr", "@" + s.setName, "drop"},
	}
	for _, args := range cmds {
		// Idempotent: ignore "already exists" errors.
		_ = exec.CommandContext(ctx, args[0], args[1:]...).Run()
	}
	return nil
}

// Block adds ip to the nftables set.
func (s *NftablesSink) Block(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "nft", "add", "element", "inet", nftTable, s.setName, "{", ip, "}").Run(); err != nil {
		return fmt.Errorf("enforce/nftables: block %s: %w", ip, err)
	}
	return nil
}

// Unblock removes ip from the nftables set.
func (s *NftablesSink) Unblock(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "nft", "delete", "element", "inet", nftTable, s.setName, "{", ip, "}").Run(); err != nil {
		return fmt.Errorf("enforce/nftables: unblock %s: %w", ip, err)
	}
	return nil
}

// Close is a no-op: the nftables rules persist across daemon restarts.
func (s *NftablesSink) Close() error { return nil }

// Compile-time interface check.
var _ Sink = (*NftablesSink)(nil)
