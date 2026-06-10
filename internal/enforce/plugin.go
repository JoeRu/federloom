// Package enforce is the data plane: the only place that writes to the firewall.
// Kept deliberately small and isolated because it is security-critical.
//
// A Sink applies block decisions. Backends implement Sink — see
// .claude/skills/enforce-backend.
package enforce

import "context"

// Sink applies block decisions to a firewall backend.
// Implementations must be safe for concurrent use.
type Sink interface {
	Name() string
	// Start creates the required firewall structures (idempotent). Must be called before Block/Unblock.
	Start(ctx context.Context) error
	// Block adds ip to the deny set.
	Block(ip string) error
	// Unblock removes ip from the deny set.
	Unblock(ip string) error
	// Close releases any resources held by the backend (does NOT flush the deny set).
	Close() error
}
