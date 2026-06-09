// Package enforce is the data plane: the only place that writes to the firewall.
// Kept deliberately small and isolated because it is security-critical.
//
// A Sink applies block decisions. Backends implement Sink — see
// .claude/skills/enforce-backend.
package enforce

import "github.com/JoeRu/swarmguard/pkg/proto"

// Sink applies the locally-decided blocklist to an enforcement backend.
type Sink interface {
	Name() string
	// Apply reconciles the backend to exactly the given blocked IPs (idempotent).
	Apply(blocked []proto.ScoreEntry) error
}
