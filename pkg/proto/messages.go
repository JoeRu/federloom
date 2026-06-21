// Package proto defines the on-the-wire message types exchanged between
// SwarmGuard nodes. This is the stable public contract (spec §7). Changes here
// ripple through the whole network — see .claude/skills/wire-protocol.
package proto

import "time"

// SchemaVersion is bumped on any breaking change to the wire format.
const SchemaVersion = 0 // 0 = pre-release, unstable

// Event is a single observed attack report (spec §7.1).
type Event struct {
	IP          string    `json:"ip"`         // cleartext IPv4/IPv6 (hashing rejected, spec §9)
	Reason      string    `json:"reason"`     // e.g. "smtp-auth-bruteforce", "dict-attack", "spam"
	Timestamp   time.Time `json:"ts"`         // time of observation
	PortClass   string    `json:"port_class"` // target port class (for plausibility checks)
	ReporterID  string    `json:"reporter"`   // pseudonymous node ID (public key)
	Signature   []byte    `json:"sig"`        // signature of the reporter
	SubnetID    string    `json:"subnet"`     // origin trust domain (federation, spec §5)
	OriginTrace []string  `json:"origin"`     // provenance chain (anti feedback-loop, spec §5.2)
}

// ScoreEntry is the aggregated reputation for one IP within a trust domain (spec §7.2).
type ScoreEntry struct {
	IP            string    `json:"ip"`
	Score         float64   `json:"score"`         // normalised, e.g. 0..100
	Corroboration int       `json:"corroboration"` // count + diversity of independent reporters
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Reasons       []string  `json:"reasons"`
	Disputes      int       `json:"disputes"` // whitelist / anti-trust votes
}

// AnchorEntry is a trust anchor public key with local weight (spec §7.3).
type AnchorEntry struct {
	KeyID      string    `json:"key_id"`
	Label      string    `json:"label"`
	Weight     float64   `json:"weight"`
	ValidUntil time.Time `json:"valid_until"`
	Source     string    `json:"source"` // "project-default" | "self-added" | "subnet"
}

// WhitelistEntry separates never-shared local truth from shared votes (spec §7.4).
type WhitelistEntry struct {
	IPOrRange string `json:"ip_or_range"`
	Scope     string `json:"scope"`  // "local-only" (never shared) | "shared-vote"
	Source    string `json:"source"` // "install-script" | "manual" | "federation"
}
