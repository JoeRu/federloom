// Package proto defines the on-the-wire message types exchanged between
// FederLoom nodes. This is the stable public contract (spec §7). Changes here
// ripple through the whole network — see .claude/skills/wire-protocol.
package proto

import "time"

// SchemaVersion is bumped on any breaking change to the wire format.
// v2: wire cleanup (removed PortClass, ScoreEntry).
const SchemaVersion = 2

// Event is a single observed attack report (spec §7.1).
type Event struct {
	IP          string    `json:"ip"`              // cleartext IPv4/IPv6 (hashing rejected, spec §9)
	Reason      string    `json:"reason"`          // attack scenario (spec §7.1 join-key `scenario`); e.g. "smtp-auth-bruteforce"
	Timestamp   time.Time `json:"ts"`              // time of observation
	ReporterID  string    `json:"reporter"`        // pseudonymous node ID (public key)
	Signature   []byte    `json:"sig"`             // signature of the reporter
	SubnetID    string    `json:"subnet"`          // origin trust domain (federation, spec §5)
	OriginTrace []string  `json:"origin"`          // provenance chain (anti feedback-loop, spec §5.2)
	Vouch       *PeerCert `json:"vouch,omitempty"` // present if the reporter is vouched by a Person identity (spec §5.1)
	Kind        string    `json:"kind,omitempty"`  // "" = report/attack (default); "vote" = federated shared-vote dispute (spec §4.4)
}

// PeerCert binds a node's libp2p peer ID to a Person identity (spec §5.1).
// Signed by the Person identity key; a node anchors the Person's public key
// locally and every certified peer inherits that trust.
type PeerCert struct {
	PeerID     string    `json:"peer_id"`     // libp2p peer ID being vouched for
	PersonKey  []byte    `json:"person_key"`  // Ed25519 public key of the Person identity
	ValidUntil time.Time `json:"valid_until"` // cert expiry
	Sig        []byte    `json:"sig"`         // Ed25519 sig by PersonKey over (PeerID ‖ PersonKey ‖ ValidUntil RFC3339); see internal/identity
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

// RepQuery is an on-demand request for one IP's reputation (spec §11.4, E3).
// The response is an EvidenceAggregate over /federloom/repquery/v2.
type RepQuery struct {
	IP string `json:"ip"`
}

// EvidenceAggregate is the federated import type (spec §7.5): what subnets
// share and every consumer recomputes locally (§8). Carries NO reporter
// identity — only distinct-reporter counts per bucket dimension. It is the
// answer to a RepQuery over /federloom/repquery/v2.
type EvidenceAggregate struct {
	IP               string         `json:"ip"`                // IPv4 single / IPv6 prefix-normalized
	Scenarios        []string       `json:"scenarios"`         // distinct reason codes observed (§7.1)
	WindowFirst      time.Time      `json:"window_first"`      // evidence window start
	WindowLast       time.Time      `json:"window_last"`       // zero = "not found" sentinel
	DiversityBuckets map[string]int `json:"diversity_buckets"` // dimension -> distinct reporter count; MVP: "groups","reporters"
	StrangersPresent bool           `json:"strangers_present"` // un-anchored reporters contributed
	EvidenceWeight   float64        `json:"evidence_weight"`   // aggregator source weight; consumer clamps to [0,1]
}
