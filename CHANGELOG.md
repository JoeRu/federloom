# Changelog

All notable changes are documented here. Format: Keep a Changelog; versioning: SemVer.

## [Unreleased]

### Added
- **Social trust anchors (spec §5.1)** — Ed25519 Person identity keys that bind
  a human to their machines. One operator anchors another's key; every machine
  they certify inherits trust and counts as one corroboration group.
  - `internal/identity` — node key persistence, Person key generation/load,
    cert issue/verify (Ed25519 over `peerID‖PersonKey‖validUntil`), fingerprint.
  - `internal/trust` — anchor store (`anchors.json`, hot-reloaded every 10 s),
    on-wire cert cache, `Resolve(peerID)` → weight/group/anchored flag.
  - `internal/node` — spoof guard (`ReporterID != From` → drop), on-wire vouch
    verify/cache, cert-replay guard (`Vouch.PeerID != ReporterID` → ignore cert),
    trust-resolved scoring.
  - `internal/reputation` — Person-group corroboration (distinct anchor groups
    count once each); stranger flood capped at `stranger_score_cap` (default 15 pts).
  - `internal/config` — `TrustConfig` (anchor/person-key/peer-cert paths,
    `anchor_weight`, `stranger_weight`, `stranger_score_cap`).
  - `cmd/swarmctl` — full trust CLI: `identity init/show`, `peer-cert`,
    `trust add/set/remove/list/export/import`.
  - Adversarial suite (`make adversarial`) gains six new vouch scenarios:
    Sybil flood cap, anchored person counts once, forged signature, cert replay,
    expired cert, person removal applies immediately (Invariant 6).
  - Integration test: vouched vs. un-vouched event through `ProcessRemote`.
  - Docs: `docs/onboarding/03-key-management.md` (concrete CLI workflow),
    `docs/federation-guide.md` (person-to-person pairing section).

### Changed
- **Wire protocol `SchemaVersion` 0 → 1** — `pkg/proto.Event` gains
  `Vouch *PeerCert \`json:"vouch,omitempty"\``. v0 nodes ignore the field;
  v1 senders that send to a v0 node are treated as strangers (no cert verified).
  This is a **breaking schema change** — update all nodes in a federation before
  relying on vouched trust.
- `internal/store.ScoreRecord` gains `Groups []string`, `StrangerSeen bool`,
  `StrangerContrib float64` for group-based corroboration tracking.
- `reputation.Engine.New` takes a `strangerCap float64` third parameter.
- `reputation.Engine.Record` takes `group string` and `anchored bool` parameters.
- `transport.Node.Subscribe()` now returns `<-chan transport.ReceivedEvent`
  (wraps `proto.Event` + `From string` verified publisher ID).

### Initial scaffold
- Initial scaffold: spec, project structure, plugin interfaces (ingest/enforce),
  wire protocol (`pkg/proto`), federation onboarding docs, Claude skills.
