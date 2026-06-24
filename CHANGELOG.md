# Changelog

All notable changes are documented here. Format: Keep a Changelog; versioning: SemVer.

## [Unreleased]

### Added
- `internal/observability`: dual-output Observer — Prometheus `/metrics` (port 9101) + SQLite
  event history with configurable retention (default 15 days). Both disabled by default.
- Six Prometheus metrics: `federloom_events_received_total`, `federloom_rules_fired_total`,
  `federloom_blocked_ips`, `federloom_ip_score`, `federloom_federation_peers`,
  `federloom_events_federated_total`.
- SQLite tables: `events`, `rule_firings`, `blocks` with precomputed `expected_unblock`
  (due-time for active blocks).
- `deploy/grafana/federloom-dashboard.json`: importable Grafana dashboard covering live
  Prometheus panels and local SQLite history panels.
- `rules.Evaluate` now returns `(Action, string)` — matched rule name available for metrics.
- Honeypot, mailcow, and wordpress deploy configs updated to enable observability.

### Changed
- `internal/rules`: `Evaluate` signature changed to `(Action, string)`.

### Added
- **CrowdSec ingest adapter** (`internal/ingest/crowdsec.go`): polls `/v1/decisions/stream`
  and `/v1/alerts` from a local CrowdSec LAPI instance; decisions emit
  `crowdsec-decision` events, alerts map via `scenarioMap` to existing FederLoom
  reason strings or fall back to `crowdsec-alert`. Opt-in via `ingest.crowdsec.enabled`.
- Three CrowdSec rules in `deploy/examples/rules.yaml`: `crowdsec-decision` (block),
  `crowdsec-alert-corroborated` (block ≥ 2 sources), `crowdsec-alert-watch` (watch).

### Added (rules engine)
- **Pure YAML rules engine** — `internal/rules` package replaces the single
  `block_threshold` scalar with a hot-reloadable `rules.yaml` file.
  - `RuleSet.Evaluate(event, scoreRecord, burstStore)` — first-match rule
    evaluation with AND conditions: `reason`, `min_score`, `min_corroboration`,
    `anchored_only`, `min_burst`+`burst_window`.
  - `BurstStore` — in-memory sliding-window counter per (ip, reason); resets on
    restart (burst = happening now).
  - Hot-reload: file re-read on mtime+size change; corrupt file keeps last-good.
  - Rule validation: rules with unknown action or `min_burst` without `burst_window`
    are dropped with a log warning at load time.
  - Actions: `block`, `watch` (log only), `ignore`.
  - Legacy fallback: if `rules.yaml` is absent, falls back to
    `score >= block_threshold` — zero config change for existing deployments.
  - `deploy/examples/rules.yaml` — default rules covering SSH/SMTP/IMAP honeypot
    events, burst detection, and a score-based fallback.
- `internal/config` — `ReputationConfig.RulesFile string` (`yaml:"rules_file"`)
  and `Config.RulesFilePath()` helper.

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
  - `cmd/federloomctl` — full trust CLI: `identity init/show`, `peer-cert`,
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
