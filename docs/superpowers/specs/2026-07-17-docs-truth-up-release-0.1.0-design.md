# Documentation Truth-Up + First Tagged Release (v0.1.0)

**Status:** Design approved 2026-07-17
**Type:** Documentation + example-config correctness + first SemVer release. No production Go code changes (example YAML only).
**Trigger:** After Step 7 (load-shedding / A7) and the ipset IPv4-migration fix, the docs, examples, README, and CHANGELOG have drifted. A survey also found a **doc-vs-code drift bug**: the shipped examples reference `resources` config keys that do not exist in the code.

## 1. Problem

The authoritative design docs (`spec.md §12a`, `roadmap.md`, `config.md`, `architecture.md`, `threat-model.md`) were updated as A7 shipped and are current. Everything downstream of them is stale or wrong:

- **`deploy/examples/config.federated.yaml` documents phantom config keys.** Its `resources:` block sets `max_cpu_percent: 25` and `max_bandwidth_kbps: 512` — **neither exists in `internal/config.ResourcesConfig`**, whose only field is `MaxEventsPerSec` (`yaml:"max_events_per_sec"`). Operators copying this example get silently-ignored keys and no working budget. This is the deferred "document `max_events_per_sec` in `deploy/examples/*.yaml`" TODO *and* a correctness bug.
- **`CHANGELOG.md`** has a "Wire v2 (breaking)" banner + an `[Unreleased]` pile, but no entry for load-shedding (A7), disputes (A3), materialise-on-verdict (A5), EvidenceAggregate (A1), diversity weighting (A2), repquery hardening (B1/B3/B5), or the ipset IPv4-migration fix. No SemVer tag exists yet (`git tag` shows only `checkpoint/roadmap-step4`).
- **`README.md`** (last touched 2026-07-07) core-ideas/features omit load-shedding, disputes, materialise, and the observability metrics.

Scope decision (approved): **targeted truth-up** — fix the drift and add the shipped features; do NOT audit the older peripheral docs (`getting-started`, `project-structure`, `federation-guide`, `dnsbl-integration`, `plugins`, `onboarding/*`, `prior-art`) unless a §4 reconciliation surfaces an outright error.

## 2. Goals / non-goals

**Goals:** (a) examples reference only real config keys and document `resources.max_events_per_sec`; (b) `CHANGELOG.md` cut as a dated `0.1.0` release covering everything shipped to date; (c) `README.md` names the recent features in its existing terse style; (d) the 5 current docs reconciled with the new wording and the deploy/examples TODO closed in the roadmap; (e) an annotated `v0.1.0` git tag.

**Non-goals:** rewriting narrative docs; new features or code; ASN/geo diversity or other roadmap-open items; pushing the tag or creating a GitHub release without explicit go-ahead (outward-facing).

## 3. Design

### 3.1 Example configs (`deploy/examples/`)

- **`config.federated.yaml`** — replace the phantom `resources` block:
  ```yaml
  resources:
    # Good-neighbour processing-rate budget (spec §11.5). 0 = off (default).
    # Above the budget the node sheds NETWORK-CONTRIBUTION work only — remote
    # gossip scoring, bridge re-emission, on-demand federated queries — while
    # local protection (own ingest → score → enforce) always runs.
    max_events_per_sec: 0
  ```
- **`config.solo.yaml`** — add a commented `resources` block mirroring the file's existing commented-`observability` style (off by default; note local protection is never shed):
  ```yaml
  # Optional good-neighbour budget (spec §11.5, disabled by default).
  # resources:
  #   max_events_per_sec: 0   # sheds network-contribution work only; local protection never shed
  ```
- **`config.isolated.yaml`** — deliberately minimal; leave unchanged (it carries no bogus keys and an isolated node does little network-contribution work).
- **`rules.yaml`** — out of scope (not a node config).

### 3.2 CHANGELOG — cut `## [0.1.0] - 2026-07-17`

Restructure the top of `CHANGELOG.md` into the project's first tagged release. A single dated heading folds the current "Wire v2 (breaking)" banner and the `[Unreleased]` entries, plus the missing shipped features, into Keep-a-Changelog subsections:

```
## [0.1.0] - 2026-07-17

### Added
- Resource budget + graceful load shedding (§11.5): `resources.max_events_per_sec`
  processing-rate governor with shed hysteresis; sheds network-contribution work
  (remote scoring, bridge re-emit, federated query) while local protection is never
  shed; off by default. Metrics `federloom_shed_total{kind}`, `federloom_shed_mode`,
  `federloom_processing_rate`.
- Disputes / anti-trust votes (§4.4): federated diversity-weighted shared-vote;
  unblocks federated blocks only; anchored-gated diversity credit (Sybil-resistant).
- Materialise-on-verdict (E3 §8): a block-worthy federated verdict for an IP that
  contacted you pushes into ipset (O(1)); diversity-gated, TTL-bounded, opt-in.
- `EvidenceAggregate` federated import + scale-free local recompute (§5.2/§7.5/§8);
  diversity-weighted corroboration via subnet buckets (§4.2).
- Observability plane (default OFF): Prometheus /metrics + SQLite event history.
  [fold existing [Unreleased] metric list here]

### Changed
- Repquery responder authorization: `/federloom/repquery/v1` is trust-store gated
  and fails closed (B1); bounded querier cache + singleflight (B3).
  [fold existing [Unreleased] Changed entries here]

### Fixed
- enforce/ipset: auto-migrate a pre-timeout IPv4 set on upgrade (drop referencing
  rules → destroy → recreate with timeout) instead of crash-looping; fails closed
  if the recreate itself fails.

### Breaking
- Wire v2 (SchemaVersion 2): signed `SubnetID`; federation discount keyed on signed
  origin subnet (not `OriginTrace` hop count); removed `port_class` + `ScoreEntry`;
  gossip topic `federloom/events/v0` → `federloom/events/v2`. Hard cutover — all
  nodes upgrade together. [fold the existing Wire v2 banner text here verbatim-ish]
```

The pre-existing historical sections (`### Added (rules engine)`, `### Added`, `### Changed`, `### Initial scaffold`) remain **below** the 0.1.0 heading as the pre-release history — do not delete them; they document the scaffold that predates the tag.

### 3.3 README

In `README.md` "Core ideas" (and the features it lists), add one terse line each, matching the surrounding voice — no structural rewrite:
- Load shedding — a good-neighbour processing-rate budget that sheds only network-contribution work under load; local protection always runs; off by default.
- Disputes — federated anti-trust votes that can retract a federated block.
- Materialise-on-verdict — a strong federated verdict about an IP that contacted you enforces locally (O(1) ipset).
- Observability — optional Prometheus metrics + SQLite history (default off).

### 3.4 Reconcile the current docs

Light pass over `spec.md`, `roadmap.md`, `config.md`, `architecture.md`, `threat-model.md`: confirm wording agrees with the new CHANGELOG/README, and in `roadmap.md` flip the "document `resources.max_events_per_sec` in `deploy/examples/*.yaml`" TODO to done (§3.1 delivers it). Expect near-zero edits — these were updated as A7 shipped; change only what actually disagrees.

### 3.5 Tag

After the docs merge to `main`: create an **annotated** tag `v0.1.0` on the merge commit. Pushing the tag and/or creating a GitHub release is outward-facing and **requires explicit go-ahead** — the plan stops at the local tag and asks.

## 4. Verification

No unit tests (docs/YAML). Two gates:

1. **Example-key audit (blocks completion):** every `yaml:"..."` key used in `deploy/examples/*.yaml` must exist as a struct tag under `internal/config`. Concretely: extract the leaf keys from the example YAML and confirm each appears in `grep -rho 'yaml:"[^"]*"' internal/config/`. Must report zero unknown keys (in particular, `max_cpu_percent` / `max_bandwidth_kbps` must be gone and `max_events_per_sec` present).
2. **Release-coverage check:** every roadmap-`✅ resolved` feature in scope (A1, A2, A3, A5, A7, wire-v2 C1/B2/B7, repquery B1/B3/B5, the ipset fix) is named in the `0.1.0` CHANGELOG section.
3. Sanity: `go build ./...` still green (proves no example/doc edit accidentally touched code), and a grep that `README.md` no longer omits the four feature names.

## 5. Acceptance

Examples document only real keys and carry `resources.max_events_per_sec` (off); `CHANGELOG.md` opens with a dated `0.1.0` release covering all shipped features incl. load-shedding and the ipset fix; `README.md` names the recent features; the roadmap deploy/examples TODO is closed; an annotated `v0.1.0` tag exists locally; the key-audit gate reports zero unknown example keys. No production code changed.
