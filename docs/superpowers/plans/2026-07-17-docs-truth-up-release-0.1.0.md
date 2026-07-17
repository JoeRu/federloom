# Documentation Truth-Up + First Tagged Release (v0.1.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring FederLoom's examples, CHANGELOG, README, and current docs into agreement with the shipped code, and cut the project's first SemVer release `v0.1.0`.

**Architecture:** Docs-and-YAML only — NO production Go code changes. Fix a doc-vs-code drift bug in the example configs (phantom `resources` keys), fold everything shipped to date into a dated `0.1.0` CHANGELOG section, add the recent features to the README, reconcile the five already-current docs, then tag `v0.1.0`.

**Tech Stack:** Markdown, YAML, `git`. Verification via `grep`/`go build` (no unit tests — this is docs).

## Global Constraints

- **No production code changes.** Only `deploy/examples/*.yaml`, `CHANGELOG.md`, `README.md`, and `docs/*.md` may change. `go build ./...` must stay green (a proxy proving no `.go` file was touched).
- **The only real `resources` config key is `max_events_per_sec`** (`internal/config.ResourcesConfig`, `yaml:"max_events_per_sec"`, `float64`, default `0` = off). `max_cpu_percent` and `max_bandwidth_kbps` do NOT exist and must be removed wherever they appear.
- **Load-shedding framing (copy verbatim where quoted):** off by default; sheds NETWORK-CONTRIBUTION work only (remote gossip scoring, bridge re-emission, on-demand federated queries); local protection (own ingest → score → enforce) is never shed (spec §11.5).
- **Version = `0.1.0`**, release date `2026-07-17`. First tag; pre-1.0 (the wire-v2 break is acceptable under 0.x).
- Conventional Commits. `docs:` / `chore:` prefixes for these changes.
- Do NOT push the tag or create a GitHub release without explicit user go-ahead (outward-facing) — Task 5 stops at a local annotated tag.

---

### Task 1: Fix example configs + key-audit gate

**Files:**
- Modify: `deploy/examples/config.federated.yaml` (the phantom `resources` block, ~lines 13-15)
- Modify: `deploy/examples/config.solo.yaml` (add a commented `resources` block)
- Leave unchanged: `deploy/examples/config.isolated.yaml` (minimal by design), `deploy/examples/rules.yaml`

**Interfaces:**
- Produces: example configs whose every node-config key exists in `internal/config`; a repeatable key-audit command later tasks/reviewers can re-run.

- [ ] **Step 1: Run the audit to see the drift (the "failing test")**

Run:
```bash
cd /root/federloom
echo "phantom keys (must become empty):"; grep -rn 'max_cpu_percent\|max_bandwidth_kbps' deploy/examples/
echo "real knob present (must become non-empty):"; grep -rn 'max_events_per_sec' deploy/examples/
```
Expected NOW: phantom keys FOUND in `config.federated.yaml`; `max_events_per_sec` NOT found. This is the drift to fix.

- [ ] **Step 2: Fix `config.federated.yaml`**

Replace the existing block (currently):
```yaml
resources:
  max_cpu_percent: 25     # good-neighbour budget (spec §11.5)
  max_bandwidth_kbps: 512
```
with:
```yaml
resources:
  # Good-neighbour processing-rate budget (spec §11.5). 0 = off (default).
  # Above the budget the node sheds NETWORK-CONTRIBUTION work only — remote
  # gossip scoring, bridge re-emission, on-demand federated queries — while
  # local protection (own ingest → score → enforce) always runs.
  max_events_per_sec: 0
```

- [ ] **Step 3: Add a commented `resources` block to `config.solo.yaml`**

Immediately BEFORE the existing `# Optional observability plane (disabled by default, spec §11.2).` comment block near the end of `deploy/examples/config.solo.yaml`, insert:
```yaml
# Optional good-neighbour budget (spec §11.5, disabled by default).
# Sheds network-contribution work only; local protection is never shed.
# resources:
#   max_events_per_sec: 0

```

- [ ] **Step 4: Run the key-audit gate (the "passing test")**

Run:
```bash
cd /root/federloom
echo "1) phantom keys gone (expect EMPTY):"; grep -rn 'max_cpu_percent\|max_bandwidth_kbps' deploy/examples/ || echo "  OK none"
echo "2) real knob present (expect a hit in config.federated.yaml):"; grep -rn 'max_events_per_sec' deploy/examples/
echo "3) unknown-key scan — every top-level/nested config key in the two active examples must exist in internal/config tags:"
valid=$(grep -rho 'yaml:"[^"]*"' internal/config/ | sed 's/yaml:"//;s/"//' | sort -u)
for f in deploy/examples/config.federated.yaml deploy/examples/config.solo.yaml deploy/examples/config.isolated.yaml; do
  # leaf keys = lines like `  key:` (ignore comments, list items, values-only)
  grep -oE '^[[:space:]]*[a-z0-9_]+:' "$f" | tr -d ' :' | sort -u | while read k; do
    echo "$valid" | grep -qx "$k" || echo "  UNKNOWN key '$k' in $f"
  done
done
echo "   (any 'UNKNOWN' line above is a real drift to fix; expect NONE)"
```
Expected: (1) empty, (2) one hit, (3) NO `UNKNOWN` lines. If an `UNKNOWN` appears, it is either a genuine drift (fix it) or a nested-list edge case (e.g. `source:` under `anchors:` — `source` IS a valid tag, so it passes). Only real absent keys should surface.

- [ ] **Step 5: Commit**

```bash
cd /root/federloom
git add deploy/examples/config.federated.yaml deploy/examples/config.solo.yaml
git commit -m "docs(examples): replace phantom resources keys with real max_events_per_sec"
```

---

### Task 2: CHANGELOG — cut `## [0.1.0] - 2026-07-17`

**Files:**
- Modify: `CHANGELOG.md` (the top: the `## Wire v2 (breaking)` banner + `## [Unreleased]` heading, lines 5-21)

**Interfaces:**
- Consumes: nothing.
- Produces: a dated `0.1.0` release section naming every shipped feature — later verified by the coverage grep.

- [ ] **Step 1: Coverage check (the "failing test")**

Run:
```bash
cd /root/federloom
echo "features that MUST appear in CHANGELOG 0.1.0 (each expect a hit AFTER the edit):"
for t in 'max_events_per_sec\|load shedding' 'dispute' 'materiali' 'EvidenceAggregate' 'ipset.*migrat\|timeout-less'; do
  printf "  %-30s " "$t:"; grep -iq "$t" CHANGELOG.md && echo FOUND || echo MISSING
done
echo "version heading present? (expect MISSING now):"; grep -n '## \[0.1.0\]' CHANGELOG.md || echo "  no 0.1.0 heading yet"
```
Expected NOW: `load shedding`, `dispute`, `materiali`, `EvidenceAggregate`, `ipset migration` all MISSING; no `0.1.0` heading.

- [ ] **Step 2: Rewrite the top of `CHANGELOG.md`**

Replace the current top region — the `## Wire v2 (SchemaVersion 2) — breaking` banner AND the `## [Unreleased]` heading line (i.e. everything from `## Wire v2` down to and including the `## [Unreleased]` line, but NOT the `### Added` subsections beneath it) — with the following. The existing `### Added` / `### Changed` / `### Added (rules engine)` / `### Initial scaffold` subsections stay exactly where they are, now nested under the new `## [0.1.0]` heading:

```markdown
## [0.1.0] - 2026-07-17

First tagged release. Covers the full scaffold through Step 7 (load shedding).
Pre-1.0: the Wire v2 change below is breaking, acceptable under 0.x semantics.

### Added
- **Resource budget + graceful load shedding (§11.5).** `resources.max_events_per_sec`
  drives a processing-rate governor with shed hysteresis. Above the budget the node
  sheds network-contribution work only — remote gossip scoring, bridge re-emission,
  on-demand federated queries — while local protection (own ingest → score → enforce)
  is never shed. Off by default (budget 0). Metrics `federloom_shed_total{kind}`,
  `federloom_shed_mode`, `federloom_processing_rate`.
- **Disputes / anti-trust votes (§4.4).** Federated diversity-weighted shared-vote that
  can retract a *federated* block; unblocks federated blocks only, never a local decision;
  the diversity credit is anchored-gated so a single stranger cannot fabricate subnets.
- **Materialise-on-verdict (E3 §8).** A block-worthy federated verdict for an IP that has
  contacted you is pushed into ipset (O(1) path); diversity-gated, TTL-bounded, opt-in.
- **`EvidenceAggregate` federated import + scale-free local recompute** (§5.2/§7.5/§8) and
  **diversity-weighted corroboration** via subnet buckets (§4.2).

### Changed
- **Repquery responder authorization (B1).** `/federloom/repquery/v1` is trust-store gated
  and fails closed; bounded querier cache + singleflight de-dup (B3).

### Fixed
- **enforce/ipset: auto-migrate a pre-timeout IPv4 set on upgrade.** A `federloom` IPv4 set
  created before timeout support failed the `-exist` create on a header mismatch and the
  node crash-looped; the IPv4 path now migrates (drop referencing rules → destroy → recreate
  with timeout) like the IPv6 path. A failure of the recreate itself stays fatal (fail closed).

### Breaking — Wire v2 (SchemaVersion 2)
- **Signed `SubnetID`** (domain strings `federloom-event-v2` / `federloom-vote-v2`): a relay
  can no longer rewrite the origin subnet — the diversity/home-subnet key is cryptographically
  bound to the originator (closes B7).
- **Federation discount keyed on signed origin subnet** — a non-anchored, cross-boundary event
  is discounted once (signed `SubnetID` ≠ receiver's subnet), not once per self-reported
  `OriginTrace` hop; hop count no longer affects scoring (closes B2). `OriginTrace` remains for
  the feedback-loop guard, trace-cap, and dedup.
- **Removed** the deprecated `port_class` `Event` field and the unused `ScoreEntry` type (C1).
- **Gossip topic** `federloom/events/v0` → `federloom/events/v2`.
- **Hard cutover:** no v1↔v2 compatibility — all nodes upgrade together.

### Added (observability)
```

NOTE: the trailing `### Added (observability)` line above renames the FIRST existing
`### Added` subsection (the observability/Prometheus/SQLite one currently directly under
`## [Unreleased]`) so it reads clearly within 0.1.0 — leave its bullet list untouched.
All other existing subsections (`### Changed`, the CrowdSec `### Added`, `### Added (rules
engine)`, the trust-anchors `### Added`, the wire v0→v1 `### Changed`, `### Initial scaffold`)
remain byte-for-byte, now nested under `## [0.1.0]`.

- [ ] **Step 3: Run the coverage check (the "passing test")**

Run the same command as Step 1.
Expected: all five feature tokens FOUND; `## [0.1.0]` heading present. Also confirm no orphan:
```bash
grep -n '## Wire v2\|## \[Unreleased\]' CHANGELOG.md || echo "OK: old banner + Unreleased heading removed"
```
Expected: `OK: ...` (both old headings gone).

- [ ] **Step 4: Commit**

```bash
cd /root/federloom
git add CHANGELOG.md
git commit -m "docs(changelog): cut v0.1.0 — load shedding, disputes, materialise, ipset fix, wire v2"
```

---

### Task 3: README — name the recent features

**Files:**
- Modify: `README.md` (the `## Core ideas` bullet list)

**Interfaces:**
- Produces: a README whose Core ideas name load-shedding, disputes, materialise-on-verdict, and observability.

- [ ] **Step 1: Coverage check (the "failing test")**

Run:
```bash
cd /root/federloom
for t in 'load shed\|shed' 'dispute' 'materiali' 'Prometheus\|observability'; do
  printf "  %-24s " "$t:"; grep -iq "$t" README.md && echo FOUND || echo MISSING
done
```
Expected NOW: all MISSING.

- [ ] **Step 2: Add the feature lines**

In `README.md`, inside `## Core ideas`, immediately AFTER the existing
`- **Scales by querying, not replicating** (spec §11): …` bullet and BEFORE the
`- **GDPR by design** (spec §9): …` bullet, insert these four bullets (match the
existing terse voice and the `**bold lead** (spec §ref):` style):
```markdown
- **Good-neighbour load shedding** (spec §11.5): an optional processing-rate budget
  (`resources.max_events_per_sec`, off by default) sheds network-contribution work
  under load — remote scoring, bridge re-emit, federated queries — while local
  protection always runs.
- **Disputes** (spec §4.4): federated anti-trust votes can retract a *federated*
  block; a single stranger can't (diversity is anchored-gated).
- **Materialise-on-verdict** (E3 §8): a strong federated verdict about an IP that
  contacted you enforces locally via ipset (O(1)); opt-in, TTL-bounded.
- **Observability** (spec §11.2, default OFF): optional Prometheus `/metrics` and a
  local SQLite event history.
```

- [ ] **Step 3: Coverage check (the "passing test")**

Run the same command as Step 1.
Expected: all four FOUND. Then confirm no code was touched: `go build ./... && echo build-ok`.

- [ ] **Step 4: Commit**

```bash
cd /root/federloom
git add README.md
git commit -m "docs(readme): add load shedding, disputes, materialise, observability to core ideas"
```

---

### Task 4: Reconcile current docs + close roadmap TODO + full gate

**Files:**
- Modify: `docs/roadmap.md` (the deploy/examples TODO, around line 148)
- Read-and-reconcile (edit only on real disagreement): `docs/spec.md` (§12a), `docs/config.md`, `docs/architecture.md`, `docs/threat-model.md`

**Interfaces:**
- Consumes: Tasks 1-3 (examples now carry the knob → the TODO is satisfiable).
- Produces: the five current docs consistent with the new CHANGELOG/README; the deploy/examples TODO marked done.

- [ ] **Step 1: Locate the roadmap TODO**

Run:
```bash
cd /root/federloom
grep -n 'deploy/examples' docs/roadmap.md
sed -n '143,150p' docs/roadmap.md
```
This shows the "document `resources.max_events_per_sec` in `deploy/examples/*.yaml`" follow-up (around line 148).

- [ ] **Step 2: Mark the roadmap TODO done**

Edit that follow-up line/sentence in `docs/roadmap.md` so it reads as completed, e.g. change the pending "TODO: document `resources.max_events_per_sec` in `deploy/examples/*.yaml`." to:
```
Done 2026-07-17: `resources.max_events_per_sec` documented in `deploy/examples/config.federated.yaml` (active) and `config.solo.yaml` (commented).
```
Preserve the surrounding sentence structure; change only the status of this one item.

- [ ] **Step 3: Reconcile the five current docs (edit only on disagreement)**

Run:
```bash
cd /root/federloom
echo "these were updated as A7 shipped — confirm they still agree with the new CHANGELOG/README wording:"
grep -n 'max_events_per_sec\|load shed\|shed_mode\|§11.5' docs/spec.md docs/config.md docs/architecture.md docs/threat-model.md | head -30
```
Read the hits. The expectation is **zero edits** — these were written correctly when A7 shipped. Only change a line if it factually disagrees with the shipped behaviour (e.g. wrong metric name, wrong default, claims local protection can be shed). If everything agrees, make no edits and note that in the commit body.

- [ ] **Step 4: Full verification gate**

Run:
```bash
cd /root/federloom
echo "=== no production code touched on this branch ==="; git diff --name-only main...HEAD | grep -E '\.go$' && echo "FAIL: a .go file changed" || echo "OK: docs/yaml only"
echo "=== build still green ==="; go build ./... && echo build-ok
echo "=== example key-audit (Task 1 gate, re-run) ==="; grep -rn 'max_cpu_percent\|max_bandwidth_kbps' deploy/examples/ && echo "FAIL phantom key" || echo "OK no phantom keys"
echo "=== CHANGELOG coverage (Task 2 gate, re-run) ==="; for t in 'load shedding\|max_events_per_sec' dispute materiali EvidenceAggregate 'ipset.*migrat\|timeout-less'; do grep -iq "$t" CHANGELOG.md && echo "OK $t" || echo "FAIL missing $t"; done
echo "=== roadmap TODO closed ==="; grep -n 'Done 2026-07-17.*max_events_per_sec' docs/roadmap.md && echo OK || echo "FAIL TODO not closed"
```
Expected: `OK: docs/yaml only`, `build-ok`, `OK no phantom keys`, all `OK <token>` for coverage, and `OK` for the roadmap TODO.

- [ ] **Step 5: Commit**

```bash
cd /root/federloom
git add docs/roadmap.md docs/spec.md docs/config.md docs/architecture.md docs/threat-model.md
git commit -m "docs: close deploy/examples TODO; reconcile spec/config/architecture/threat-model with v0.1.0"
```
(If Step 3 produced no edits to the four reconciled docs, they simply won't be staged — that is expected; the roadmap change still commits.)

---

### Task 5 (POST-MERGE): tag `v0.1.0`

**Do this ONLY after the branch has merged to `main`** (via superpowers:finishing-a-development-branch) and the whole-branch review is clean. This creates a LOCAL annotated tag only.

- [ ] **Step 1: Create the annotated tag on the main merge commit**

```bash
cd /root/federloom
git checkout main && git pull --ff-only 2>/dev/null || git checkout main
git tag -a v0.1.0 -m "FederLoom v0.1.0 — first tagged release

Scaffold through Step 7 (load shedding). See CHANGELOG.md [0.1.0].
Breaking: Wire v2 (SchemaVersion 2)."
git tag -l v0.1.0
git show v0.1.0 --stat --no-patch | head
```
Expected: `v0.1.0` listed; the tag points at the main HEAD merge commit.

- [ ] **Step 2: STOP and ask before pushing**

Do NOT run `git push origin v0.1.0` or create a GitHub release. Report to the user that the local `v0.1.0` tag exists and ask whether to push it / cut a GitHub release (both outward-facing).
