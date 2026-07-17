# Resource Budget + Load Shedding (Roadmap Step 7 / A7)

**Status:** Design approved 2026-07-17
**Source:** [docs/roadmap.md](../../roadmap.md) Step 7 — item A7 (the "good-neighbor"
resilience half of the scale cluster). Spec §11.5 ("the protection mechanism
must never itself become the performance problem"; resource budget; graceful
degradation / load shedding; local protection takes precedence over network
contribution). Leitprinzip 1/8 (local sovereignty).
**Prerequisite:** none beyond the current `main` (E1–E3, D, Step 4/5/6 merged).
The `internal/resources` package exists as a doc-only stub.
**Scope note:** Step 7 is a cluster. This spec is ONLY A7 (load shedding). The
A6 federation-scale work — federation bloom distribution, DHT content routing,
batch/multi-IP queries — is deferred until real telemetry from a larger
deployment justifies it (roadmap "do this when measurements say so"). The
local-store bloom pre-filter is already built (`internal/store/bloom.go`).

---

## 1. Problem

§11.5's flagship principle: a defensive daemon must never become the box's own
performance problem. Under a load spike — a local attack wave saturating the
ingest path, or a gossip flood from the federation — the node must keep
protecting itself locally and shed the *network-contribution* work it can't
afford, rather than melting down trying to do everything. Today there is no
such governor: every remote event is verified + scored, every bridge re-emits,
every DNSBL/API miss fires a federated query, regardless of load.

## 2. Decisions made during brainstorming (user-selected)

1. **Build A7 first** (defer A6 scale optimizations until telemetry justifies).
2. **Control signal = a processing-rate budget** (`max_events_per_sec`, total).
   Local ingest is metered but never shed; remote/network work is shed once the
   node's total processing rate exceeds the budget. One legible knob handles
   both overload sources (local attack → local consumes budget → remote shed;
   gossip flood → remote shed directly), always keeping local protection alive.
   Not CPU/cgroup sampling (that is deployment's job) nor queue-depth.
3. **Shed = drop; "sync later" = eventual consistency.** Dropped remote work is
   not queued or replayed; catch-up is emergent (gossip resumes when load
   drops; other nodes serve the events via on-demand query; ongoing attacks
   re-establish reputation). No persistent replay, no unbounded memory.

## 3. Scope

**In:** the `resources.Governor` (rate meter + shed decision with hysteresis);
`Shed()` gates at the sheddable sites; the never-shed local-protection
guarantee; one config knob (off by default); three observability metrics;
tests.
**Out:** cgroup/`nice`/CPU-limit enforcement (systemd/docker deployment
concern, not app code); the A6 federation-scale work (bloom distribution, DHT
routing, batch queries); any persistent/queued replay of shed work; changes to
the scoring, enforcement, or wire paths beyond adding a skip-when-shedding gate.

**Follow-up (flagged, later):** add `resources.max_events_per_sec` as a
commented example in `deploy/examples/*.yaml` — this spec documents it in
`docs/config.md`, but wiring it into the shipped example configs is a
separate later TODO, not part of this feature.

---

## 4. The governor (`internal/resources`)

A small, concurrency-safe rate meter + shed-state machine. Indicative shape
(the plan pins exact signatures):

```go
// Governor decides whether sheddable (network-contribution) work should be
// skipped because the node's processing rate is over budget. Local protection
// work is charged but never gated. Zero budget => never sheds (feature off).
type Governor struct { ... } // sliding-window counter + shed flag, mutex-guarded

// NewGovernor with a per-second budget; budget <= 0 means unlimited (off).
func NewGovernor(maxPerSec float64) *Governor

// Charge records one unit of processed work (local OR remote) against the
// current 1-second window.
func (g *Governor) Charge()

// Shed reports whether the node is currently over budget and sheddable work
// should be skipped. Hysteresis: enters shed at the budget, exits only when the
// rate falls to sheddExitFraction × budget (a constant, e.g. 0.8), so it does
// not flap around the threshold. Always false when budget <= 0.
func (g *Governor) Shed() bool
```

The window is a simple time-bucketed count (e.g. a ring of per-100ms buckets
summed over the last second), so it needs no background goroutine — it is
evaluated lazily on `Charge`/`Shed`. `sheddExitFraction` is an internal
constant, not an operator knob (YAGNI).

## 5. Metered vs shed — the priority invariant

- **Local ingest → score → enforce: metered, NEVER shed.** `processLocal`
  calls `gov.Charge()` (so local load counts toward the budget) but its
  scoring/enforcement always runs. This is the non-negotiable §11.5 / Leitprinzip
  invariant: local protection precedes network contribution.
- **Sheddable sites** each check `gov.Shed()` and skip (after `Charge`, or
  before doing the expensive work) when shedding, incrementing the shed metric:
  1. `node.ProcessRemote` — skip verification + scoring of a *remote* gossip
     event (report or vote) when shedding. (Charge on entry so remote load
     still counts toward the rate the operator sees.)
  2. `node.reemitIfBridge` — skip bridge re-emission when shedding. This is the
     only *forwarded* outbound path; a node's own locally-originated events and
     shared-votes are local-protection output and are published normally (never
     shed).
  3. `repquery.Resolver` federated path — skip the on-demand federated query
     when shedding; return the local-only answer (identical to E3's existing
     timeout fallback, so no new "not found" semantics).

Because local ingest charges the budget, a sustained local attack wave consumes
it and remote work sheds automatically — CPU flows to local protection +
enforcement.

## 6. "Sync later" via eventual consistency (no replay)

Dropped remote work is not stored. The node resumes full processing when the
rate falls below the exit threshold. Reputation catch-up is a property of the
existing substrate: gossip re-broadcasts, non-shedding peers hold the events
and answer on-demand queries, and continued attacks generate fresh events. The
node's *own* attackers remain blocked throughout — the local path never shed.

## 7. Config (`internal/config`, overridable — Leitprinzip 7)

- `resources.max_events_per_sec` (float64, default **0 = unlimited / OFF**).
  With no budget configured the governor never sheds → behaviour is byte-for-byte
  as today (full backward compatibility). Under `ResourcesConfig` (new nested
  config block, or top-level — the plan follows the existing config layout).
- Documented in `docs/config.md`: what shedding is, that local protection is
  never shed, that it is off by default and reduces only network contribution,
  and that OS-level CPU/bandwidth limits (`nice`/cgroups/systemd) are a
  complementary deployment concern.

## 8. Observability (existing plane)

Three metrics so an operator can see shedding and gather the telemetry that
later informs A6:
- `federloom_shed_total{kind}` — counter of shed items (`kind` ∈
  `remote_event`, `bridge_reemit`, `federated_query`).
- `federloom_shed_mode` — gauge 0/1 (currently shedding).
- `federloom_processing_rate` — gauge, the governor's current events/sec.

## 9. Security / invariants

- **Load-shedding only ever REDUCES network participation.** It never blocks,
  never raises a score, never bypasses never-block/whitelist or the
  anchored-corroboration backstop, never mutates enforcement. Dropping a remote
  event/vote is the safe direction.
- **Local protection + enforcement always run** (the priority invariant) — a
  node under attack still scores and blocks its own attackers.
- **Induced-shedding is bounded:** a peer flooding gossip to push a victim into
  shed mode only makes the victim contribute less to the federation and protect
  itself locally as normal — it cannot make the victim mis-enforce or drop a
  local block. (It is a mild availability nudge on network contribution, not an
  integrity attack.)
- **Off by default:** zero budget ⇒ no shedding ⇒ unchanged behaviour.
- No new wire surface, no hashing, no enforcement-path change.

## 10. Testing

- **Governor unit:** below budget → `Shed()` false; sustained charging over
  budget → true; hysteresis (stays shedding until rate ≤ exit fraction, then
  clears); rate decays as the window advances; `maxPerSec <= 0` → never sheds.
  Concurrency-safe under `-race`.
- **Priority invariant (node):** with a tiny budget and a burst of remote
  events, the shed counter rises and remote scores are NOT updated, WHILE a
  local ingest event in the same window still scores and (if block-worthy)
  blocks — proving local protection is never shed.
- **Federated-query shed:** a Resolver with a shedding governor returns the
  local-only answer (no federated query fired), identical to the timeout path.
- **Off (budget 0):** behaviour byte-for-byte as today; existing suites pass
  unchanged.
- **Adversarial:** a gossip flood induces shed mode but never produces a wrong
  block and never starves local enforcement; a shed dispute simply delays an
  unblock (re-arrives via gossip) — no integrity effect.
- **Full gate:** build, vet, gofmt, unit, `-race`, adversarial, integration.

## 11. Docs

- `docs/config.md`: `resources.max_events_per_sec` (off by default; only sheds
  network contribution; local protection never shed; complements OS limits).
- `docs/spec.md` §12a: §11.5 good-neighbor / load-shedding → DONE (A7);
  A6 (bloom-dist/DHT/batch) remains PLANNED.
- `docs/roadmap.md`: A7 ✅; Step 7 partially done (A7 shipped, A6 deferred).
- `docs/architecture.md` + `docs/threat-model.md`: the observability plane
  gains shed metrics; shedding reduces only network contribution, never local
  enforcement.

## 12. Acceptance

With a configured `max_events_per_sec`, a node under a remote-event flood enters
shed mode (metric + gauge reflect it), drops the excess remote/bridge/federated
work, and continues to score and block its own locally-ingested attackers
unimpeded; when the flood subsides it resumes full processing; with no budget
configured (default) behaviour is byte-for-byte as today; shedding never causes
a wrong block or bypasses any protection.
