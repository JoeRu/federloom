# Structural Stranger-Block Guarantee + Rule Lint

**Status:** Design approved 2026-07-07
**Source:** Final whole-branch review of remediation batch A+B — Minor finding #1
(the P0-1/P0-2 guarantee is enforced by rule *configuration*, not code) plus the
pre-existing gofmt drift item.
**Prerequisite:** batch A+B (merged to `main` at `354215b`) — P0-1 (corroboration
counts anchored groups only) and P0-2 (only anchored reporters feed the burst
window) are already in place.

---

## 1. Problem

After batch A+B, a remote stranger cannot force a block **through the shipped
rule files**. But `rules.Evaluate` (`internal/rules/rule.go:111-137`) returns
`ActionBlock` as soon as a rule matches, and each `min_*` gate is skipped when
its value is zero. Two `rules.yaml` shapes would let a single un-anchored remote
event reach `sink.Block`:

1. **Bare `reason` + `action: block`** with no `min_*` fields — matches on
   reason alone and fires for one stranger event.
2. **`min_score` below `strangerScoreCap`** (default 15) — e.g. `min_score: 10`;
   a stranger can reach the cap and cross it.

The legacy fallback (`len(rules) == 0` → `rec.Score >= fallback`) is a third path
if `BlockThreshold < strangerScoreCap`.

The guarantee is therefore contingent on configuration a hostile or careless
edit can break — reopening exactly the hole batch A+B closed. This design makes
the guarantee **code-level and config-independent**, and adds an advisory lint so
operators are told at load time when a block rule looks stranger-exploitable.

**Non-goal:** changing the trust/scoring model, the wire contract, or any shipped
rule file. The shipped rules are already safe and must produce zero lint
warnings.

---

## 2. Architecture

Three independent units, each testable in isolation:

- **Enforcement backstop** — `internal/node/node.go`, `ProcessRemote`. The single
  structural guarantee. One guard at the one place remote input reaches the
  enforce sink.
- **Rule lint** — `internal/rules/rule.go`. A pure function
  `lintBlockRules(rules, cap) []string` plus a threaded `strangerScoreCap`; the
  existing `reload()` logs the returned warnings. Advisory only.
- **gofmt housekeeping** — mechanical, separate commit.

The backstop is the safety mechanism; the lint is operator feedback. They are
deliberately decoupled: the lint never blocks loading, and the backstop never
reads rule metadata — it reasons only about the aggregate evidence.

---

## 3. Component 1 — Enforcement backstop (structural guarantee)

**File:** `internal/node/node.go`, function `ProcessRemote`, immediately after the
existing `action, ruleName := n.rules.Evaluate(e, rec, n.burst)` call (~line 387).

**Rule:** a remote event may never *force* a block on evidence that is entirely
un-anchored. `rec.Groups` (post-P0-1) holds only distinct anchored Person names,
so `len(rec.Groups) == 0` means the IP's only evidence is stranger evidence.

```go
action, ruleName := n.rules.Evaluate(e, rec, n.burst)
// Structural guarantee (spec Leitprinzip 8): a remote/stranger signal may never
// FORCE a block. If a block rule matched but no anchored Person group has
// vouched for this IP (len(Groups)==0 → stranger-only evidence), downgrade the
// block to watch regardless of rule configuration. This backstops any rules.yaml
// shape (bare-reason block, min_score < strangerScoreCap, legacy fallback) that
// would otherwise let un-anchored input reach the enforce sink.
if action == rules.ActionBlock && len(rec.Groups) == 0 {
	log.Printf("node: downgrading stranger-only block to watch for %s (rule %q, no anchored corroboration)", e.IP, ruleName)
	action = rules.ActionWatch
}
```

**Why `ProcessRemote` only:** `processLocal` records the node's own observations
with `anchored=true, group=selfID`, so a locally-observed IP always has
`len(Groups) ≥ 1` and legitimate local/honeypot blocks are unaffected. Applying
the guard only on the remote path keeps the local sensor path untouched and makes
the intent explicit.

**Behaviour after downgrade:** the existing `switch action` handles
`ActionWatch` (logs a watch line); `n.obs.RecordEvent(e, rec.Score, ruleName,
string(action))` records the event with the downgraded action `"watch"` and the
matched rule name. No block is applied; the event is still observed.

**Cases covered (asserted by tests §6):**
- Bare-reason block rule + stranger → `len(Groups)==0` → watch. ✓
- `min_score` below cap + stranger flood → score ≤ cap but `len(Groups)==0` →
  watch. ✓
- Legacy fallback block + stranger → caught after `Evaluate` → watch. ✓
- Anchored remote reporter (adds its group) → `len(Groups) > 0` → block. ✓
- Mixed anchored + stranger evidence → `len(Groups) > 0` → block (anchored
  evidence justifies it). ✓

---

## 4. Component 2 — Load-time rule lint (advisory)

**File:** `internal/rules/rule.go`.

**4.1 Thread the stranger cap.** `RuleSet` currently knows `fallback` (the block
threshold) but not `strangerScoreCap`. Add it:

- `Load(path string, fallbackThreshold float64) *RuleSet` →
  `Load(path string, fallbackThreshold, strangerScoreCap float64) *RuleSet`.
- Store `strangerCap float64` on `RuleSet`.
- Update the single production caller `internal/node/node.go:166`:
  `rules.Load(cfg.RulesFilePath(), cfg.Reputation.BlockThreshold, cfg.Trust.StrangerScoreCap)`.
- Update any test callers of `rules.Load` to pass a cap (use `15` to match the
  default).

**4.2 Lint function.** A pure, testable function:

```go
// lintBlockRules returns one human-readable warning per rule that could let an
// un-anchored (stranger) reporter cause a block. A block rule is "stranger-safe"
// when it requires anchored evidence or a threshold strangers cannot reach:
//   - min_corroboration >= 1  (post-P0-1, corroboration counts anchored groups only)
//   - anchored_only            (rule is gated on anchored evidence)
//   - min_burst >= 1           (post-P0-2, only anchored reporters feed the burst window)
//   - min_score >= strangerCap (a stranger's score is capped below this)
// Rules that are not block actions are ignored. The returned warnings are
// advisory: the node-level backstop (spec §3) already guarantees safety.
func lintBlockRules(rules []Rule, strangerCap float64) []string
```

Logic per rule with `Action == ActionBlock`:
- safe if `MinCorroboration >= 1 || AnchoredOnly || MinBurst >= 1 || (MinScore >= strangerCap)`.
- otherwise append:
  `fmt.Sprintf("rule %q can block on un-anchored (stranger) input: no min_corroboration, no anchored_only, no min_burst, and min_score (%.0f) < stranger_score_cap (%.0f); the node-level backstop will downgrade such blocks to watch", r.Name, r.MinScore, strangerCap)`.

**4.3 Legacy-fallback warning.** In `reload()`, when the rule list is empty and
`rs.fallback < rs.strangerCap`, log once:
`"rules: legacy fallback threshold (%.0f) is below stranger_score_cap (%.0f); stranger-only score could reach it, but the node-level backstop prevents the block"`.

**4.4 Wiring.** In `reload()`, after `validateRules`, call `lintBlockRules(loaded,
rs.strangerCap)` and `log.Printf("rules: %s", w)` for each warning. The lint runs
on every successful (re)load; it never rejects a rule or changes behaviour.

**Shipped-rule check:** every shipped block rule has `min_corroboration ≥ 1`,
`min_burst ≥ 1`, or `min_score: 75 (≥ 15)`; the `watch-all` honeypot rule is not
a block action. So `make build` + a run against `deploy/*/rules.yaml` yields zero
lint warnings — verified by a test in §6.

---

## 5. Component 3 — gofmt housekeeping

Run `gofmt -w` on the four files that were already unformatted at `main`
(`internal/federation/invitation.go`, `internal/ingest/opencanary.go`,
`internal/node/node.go`, `cmd/federloomctl/setup.go`) and commit separately from
the behavioural change. `node.go` will also carry the Component-1 edit; that is
fine — the gofmt commit is a distinct, earlier commit so the diff stays readable.
Sequence: gofmt commit first (pure formatting), then the behavioural commits on
top.

---

## 6. Testing

**Backstop (adversarial, `test/adversarial/injection_test.go` — extend the
existing file):**
- `TestBareReasonBlockRuleStrangerDowngraded`: a rules file with a single
  `{reason: "ssh-probe", action: block}` rule (no `min_*`); a stranger remote
  `ssh-probe` event → `len(sink.blocked) == 0`.
- `TestLowMinScoreBlockRuleStrangerDowngraded`: rules file with
  `{min_score: 10, action: block}`; drive enough stranger events to reach the
  cap → `len(sink.blocked) == 0`.
- `TestBareReasonBlockRuleAnchoredStillBlocks`: same bare-reason rule; an
  anchored reporter's `ssh-probe` event → `len(sink.blocked) == 1`. Regression
  proving the backstop only stops stranger-only blocks.

Reuse the `newInjectionNode` / `anchoredEvent` helpers already added in batch A+B.

**Lint (unit, `internal/rules/rule_test.go`):**
- `lintBlockRules` returns a warning for a bare-reason block rule and for a
  `min_score:10` block rule (cap 15).
- returns no warning for block rules gated by `min_corroboration:1`,
  `anchored_only:true`, `min_burst:15`, or `min_score:75`.
- returns no warning for a `watch` rule regardless of gating.
- a test loads each `deploy/*/rules.yaml` and `deploy/examples/rules.yaml`
  through `lintBlockRules(..., 15)` and asserts zero warnings (guards against a
  future shipped-rule regression).

**Full-suite acceptance:** `make build test adversarial`, `go vet`, and
`gofmt -l internal/ pkg/ cmd/ test/` returns empty (Component 3 clears the drift).

---

## 7. Out of scope / open questions

- No change to `anchored_only`'s existing `if r.AnchoredOnly && rec.StrangerSeen
  { continue }` semantics. It remains a fail-safe suppressor; the backstop is the
  real guarantee. Redefining `anchored_only` is deferred (would be a rule-
  semantics change with its own migration concern).
- Lint is advisory by decision (§ approved). If operators later want a strict
  mode that refuses unsafe block rules, that is a future opt-in flag, not this
  change.
- The backstop uses `len(rec.Groups) == 0` as the "stranger-only" test. An IP
  that once had an anchored voucher keeps that group, so later stranger events on
  it can still block — correct, because anchored evidence for that IP exists.

---

## 8. Acceptance

A block rule of *any* configuration can no longer cause a receiving node to block
an IP on stranger-only remote evidence (asserted by the two downgrade tests),
while anchored/local evidence still blocks (regression test). Operators loading a
stranger-exploitable block rule see a clear warning at load time. `gofmt -l` is
clean across the tree. No shipped rule file changes and no wire-contract change.
