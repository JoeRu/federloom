# Structural Stranger-Block Guarantee + Rule Lint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the "no stranger-forced block" guarantee code-level and config-independent (a `ProcessRemote` backstop), add an advisory load-time lint that flags stranger-exploitable block rules, and clear pre-existing gofmt drift.

**Architecture:** A single guard in `node.go` `ProcessRemote` downgrades any block to watch when the IP has no anchored corroboration (`len(rec.Groups) == 0`), backstopping every `rules.yaml` shape. A pure `lintBlockRules` function in the rules package logs advisory warnings at load. gofmt housekeeping lands first as a pure-formatting commit.

**Tech Stack:** Go 1.22, `go test` (unit + `adversarial` build tag), YAML rules.

## Global Constraints

- Go module `github.com/JoeRu/federloom`, Go 1.22. Conventional Commits.
- `internal/node` and `internal/rules` are security-critical: surgical changes, extra care.
- Invariant 8 (spec Leitprinzip 8): no imported/remote signal may FORCE a block; strangers may raise score (capped at `stranger_score_cap`, default 15) and trigger `watch`, never `block`.
- The backstop is the guarantee; the lint is advisory ONLY (warn, never refuse/mutate rules).
- "Stranger-only evidence" test is `len(rec.Groups) == 0` (Groups holds only anchored Person names after batch A+B P0-1).
- A block rule is "stranger-safe" iff `min_corroboration >= 1` OR `anchored_only` OR `min_burst >= 1` OR `min_score >= stranger_score_cap`.
- No shipped `deploy/*/rules.yaml` file changes; no wire-contract (`pkg/proto`) change. Shipped rules must produce ZERO lint warnings.
- Reason weights (for test score math): `ssh-auth-success` = 40, `ssh-probe` = 2. `stranger_weight` default = 0.3, `stranger_score_cap` = 15.

---

### Task 1: gofmt housekeeping (Component 3)

Clear the four files that were already unformatted at `main` before any behavioural change, so later edits land on formatted files and `gofmt -l` ends clean. Pure formatting — no logic change.

**Files:**
- Modify: `internal/federation/invitation.go`, `internal/ingest/opencanary.go`, `internal/node/node.go`, `cmd/federloomctl/setup.go` (formatting only)

**Interfaces:** none.

- [ ] **Step 1: Confirm the drift exists**

Run: `gofmt -l internal/ pkg/ cmd/ test/`
Expected: prints exactly these four paths (order may vary):
```
internal/federation/invitation.go
internal/ingest/opencanary.go
internal/node/node.go
cmd/federloomctl/setup.go
```

- [ ] **Step 2: Format the four files**

Run: `gofmt -w internal/federation/invitation.go internal/ingest/opencanary.go internal/node/node.go cmd/federloomctl/setup.go`

- [ ] **Step 3: Verify the tree is clean and still builds**

Run: `gofmt -l internal/ pkg/ cmd/ test/ && echo "GOFMT CLEAN" && go build ./...`
Expected: `GOFMT CLEAN` printed (no file paths before it) and a clean build.

- [ ] **Step 4: Confirm the diff is formatting-only**

Run: `git diff --stat`
Expected: only the four files above, with no logic changes (whitespace/alignment only). Spot-check `git diff internal/node/node.go` shows only struct-field comment realignment.

- [ ] **Step 5: Commit**

```bash
git add internal/federation/invitation.go internal/ingest/opencanary.go internal/node/node.go cmd/federloomctl/setup.go
git commit -m "style: gofmt pre-existing drift in four files"
```

---

### Task 2: Rule lint + stranger-cap threading (Component 2)

Thread `stranger_score_cap` into the rules layer and add an advisory lint that warns (at load) on block rules that could fire on un-anchored input. Advisory only — never rejects or mutates rules.

**Files:**
- Modify: `internal/rules/rule.go` (add `strangerCap` field, change `Load` signature, add `lintBlockRules`, wire into `reload`/`Load`)
- Modify: `internal/node/node.go` (update the one `rules.Load` call)
- Modify: `internal/node/node_test.go` (update the one `rules.Load` call)
- Test: `internal/rules/rule_test.go` (package `rules` — can call the unexported `lintBlockRules`)

**Interfaces:**
- Consumes: existing `Rule` fields `Name string`, `Reason string`, `MinScore float64`, `MinCorroboration int`, `AnchoredOnly bool`, `MinBurst int`, `Action Action`; `ActionBlock`, `ActionWatch` constants; `duration struct{ time.Duration }`.
- Produces: `func Load(path string, fallbackThreshold, strangerScoreCap float64) *RuleSet` (new 3-arg signature); `func lintBlockRules(rules []Rule, strangerCap float64) []string` (unexported).

- [ ] **Step 1: Write the failing lint unit tests**

Add to `internal/rules/rule_test.go` (it is `package rules`). If `os`, `time`, and `gopkg.in/yaml.v3` are not already imported there, add them.

```go
func TestLintBlockRulesFlagsUnsafe(t *testing.T) {
	rules := []Rule{
		{Name: "bare-block", Reason: "ssh-probe", Action: ActionBlock},
		{Name: "low-score", MinScore: 10, Action: ActionBlock},
	}
	w := lintBlockRules(rules, 15)
	if len(w) != 2 {
		t.Fatalf("expected 2 warnings, got %d: %v", len(w), w)
	}
}

func TestLintBlockRulesAllowsSafe(t *testing.T) {
	rules := []Rule{
		{Name: "corr", MinCorroboration: 1, Action: ActionBlock},
		{Name: "anchored", AnchoredOnly: true, Action: ActionBlock},
		{Name: "burst", MinBurst: 15, BurstWindow: duration{10 * time.Minute}, Action: ActionBlock},
		{Name: "score", MinScore: 75, Action: ActionBlock},
		{Name: "watch-bare", Reason: "ssh-probe", Action: ActionWatch},
	}
	if w := lintBlockRules(rules, 15); len(w) != 0 {
		t.Errorf("expected no warnings, got %d: %v", len(w), w)
	}
}

func TestShippedRulesAreStrangerSafe(t *testing.T) {
	files := []string{
		"../../deploy/examples/rules.yaml",
		"../../deploy/mailcow/rules.yaml",
		"../../deploy/wordpress/rules.yaml",
		"../../deploy/honeypot/rules.yaml",
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var rules []Rule
		if err := yaml.Unmarshal(data, &rules); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		if w := lintBlockRules(rules, 15); len(w) != 0 {
			t.Errorf("%s has stranger-exploitable block rules: %v", f, w)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail to compile / fail**

Run: `go test ./internal/rules/ -run 'TestLint|TestShippedRules' -v`
Expected: FAIL — `lintBlockRules` undefined (compile error).

- [ ] **Step 3: Add the `strangerCap` field and change `Load`**

In `internal/rules/rule.go`, add the field to `RuleSet` (after `fallback`):

```go
	fallback float64 // score threshold used when rules list is empty (legacy mode)
	strangerCap float64 // stranger_score_cap; used only by the load-time lint (advisory)
	loaded   bool    // true after first successful file read (Fix 2)
```

Replace the `Load` function with the 3-arg version plus the legacy-fallback advisory:

```go
// Load returns a RuleSet backed by path. If path is empty or the file does not
// exist, Evaluate uses fallbackThreshold for legacy score-based blocking.
// strangerScoreCap is used only by the advisory load-time lint (lintBlockRules).
func Load(path string, fallbackThreshold, strangerScoreCap float64) *RuleSet {
	rs := &RuleSet{path: path, fallback: fallbackThreshold, strangerCap: strangerScoreCap}
	rs.reload()
	// Legacy-mode advisory: with no rules file, a bare score >= fallback blocks.
	// If fallback is below the stranger cap, stranger-only score could reach it —
	// the node-level backstop still prevents the block, but warn the operator.
	if len(rs.rules) == 0 && rs.fallback < rs.strangerCap {
		log.Printf("rules: legacy fallback threshold (%.0f) is below stranger_score_cap (%.0f); stranger-only score could reach it, but the node-level backstop prevents the block", rs.fallback, rs.strangerCap)
	}
	return rs
}
```

- [ ] **Step 4: Add `lintBlockRules` and wire it into `reload`**

In `internal/rules/rule.go`, add the function (place it after `validateRules`):

```go
// lintBlockRules returns one advisory warning per block rule that could fire on
// un-anchored (stranger) input. A block rule is stranger-safe when it requires
// anchored evidence or a threshold strangers cannot reach:
//   - min_corroboration >= 1  (corroboration counts anchored groups only, P0-1)
//   - anchored_only            (gated on anchored evidence)
//   - min_burst >= 1           (only anchored reporters feed the burst window, P0-2)
//   - min_score >= strangerCap (a stranger's score is capped below this)
// Non-block rules are ignored. Warnings are advisory: the node-level backstop
// already guarantees no stranger-only block is applied.
func lintBlockRules(rules []Rule, strangerCap float64) []string {
	var warnings []string
	for _, r := range rules {
		if r.Action != ActionBlock {
			continue
		}
		safe := r.MinCorroboration >= 1 || r.AnchoredOnly || r.MinBurst >= 1 || r.MinScore >= strangerCap
		if !safe {
			warnings = append(warnings, fmt.Sprintf("rule %q can block on un-anchored (stranger) input: no min_corroboration, no anchored_only, no min_burst, and min_score (%.0f) < stranger_score_cap (%.0f); the node-level backstop will downgrade such blocks to watch", r.Name, r.MinScore, strangerCap))
		}
	}
	return warnings
}
```

In `reload()`, right after the `loaded = validateRules(loaded, rs.path)` line and before `info, _ := os.Stat(rs.path)`, add the lint logging:

```go
	loaded = validateRules(loaded, rs.path)
	for _, w := range lintBlockRules(loaded, rs.strangerCap) {
		log.Printf("rules: %s", w)
	}
```

(`fmt` and `log` are already imported in `rule.go`.)

- [ ] **Step 5: Update the two `rules.Load` callers**

In `internal/node/node.go` (~line 166), change:
```go
		rules:       rules.Load(cfg.RulesFilePath(), cfg.Reputation.BlockThreshold),
```
to:
```go
		rules:       rules.Load(cfg.RulesFilePath(), cfg.Reputation.BlockThreshold, cfg.Trust.StrangerScoreCap),
```

In `internal/node/node_test.go` (~line 52), change:
```go
		rules:      rules.Load("", cfg.Reputation.BlockThreshold),
```
to:
```go
		rules:      rules.Load("", cfg.Reputation.BlockThreshold, cfg.Trust.StrangerScoreCap),
```

- [ ] **Step 6: Run the lint tests + build**

Run: `go test ./internal/rules/ -run 'TestLint|TestShippedRules' -v && go build ./...`
Expected: all three tests PASS; build clean.

- [ ] **Step 7: Run the rules + node suites (regression)**

Run: `go test ./internal/rules/... ./internal/node/...`
Expected: PASS.

- [ ] **Step 8: Format edited files and commit**

```bash
gofmt -w internal/rules/rule.go internal/rules/rule_test.go internal/node/node.go internal/node/node_test.go
git add internal/rules/rule.go internal/rules/rule_test.go internal/node/node.go internal/node/node_test.go
git commit -m "feat(rules): advisory lint for stranger-exploitable block rules"
```

(The `gofmt -w` realigns the new `strangerCap` struct field with its neighbours; committing an unformatted file would fail Task 4's `gofmt -l` gate.)

---

### Task 3: ProcessRemote anchored-backing backstop (Component 1)

The structural guarantee: in `ProcessRemote`, downgrade any block to watch when the IP has no anchored corroboration. Config-independent — catches bare-reason blocks, low `min_score`, and the legacy fallback.

**Files:**
- Modify: `internal/node/node.go` (`ProcessRemote`, right after `rules.Evaluate`)
- Test: `test/adversarial/injection_test.go` (extend the file from batch A+B)

**Interfaces:**
- Consumes: `rules.ActionBlock`, `rules.ActionWatch`; `rec.Groups []string`; existing test helpers `anchoredEvent(t, n, dir, ip, reason)` and the package-local `mockSink` (`blocked []string`); `node.New`, `(*node.Node).ProcessRemote`, `(*node.Node).SetSinkForTest`, `(*node.Node).SetTrustReloadInterval`; `config.Defaults()`, `cfg.Reputation.RulesFile`.
- Produces: `newNodeWithRules(t *testing.T, rulesYAML string) (*node.Node, string, *mockSink)` (general test helper; the existing `newInjectionNode` is refactored to delegate to it).

- [ ] **Step 1: Write the failing backstop scenarios**

In `test/adversarial/injection_test.go`, add two rule constants and a general node-builder, refactor the existing `newInjectionNode` to delegate, and add three tests. First add the constants near the existing `injectionRules`:

```go
const bareReasonRules = `
- name: bare-probe-block
  reason: ssh-probe
  action: block
`

const lowScoreRules = `
- name: low-score-block
  min_score: 10
  action: block
`
```

Add the general helper (it is the body of the existing `newInjectionNode`, parameterised on the rules text):

```go
// newNodeWithRules builds a solo Node with the given rules.yaml content and a
// mock sink installed so Block calls are observable.
func newNodeWithRules(t *testing.T, rulesYAML string) (*node.Node, string, *mockSink) {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.RulesFile = rulesPath

	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	n.SetTrustReloadInterval(0)
	sink := &mockSink{}
	n.SetSinkForTest(sink)
	t.Cleanup(func() { n.CloseStores() })
	return n, dir, sink
}
```

Replace the existing `newInjectionNode` body so it delegates (DRY — keeps the batch A+B tests working unchanged):

```go
func newInjectionNode(t *testing.T) (*node.Node, string, *mockSink) {
	t.Helper()
	return newNodeWithRules(t, injectionRules)
}
```

Add the three tests:

```go
// TestBareReasonBlockRuleStrangerDowngraded: a block rule with no min_* gates
// (bare reason) must NOT let an un-anchored remote reporter force a block — the
// node-level backstop downgrades it to watch (no anchored corroboration).
func TestBareReasonBlockRuleStrangerDowngraded(t *testing.T) {
	n, _, sink := newNodeWithRules(t, bareReasonRules)
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "203.0.113.20", Reason: "ssh-probe", ReporterID: "stranger-peer"},
		From:  "stranger-peer",
	})
	if len(sink.blocked) != 0 {
		t.Errorf("bare-reason block rule let a stranger block; want 0, got %d", len(sink.blocked))
	}
}

// TestLowMinScoreBlockRuleStrangerDowngraded: a block rule whose min_score is
// below the stranger cap must still not let a stranger flood force a block.
func TestLowMinScoreBlockRuleStrangerDowngraded(t *testing.T) {
	n, _, sink := newNodeWithRules(t, lowScoreRules)
	// ssh-auth-success (weight 40) × stranger weight 0.3 → ~12 on the first event,
	// capping toward 15 — always >= min_score:10, so the rule matches every time.
	for i := 0; i < 3; i++ {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: "203.0.113.21", Reason: "ssh-auth-success", ReporterID: "stranger-peer"},
			From:  "stranger-peer",
		})
	}
	if len(sink.blocked) != 0 {
		t.Errorf("low min_score block rule let a stranger flood block; want 0, got %d", len(sink.blocked))
	}
}

// TestBareReasonBlockRuleAnchoredStillBlocks: the backstop only stops
// stranger-only blocks — an anchored reporter still blocks via the same
// bare-reason rule (regression).
func TestBareReasonBlockRuleAnchoredStillBlocks(t *testing.T) {
	n, dir, sink := newNodeWithRules(t, bareReasonRules)
	re := anchoredEvent(t, n, dir, "203.0.113.22", "ssh-probe")
	n.ProcessRemote(re)
	if len(sink.blocked) != 1 || sink.blocked[0] != "203.0.113.22" {
		t.Errorf("anchored reporter should block via bare-reason rule; got blocked=%v", sink.blocked)
	}
}
```

- [ ] **Step 2: Run the new tests to see the failing state**

Run: `go test -tags adversarial ./test/adversarial/ -run 'BareReasonBlockRuleStrangerDowngraded|LowMinScoreBlockRuleStrangerDowngraded|BareReasonBlockRuleAnchoredStillBlocks' -v`
Expected: the two `...Downgraded` tests FAIL (a stranger currently blocks → `len(sink.blocked)==1`); `TestBareReasonBlockRuleAnchoredStillBlocks` PASSES (anchored already blocks). This confirms the gap the backstop closes.

- [ ] **Step 3: Add the backstop in `ProcessRemote`**

In `internal/node/node.go`, `ProcessRemote`, the code currently reads:

```go
	rec, _ := n.rep.GetRecord(e.IP)
	action, ruleName := n.rules.Evaluate(e, rec, n.burst)
	switch action {
	case rules.ActionBlock:
```

Insert the backstop between `Evaluate` and `switch`:

```go
	rec, _ := n.rep.GetRecord(e.IP)
	action, ruleName := n.rules.Evaluate(e, rec, n.burst)
	// Structural guarantee (spec Leitprinzip 8): a remote signal may never FORCE a
	// block on stranger-only evidence. rec.Groups holds only anchored Person names
	// (P0-1), so len==0 means no anchored voucher backs this IP; downgrade any block
	// to watch regardless of rule configuration (bare-reason block, min_score below
	// the stranger cap, or legacy fallback).
	if action == rules.ActionBlock && len(rec.Groups) == 0 {
		log.Printf("node: downgrading stranger-only block to watch for %s (rule %q, no anchored corroboration)", e.IP, ruleName)
		action = rules.ActionWatch
	}
	switch action {
	case rules.ActionBlock:
```

Do NOT change `processLocal` — local observations self-anchor (`group=selfID`), so their blocks are already anchored-backed.

- [ ] **Step 4: Run the new tests to verify all pass**

Run: `go test -tags adversarial ./test/adversarial/ -run 'BareReasonBlockRuleStrangerDowngraded|LowMinScoreBlockRuleStrangerDowngraded|BareReasonBlockRuleAnchoredStillBlocks' -v`
Expected: all three PASS.

- [ ] **Step 5: Run the full adversarial + node suites (regression)**

Run: `go test -tags adversarial ./test/adversarial/... && go test ./internal/node/...`
Expected: PASS — the batch A+B injection tests (`TestStrangerCannotInject...`, `TestAnchored...`) still pass alongside the new ones.

- [ ] **Step 6: Format edited files and commit**

```bash
gofmt -w internal/node/node.go test/adversarial/injection_test.go
git add internal/node/node.go test/adversarial/injection_test.go
git commit -m "fix(node): backstop — downgrade stranger-only remote blocks to watch"
```

---

### Task 4: Final verification

Confirm the whole change builds, all suites pass, gofmt is clean, and the acceptance criteria hold.

**Files:** none (verification only).

- [ ] **Step 1: Build, vet, format**

Run: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/`
Expected: builds; vet clean; `gofmt -l` prints NOTHING (Task 1 cleared the drift and Tasks 2-3 added formatted code).

- [ ] **Step 2: Full unit + adversarial suites**

Run: `go test ./... && go test -tags adversarial ./test/adversarial/...`
Expected: all PASS.

- [ ] **Step 3: Confirm the acceptance scenarios explicitly**

Run: `go test -tags adversarial ./test/adversarial/ -run 'Downgraded|AnchoredStillBlocks' -v && go test ./internal/rules/ -run 'TestLint|TestShippedRules' -v`
Expected: `TestBareReasonBlockRuleStrangerDowngraded` PASS, `TestLowMinScoreBlockRuleStrangerDowngraded` PASS, `TestBareReasonBlockRuleAnchoredStillBlocks` PASS, `TestLintBlockRulesFlagsUnsafe` PASS, `TestLintBlockRulesAllowsSafe` PASS, `TestShippedRulesAreStrangerSafe` PASS — i.e. no rule configuration lets stranger-only remote input block, anchored/local evidence still blocks, and every shipped rule is stranger-safe.
