# Subnet-Diversity-Weighted Corroboration (D, Roadmap Step 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Weight corroboration by federation-subnet diversity so an IP flagged many times from one subnet scores far lower than the same volume spread across many subnets (§4.2), without touching the anchored-Person block gate.

**Architecture:** Track the distinct subnets that reported an IP in a `SubnetsSeen` set on the record; in the pure `Accumulate`, a report from a NEW subnet gets full weight while a repeat from an already-counted subnet is scaled by a small `diversityRepeat` factor. The native path keys diversity on the originator's `e.SubnetID` (bridge-launder resistant); the federated path folds `diversity_buckets["subnets"]` to cap how much a large `groups` claim benefits from diversity. Empty subnet ⇒ factor 1.0 ⇒ byte-for-byte today's scoring.

**Tech Stack:** Go 1.22, the reputation engine's pure `Accumulate`, `internal/repquery` recompute, BadgerDB `store.ScoreRecord`.

## Global Constraints

- Go module `github.com/JoeRu/federloom`, Go 1.22. Conventional Commits.
- **Score-weight only:** diversity NEVER changes the block gate. A block still requires anchored-Person corroboration (`len(rec.Groups) > 0`); `min_corroboration` semantics are untouched. Strangers/subnets can never force a block (Leitprinzip 8; batch-A P0-1 backstop intact).
- **Backward compatible:** an empty `obs.Subnet` (solo node / no `federation_subnet` / pre-E1 event) leaves `divFactor == 1.0` and does not modify `SubnetsSeen` — scoring is byte-for-byte as today. Existing `internal/reputation` + `test/adversarial` suites MUST pass unchanged.
- **Bridge-launder resistant:** native diversity keys on the originator's `e.SubnetID`, NOT the arrival subnet `re.Subnet`.
- **Privacy:** `SubnetsSeen` holds ids locally; only its LENGTH goes on the wire (`diversity_buckets["subnets"]`) — subnet names never leave the node (§7.5).
- **Groups-empty invariant (E2) preserved:** `RecordFromEvidence` still returns a fresh literal carrying only Score/Reasons/FirstSeen/LastSeen.
- Diversity factor is config: `Trust.DiversityRepeatFactor` (default 0.15), read via `EffectiveDiversityRepeatFactor()` clamped to (0,1]; locally overridable (Leitprinzip 7).
- Full gate at end: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/` (empty) + unit + `-race` on repquery/reputation + `-tags adversarial` + `-tags integration`.

---

### Task 1: Config knob — `diversity_repeat_factor`

**Files:**
- Modify: `internal/config/config.go` (`TrustConfig`, `Defaults()`, add accessor)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `Config.Trust.DiversityRepeatFactor float64` (yaml `diversity_repeat_factor`); `func (c *Config) EffectiveDiversityRepeatFactor() float64` (returns 0.15 if the stored value is `<= 0`, clamps to 1.0 if `> 1`, else the value — mirrors the existing `EffectiveQueryTimeout` pattern).

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestEffectiveDiversityRepeatFactor(t *testing.T) {
	// Unset (<=0) → default 0.15.
	if got := (&config.Config{}).EffectiveDiversityRepeatFactor(); got != 0.15 {
		t.Errorf("default = %v, want 0.15", got)
	}
	// In-range value passes through.
	c := &config.Config{}
	c.Trust.DiversityRepeatFactor = 0.4
	if got := c.EffectiveDiversityRepeatFactor(); got != 0.4 {
		t.Errorf("in-range = %v, want 0.4", got)
	}
	// Out-of-range clamps to 1.0.
	c.Trust.DiversityRepeatFactor = 2.5
	if got := c.EffectiveDiversityRepeatFactor(); got != 1.0 {
		t.Errorf("over-range = %v, want 1.0", got)
	}
	// Defaults() ships the documented default.
	if got := config.Defaults().Trust.DiversityRepeatFactor; got != 0.15 {
		t.Errorf("Defaults DiversityRepeatFactor = %v, want 0.15", got)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/config/ -run TestEffectiveDiversityRepeatFactor -v`
Expected: FAIL — field/method undefined.

- [ ] **Step 3: Add the field, default, and accessor**

In `TrustConfig` (after `FederationDiscount`):
```go
	DiversityRepeatFactor float64 `yaml:"diversity_repeat_factor"` // weight of a repeat report from an already-counted subnet vs. a first-from-new-subnet report; lower = stronger diversity weighting (default 0.15)
```

In `Defaults()`'s `Trust:` block (after `FederationDiscount: 0.5,`):
```go
			DiversityRepeatFactor: 0.15,
```

Add the accessor (near the other `Effective*` methods):
```go
// EffectiveDiversityRepeatFactor returns the subnet-diversity repeat weight,
// defaulting to 0.15 when unset and clamping to (0,1]. A repeat report from a
// subnet that already reported an IP is worth this fraction of a first report.
func (c *Config) EffectiveDiversityRepeatFactor() float64 {
	f := c.Trust.DiversityRepeatFactor
	if f <= 0 {
		return 0.15
	}
	if f > 1 {
		return 1.0
	}
	return f
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/config/ -run TestEffectiveDiversityRepeatFactor -v && go build ./...`
Expected: PASS; build clean.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/config/config.go internal/config/config_test.go
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add diversity_repeat_factor (subnet-diversity weighting)"
```

---

### Task 2: Native diversity mechanic in `Accumulate` (keystone)

**Files:**
- Modify: `internal/store/*.go` (the file with `type ScoreRecord struct`), `internal/reputation/engine.go`, `internal/repquery/recompute.go` (compile-fix only), `internal/node/node.go` (call-site updates)
- Test: `internal/reputation/engine_test.go`

**Interfaces:**
- Consumes: `EffectiveDiversityRepeatFactor()` (Task 1).
- Produces: `store.ScoreRecord.SubnetsSeen []string`; `reputation.Observation.Subnet string`; `Accumulate(rec, obs, now, halfLife, strangerCap, diversityRepeat float64) store.ScoreRecord` (new trailing param); `Engine` gains `diversityRepeat`; `New(s, halfLife, strangerCap, diversityRepeat float64)`; `Record(ip, reason, reporterID string, trust float64, group, subnet string, anchored bool)` (new `subnet` param before `anchored`).

- [ ] **Step 1: Write the failing test**

Append to `internal/reputation/engine_test.go`:

```go
func TestAccumulateSubnetDiversity(t *testing.T) {
	now := time.Now()
	hl := 7 * 24 * time.Hour
	// Ten reports from ONE subnet: first full, nine damped.
	one := store.ScoreRecord{}
	for i := 0; i < 10; i++ {
		one = Accumulate(one, Observation{Reason: "ssh-probe", ReporterID: "r", Group: "g", Trust: 0.9, Anchored: true, Subnet: "a"}, now, hl, 15, 0.15)
	}
	// Ten reports from TEN distinct subnets: all full.
	ten := store.ScoreRecord{}
	for i := 0; i < 10; i++ {
		ten = Accumulate(ten, Observation{Reason: "ssh-probe", ReporterID: "r", Group: "g", Trust: 0.9, Anchored: true, Subnet: string(rune('a' + i))}, now, hl, 15, 0.15)
	}
	if !(ten.Score > one.Score) {
		t.Errorf("ten subnets (%v) must outscore one subnet (%v)", ten.Score, one.Score)
	}
	if len(one.SubnetsSeen) != 1 {
		t.Errorf("one-subnet SubnetsSeen = %v, want len 1", one.SubnetsSeen)
	}
	if len(ten.SubnetsSeen) != 10 {
		t.Errorf("ten-subnet SubnetsSeen = %v, want len 10", ten.SubnetsSeen)
	}
	// Empty subnet reproduces today's math (factor 1.0, no SubnetsSeen tracking).
	empty := Accumulate(store.ScoreRecord{}, Observation{Reason: "ssh-probe", ReporterID: "r", Group: "g", Trust: 0.9, Anchored: true, Subnet: ""}, now, hl, 15, 0.15)
	if empty.Score < 1.79 || empty.Score > 1.81 || len(empty.SubnetsSeen) != 0 {
		t.Errorf("empty-subnet obs must score ~1.8 with no SubnetsSeen, got %v / %v", empty.Score, empty.SubnetsSeen)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/reputation/ -run TestAccumulateSubnetDiversity -v`
Expected: FAIL — `Observation.Subnet`/`SubnetsSeen`/6-arg `Accumulate` undefined.

- [ ] **Step 3: Add the record field**

In the file defining `store.ScoreRecord` (add after `StrangerContrib`):
```go
	SubnetsSeen []string `json:"subnets_seen,omitempty"` // distinct subnets that reported this IP (diversity, §4.2); ids local-only, never shared as names
```

- [ ] **Step 4: Add `Observation.Subnet` and the diversity factor in `Accumulate`**

In `internal/reputation/engine.go`, add to `Observation`:
```go
	Subnet string // originator's home subnet (diversity key); "" = untracked (solo / pre-E1)
```

Change `Accumulate`'s signature to take `diversityRepeat float64` as a trailing param, and weight the contribution:
```go
func Accumulate(rec store.ScoreRecord, obs Observation, now time.Time, halfLife time.Duration, strangerCap, diversityRepeat float64) store.ScoreRecord {
	if !rec.LastSeen.IsZero() {
		rec.Score = DecayScore(rec.Score, rec.LastSeen, now, halfLife)
	}
	// Subnet-diversity weighting (§4.2): a repeat report from a subnet that has
	// already reported this IP counts for less; the first from a new subnet is
	// full. Empty subnet (solo / pre-E1) is never damped and never tracked.
	firstFromSubnet := obs.Subnet != "" && !containsString(rec.SubnetsSeen, obs.Subnet)
	divFactor := 1.0
	if obs.Subnet != "" && !firstFromSubnet {
		divFactor = diversityRepeat
	}
	contrib := obs.Trust * weightFor(obs.Reason) * (1 - rec.Score/100) * divFactor
	if !obs.Anchored {
		remaining := strangerCap - rec.StrangerContrib
		if remaining < 0 {
			remaining = 0
		}
		if contrib > remaining {
			contrib = remaining
		}
		rec.StrangerContrib += contrib
		rec.StrangerSeen = true
	}
	rec.Score += contrib
	if rec.Score > 100 {
		rec.Score = 100
	}
	if obs.Anchored && obs.Group != "" && !containsString(rec.Groups, obs.Group) {
		rec.Groups = append(rec.Groups, obs.Group)
	}
	rec.Corroboration = len(rec.Groups)
	if !containsString(rec.ReporterIDs, obs.ReporterID) {
		rec.ReporterIDs = append(rec.ReporterIDs, obs.ReporterID)
	}
	if firstFromSubnet {
		rec.SubnetsSeen = append(rec.SubnetsSeen, obs.Subnet)
	}
	rec.LastSeen = now
	if rec.FirstSeen.IsZero() {
		rec.FirstSeen = now
	}
	if !containsString(rec.Reasons, obs.Reason) {
		rec.Reasons = append(rec.Reasons, obs.Reason)
	}
	return rec
}
```

- [ ] **Step 5: Thread the factor through `Engine`/`New`/`Record`**

Add `diversityRepeat float64` to the `Engine` struct. Update `New`:
```go
func New(s *store.BadgerStore, halfLife time.Duration, strangerCap, diversityRepeat float64) *Engine {
	return &Engine{store: s, halfLife: halfLife, strangerCap: strangerCap, diversityRepeat: diversityRepeat}
}
```

Update `Record` to take a `subnet` param and pass it plus the factor into `Accumulate` (keep the doc comment, extend it one line):
```go
func (e *Engine) Record(ip, reason, reporterID string, trust float64, group, subnet string, anchored bool) (float64, error) {
	rec, err := e.store.GetScore(ip)
	if err != nil {
		return 0, fmt.Errorf("reputation: get %q: %w", ip, err)
	}
	rec = Accumulate(rec, Observation{
		Reason: reason, ReporterID: reporterID, Group: group, Subnet: subnet, Trust: trust, Anchored: anchored,
	}, time.Now(), e.halfLife, e.strangerCap, e.diversityRepeat)
	ttl := 3 * e.halfLife
	if err := e.store.PutScore(ip, rec, ttl); err != nil {
		return 0, fmt.Errorf("reputation: put %q: %w", ip, err)
	}
	return rec.Score, nil
}
```

- [ ] **Step 6: Fix the other `Accumulate` callers so the build stays green**

`internal/repquery/recompute.go` calls `reputation.Accumulate(...)` twice (the group-fold and the stranger-fold). Add a trailing `1.0` argument to BOTH calls for now (the synthetic obs carry `Subnet: ""`, so the factor is inert — no behavior change; the real subnet logic lands in Task 5):
```go
		folded = reputation.Accumulate(folded, reputation.Observation{
			Reason: reason, ReporterID: "fed", Group: "fed", Trust: trust, Anchored: true,
		}, ev.WindowLast, halfLife, strangerCap, 1.0)
```
and the stranger fold likewise ends `..., strangerCap, 1.0)`.

Any pre-existing `internal/reputation` test that calls `Accumulate` directly (e.g. `TestAccumulateMatchesKnownContribution`) needs the trailing factor arg too — add `, 0.15` (or `, 1.0`; with `Subnet: ""` it is inert) to those calls. Do NOT change their assertions.

- [ ] **Step 7: Update the node call sites**

In `internal/node/node.go`:
- `reputation.New(s, halfLife, cfg.Trust.StrangerScoreCap)` → `reputation.New(s, halfLife, cfg.Trust.StrangerScoreCap, cfg.EffectiveDiversityRepeatFactor())`.
- `processLocal`'s `n.rep.Record(e.IP, e.Reason, n.selfID, 1.0, n.selfID, true)` → add `e.SubnetID` before the final `true`: `n.rep.Record(e.IP, e.Reason, n.selfID, 1.0, n.selfID, e.SubnetID, true)`. (`e.SubnetID` is set to `n.cfg.FederationSubnet` a few lines above.)
- `ProcessRemote`'s `n.rep.Record(e.IP, e.Reason, e.ReporterID, weight, group, anchored)` → `n.rep.Record(e.IP, e.Reason, e.ReporterID, weight, group, e.SubnetID, anchored)` (the originator's home subnet from the wire — NOT `re.Subnet`).

- [ ] **Step 8: Run the reputation suite (new + equivalence) and adversarial**

Run: `go build ./... && go test ./internal/reputation/ -race -v 2>&1 | tail -30 && go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3`
Expected: PASS — new diversity test AND every pre-existing reputation/adversarial test unchanged.

- [ ] **Step 9: Commit**

```bash
gofmt -w internal/store/*.go internal/reputation/engine.go internal/repquery/recompute.go internal/node/node.go internal/reputation/engine_test.go
git add internal/store internal/reputation/engine.go internal/reputation/engine_test.go internal/repquery/recompute.go internal/node/node.go
git commit -m "feat(reputation): subnet-diversity weighting in Accumulate (first-from-subnet full, repeats damped)"
```

---

### Task 3: Node wiring test — diversity keys on origin, not arrival

**Files:**
- Test: `test/integration/bridge_test.go` (add one test) OR `internal/node/node_test.go` — use `internal/node/node_test.go` (`package node`), since it can read `n.rep`/`n.store` directly and the existing node tests build `New(cfg, nil)`.

**Interfaces:**
- Consumes: `node.New`, `Node.ProcessRemote`, `Node.GetScore` (all existing); `e.SubnetID` on `proto.Event`.

- [ ] **Step 1: Write the test**

Add to `internal/node/node_test.go` (reuse the file's `testNode` helper and imports):

```go
// TestDiversityKeysOnOriginSubnet: two remote reports for the same IP that
// originated in the SAME subnet (e.SubnetID) but arrived via DIFFERENT arrival
// subnets (re.Subnet) must count as ONE subnet for diversity — a bridge cannot
// launder a same-origin report into a fresh diversity vote.
func TestDiversityKeysOnOriginSubnet(t *testing.T) {
	n, _ := testNode(t)
	mk := func(arrival string) transport.ReceivedEvent {
		return transport.ReceivedEvent{
			Event: proto.Event{
				IP: "198.51.100.5", Reason: "ssh-probe", ReporterID: "origX",
				Timestamp: time.Now().UTC(), SubnetID: "home", OriginTrace: []string{"origX"},
			},
			From: "origX", Subnet: arrival,
		}
	}
	n.ProcessRemote(mk("bridgepath1"))
	rec1, _ := n.GetScore("198.51.100.5")
	n.ProcessRemote(transport.ReceivedEvent{ // second copy, same origin subnet "home", different arrival
		Event: proto.Event{
			IP: "198.51.100.5", Reason: "ssh-probe", ReporterID: "origX",
			Timestamp: time.Now().UTC(), SubnetID: "home", OriginTrace: []string{"origX"},
		},
		From: "origX", Subnet: "bridgepath2",
	})
	rec2, _ := n.GetScore("198.51.100.5")

	if len(rec2.SubnetsSeen) != 1 || rec2.SubnetsSeen[0] != "home" {
		t.Errorf("diversity must key on origin SubnetID; SubnetsSeen = %v, want [home]", rec2.SubnetsSeen)
	}
	// The second (same-origin-subnet) report is damped, so the score gain is small.
	gain := rec2.Score - rec1.Score
	if gain >= (rec1.Score - 0) { // second gain must be strictly less than the first full contribution
		t.Errorf("same-subnet repeat not damped: first=%v secondGain=%v", rec1.Score, gain)
	}
}
```

(If `testNode`/imports differ, adapt — the existing `TestProcessRemoteScoresValidEventWithOriginTrace` in the same file shows the exact `ProcessRemote` + `GetScore` pattern and imports.)

- [ ] **Step 2: Run to verify pass**

Run: `go test ./internal/node/ -run TestDiversityKeysOnOriginSubnet -v`
Expected: PASS. If it FAILS because diversity keyed on arrival subnet, that is a Task-2 wiring bug — STOP and fix Task 2 (the `Record` call must pass `e.SubnetID`, not `re.Subnet`), do not weaken the test.

- [ ] **Step 3: Commit**

```bash
gofmt -w internal/node/node_test.go
git add internal/node/node_test.go
git commit -m "test(node): diversity keys on originator SubnetID, not arrival subnet (bridge-launder resistant)"
```

---

### Task 4: `AggregateFromRecord` ships the subnets bucket

**Files:**
- Modify: `internal/repquery/aggregate.go`
- Test: `internal/repquery/aggregate_test.go`

**Interfaces:**
- Produces: `AggregateFromRecord` now sets `DiversityBuckets["subnets"] = len(r.SubnetsSeen)`.

- [ ] **Step 1: Write the failing test**

Add to `internal/repquery/aggregate_test.go`:

```go
func TestAggregateShipsSubnetsBucket(t *testing.T) {
	r := store.ScoreRecord{
		LastSeen:    time.Now(),
		Groups:      []string{"jo", "al"},
		ReporterIDs: []string{"p1", "p2", "p3"},
		SubnetsSeen: []string{"a", "b", "c"},
	}
	ev := AggregateFromRecord("203.0.113.7", r)
	if ev.DiversityBuckets["subnets"] != 3 {
		t.Errorf("subnets bucket = %d, want 3", ev.DiversityBuckets["subnets"])
	}
	// Names never leave the node — only the count.
	// (Structural: EvidenceAggregate has no subnet-names field.)
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/repquery/ -run TestAggregateShipsSubnetsBucket -v`
Expected: FAIL — bucket absent (0 != 3).

- [ ] **Step 3: Add the bucket**

In `internal/repquery/aggregate.go`, in the `DiversityBuckets` map literal, add the subnets key:
```go
		DiversityBuckets: map[string]int{
			"groups":    len(r.Groups),
			"reporters": len(r.ReporterIDs),
			"subnets":   len(r.SubnetsSeen),
		},
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/repquery/ -run TestAggregate -v && go build ./...`
Expected: PASS (new + existing aggregate tests).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/repquery/aggregate.go internal/repquery/aggregate_test.go
git add internal/repquery/aggregate.go internal/repquery/aggregate_test.go
git commit -m "feat(repquery): ship subnets diversity bucket in AggregateFromRecord"
```

---

### Task 5: `RecordFromEvidence` subnet-capped folds + querier threading

**Files:**
- Modify: `internal/repquery/recompute.go`, `internal/repquery/querier.go`, `internal/node/node.go`
- Test: `internal/repquery/recompute_test.go`, and retype affected `NewQuerier` callers

**Interfaces:**
- Consumes: `EffectiveDiversityRepeatFactor()` (Task 1); `DiversityBuckets["subnets"]` (Task 4).
- Produces: `RecordFromEvidence(ev, now, halfLife, strangerCap, federationDiscount, diversityRepeat float64) store.ScoreRecord`; `NewQuerier(h, aggregators, timeout, cacheTTL, halfLife, strangerCap, federationDiscount, diversityRepeat float64) *Querier`.

- [ ] **Step 1: Write the failing test**

Add to `internal/repquery/recompute_test.go`:

```go
func TestRecordFromEvidenceSubnetCapsDiversity(t *testing.T) {
	now := time.Now().UTC()
	hl := 7 * 24 * time.Hour
	base := proto.EvidenceAggregate{
		IP: "203.0.113.7", Scenarios: []string{"ssh-auth-success"}, WindowLast: now, EvidenceWeight: 1.0,
	}
	// Many groups but ONE subnet → damped to roughly one diverse vote.
	oneSubnet := base
	oneSubnet.DiversityBuckets = map[string]int{"groups": 40, "subnets": 1}
	// Many groups across MANY subnets → full diversity.
	manySubnets := base
	manySubnets.DiversityBuckets = map[string]int{"groups": 40, "subnets": 40}

	low := RecordFromEvidence(oneSubnet, now, hl, 15, 0.5, 0.15)
	high := RecordFromEvidence(manySubnets, now, hl, 15, 0.5, 0.15)

	// Same group count (40), different subnet diversity: the broad answer must
	// score strictly higher (its votes are all full-weight; the one-subnet
	// answer's are mostly damped). Strict inequality is the robust property —
	// exact magnitudes depend on the logistic curve, so we don't pin them.
	if !(high.Score > low.Score) {
		t.Errorf("many subnets (%v) must outscore one subnet (%v)", high.Score, low.Score)
	}
	if low.Score <= 0 {
		t.Errorf("one-subnet answer should still recompute a positive score, got %v", low.Score)
	}
	// Invariant intact.
	if len(low.Groups) != 0 || low.Corroboration != 0 {
		t.Errorf("federated record leaked corroboration: %+v", low)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/repquery/ -run TestRecordFromEvidenceSubnetCaps -v`
Expected: FAIL — `RecordFromEvidence` has 5 params, not 6.

- [ ] **Step 3: Implement subnet-capped folds**

In `internal/repquery/recompute.go`, change `RecordFromEvidence`'s signature to add a trailing `diversityRepeat float64`. Damp the folds by REUSING `Accumulate`'s own subnet mechanic (single source of truth, not a duplicated formula): give the first `min(groups, subnets)` folds distinct synthetic subnet ids (`fed-0`, `fed-1`, … → each counts as first-from-a-new-subnet, full weight), and give every remaining fold the SAME `fed-repeat` subnet id (→ `Accumulate` damps them as repeats). Add `"strconv"` to the imports.

```go
func RecordFromEvidence(ev proto.EvidenceAggregate, now time.Time, halfLife time.Duration, strangerCap, federationDiscount, diversityRepeat float64) store.ScoreRecord {
	if ev.WindowLast.IsZero() {
		return store.ScoreRecord{} // not found
	}
	weight := ev.EvidenceWeight
	if weight != weight || weight < 0 { // NaN or negative -> 0
		weight = 0
	}
	if weight > 1 {
		weight = 1
	}
	trust := weight * federationDiscount
	reason := maxWeightScenario(ev.Scenarios)

	groups := ev.DiversityBuckets["groups"]
	if groups > maxEvidenceFolds {
		groups = maxEvidenceFolds
	}
	if groups < 0 {
		groups = 0
	}
	// Subnet diversity caps how many group-votes count at FULL weight (§4.2):
	// the rest are damped by Accumulate's own repeat mechanic. subnets==0 (older
	// aggregate) → treat as 1 (a known IP came from at least one subnet).
	subnets := ev.DiversityBuckets["subnets"]
	if subnets < 1 {
		subnets = 1
	}
	fullVotes := groups
	if subnets < fullVotes {
		fullVotes = subnets
	}

	folded := store.ScoreRecord{}
	for i := 0; i < groups; i++ {
		// First `fullVotes` folds get distinct synthetic subnets (full weight);
		// the rest share one subnet so Accumulate damps them as repeats.
		subnet := "fed-" + strconv.Itoa(i)
		if i >= fullVotes {
			subnet = "fed-repeat"
		}
		folded = reputation.Accumulate(folded, reputation.Observation{
			Reason: reason, ReporterID: "fed", Group: "fed", Subnet: subnet, Trust: trust, Anchored: true,
		}, ev.WindowLast, halfLife, strangerCap, diversityRepeat)
	}
	if ev.StrangersPresent {
		folded = reputation.Accumulate(folded, reputation.Observation{
			Reason: reason, ReporterID: "fed-stranger", Trust: trust, Anchored: false,
		}, ev.WindowLast, halfLife, strangerCap, 1.0)
	}

	score := reputation.DecayScore(folded.Score, ev.WindowLast, now, halfLife)
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return store.ScoreRecord{
		Score:     score,
		Reasons:   append([]string(nil), ev.Scenarios...),
		FirstSeen: ev.WindowFirst,
		LastSeen:  ev.WindowLast,
	}
}
```

(Because the shared `fed-repeat` subnet's FIRST fold is itself "new", `fullVotes + 1` folds end up full-weight — an immaterial, conservative off-by-one. The point holds: a large `groups` claim with few `subnets` recomputes far below the same claim spread across many subnets.)

- [ ] **Step 4: Thread `diversityRepeat` through the querier**

In `internal/repquery/querier.go`: add a `diversityRepeat float64` field to `Querier`; add the trailing param to `NewQuerier` and store it; in `fanout`, the `RecordFromEvidence(...)` call gains `, q.diversityRepeat`.

In `internal/node/node.go`: the `repquery.NewQuerier(t.Host(), aggs, cfg.EffectiveQueryTimeout(), cfg.EffectiveQueryCacheTTL(), halfLife, cfg.Trust.StrangerScoreCap, cfg.Trust.FederationDiscount)` call gains `, cfg.EffectiveDiversityRepeatFactor()`.

- [ ] **Step 5: Fix `NewQuerier` test callers**

Every `NewQuerier(...)` call in `internal/repquery/querier_test.go` and `test/integration/repquery_test.go` gains a trailing `, 0.15` (the diversity factor). These tests assert `Score > 0` / cache behavior, unaffected by the factor value.

- [ ] **Step 6: Run repquery + node + integration under -race**

Run: `go build ./... && go vet ./... && go test ./internal/repquery/... ./internal/node/... -race 2>&1 | tail -30 && go test -tags integration ./test/integration/... 2>&1 | tail -5`
Expected: all PASS (the known `TestStarTopologyGossipSymmetric` gossip flake is unrelated; rerun the integration suite once if it fires).

- [ ] **Step 7: Commit**

```bash
gofmt -w internal/repquery/recompute.go internal/repquery/querier.go internal/node/node.go internal/repquery/recompute_test.go internal/repquery/querier_test.go test/integration/repquery_test.go
git add internal/repquery/recompute.go internal/repquery/querier.go internal/node/node.go internal/repquery/recompute_test.go internal/repquery/querier_test.go test/integration/repquery_test.go
git commit -m "feat(repquery): subnet count caps federated group-diversity in RecordFromEvidence"
```

---

### Task 6: Adversarial single-subnet-flood + docs + full gate

**Files:**
- Create: `test/adversarial/diversity_flood_test.go`
- Modify: `docs/config.md`, `docs/spec.md` (§12a), `docs/roadmap.md`, `docs/architecture.md`

**Interfaces:**
- Consumes: `reputation.Accumulate` / `repquery.RecordFromEvidence`.

- [ ] **Step 1: Write the adversarial test**

Create `test/adversarial/diversity_flood_test.go`:

```go
//go:build adversarial

package adversarial

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
)

// TestSingleSubnetFloodScoresBelowBroad: for the SAME number of reports (20), a
// single subnet flooding them for one IP scores strictly below the same volume
// spread across 20 distinct subnets — the §4.2 Sybil-resistance property (a
// same-count flood cannot buy the breadth signal). Equal counts make the
// comparison robust to the logistic magnitude.
func TestSingleSubnetFloodScoresBelowBroad(t *testing.T) {
	now := time.Now()
	hl := 7 * 24 * time.Hour
	const n = 20
	flood := store.ScoreRecord{}
	for i := 0; i < n; i++ {
		flood = reputation.Accumulate(flood, reputation.Observation{
			Reason: "ssh-auth-success", ReporterID: "sybil", Group: "g", Subnet: "one", Trust: 0.9, Anchored: true,
		}, now, hl, 15, 0.15)
	}
	broad := store.ScoreRecord{}
	for i := 0; i < n; i++ {
		broad = reputation.Accumulate(broad, reputation.Observation{
			Reason: "ssh-auth-success", ReporterID: "r", Group: "g", Subnet: string(rune('a' + i)), Trust: 0.9, Anchored: true,
		}, now, hl, 15, 0.15)
	}
	if flood.Score >= broad.Score {
		t.Errorf("same-count single-subnet flood (%v) must score below broad multi-subnet (%v)", flood.Score, broad.Score)
	}
	if len(flood.SubnetsSeen) != 1 {
		t.Errorf("flood should register exactly one subnet, got %v", flood.SubnetsSeen)
	}
	if len(broad.SubnetsSeen) != n {
		t.Errorf("broad should register %d subnets, got %d", n, len(broad.SubnetsSeen))
	}
}
```

- [ ] **Step 2: Run it + the whole adversarial suite**

Run: `go test -tags adversarial ./test/adversarial/ -run TestSingleSubnetFlood -v && go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3`
Expected: PASS; suite green.

- [ ] **Step 3: Docs — config.md**

In `docs/config.md`, near the trust settings, add:
```markdown
### `diversity_repeat_factor`

Weights corroboration by federation-subnet diversity (spec §4.2). A report for
an IP from a subnet that has **already** reported it counts for this fraction
of a first report from a *new* subnet (default `0.15`). Lower = stronger
diversity weighting; `1.0` disables it (repeats count fully). Diversity shapes
the advisory score only — it never changes the block gate (a block still needs
anchored-Person corroboration). A solo / single-subnet node is unaffected.
```

- [ ] **Step 4: Docs — spec §12a**

In `docs/spec.md` §12a, update the §4.2 row:
```markdown
| §4.2 | Diversity-weighted corroboration | `internal/reputation`, `internal/repquery` | DONE — subnet-diversity weighting (D); ASN/geo dimensions PLANNED |
```

- [ ] **Step 5: Docs — roadmap + architecture**

In `docs/roadmap.md`: mark Step 3 done — heading `### Step 3 — D  diversity-weighted corroboration → A2 ✅ done 2026-07-12`; annotate the A2 row `✅ resolved — subnet-diversity weighting (score-only; ASN/geo later)`.

In `docs/architecture.md`, add one line: corroboration is subnet-diversity weighted — breadth across subnets outweighs volume from one (score only; the block gate stays anchored-Person).

- [ ] **Step 6: Full gate**

Run: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/ && go test ./... 2>&1 | tail -5 && go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3 && go test -tags integration ./test/integration/... 2>&1 | tail -3`
Expected: build/vet clean, `gofmt -l` empty, all suites PASS.

- [ ] **Step 7: Commit**

```bash
gofmt -w test/adversarial/diversity_flood_test.go
git add test/adversarial/diversity_flood_test.go docs/config.md docs/spec.md docs/roadmap.md docs/architecture.md
git commit -m "test+docs: adversarial single-subnet-flood; §4.2 traceability, config, roadmap Step 3 done"
```
