# EvidenceAggregate + Scale-Free Local Recompute (E2, Roadmap Step 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the federated query's raw `ScoreEntry` answer with a §7.5 `EvidenceAggregate` that every consumer recomputes into its own score through the reputation engine's own accumulation math — retiring E3's cross-domain score merge (roadmap B4).

**Architecture:** Extract `reputation.Record`'s accumulation into a pure `Accumulate` function. The responder answers an `EvidenceAggregate` (distinct-reporter counts per bucket, never identity) over a new `/federloom/repquery/v2`; the querier recomputes each aggregate locally via `RecordFromEvidence` (folding synthetic votes through `Accumulate`) and merges by max-of-recomputed score. A federated answer NEVER carries `Groups`, so it can never manufacture anchored corroboration toward the block backstop.

**Tech Stack:** Go 1.22, libp2p streams, BadgerDB-backed `store.ScoreRecord`, existing repquery querier/cache/singleflight from Step 1.

## Global Constraints

- Go module `github.com/JoeRu/federloom`, Go 1.22. Conventional Commits.
- **Clean break:** `/federloom/repquery/v2` REPLACES v1 — no dual registration, no fallback. `proto.ScoreEntry` reverts to reserved/unused (kept in `pkg/proto`, slated for C1 removal; do NOT delete it). `convert.go` (`EntryFromRecord`/`RecordFromEntry`) is deleted.
- **Critical invariant:** the record returned by `RecordFromEvidence` has EMPTY `Groups`, `ReporterIDs`, `Corroboration=0`, `StrangerSeen=false`. A federated answer must never satisfy the batch-A block backstop (`len(rec.Groups) > 0`). The synthetic anchored votes exist only inside the fold, to drive the SCORE.
- **Scale-free:** the consumer recomputes using ITS OWN `halfLife`, `strangerCap`, `FederationDiscount`, and reason-weight table (`reputation.WeightFor`). No foreign score is ever trusted directly.
- **Merge:** max of locally-recomputed `Score` across aggregators; `Reasons` = union of scenario lists.
- **Read-only preserved:** recompute is pure; no store or enforcement writes anywhere on this branch (materialise is Step 4).
- **Aggregator projection carries counts only** — `Groups`/`ReporterIDs` contents never leave the node (§7.5, spec §9 no hashing-anonymisation).
- **Engine equivalence:** the `Record` refactor is behavior-preserving — existing `internal/reputation` + `test/adversarial` suites must pass UNCHANGED.
- **Backward compat:** empty `federation_aggregators` ⇒ local-only, byte-for-byte as today. Step 1's responder authorization + stream deadline are untouched.
- Full gate at the end: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/` (empty) + unit + `-race` on repquery/reputation + `-tags adversarial` + `-tags integration`.

---

### Task 1: `EvidenceAggregate` wire type

**Files:**
- Modify: `pkg/proto/messages.go`
- Test: `pkg/proto/messages_test.go` (create if absent; else append)

**Interfaces:**
- Produces: `proto.EvidenceAggregate{ IP string; Scenarios []string; WindowFirst, WindowLast time.Time; DiversityBuckets map[string]int; StrangersPresent bool; EvidenceWeight float64 }` with JSON tags.

- [ ] **Step 1: Write the failing test**

Add to `pkg/proto/messages_test.go` (package `proto` — check the existing test package clause and match it):

```go
func TestEvidenceAggregateJSONRoundTrip(t *testing.T) {
	ev := EvidenceAggregate{
		IP:               "203.0.113.7",
		Scenarios:        []string{"ssh-probe", "ssh-auth-bruteforce"},
		WindowFirst:      time.Unix(1000, 0).UTC(),
		WindowLast:       time.Unix(2000, 0).UTC(),
		DiversityBuckets: map[string]int{"groups": 3, "reporters": 9},
		StrangersPresent: true,
		EvidenceWeight:   1.0,
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back EvidenceAggregate
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.IP != ev.IP || back.DiversityBuckets["groups"] != 3 ||
		!back.StrangersPresent || !back.WindowLast.Equal(ev.WindowLast) ||
		len(back.Scenarios) != 2 {
		t.Errorf("round trip lost fields: %+v", back)
	}
}
```

Ensure imports `encoding/json`, `testing`, `time`.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./pkg/proto/ -run TestEvidenceAggregateJSONRoundTrip -v`
Expected: FAIL — `EvidenceAggregate` undefined.

- [ ] **Step 3: Add the type**

In `pkg/proto/messages.go`, after the `RepQuery` type add:

```go
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
```

Also update the `ScoreEntry` doc comment (currently "…exchanged as the query answer") to note it is reserved/unused again pending the C1 wire cleanup:

```go
// ScoreEntry is the aggregated reputation for one IP within a trust domain (spec §7.2).
// RESERVED / currently unused: E2 replaced the query answer with EvidenceAggregate.
// Slated for removal in the events-v1 wire cleanup (roadmap C1).
```

`time` is already imported in messages.go.

- [ ] **Step 4: Run to verify pass**

Run: `go test ./pkg/proto/ -run TestEvidenceAggregateJSONRoundTrip -v && go build ./...`
Expected: PASS; build clean.

- [ ] **Step 5: Commit**

```bash
gofmt -w pkg/proto/messages.go pkg/proto/messages_test.go
git add pkg/proto/messages.go pkg/proto/messages_test.go
git commit -m "feat(proto): add EvidenceAggregate wire type (§7.5); ScoreEntry reverts to reserved"
```

---

### Task 2: Pure `Accumulate` refactor of the reputation engine (keystone)

**Files:**
- Modify: `internal/reputation/engine.go`
- Test: `internal/reputation/engine_test.go` (append)

**Interfaces:**
- Produces: `type Observation struct { Reason, ReporterID, Group string; Trust float64; Anchored bool }`; `func Accumulate(rec store.ScoreRecord, obs Observation, now time.Time, halfLife time.Duration, strangerCap float64) store.ScoreRecord`; `func WeightFor(reason string) float64`. `Record`'s external behavior is unchanged.
- Consumes: existing `DecayScore`, `weightFor`, `containsString`.

- [ ] **Step 1: Write the failing test**

Append to `internal/reputation/engine_test.go`:

```go
func TestAccumulateMatchesKnownContribution(t *testing.T) {
	// One anchored ssh-probe (weight 2) at trust 0.9 onto an empty record:
	// contrib = 0.9 * 2 * (1 - 0/100) = 1.8.
	now := time.Now()
	rec := Accumulate(store.ScoreRecord{}, Observation{
		Reason: "ssh-probe", ReporterID: "r1", Group: "jo", Trust: 0.9, Anchored: true,
	}, now, 7*24*time.Hour, 15)
	if rec.Score < 1.79 || rec.Score > 1.81 {
		t.Errorf("Score = %v, want ~1.8", rec.Score)
	}
	if len(rec.Groups) != 1 || rec.Groups[0] != "jo" || rec.Corroboration != 1 {
		t.Errorf("anchored group not recorded: %+v", rec)
	}
	// Stranger contribution is capped at strangerCap.
	rec2 := store.ScoreRecord{}
	for i := 0; i < 100; i++ {
		rec2 = Accumulate(rec2, Observation{Reason: "smtp-spamtrap", ReporterID: "s", Trust: 0.3, Anchored: false}, now, 7*24*time.Hour, 15)
	}
	if rec2.Score > 15.001 || !rec2.StrangerSeen {
		t.Errorf("stranger cap not honored: score=%v", rec2.Score)
	}
	if len(rec2.Groups) != 0 {
		t.Errorf("stranger must not add groups: %+v", rec2.Groups)
	}
}

func TestWeightForExported(t *testing.T) {
	if WeightFor("ssh-auth-success") != 40 || WeightFor("unknown-reason") != 2 {
		t.Errorf("WeightFor: got %v/%v", WeightFor("ssh-auth-success"), WeightFor("unknown-reason"))
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/reputation/ -run 'TestAccumulate|TestWeightForExported' -v`
Expected: FAIL — `Accumulate`/`Observation`/`WeightFor` undefined.

- [ ] **Step 3: Extract `Accumulate` and rewrite `Record` to use it**

In `internal/reputation/engine.go` add:

```go
// Observation is one scoring input — a native event or a synthetic evidence vote.
type Observation struct {
	Reason     string
	ReporterID string
	Group      string
	Trust      float64
	Anchored   bool
}

// Accumulate applies obs to rec (lazily decayed to now) and returns the updated
// record. Pure: no store access. This is the single accumulation path — both
// Record (native events) and the federated recompute (internal/repquery) fold
// through it, so a federated score is computed under the same math as a local one.
func Accumulate(rec store.ScoreRecord, obs Observation, now time.Time, halfLife time.Duration, strangerCap float64) store.ScoreRecord {
	if !rec.LastSeen.IsZero() {
		rec.Score = DecayScore(rec.Score, rec.LastSeen, now, halfLife)
	}
	contrib := obs.Trust * weightFor(obs.Reason) * (1 - rec.Score/100)
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
	// Corroboration counts distinct ANCHORED Person groups only (spec Leitprinzip 8;
	// batch A P0-1) — strangers never satisfy a min_corroboration block rule.
	if obs.Anchored && obs.Group != "" && !containsString(rec.Groups, obs.Group) {
		rec.Groups = append(rec.Groups, obs.Group)
	}
	rec.Corroboration = len(rec.Groups)
	if !containsString(rec.ReporterIDs, obs.ReporterID) {
		rec.ReporterIDs = append(rec.ReporterIDs, obs.ReporterID)
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

// WeightFor returns the score-contribution weight for a reason code (the local
// weight table). Exported so the federated recompute can pick the highest-weight
// scenario as its vote reason (§8: recomputed under the consumer's own rules).
func WeightFor(reason string) float64 { return weightFor(reason) }
```

Replace the body of `Record` (keep its signature and doc comment) with:

```go
func (e *Engine) Record(ip, reason, reporterID string, trust float64, group string, anchored bool) (float64, error) {
	rec, err := e.store.GetScore(ip)
	if err != nil {
		return 0, fmt.Errorf("reputation: get %q: %w", ip, err)
	}
	rec = Accumulate(rec, Observation{
		Reason: reason, ReporterID: reporterID, Group: group, Trust: trust, Anchored: anchored,
	}, time.Now(), e.halfLife, e.strangerCap)
	ttl := 3 * e.halfLife
	if err := e.store.PutScore(ip, rec, ttl); err != nil {
		return 0, fmt.Errorf("reputation: put %q: %w", ip, err)
	}
	return rec.Score, nil
}
```

- [ ] **Step 4: Run — new tests AND the full existing reputation suite (equivalence)**

Run: `go test ./internal/reputation/ -race -v 2>&1 | tail -30`
Expected: PASS — the new tests AND every pre-existing engine test (equivalence by regression: `Record` behaves identically).

- [ ] **Step 5: Run the adversarial suite (equivalence under attack scenarios)**

Run: `go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3`
Expected: PASS unchanged.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/reputation/engine.go internal/reputation/engine_test.go
git add internal/reputation/engine.go internal/reputation/engine_test.go
git commit -m "refactor(reputation): extract pure Accumulate from Record; export WeightFor"
```

---

### Task 3: Aggregator-side projection `AggregateFromRecord`

**Files:**
- Create: `internal/repquery/aggregate.go`
- Test: `internal/repquery/aggregate_test.go`

**Interfaces:**
- Produces: `func AggregateFromRecord(ip string, r store.ScoreRecord) proto.EvidenceAggregate`.

- [ ] **Step 1: Write the failing test**

Create `internal/repquery/aggregate_test.go`:

```go
package repquery

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/store"
)

func TestAggregateFromRecord(t *testing.T) {
	now := time.Now().UTC()
	r := store.ScoreRecord{
		Score:        60,
		FirstSeen:    now.Add(-time.Hour),
		LastSeen:     now,
		Reasons:      []string{"ssh-probe", "ssh-auth-bruteforce"},
		Groups:       []string{"jo", "al"},
		ReporterIDs:  []string{"p1", "p2", "p3"},
		StrangerSeen: true,
	}
	ev := AggregateFromRecord("203.0.113.7", r)
	if ev.IP != "203.0.113.7" || ev.DiversityBuckets["groups"] != 2 ||
		ev.DiversityBuckets["reporters"] != 3 || !ev.StrangersPresent ||
		!ev.WindowLast.Equal(now) || ev.EvidenceWeight != 1.0 || len(ev.Scenarios) != 2 {
		t.Errorf("projection wrong: %+v", ev)
	}
	// Privacy: no reporter identity leaks — only counts.
	// (Structural: EvidenceAggregate has no identity field; asserting the type
	// carries counts is enough.)

	// Empty record → not-found sentinel (zero WindowLast).
	empty := AggregateFromRecord("1.1.1.1", store.ScoreRecord{})
	if !empty.WindowLast.IsZero() {
		t.Errorf("empty record should yield zero WindowLast, got %v", empty.WindowLast)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/repquery/ -run TestAggregateFromRecord -v`
Expected: FAIL — `AggregateFromRecord` undefined.

- [ ] **Step 3: Implement**

Create `internal/repquery/aggregate.go`:

```go
package repquery

import (
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// AggregateFromRecord projects a local ScoreRecord onto the wire EvidenceAggregate
// (spec §7.5). It shares only distinct-reporter COUNTS per bucket — never the
// Groups/ReporterIDs contents themselves (§7.5 "never reporter identity").
func AggregateFromRecord(ip string, r store.ScoreRecord) proto.EvidenceAggregate {
	return proto.EvidenceAggregate{
		IP:          ip,
		Scenarios:   r.Reasons,
		WindowFirst: r.FirstSeen,
		WindowLast:  r.LastSeen, // zero => "not found" sentinel
		DiversityBuckets: map[string]int{
			"groups":    len(r.Groups),
			"reporters": len(r.ReporterIDs),
		},
		StrangersPresent: r.StrangerSeen,
		EvidenceWeight:   1.0,
	}
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/repquery/ -run TestAggregateFromRecord -v && go build ./...`
Expected: PASS; build clean (nothing wired to it yet).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/repquery/aggregate.go internal/repquery/aggregate_test.go
git add internal/repquery/aggregate.go internal/repquery/aggregate_test.go
git commit -m "feat(repquery): AggregateFromRecord projection (counts only, §7.5)"
```

---

### Task 4: Consumer recompute `RecordFromEvidence` (Groups-empty invariant)

**Files:**
- Create: `internal/repquery/recompute.go`
- Test: `internal/repquery/recompute_test.go`

**Interfaces:**
- Consumes: `reputation.Accumulate`, `reputation.Observation`, `reputation.WeightFor`, `reputation.DecayScore` (Task 2).
- Produces: `func RecordFromEvidence(ev proto.EvidenceAggregate, now time.Time, halfLife time.Duration, strangerCap, federationDiscount float64) store.ScoreRecord`.

- [ ] **Step 1: Write the failing test**

Create `internal/repquery/recompute_test.go`:

```go
package repquery

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/pkg/proto"
)

func TestRecordFromEvidenceRecomputesLocally(t *testing.T) {
	now := time.Now().UTC()
	ev := proto.EvidenceAggregate{
		IP:               "203.0.113.7",
		Scenarios:        []string{"ssh-probe", "ssh-auth-success"}, // max weight = ssh-auth-success (40)
		WindowFirst:      now.Add(-time.Hour),
		WindowLast:       now,
		DiversityBuckets: map[string]int{"groups": 3, "reporters": 9},
		StrangersPresent: false,
		EvidenceWeight:   1.0,
	}
	rec := RecordFromEvidence(ev, now, 7*24*time.Hour, 15, 0.5)

	// Score is recomputed locally and positive; more groups => higher.
	if rec.Score <= 0 {
		t.Fatalf("expected positive recomputed score, got %v", rec.Score)
	}
	// CRITICAL INVARIANT: a federated answer never manufactures anchored corroboration.
	if len(rec.Groups) != 0 || rec.Corroboration != 0 || len(rec.ReporterIDs) != 0 || rec.StrangerSeen {
		t.Errorf("federated record leaked corroboration state: %+v", rec)
	}
	// Reasons carry the scenario union; window preserved.
	if len(rec.Reasons) != 2 || !rec.LastSeen.Equal(now) {
		t.Errorf("reasons/window wrong: %+v", rec)
	}

	// More groups => strictly higher score (diversity is carried across the import).
	evMore := ev
	evMore.DiversityBuckets = map[string]int{"groups": 6, "reporters": 12}
	recMore := RecordFromEvidence(evMore, now, 7*24*time.Hour, 15, 0.5)
	if recMore.Score <= rec.Score {
		t.Errorf("more groups should recompute higher: %v !> %v", recMore.Score, rec.Score)
	}
}

func TestRecordFromEvidenceNotFoundAndStrangerOnly(t *testing.T) {
	now := time.Now().UTC()
	// Zero WindowLast => empty record (not found).
	empty := RecordFromEvidence(proto.EvidenceAggregate{IP: "1.1.1.1"}, now, time.Hour, 15, 0.5)
	if !empty.LastSeen.IsZero() || empty.Score != 0 {
		t.Errorf("not-found evidence should yield empty record, got %+v", empty)
	}
	// Stranger-only evidence is bounded by the local stranger cap.
	strangerOnly := proto.EvidenceAggregate{
		IP: "2.2.2.2", Scenarios: []string{"smtp-spamtrap"}, WindowLast: now,
		DiversityBuckets: map[string]int{"groups": 0, "reporters": 5}, StrangersPresent: true, EvidenceWeight: 1.0,
	}
	rec := RecordFromEvidence(strangerOnly, now, 7*24*time.Hour, 15, 0.5)
	if rec.Score > 15.001 {
		t.Errorf("stranger-only evidence exceeded local cap: %v", rec.Score)
	}
	if len(rec.Groups) != 0 {
		t.Errorf("stranger-only must not add groups: %+v", rec.Groups)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/repquery/ -run TestRecordFromEvidence -v`
Expected: FAIL — `RecordFromEvidence` undefined.

- [ ] **Step 3: Implement**

Create `internal/repquery/recompute.go`:

```go
package repquery

import (
	"time"

	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// maxWeightScenario returns the scenario with the highest local weight (the vote
// reason for the recompute). "" if scenarios is empty (weightFor("") = default).
func maxWeightScenario(scenarios []string) string {
	best := ""
	bestW := -1.0
	for _, s := range scenarios {
		if w := reputation.WeightFor(s); w > bestW {
			bestW, best = w, s
		}
	}
	return best
}

// RecordFromEvidence recomputes a local ScoreRecord from a federated
// EvidenceAggregate using the CONSUMER's own parameters (§8: recomputed under
// your own rules). It folds synthetic anchored votes — one per counted group —
// plus one capped stranger vote if strangers were present, through the same
// reputation.Accumulate math native events use.
//
// CRITICAL INVARIANT: the returned record's Groups/ReporterIDs are empty and
// Corroboration is 0. The synthetic anchored votes drive the SCORE only; the
// answer must never satisfy the anchored-corroboration block backstop
// (len(rec.Groups) > 0). The score alone is advisory (DNSBL/API), threshold-governed.
func RecordFromEvidence(ev proto.EvidenceAggregate, now time.Time, halfLife time.Duration, strangerCap, federationDiscount float64) store.ScoreRecord {
	if ev.WindowLast.IsZero() {
		return store.ScoreRecord{} // not found
	}
	weight := ev.EvidenceWeight
	if weight < 0 {
		weight = 0
	}
	if weight > 1 {
		weight = 1
	}
	trust := weight * federationDiscount
	reason := maxWeightScenario(ev.Scenarios)

	// Fold one synthetic anchored vote per counted group at the evidence window
	// instant (intra-fold decay is therefore zero; one real-time decay follows).
	// The labels are constant on purpose: reputation.Accumulate adds each vote's
	// contribution to the score BEFORE the group/reporter dedup, so N folds raise
	// the score with N regardless of label distinctness — diversity (group count)
	// drives the score through the NUMBER of folds, and the discarded Groups slice
	// stays length ≤ 1 either way (we never return it — the invariant).
	folded := store.ScoreRecord{}
	groups := ev.DiversityBuckets["groups"]
	for i := 0; i < groups; i++ {
		folded = reputation.Accumulate(folded, reputation.Observation{
			Reason: reason, ReporterID: "fed", Group: "fed", Trust: trust, Anchored: true,
		}, ev.WindowLast, halfLife, strangerCap)
	}
	if ev.StrangersPresent {
		folded = reputation.Accumulate(folded, reputation.Observation{
			Reason: reason, ReporterID: "fed-stranger", Trust: trust, Anchored: false,
		}, ev.WindowLast, halfLife, strangerCap)
	}

	score := folded.Score
	if !ev.WindowLast.IsZero() {
		score = reputation.DecayScore(score, ev.WindowLast, now, halfLife)
	}

	// Rebuild a record that carries the recomputed SCORE and provenance-safe
	// metadata ONLY — never Groups/ReporterIDs/Corroboration (the invariant).
	return store.ScoreRecord{
		Score:     score,
		Reasons:   append([]string(nil), ev.Scenarios...),
		FirstSeen: ev.WindowFirst,
		LastSeen:  ev.WindowLast,
	}
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/repquery/ -run TestRecordFromEvidence -race -v && go build ./...`
Expected: PASS; build clean.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/repquery/recompute.go internal/repquery/recompute_test.go
git add internal/repquery/recompute.go internal/repquery/recompute_test.go
git commit -m "feat(repquery): RecordFromEvidence — scale-free local recompute (Groups always empty)"
```

---

### Task 5: The wire switch — responder v2 + querier/resolver retype to ScoreRecord

This is the one atomic, coherent wire change: responder answers `EvidenceAggregate`, protocol becomes v2, querier decodes/recomputes/merges into `store.ScoreRecord`, resolver returns the record directly, `convert.go` is deleted, and all repquery/node/integration tests are retyped. Every prior task kept the build green; this task flips the wire in a single commit.

**Files:**
- Modify: `internal/repquery/responder.go`, `internal/repquery/querier.go`, `internal/repquery/resolver.go`, `internal/node/node.go`
- Delete: `internal/repquery/convert.go`, `internal/repquery/convert_test.go`
- Test (retype): `internal/repquery/responder_test.go`, `internal/repquery/querier_test.go`, `internal/repquery/resolver_test.go`, `test/integration/repquery_test.go`, `internal/node/wiring_repquery_test.go`

**Interfaces:**
- Consumes: `AggregateFromRecord` (Task 3), `RecordFromEvidence` (Task 4).
- Produces: `ProtocolID = "/federloom/repquery/v2"`; `NewQuerier(h host.Host, aggregators []peer.AddrInfo, timeout, cacheTTL time.Duration, halfLife time.Duration, strangerCap, federationDiscount float64) *Querier`; `Querier.Query(ctx, ip) (store.ScoreRecord, bool)`.

- [ ] **Step 1: Switch the protocol id + responder answer**

In `internal/repquery/responder.go`: change the const to
`const ProtocolID = "/federloom/repquery/v2"`. In the handler, replace the encode line with the aggregate projection:

```go
		// Empty record → EvidenceAggregate with zero WindowLast means "not found".
		if err := json.NewEncoder(str).Encode(AggregateFromRecord(q.IP, rec)); err != nil {
			log.Printf("repquery: write answer for %s: %v", peerID, err)
		}
```

Update the handler doc comment mentioning "one ScoreEntry" to "one EvidenceAggregate".

- [ ] **Step 2: Retype the querier to recompute + merge into ScoreRecord**

In `internal/repquery/querier.go`:
- `cacheEntry.entry` becomes `store.ScoreRecord`.
- `Querier` gains fields `halfLife time.Duration`, `strangerCap, federationDiscount float64`.
- `NewQuerier` gains those three params (append to the signature) and stores them.
- `Query` returns `(store.ScoreRecord, bool)`; the `qres` struct's `entry` becomes `store.ScoreRecord`; the cache read/write use `store.ScoreRecord`.
- `fanout` returns `(store.ScoreRecord, bool)`: for each aggregator it calls `ask` (now returning `proto.EvidenceAggregate`), recomputes via `RecordFromEvidence(ev, time.Now(), q.halfLife, q.strangerCap, q.federationDiscount)`, keeps the max-`Score` record, unions `Reasons`. Skeleton:

```go
func (q *Querier) fanout(ctx context.Context, ip string) (store.ScoreRecord, bool) {
	qctx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	type res struct {
		ev proto.EvidenceAggregate
		ok bool
	}
	ch := make(chan res, len(q.aggregators))
	for _, agg := range q.aggregators {
		go func(a peer.AddrInfo) {
			ev, ok := q.ask(qctx, a, ip)
			ch <- res{ev, ok}
		}(agg)
	}

	var best store.ScoreRecord
	found := false
	reasons := map[string]bool{}
collect:
	for i := 0; i < len(q.aggregators); i++ {
		select {
		case r := <-ch:
			if !r.ok {
				continue
			}
			rec := RecordFromEvidence(r.ev, time.Now(), q.halfLife, q.strangerCap, q.federationDiscount)
			if rec.LastSeen.IsZero() {
				continue
			}
			for _, rs := range rec.Reasons {
				reasons[rs] = true
			}
			if !found || rec.Score > best.Score {
				best = rec
			}
			found = true
		case <-qctx.Done():
			break collect
		}
	}
	if found {
		best.Reasons = best.Reasons[:0]
		for rs := range reasons {
			best.Reasons = append(best.Reasons, rs)
		}
	}
	return best, found
}
```

- `ask` now returns `(proto.EvidenceAggregate, bool)`: decode `proto.EvidenceAggregate` instead of `proto.ScoreEntry`; the not-found sentinel test becomes `ev.WindowLast.IsZero()`. Keep the stream deadline + encode `RepQuery` exactly as today.

- [ ] **Step 3: Resolver returns the recomputed record directly**

In `internal/repquery/resolver.go`, the federated branch becomes:

```go
	if rec2, ok := r.q.Query(context.Background(), ip); ok {
		return rec2, nil
	}
	return rec, nil // federated miss → the (empty) local record
```

Remove the `RecordFromEntry` call (and its now-unused import if any).

- [ ] **Step 4: Delete the v1 conversion**

```bash
git rm internal/repquery/convert.go internal/repquery/convert_test.go
```

(`proto.ScoreEntry` stays in `pkg/proto` — do NOT delete it.)

- [ ] **Step 5: Update the node wiring to pass recompute params**

In `internal/node/node.go`, the `NewQuerier` call (inside the aggregator-gated block) gains the three params:

```go
			q := repquery.NewQuerier(t.Host(), aggs, cfg.EffectiveQueryTimeout(), cfg.EffectiveQueryCacheTTL(),
				halfLife, cfg.Trust.StrangerScoreCap, cfg.Trust.FederationDiscount)
```

(`halfLife` is the local var from `node.New`; `cfg.Trust.StrangerScoreCap` and `cfg.Trust.FederationDiscount` already exist.)

- [ ] **Step 6: Retype the tests (mechanical — no assertion may become vacuous)**

Apply these exact changes; a recomputed score is NOT the aggregator's stored score, so exact-value assertions become "positive / non-zero", but every test must still prove the fetch happened:

- `internal/repquery/responder_test.go`:
  - The `queryOnce` helper's return type and the decoded var become `proto.EvidenceAggregate`.
  - `TestResponderAuthorization`: the authorized case asserts the decoded aggregate has `WindowLast` non-zero and `DiversityBuckets["reporters"] >= 1` (a real answer) instead of `e.Score == 88`. Reject cases unchanged (still expect a decode error / reset).
  - `TestResponderServesLocalScore`: assert `ev.IP` and `ev.WindowLast` non-zero + a bucket count matching the fake store's record; rename to `...ServesLocalEvidence` if desired.
  - `TestResponderUnknownIPIsEmpty`: assert `ev.WindowLast.IsZero()` (was `LastSeen`).
  - `TestResponderStreamDeadlineClosesIdleStream`: unchanged (never decodes an answer).
- `internal/repquery/querier_test.go`:
  - Every `proto.ScoreEntry` type/var becomes `store.ScoreRecord`; `NewQuerier(...)` calls gain `7*24*time.Hour, 15, 0.5` (halfLife, strangerCap, discount).
  - `TestQuerierFetchesAndCaches`: assert the returned `store.ScoreRecord` has `Score > 0` and `!LastSeen.IsZero()` (recomputed), not `== 70`. Cache-hit assertion (responder called once) unchanged.
  - `TestQuerierSingleflight`: assert `rec.Score > 0 && ok`; the `calls == 1` assertion is the real check, unchanged.
  - `TestQuerierPreservesScoreZeroAnswer`: the aggregator's record has a real reporter (`reporters >= 1`) with `LastSeen` set; assert the recomputed record is `ok == true` and `!LastSeen.IsZero()` (a known IP is not lost even if its recomputed score is small) — this preserves the original test's intent (known ≠ not-found) under the evidence model.
  - `TestQuerierTimeoutDoesNotHang`, `TestQuerierCacheBounded`: retype the returned value; the timeout/bound assertions are unchanged (both use `ok`/cache size, not score).
- `internal/repquery/resolver_test.go`: `fixedStore` and the local-hit/miss tests use `store.ScoreRecord` already; only compile fixes if `RecordFromEntry` was referenced (it is not). Verify it still builds.
- `test/integration/repquery_test.go` (`TestFederatedLookupFetchesFromAggregator`): `NewQuerier(...)` gains the three params; assert the resolver's returned record has `Score > 0 && !LastSeen.IsZero()` (recomputed from B's evidence) instead of `== 92`; the unknown-IP case still asserts an empty record.
- `internal/node/wiring_repquery_test.go`:
  - `TestNodeWiringFederatesBothReadSurfaces`: assert both surfaces return `Score > 0` (recomputed) and non-zero `LastSeen`, not `== 91`. The two-surface structure (both API and DNSBL fetch) is the real check — keep it.
  - `TestResponderServeRoleAuthz`: the anchored client decodes `proto.EvidenceAggregate` (was `ScoreEntry`); assert a successful decode with non-zero `WindowLast` for a known IP; stranger reset unchanged.

- [ ] **Step 7: Build, vet, and run every touched suite under -race**

Run: `go build ./... && go vet ./... && go test ./internal/repquery/... ./internal/node/... ./pkg/proto/... -race 2>&1 | tail -30 && go test ./test/integration/ -run 'TestFederatedLookup|TestNodeWiring|TestResponderServeRole' -v 2>&1 | tail -20`
Expected: all PASS. If any retyped test now passes without actually exercising the fetch (vacuous), fix the assertion — do not leave it green-but-empty.

- [ ] **Step 8: Commit**

```bash
gofmt -w internal/repquery/responder.go internal/repquery/querier.go internal/repquery/resolver.go internal/node/node.go internal/repquery/responder_test.go internal/repquery/querier_test.go internal/repquery/resolver_test.go test/integration/repquery_test.go internal/node/wiring_repquery_test.go
git add -A internal/repquery internal/node test/integration/repquery_test.go
git commit -m "feat(repquery): switch query answer to EvidenceAggregate over /v2; recompute+merge into ScoreRecord"
```

---

### Task 6: Adversarial inflated-bucket scenario + docs + full gate

**Files:**
- Create: `test/adversarial/repquery_evidence_test.go`
- Modify: `docs/config.md`, `docs/spec.md` (§12a), `docs/roadmap.md`, `docs/architecture.md`

**Interfaces:**
- Consumes: `repquery.RecordFromEvidence` (Task 4).

- [ ] **Step 1: Write the adversarial test**

Create `test/adversarial/repquery_evidence_test.go`:

```go
//go:build adversarial

package adversarial

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/repquery"
	"github.com/JoeRu/federloom/pkg/proto"
)

// TestInflatedBucketsCannotForceBlock: a hostile aggregator claiming absurd
// diversity cannot (a) manufacture anchored corroboration (Groups stays empty,
// so the block backstop is never satisfied) nor (b) drive the recomputed score
// above the logistic ceiling. Containment for a lying aggregator is defederation.
func TestInflatedBucketsCannotForceBlock(t *testing.T) {
	now := time.Now().UTC()
	ev := proto.EvidenceAggregate{
		IP:               "203.0.113.99",
		Scenarios:        []string{"ssh-auth-success"}, // highest local weight (40)
		WindowLast:       now,
		DiversityBuckets: map[string]int{"groups": 500, "reporters": 5000},
		StrangersPresent: true,
		EvidenceWeight:   1.0,
	}
	rec := repquery.RecordFromEvidence(ev, now, 7*24*time.Hour, 15, 0.5)

	if len(rec.Groups) != 0 || rec.Corroboration != 0 {
		t.Fatalf("federated evidence manufactured corroboration: Groups=%v Corr=%d", rec.Groups, rec.Corroboration)
	}
	if rec.Score > 100 {
		t.Errorf("recomputed score exceeded logistic ceiling: %v", rec.Score)
	}
	// A record with no Groups can never satisfy the anchored-corroboration block
	// backstop (batch A: block requires len(Groups) > 0), regardless of score.
}
```

- [ ] **Step 2: Run it + the whole adversarial suite**

Run: `go test -tags adversarial ./test/adversarial/ -run TestInflatedBuckets -v && go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3`
Expected: PASS; suite green.

- [ ] **Step 3: Docs — config.md**

In `docs/config.md`, in the `federation_aggregators` section append:

```markdown
**What the answer is:** an aggregator returns an *evidence aggregate*
(distinct-reporter counts per bucket, scenarios, window) — never a finished
score. Your node **recomputes** the score locally from that evidence using
your own weight table, stranger cap, half-life, and `federation_discount`
(which doubles as the evidence-import discount). A federated answer never
carries anchored corroboration, so it can raise a DNSBL/API score (advisory,
against your threshold) but can never force a block.
```

- [ ] **Step 4: Docs — spec §12a traceability**

In `docs/spec.md` §12a, update these rows:

```markdown
| §5.2 | Federation import / discount / origin-trace | `internal/node`, `internal/transport`, `internal/repquery` | PARTIAL — origin-trace + per-hop discount (E1); evidence import via query path DONE (E2); gossip-side evidence import PLANNED |
| §7.2 | ScoreEntry aggregate | `pkg/proto` | RESERVED — replaced by EvidenceAggregate (E2); slated for C1 removal |
| §7.5 | EvidenceAggregate (federated import type) | `pkg/proto`, `internal/repquery` | DONE — the on-demand query answer, recomputed locally (E2) |
```

- [ ] **Step 5: Docs — roadmap + architecture**

In `docs/roadmap.md`: mark Step 2 done — change the Step 2 heading to `### Step 2 — E2: EvidenceAggregate + scale-free recompute → A1, resolves B4 ✅ done 2026-07-12`; annotate A1 (`✅ resolved`) and B4 (`✅ resolved — replaced by EvidenceAggregate + local recompute`) in the Part 2 tables; add `ScoreEntry` to the C1 row's list of types awaiting removal.

In `docs/architecture.md`, add one line to the query-read-path note: the query path now transports **evidence** (recomputed locally), not scores.

- [ ] **Step 6: Full gate**

Run: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/ && go test ./... 2>&1 | tail -5 && go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3 && go test -tags integration ./test/integration/... 2>&1 | tail -3`
Expected: build/vet clean, `gofmt -l` empty, all suites PASS.

- [ ] **Step 7: Commit**

```bash
gofmt -w test/adversarial/repquery_evidence_test.go
git add test/adversarial/repquery_evidence_test.go docs/config.md docs/spec.md docs/roadmap.md docs/architecture.md
git commit -m "test+docs: adversarial inflated-bucket scenario; E2 traceability, config, roadmap Step 2 done"
```
