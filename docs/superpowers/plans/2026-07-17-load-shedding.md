# Resource Budget + Load Shedding (Step 7 / A7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Under a load spike, the node sheds network-contribution work (remote gossip scoring, bridge re-emission, federated queries) while never shedding local protection — driven by a processing-rate budget, off by default.

**Architecture:** A `resources.Governor` (a ring-bucket rate meter with hysteresis) decides `Shed()`. `processLocal` charges the budget but is never gated; `ProcessRemote`, `reemitIfBridge`, and the `repquery.Resolver` federated path check `Shed()` and skip (dropping, not queuing) when over budget. Three observability metrics report shedding. Zero budget ⇒ never sheds ⇒ byte-for-byte today.

**Tech Stack:** Go 1.22, `internal/resources` (was a doc stub), Prometheus observability plane, libp2p gossip.

## Global Constraints

- Go module `github.com/JoeRu/federloom`, Go 1.22. Conventional Commits.
- **Off by default:** `resources.max_events_per_sec` default 0 ⇒ `Governor` never sheds ⇒ behaviour byte-for-byte as today. No shedding unless an operator sets a positive budget.
- **Priority invariant (non-negotiable, §11.5 / Leitprinzip 1/8):** local ingest → score → enforce is METERED (`Charge`) but NEVER gated by `Shed()`. Only network-contribution work is shed.
- **Shed = drop, never queue/replay.** A shed item is skipped and counted; nothing is stored. "Sync later" is the existing eventual-consistency substrate.
- **Shed only ever REDUCES network participation** — it never blocks, never raises a score, never bypasses never-block/whitelist or the anchored backstop, never mutates enforcement.
- Concurrency-safe: `Governor` is called from the gossip and ingest goroutines — mutex-guarded, `-race` clean.
- No new wire surface, no hashing, no enforcement-path change.
- Full gate: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/` (empty) + unit + `-race` + `-tags adversarial` + `-tags integration`.

---

### Task 1: The `Governor` (rate meter + shed hysteresis)

**Files:**
- Create: `internal/resources/governor.go` (replaces/augments the `doc.go` stub package)
- Test: `internal/resources/governor_test.go`

**Interfaces:**
- Produces: `func NewGovernor(maxPerSec float64) *Governor`; `func (g *Governor) Charge()`; `func (g *Governor) Shed() bool`; `func (g *Governor) Rate() float64`. `maxPerSec <= 0` ⇒ never sheds, `Rate()` still reports 0 without charging. The unexported `now func() time.Time` field is settable by same-package tests for a deterministic clock.

- [ ] **Step 1: Write the failing test**

Create `internal/resources/governor_test.go` (`package resources` — internal, so it can drive the clock):

```go
package resources

import (
	"sync"
	"testing"
	"time"
)

func TestGovernorSheddingWithHysteresis(t *testing.T) {
	base := time.Unix(1000, 0)
	clk := base
	g := NewGovernor(100) // 100 events/sec budget
	g.now = func() time.Time { return clk }

	// Below budget: charge 50 in the current second → not shedding.
	for i := 0; i < 50; i++ {
		g.Charge()
	}
	if g.Shed() {
		t.Fatalf("50/s under a 100/s budget must not shed; rate=%v", g.Rate())
	}

	// Push over budget in the same 1s window → shedding.
	for i := 0; i < 60; i++ {
		g.Charge()
	}
	if !g.Shed() {
		t.Fatalf("110/s over a 100/s budget must shed; rate=%v", g.Rate())
	}

	// Advance ~0.6s (past the exit fraction as old buckets fall out is not enough
	// yet); advance a full 1s so the window empties → rate 0 ≤ 0.8×budget → exit.
	clk = base.Add(1100 * time.Millisecond)
	if g.Shed() {
		t.Errorf("after the 1s window empties, must exit shed mode; rate=%v", g.Rate())
	}
}

func TestGovernorDisabled(t *testing.T) {
	g := NewGovernor(0) // unlimited / off
	for i := 0; i < 100000; i++ {
		g.Charge()
	}
	if g.Shed() {
		t.Error("budget 0 must never shed")
	}
}

func TestGovernorRaceSafe(t *testing.T) {
	g := NewGovernor(1000)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				g.Charge()
				_ = g.Shed()
				_ = g.Rate()
			}
		}()
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/resources/ -run TestGovernor -v`
Expected: FAIL — `NewGovernor`/`Governor` undefined.

- [ ] **Step 3: Implement the governor**

Create `internal/resources/governor.go`:

```go
// Package resources — good-neighbour controls: a processing-rate budget and
// load shedding under overload (spec §11.5). The Governor never sheds local
// protection work; callers gate only network-contribution work on Shed().
package resources

import (
	"sync"
	"time"
)

const (
	govBuckets        = 10                     // 100ms buckets → a 1s sliding window
	bucketDur         = 100 * time.Millisecond // width of one bucket
	sheddExitFraction = 0.8                    // exit shed only when rate ≤ 0.8×budget (hysteresis)
)

// Governor is a concurrency-safe processing-rate meter with a shed decision.
// maxPerSec <= 0 disables it (never sheds). The window is a ring of per-100ms
// buckets summed over the last second; no background goroutine — buckets are
// advanced lazily on Charge/Shed/Rate.
type Governor struct {
	mu        sync.Mutex
	maxPerSec float64
	now       func() time.Time // injectable for tests
	counts    [govBuckets]int
	lastTick  int64 // 100ms tick of the most recent advance; -1 = never charged
	shedding  bool
}

// NewGovernor builds a Governor with a per-second budget. budget <= 0 = off.
func NewGovernor(maxPerSec float64) *Governor {
	return &Governor{maxPerSec: maxPerSec, now: time.Now, lastTick: -1}
}

func (g *Governor) tick() int64 { return g.now().UnixNano() / int64(bucketDur) }

// advanceLocked zeros the buckets for ticks elapsed since lastTick. Holds mu.
func (g *Governor) advanceLocked(t int64) {
	if g.lastTick < 0 {
		g.lastTick = t
		return
	}
	elapsed := t - g.lastTick
	if elapsed <= 0 {
		return
	}
	if elapsed >= govBuckets {
		for i := range g.counts {
			g.counts[i] = 0
		}
	} else {
		for i := int64(1); i <= elapsed; i++ {
			g.counts[(g.lastTick+i)%govBuckets] = 0
		}
	}
	g.lastTick = t
}

func (g *Governor) rateLocked() float64 {
	sum := 0
	for _, c := range g.counts {
		sum += c
	}
	return float64(sum) // events in the last 1s window == events/sec
}

// Charge records one unit of processed work against the current window.
func (g *Governor) Charge() {
	if g.maxPerSec <= 0 {
		return
	}
	g.mu.Lock()
	t := g.tick()
	g.advanceLocked(t)
	g.counts[t%govBuckets]++
	g.mu.Unlock()
}

// Shed reports whether the node is over budget and sheddable work should skip.
// Hysteresis: enters at the budget, exits only at ≤ sheddExitFraction×budget.
func (g *Governor) Shed() bool {
	if g.maxPerSec <= 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.advanceLocked(g.tick())
	rate := g.rateLocked()
	if g.shedding {
		if rate <= g.maxPerSec*sheddExitFraction {
			g.shedding = false
		}
	} else if rate >= g.maxPerSec {
		g.shedding = true
	}
	return g.shedding
}

// Rate returns the current events/sec over the last window.
func (g *Governor) Rate() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.advanceLocked(g.tick())
	return g.rateLocked()
}
```

You may delete the now-superseded `internal/resources/doc.go` if its package comment duplicates governor.go's (keep exactly one `package resources` doc comment).

- [ ] **Step 4: Run to verify pass (incl. -race)**

Run: `go test ./internal/resources/ -race -v 2>&1 | tail -20 && go build ./...`
Expected: PASS; build clean.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/resources/governor.go internal/resources/governor_test.go
git rm -q internal/resources/doc.go 2>/dev/null || true
git add internal/resources/
git commit -m "feat(resources): processing-rate Governor with shed hysteresis (§11.5)"
```

---

### Task 2: Config knob — `resources.max_events_per_sec`

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `Config.Resources ResourcesConfig` (yaml `resources`) with `ResourcesConfig.MaxEventsPerSec float64` (yaml `max_events_per_sec`). Default 0 (off).

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:
```go
func TestResourcesConfigDefaultsOff(t *testing.T) {
	if config.Defaults().Resources.MaxEventsPerSec != 0 {
		t.Errorf("max_events_per_sec must default to 0 (off), got %v", config.Defaults().Resources.MaxEventsPerSec)
	}
	// YAML override is honored.
	c, err := config.LoadYAML([]byte("resources:\n  max_events_per_sec: 250\n"))
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if c.Resources.MaxEventsPerSec != 250 {
		t.Errorf("override = %v, want 250", c.Resources.MaxEventsPerSec)
	}
}
```
(Confirm `config.LoadYAML([]byte) (*Config, error)` exists — it does; it starts from `Defaults()` then unmarshals, so an omitted `resources` block keeps the zero default.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/config/ -run TestResourcesConfigDefaultsOff -v`
Expected: FAIL — `Resources`/`ResourcesConfig` undefined.

- [ ] **Step 3: Add the nested config block**

In `internal/config/config.go`, add a field to the top-level `Config` struct (near `Observability`):
```go
	Resources                 ResourcesConfig     `yaml:"resources"`
```
Add the type (near `ObservabilityConfig`):
```go
// ResourcesConfig controls the good-neighbour budget (spec §11.5). Off by
// default: max_events_per_sec 0 means unlimited (the node never sheds).
type ResourcesConfig struct {
	MaxEventsPerSec float64 `yaml:"max_events_per_sec"` // processing-rate budget; 0 = off. Only network-contribution work is shed; local protection is never shed.
}
```
`Defaults()` needs no change (zero value = off).

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/config/ -run TestResourcesConfigDefaultsOff -v && go build ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/config/config.go internal/config/config_test.go
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): resources.max_events_per_sec budget (off by default)"
```

---

### Task 3: Observability shed metrics

**Files:**
- Modify: `internal/observability/observer.go`, `internal/observability/prometheus.go`
- Test: `internal/observability/prometheus_test.go` (or `observer_test.go` — match where the existing metric tests live)

**Interfaces:**
- Produces: `func (o *Observer) RecordShed(kind string)`; `func (o *Observer) SetShedMode(on bool)`; `func (o *Observer) SetProcessingRate(r float64)`. All no-op when the Prometheus output is disabled (mirroring the existing `RecordFederated`/`UpdatePeers` guard).

- [ ] **Step 1: Write the failing test**

Add a test near the existing prometheus metric tests. First READ how the existing tests assert a metric (they likely scrape the registry via `promhttp` or `testutil.ToFloat64`); mirror that. Example shape:
```go
func TestShedMetrics(t *testing.T) {
	p, err := newPrometheusOutput(":0", 75) // or however existing tests construct it
	if err != nil {
		t.Fatalf("newPrometheusOutput: %v", err)
	}
	p.recordShed("remote_event")
	p.recordShed("remote_event")
	p.setShedMode(true)
	p.setProcessingRate(42)
	if got := testutil.ToFloat64(p.shed.WithLabelValues("remote_event")); got != 2 {
		t.Errorf("shed counter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(p.shedMode); got != 1 {
		t.Errorf("shed_mode gauge = %v, want 1", got)
	}
	if got := testutil.ToFloat64(p.procRate); got != 42 {
		t.Errorf("processing_rate gauge = %v, want 42", got)
	}
}
```
(Adapt names/constructor to the real `prometheus.go` — the field names below are `shed`/`shedMode`/`procRate`; the unexported output methods are `recordShed`/`setShedMode`/`setProcessingRate`. Import `github.com/prometheus/client_golang/prometheus/testutil` if the existing tests use it.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/observability/ -run TestShedMetrics -v`
Expected: FAIL — fields/methods undefined.

- [ ] **Step 3: Add the metrics**

In `internal/observability/prometheus.go`, add to the `prometheusOutput` struct:
```go
	shed     *prometheus.CounterVec
	shedMode prometheus.Gauge
	procRate prometheus.Gauge
```
Register them in `newPrometheusOutput` alongside the existing metrics (follow the exact registration pattern used there — `prometheus.NewCounterVec`/`NewGauge` + `reg.MustRegister`):
```go
	p.shed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "federloom_shed_total",
		Help: "Network-contribution work skipped due to the processing-rate budget (spec §11.5).",
	}, []string{"kind"})
	p.shedMode = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "federloom_shed_mode",
		Help: "1 while the node is currently shedding, else 0.",
	})
	p.procRate = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "federloom_processing_rate",
		Help: "Current processed events/sec over the last second.",
	})
	reg.MustRegister(p.shed, p.shedMode, p.procRate)
```
Add the unexported output methods on `*prometheusOutput`:
```go
func (p *prometheusOutput) recordShed(kind string)    { p.shed.WithLabelValues(kind).Inc() }
func (p *prometheusOutput) setShedMode(on bool)        { if on { p.shedMode.Set(1) } else { p.shedMode.Set(0) } }
func (p *prometheusOutput) setProcessingRate(r float64) { p.procRate.Set(r) }
```
In `internal/observability/observer.go`, add the public methods mirroring `RecordFederated`'s disabled-guard (it presumably checks `if o.prom != nil`):
```go
// RecordShed counts one shed network-contribution item (kind ∈ remote_event,
// bridge_reemit, federated_query). No-op when observability is disabled.
func (o *Observer) RecordShed(kind string) {
	if o.prom != nil {
		o.prom.recordShed(kind)
	}
}

// SetShedMode reflects whether the node is currently shedding.
func (o *Observer) SetShedMode(on bool) {
	if o.prom != nil {
		o.prom.setShedMode(on)
	}
}

// SetProcessingRate reports the governor's current events/sec.
func (o *Observer) SetProcessingRate(r float64) {
	if o.prom != nil {
		o.prom.setProcessingRate(r)
	}
}
```
(Confirm the Observer's Prometheus field name — it may be `o.prom` or similar; match the file. If the field is unexported and guarded differently, follow the existing `RecordFederated` pattern exactly.)

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/observability/ -race -v 2>&1 | tail -20 && go build ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/observability/observer.go internal/observability/prometheus.go internal/observability/prometheus_test.go
git add internal/observability/
git commit -m "feat(observability): shed_total / shed_mode / processing_rate metrics"
```

---

### Task 4: Node wiring — charge + shed gates + resolver injection

**Files:**
- Modify: `internal/node/node.go`, `internal/repquery/resolver.go`
- Test: `internal/node/node_test.go`

**Interfaces:**
- Consumes: `resources.NewGovernor` (Task 1), `cfg.Resources.MaxEventsPerSec` (Task 2), `n.obs.RecordShed/SetShedMode/SetProcessingRate` (Task 3).
- Produces: `Node.gov *resources.Governor`; `Node.SheddingForTest() bool` (public test seam for the external adversarial package, Task 5); `repquery.NewResolver(local, q, onFederated, shed func() bool)` (adds a trailing shed predicate; nil = never shed) + `(*Resolver).SetShed(func() bool)`.

**Note on test access:** `internal/node/node_test.go` and `internal/repquery/resolver_test.go` are `package node` / `package repquery` (internal test files that construct structs directly), so they read/write unexported fields (`n.gov`, `n.rep`, `n.processLocal`, `&Querier{}`) with no seam. Only the external `package adversarial` (Task 5) needs the exported `SheddingForTest` seam.

- [ ] **Step 1: Write the two failing tests**

Add to `internal/node/node_test.go` (package `node`, so it drives the governor and local path directly):
```go
// TestLoadSheddingPreservesLocalProtection: a remote flood drives the governor
// into shed mode; a LOCAL observation still scores — the §11.5 priority
// invariant that local protection is never shed.
func TestLoadSheddingPreservesLocalProtection(t *testing.T) {
	n, _ := testNode(t)
	n.gov = resources.NewGovernor(5) // 5 events/sec budget (package-internal field)

	// Flood remote events to push the governor over budget.
	for i := 0; i < 30; i++ {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: "198.51.100." + strconv.Itoa(i+1), Reason: "ssh-probe", ReporterID: "r", SubnetID: "s", Timestamp: time.Now()},
			From:  "r",
		})
	}
	if !n.gov.Shed() {
		t.Fatalf("30 remote events over a 5/s budget must put the governor in shed mode; rate=%v", n.gov.Rate())
	}

	// A LOCAL observation must STILL be recorded while shedding (never shed).
	n.processLocal(context.Background(), proto.Event{IP: "203.0.113.151", Reason: "ssh-probe"})
	rec, err := n.rep.GetRecord("203.0.113.151")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.LastSeen.IsZero() {
		t.Error("local protection was starved during shedding — local ingest must never be shed")
	}
}
```
Add to `internal/repquery/resolver_test.go` (package `repquery`), proving the federated path is skipped under shed:
```go
// TestResolverShedsFederatedQuery: when shed() is true the resolver returns the
// local-only (empty) record and does NOT fan out a federated query. A non-nil
// zero-value *Querier is passed so the federated branch is entered; the shed
// guard must short-circuit before r.q.Query is ever reached.
func TestResolverShedsFederatedQuery(t *testing.T) {
	r := NewResolver(fixedStore{}, &Querier{}, nil, func() bool { return true }) // local miss, federation "on", always shed
	rec, err := r.GetScore("203.0.113.9")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if !rec.LastSeen.IsZero() {
		t.Errorf("shedding must return the local-only (empty) record, got %+v", rec)
	}
}
```
(`fixedStore` already exists in `resolver_test.go` and yields a zero — i.e. local-miss — record. Non-vacuous: without the shed guard, `GetScore` would call `(&Querier{}).Query` on a zero-value querier and fail rather than return the empty record.)

Imports: `node_test.go` gains `strconv` and `github.com/JoeRu/federloom/internal/resources`; `context`, `time`, `transport`, `proto` are already imported.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/node/ -run TestLoadSheddingPreservesLocalProtection -v; go test ./internal/repquery/ -run TestResolverShedsFederatedQuery -v`
Expected: FAIL — `n.gov`/`resources` undefined; `NewResolver` takes 3 args not 4.

- [ ] **Step 3: Wire the governor + shed gates**

In `internal/node/node.go`:
- Add field to `Node`: `gov *resources.Governor` (import `github.com/JoeRu/federloom/internal/resources`).
- In `New`, build it before the `&Node{...}` literal and set the field: `gov := resources.NewGovernor(cfg.Resources.MaxEventsPerSec)` … `gov: gov,`.
- In `processLocal`, near the top (before scoring): `n.gov.Charge()` — local work counts toward the budget but is never gated.
- In `ProcessRemote`, right after the empty-publisher check (`if re.From == "" { … }`), add:
  ```go
  	n.gov.Charge()
  	if n.gov.Shed() {
  		n.obs.RecordShed("remote_event")
  		return // shed: drop this remote event (report or vote) — protect locally instead
  	}
  ```
  (This sheds BOTH remote reports and votes uniformly, before the expensive verify/scoring, and before the Kind-vote branch.)
- In `reemitIfBridge`, at the top: `if n.gov.Shed() { n.obs.RecordShed("bridge_reemit"); return }`.
- Where the resolver is built (`resolver = repquery.NewResolver(s, q, nil)` at node.go:180), pass a trailing `nil` shed for now: `resolver = repquery.NewResolver(s, q, nil, nil)`. `n` does not exist yet here, so wire the real shed predicate AFTER the `&Node{…}` literal (mirroring how the materialiser is wired via a setter). Immediately after `n` is built, add:
  ```go
  	if resolver != nil {
  		resolver.SetShed(func() bool {
  			if n.gov.Shed() {
  				n.obs.RecordShed("federated_query")
  				return true
  			}
  			return false
  		})
  	}
  ```
- In the 30s ticker loop (the one calling `n.obs.UpdatePeers` at node.go:280), add alongside it:
  ```go
  	n.obs.SetProcessingRate(n.gov.Rate())
  	n.obs.SetShedMode(n.gov.Shed())
  ```
- Add ONE exported test seam near the other `*Node` `…ForTest` helpers (e.g. after `SinkForTest`), used by the external adversarial package in Task 5:
  ```go
  // SheddingForTest reports the governor's current shed state. Test-only.
  func (n *Node) SheddingForTest() bool { return n.gov.Shed() }
  ```
  (`processLocal` requires no transport — with `t == nil` the sign/publish block is guarded by `n.identityKey != nil` / `n.transport != nil`, so it records and returns. No local-ingest seam is needed: `node_test.go` is package `node` and calls `n.processLocal` directly; the adversarial package drives its budget via `cfg.Resources.MaxEventsPerSec` and reads state via `SheddingForTest` + `n.GetScore`.)

In `internal/repquery/resolver.go`: add a `shed func() bool` field to `Resolver`; extend `NewResolver(local Store, q *Querier, onFederated func(ip string, rec store.ScoreRecord, subnets int), shed func() bool)` (set `shed: shed` in the literal); add `func (r *Resolver) SetShed(fn func() bool) { r.shed = fn }` (mirroring the existing `SetMaterialiser`); and in `GetScore`'s federated branch, immediately before `r.q.Query(...)`:
```go
	if r.shed != nil && r.shed() {
		return rec, nil // over budget → local-only answer (same as the E3 timeout fallback)
	}
```
Update all `NewResolver(...)` call sites to pass a trailing `nil` shed: `internal/node/node.go:180`, `internal/repquery/resolver_test.go` (4 calls: lines ~17, 25, 40, 59), `test/integration/repquery_test.go:43`. (Confirmed call-site list — `materialise_test.go` does NOT call `NewResolver`; grep `NewResolver(` before editing to be sure.)

- [ ] **Step 4: Run node + repquery + integration**

Run: `go build ./... && go test ./internal/node/ ./internal/repquery/ -race 2>&1 | tail -20 && go test -tags integration ./test/integration/ -run 'Repquery|Materialise|NodeWiring|Federat' -v 2>&1 | tail -15`
Expected: PASS — both new tests; existing node/repquery/integration tests still pass (default budget 0 ⇒ no shedding, unchanged behaviour).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/node/node.go internal/repquery/resolver.go internal/node/node_test.go internal/repquery/resolver_test.go test/integration/repquery_test.go
git add internal/node/node.go internal/repquery/resolver.go internal/node/node_test.go internal/repquery/resolver_test.go test/integration/repquery_test.go
git commit -m "feat(node): load-shedding gates for remote scoring, bridge re-emit, federated query (local never shed)"
```

---

### Task 5: Adversarial + docs + full gate

**Files:**
- Create: `test/adversarial/load_shedding_test.go`
- Modify: `docs/config.md`, `docs/spec.md` (§12a), `docs/roadmap.md`, `docs/architecture.md`, `docs/threat-model.md`

**Interfaces:**
- Consumes: `config.Defaults()`, `config.Config.Resources.MaxEventsPerSec`, `node.New`, `Node.SetSinkForTest`, `Node.SheddingForTest`, `Node.ProcessRemote`, `Node.GetScore`; the package-local `mockSink` (from `poisoning_test.go`, fields `blocked`/`unblocked`).

- [ ] **Step 1: Write the adversarial test**

Create `test/adversarial/load_shedding_test.go` (`//go:build adversarial`, `package adversarial`). Prove: a gossip flood pushes the node into shed mode yet NEVER produces a wrong block — induced shedding is a mild availability nudge on network contribution, not an integrity attack (spec §11.5 / design §9). Build the node with the public config path (mirroring `disputes_test.go`'s `config.Defaults()` + `node.New(cfg, nil)` + `SetSinkForTest`):
```go
//go:build adversarial

package adversarial

import (
	"strconv"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

// TestGossipFloodShedsButNeverMisenforces: a stranger gossip flood pushes the
// victim into shed mode (SheddingForTest true) but pushes no block — shedding
// only ever reduces network participation, never enforcement (spec §11.5).
func TestGossipFloodShedsButNeverMisenforces(t *testing.T) {
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.Resources.MaxEventsPerSec = 5 // tiny budget so the flood trips shedding
	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.CloseStores()
	sink := &mockSink{}
	n.SetSinkForTest(sink)

	for i := 0; i < 200; i++ {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: "203.0.113." + strconv.Itoa(i%254+1), Reason: "ssh-auth-bruteforce", ReporterID: "flooder", SubnetID: "s", Timestamp: time.Now()},
			From:  "flooder",
		})
	}
	// The flood tripped shed mode...
	if !n.SheddingForTest() {
		t.Fatalf("a 200-event flood over a 5/s budget must trip shed mode")
	}
	// ...but shed mode never fabricates a block (strangers cannot block, and
	// shedding only drops network work — it never enforces).
	if len(sink.blocked) > 0 {
		t.Errorf("gossip flood must never push a block, got %v", sink.blocked)
	}
}
```
(`mockSink` and `var _ enforce.Sink = (*mockSink)(nil)` already live in `poisoning_test.go` in the same package — do not redefine them. `n.SheddingForTest()` is the Task 4 seam; if the governor never engaged, this fails, so the test is non-vacuous.)

- [ ] **Step 2: Run it + the whole adversarial suite**

Run: `go test -tags adversarial ./test/adversarial/ -run TestGossipFloodSheds -v && go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3`
Expected: PASS.

- [ ] **Step 3: Docs — config.md**

Add to `docs/config.md`:
```markdown
### `resources.max_events_per_sec`

Good-neighbour load shedding (spec §11.5). When set to a positive value, the
node caps its total processing rate at this many events/sec; above the budget it
**sheds network-contribution work** — remote gossip scoring, bridge
re-emission, and on-demand federated queries — while **local protection (your
own ingest → score → enforce) always runs**. Shedding only ever *reduces*
network participation; it never blocks, never bypasses a whitelist/never-block,
and never mutates enforcement. Default `0` = **off** (no shedding). This
complements OS-level limits (`nice`/cgroups/systemd), which stay a deployment
concern. Metrics: `federloom_shed_total{kind}`, `federloom_shed_mode`,
`federloom_processing_rate`.
```

- [ ] **Step 4: Docs — spec §12a + roadmap + architecture + threat-model**

- `docs/spec.md` §12a: §11.5 good-neighbor / load-shedding → DONE (A7 — processing-rate budget, local never shed); note A6 (bloom-dist/DHT/batch) remains PLANNED.
- `docs/roadmap.md`: mark A7 resolved (`✅ resolved — load shedding 2026-07-17`); annotate Step 7 as partially done (A7 shipped; A6 deferred pending telemetry). Also add the flagged follow-up: "document `resources.max_events_per_sec` in `deploy/examples/*.yaml` (TODO)".
- `docs/architecture.md`: one line — a processing-rate governor sheds network-contribution work under load; local protection is never shed.
- `docs/threat-model.md`: a row — induced shedding (a peer flooding gossip to push a victim into shed mode) only reduces the victim's network contribution; it cannot cause a wrong block or starve local enforcement.

- [ ] **Step 5: Full gate**

Run: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/ && go test ./... 2>&1 | tail -5 && go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3 && go test -tags integration ./test/integration/... 2>&1 | tail -3`
Expected: build/vet clean, `gofmt -l` empty, all suites PASS. (Known integration timing flakes `TestStarTopologyGossipSymmetric` / `TestNodeWiringFederatesBothReadSurfaces` under `-race` first run — rerun the integration suite once if only those fire.)

- [ ] **Step 6: Commit**

```bash
gofmt -w test/adversarial/load_shedding_test.go
git add test/adversarial/load_shedding_test.go docs/config.md docs/spec.md docs/roadmap.md docs/architecture.md docs/threat-model.md
git commit -m "test+docs: adversarial gossip-flood shed test; §11.5 traceability, config, roadmap A7 done"
```
