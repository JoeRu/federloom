# Materialise-on-Verdict (Roadmap Step 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On a block-worthy, diversity-gated federated verdict for an IP that contacted a protected service, push a TTL-bounded O(1) block into the enforce sink — completing E3's "pull discovers, push enforces".

**Architecture:** The enforce `Sink` gains a timed `BlockFor(ip, ttl)`; the querier surfaces the merged evidence's `subnets` count; the read-only resolver invokes an enforcement-agnostic callback on a federated hit; the node owns the gate (enabled ∧ score≥threshold ∧ subnets≥floor ∧ ¬never-block ∧ ¬whitelist) and the `BlockFor` write. Off by default.

**Tech Stack:** Go 1.22, ipset/nftables/CrowdSec sinks, libp2p federated query, BadgerDB.

## Global Constraints

- Go module `github.com/JoeRu/federloom`, Go 1.22. Conventional Commits.
- **Opt-in, default OFF:** `federation_materialize` default false ⇒ behaviour byte-for-byte Steps 1–3.
- **Federated gate:** materialise iff enabled ∧ recomputed score ≥ `federation_block_threshold` (default 80) ∧ evidence `subnets` ≥ `federation_block_min_subnets` (default 3) ∧ IP not never-block ∧ not whitelisted. never-block/whitelist checked FIRST (always win).
- **TTL-bounded:** federated blocks use `BlockFor(ip, federation_block_ttl)` (default 1h) and self-expire. Local blocks keep using `Block(ip)` (permanent) — byte-for-byte unchanged.
- **Read-only resolver preserved:** `repquery` never writes the store or firewall; it invokes a callback. The `BlockFor` write lives only in `internal/node` / `internal/enforce`.
- **Local block path + anchored backstop UNCHANGED.** This is a parallel federated-only gate.
- **`internal/enforce` is security-critical (CLAUDE.md invariant 7):** `Block` unchanged; `BlockFor` + the ipset `timeout 0` set-creation get conservative review; the set-creation change must be a no-op for permanent entries.
- Full gate at end: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/` (empty) + unit + `-race` + `-tags adversarial` + `-tags integration`.

---

### Task 1: Config — materialise knobs

**Files:**
- Modify: `internal/config/config.go` (top-level `Config`, `Defaults()`, accessor)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `Config.FederationMaterialize bool` (yaml `federation_materialize`), `Config.FederationBlockThreshold float64` (yaml `federation_block_threshold`), `Config.FederationBlockMinSubnets int` (yaml `federation_block_min_subnets`), `Config.FederationBlockTTL Duration` (yaml `federation_block_ttl`); `func (c *Config) EffectiveFederationBlockTTL() time.Duration` (default 1h when `<= 0`).

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestFederationMaterializeDefaults(t *testing.T) {
	d := config.Defaults()
	if d.FederationMaterialize {
		t.Error("FederationMaterialize must default OFF")
	}
	if d.FederationBlockThreshold != 80 {
		t.Errorf("FederationBlockThreshold default = %v, want 80", d.FederationBlockThreshold)
	}
	if d.FederationBlockMinSubnets != 3 {
		t.Errorf("FederationBlockMinSubnets default = %v, want 3", d.FederationBlockMinSubnets)
	}
	if got := config.Defaults().EffectiveFederationBlockTTL(); got != time.Hour {
		t.Errorf("EffectiveFederationBlockTTL default = %v, want 1h", got)
	}
	// Unset (<=0) TTL → default 1h.
	if got := (&config.Config{}).EffectiveFederationBlockTTL(); got != time.Hour {
		t.Errorf("unset TTL = %v, want 1h", got)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/config/ -run TestFederationMaterializeDefaults -v`
Expected: FAIL — fields/method undefined.

- [ ] **Step 3: Add fields, defaults, accessor**

In the top-level `Config` struct (near the other `Federation*` fields, ~line 55):
```go
	FederationMaterialize    bool     `yaml:"federation_materialize"`      // push block-worthy federated verdicts into the firewall (default OFF)
	FederationBlockThreshold float64  `yaml:"federation_block_threshold"`  // recomputed-score floor to materialise (default 80)
	FederationBlockMinSubnets int     `yaml:"federation_block_min_subnets"`// evidence subnet-diversity floor to materialise (default 3)
	FederationBlockTTL       Duration `yaml:"federation_block_ttl"`        // TTL of a materialised federated block (default 1h)
```

In `Defaults()` (top-level, alongside `FederationMode: "solo"`):
```go
		FederationBlockThreshold:  80,
		FederationBlockMinSubnets: 3,
```
(`FederationMaterialize` false and `FederationBlockTTL` zero are the desired zero-value defaults; the TTL default is applied by the accessor.)

Add the accessor (near `EffectiveQueryCacheTTL`):
```go
// EffectiveFederationBlockTTL returns the TTL for a materialised federated
// block, defaulting to 1h when unset.
func (c *Config) EffectiveFederationBlockTTL() time.Duration {
	if c.FederationBlockTTL.Duration <= 0 {
		return time.Hour
	}
	return c.FederationBlockTTL.Duration
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/config/ -run TestFederationMaterializeDefaults -v && go build ./...`
Expected: PASS; build clean.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/config/config.go internal/config/config_test.go
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add federation materialise knobs (off by default, threshold/subnets/ttl)"
```

---

### Task 2: `Sink.BlockFor` — timed blocks across all backends (security-critical)

**Files:**
- Modify: `internal/enforce/plugin.go` (interface), `internal/enforce/ipset.go`, `internal/enforce/nftables.go`, `internal/enforce/crowdsec.go`
- Modify (test mock): `test/adversarial/poisoning_test.go` (`mockSink`)
- Test: `internal/enforce/ipset_test.go` (create if absent, else append)

**Interfaces:**
- Produces: `Sink.BlockFor(ip string, ttl time.Duration) error` on all three backends; `mockSink.BlockFor` records `(ip, ttl)`.

- [ ] **Step 1: Write the failing test**

Create/append `internal/enforce/ipset_test.go` (match the package clause of existing enforce tests — `package enforce`):

```go
func TestIpsetBlockForIssuesTimeout(t *testing.T) {
	var calls [][]string
	s := NewIpset("testset", []string{"INPUT"})
	s.run = func(ctx context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	if err := s.BlockFor("203.0.113.9", 90*time.Second); err != nil {
		t.Fatalf("BlockFor: %v", err)
	}
	// Expect: ipset add testset 203.0.113.9 timeout 90 -exist
	last := calls[len(calls)-1]
	joined := strings.Join(last, " ")
	if !strings.Contains(joined, "add testset 203.0.113.9") || !strings.Contains(joined, "timeout 90") {
		t.Errorf("BlockFor args = %v, want add with 'timeout 90'", last)
	}
}

func TestIpsetStartCreatesWithTimeoutCapability(t *testing.T) {
	var calls [][]string
	s := NewIpset("testset", []string{"INPUT"})
	s.run = func(ctx context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	_ = s.Start(context.Background())
	// The v4 create must include "timeout 0" so per-entry timeouts are allowed.
	found := false
	for _, c := range calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, "create testset hash:ip") && strings.Contains(j, "timeout 0") {
			found = true
		}
	}
	if !found {
		t.Errorf("Start did not create the v4 set with 'timeout 0'; calls=%v", calls)
	}
}
```

Ensure imports: `context`, `strings`, `testing`, `time`. (Confirm `NewIpset`'s exact signature and that `run` is an assignable field — it is; existing enforce tests assign `s.run`.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/enforce/ -run 'TestIpsetBlockFor|TestIpsetStartCreates' -v`
Expected: FAIL — `BlockFor` undefined; Start lacks `timeout 0`.

- [ ] **Step 3: Extend the interface**

In `internal/enforce/plugin.go`, add to `Sink` (after `Block`):
```go
	// BlockFor adds ip to the deny set with a TTL after which the backend
	// auto-removes it. Used for provisional (federated) blocks. ttl<=0 behaves
	// like Block (permanent).
	BlockFor(ip string, ttl time.Duration) error
```
Add `"time"` to the imports if not present.

- [ ] **Step 4: ipset — `timeout 0` set-creation + `BlockFor`**

In `internal/enforce/ipset.go` `Start`, add `"timeout", "0"` to BOTH `ipset create` commands (v4 `hash:ip` and v6 `hash:net`), before the trailing `"-exist"`:
```go
	if err := s.run(ctx, "ipset", "create", s.setName, "hash:ip", "family", "inet", "timeout", "0", "-exist"); err != nil {
```
and the same `"timeout", "0"` insertion for the two `set6` `hash:net` creates. (`timeout 0` = per-entry timeouts allowed, default no expiry — `Block` entries stay permanent.)

Add `BlockFor` (mirrors `Block`, with a per-entry timeout; `ttl<=0` falls back to `Block`):
```go
// BlockFor adds ip with a TTL (seconds) after which ipset auto-removes it.
func (s *IpsetSink) BlockFor(ip string, ttl time.Duration) error {
	if ttl <= 0 {
		return s.Block(ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	set := s.ipSet(ip)
	secs := strconv.Itoa(int(ttl.Seconds()))
	if err := s.run(ctx, "ipset", "add", set, ip, "timeout", secs, "-exist"); err != nil {
		return fmt.Errorf("enforce/ipset: blockFor %s: %w", ip, err)
	}
	return nil
}
```
Add `"strconv"` to the imports.

- [ ] **Step 5: nftables — timeout-capable sets + `BlockFor`**

In `internal/enforce/nftables.go` `Start`, change the two `add set` declarations to include a `timeout` flag so elements may carry timeouts (permanent elements still allowed):
```go
		{"nft", "add", "set", "inet", nftTable, s.setName, "{ type ipv4_addr; flags interval, timeout; }"},
		{"nft", "add", "set", "inet", nftTable, s.set6(), "{ type ipv6_addr; flags interval, timeout; }"},
```
Add `BlockFor`:
```go
// BlockFor adds ip with a TTL after which nftables auto-removes the element.
func (s *NftablesSink) BlockFor(ip string, ttl time.Duration) error {
	if ttl <= 0 {
		return s.Block(ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dur := fmt.Sprintf("%ds", int(ttl.Seconds()))
	if err := s.run(ctx, "nft", "add", "element", "inet", nftTable, s.nftSet(ip), "{", ip, "timeout", dur, "}"); err != nil {
		return fmt.Errorf("enforce/nftables: blockFor %s: %w", ip, err)
	}
	return nil
}
```

- [ ] **Step 6: CrowdSec — `BlockFor` with a custom decision duration**

In `internal/enforce/crowdsec.go`, `Block` builds an alert with a single decision whose `Duration: s.banDur.String()`. Refactor so the alert-posting body is shared, parameterised by duration. Extract the existing `Block` body into `func (s *CrowdSecSink) blockWithDuration(ip string, dur time.Duration) error` (identical to today's `Block` but using `dur.String()` in the decision's `Duration`), then:
```go
func (s *CrowdSecSink) Block(ip string) error {
	return s.blockWithDuration(ip, s.banDur)
}

// BlockFor submits a CrowdSec decision with an explicit duration (ttl).
func (s *CrowdSecSink) BlockFor(ip string, ttl time.Duration) error {
	if ttl <= 0 {
		return s.Block(ip)
	}
	return s.blockWithDuration(ip, ttl)
}
```
(Move the whole existing `Block` implementation into `blockWithDuration`, replacing the hardcoded `s.banDur.String()` with `dur.String()`. Do not change any other field of the alert.)

- [ ] **Step 7: Update the test mock**

In `test/adversarial/poisoning_test.go`, `mockSink` currently has `Block`/`Unblock`. Add a TTL-recording field and `BlockFor`:
```go
type blockForCall struct {
	IP  string
	TTL time.Duration
}
```
Add to the `mockSink` struct a field `blockedFor []blockForCall`, and the method:
```go
func (m *mockSink) BlockFor(ip string, ttl time.Duration) error {
	m.blockedFor = append(m.blockedFor, blockForCall{ip, ttl})
	return nil
}
```
Add `"time"` to that file's imports if missing. (Any other test-only `Sink` implementations that now fail to compile must get the same `BlockFor` — grep `func (.*) Block(ip string) error` under `test/` and `internal/` test files and add `BlockFor` to each.)

- [ ] **Step 8: Run enforce + build**

Run: `go build ./... && go vet ./internal/enforce/... && go test ./internal/enforce/ -race -v 2>&1 | tail -20`
Expected: PASS — the two new ipset tests plus all pre-existing enforce tests (Block unchanged).

- [ ] **Step 9: Commit**

```bash
gofmt -w internal/enforce/plugin.go internal/enforce/ipset.go internal/enforce/nftables.go internal/enforce/crowdsec.go internal/enforce/ipset_test.go test/adversarial/poisoning_test.go
git add internal/enforce test/adversarial/poisoning_test.go
git commit -m "feat(enforce): Sink.BlockFor timed blocks (ipset/nftables/crowdsec); ipset sets gain timeout capability"
```

---

### Task 3: Read path surfaces subnets + resolver materialise callback

**Files:**
- Modify: `internal/repquery/querier.go`, `internal/repquery/resolver.go`
- Test: `internal/repquery/querier_test.go`, `internal/repquery/resolver_test.go`

**Interfaces:**
- Produces: `Querier.Query(ctx, ip) (store.ScoreRecord, int, bool)` (adds the merged answer's `subnets` count); `NewResolver(local Store, q *Querier, onFederated func(ip string, rec store.ScoreRecord, subnets int)) *Resolver` (callback may be nil = no materialise). The resolver stays read-only: it invokes `onFederated` on a federated hit and does NOT write anything itself.

- [ ] **Step 1: Write the failing tests**

Add to `internal/repquery/resolver_test.go`:

```go
func TestResolverInvokesMaterialiseCallbackOnFederatedHit(t *testing.T) {
	var gotIP string
	var gotSubnets int
	called := 0
	q := &Querier{} // not used — we force the federated path via a stub below
	_ = q
	// Use a resolver whose local store misses and whose querier returns a federated hit.
	local := fixedStore{} // empty (miss)
	r := NewResolver(local, nil, func(ip string, rec store.ScoreRecord, subnets int) {
		called++
		gotIP = ip
		gotSubnets = subnets
	})
	// With q == nil the federated path is skipped, so the callback must NOT fire.
	if _, err := r.GetScore("1.2.3.4"); err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if called != 0 {
		t.Errorf("callback fired with no querier; called=%d", called)
	}
	_ = gotIP
	_ = gotSubnets
}

func TestResolverLocalHitDoesNotMaterialise(t *testing.T) {
	local := fixedStore{rec: store.ScoreRecord{Score: 90, LastSeen: time.Now()}}
	called := 0
	r := NewResolver(local, nil, func(string, store.ScoreRecord, int) { called++ })
	if _, err := r.GetScore("1.2.3.4"); err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if called != 0 {
		t.Errorf("local hit must not materialise; called=%d", called)
	}
}
```

(The federated-hit callback firing is covered end-to-end by Task 4's integration test, which has a real querier returning a federated record + subnets. `fixedStore` is the existing resolver-test stub; confirm its field name is `rec`.)

Add to `internal/repquery/querier_test.go` — update the existing `q.Query(...)` call sites to the 3-return form and assert the subnets value where a known aggregate is served. For `TestQuerierFetchesAndCaches` (aggregator record has `Groups`/subnets), change `e, ok := q.Query(ctx, "9.9.9.9")` to `e, subnets, ok := q.Query(ctx, "9.9.9.9")` and add `if subnets < 0 { t.Fatalf(...) }` (the exact count depends on the fake store's `SubnetsSeen`; assert `subnets == len(fakeStore.SubnetsSeen)` if the fake sets it, else `>= 0`). Every other `q.Query(...)` call in this file gets the middle `_` return.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/repquery/ -run 'TestResolver|TestQuerier' -v`
Expected: FAIL — `NewResolver` takes 2 args; `Query` returns 2 values.

- [ ] **Step 3: Surface subnets from the querier**

In `internal/repquery/querier.go`:
- `cacheEntry` gains `subnets int`.
- `Query` returns `(store.ScoreRecord, int, bool)`; the cache read returns `c.entry, c.subnets, c.ok`; the singleflight result struct carries subnets; the cache write stores it.
- `fanout` returns `(store.ScoreRecord, int, bool)`: while collecting, track the `subnets` of the aggregate that produced the current `best` record. Concretely, `ask` returns `(proto.EvidenceAggregate, bool)`; when a recomputed record becomes the new `best`, capture `bestSubnets = r.ev.DiversityBuckets["subnets"]`. Return `best, bestSubnets, found`.

Skeleton for the collect loop:
```go
	var best store.ScoreRecord
	bestSubnets := 0
	found := false
	reasons := map[string]bool{}
collect:
	for i := 0; i < len(q.aggregators); i++ {
		select {
		case r := <-ch:
			if !r.ok {
				continue
			}
			rec := RecordFromEvidence(r.ev, time.Now(), q.halfLife, q.strangerCap, q.federationDiscount, q.diversityRepeat)
			if rec.LastSeen.IsZero() {
				continue
			}
			for _, rs := range rec.Reasons {
				reasons[rs] = true
			}
			if !found || rec.Score > best.Score {
				best = rec
				bestSubnets = r.ev.DiversityBuckets["subnets"]
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
	return best, bestSubnets, found
```

- [ ] **Step 4: Resolver callback**

In `internal/repquery/resolver.go`:
```go
type Resolver struct {
	local       Store
	q           *Querier
	onFederated func(ip string, rec store.ScoreRecord, subnets int) // nil = no materialise
}

// NewResolver wraps a local store; q may be nil (federation off); onFederated
// may be nil (no materialise). onFederated is invoked on a FEDERATED hit only
// — the resolver never writes; the callback owner (the node) decides enforcement.
func NewResolver(local Store, q *Querier, onFederated func(ip string, rec store.ScoreRecord, subnets int)) *Resolver {
	return &Resolver{local: local, q: q, onFederated: onFederated}
}

func (r *Resolver) GetScore(ip string) (store.ScoreRecord, error) {
	rec, err := r.local.GetScore(ip)
	if err != nil {
		return rec, err
	}
	if !rec.LastSeen.IsZero() || r.q == nil {
		return rec, nil // local hit, or federation disabled
	}
	if rec2, subnets, ok := r.q.Query(context.Background(), ip); ok {
		if r.onFederated != nil {
			r.onFederated(ip, rec2, subnets)
		}
		return rec2, nil
	}
	return rec, nil // federated miss → the (empty) local record
}
```

- [ ] **Step 5: Run repquery under -race**

Run: `go build ./... && go test ./internal/repquery/... -race -v 2>&1 | tail -30`
Expected: PASS (resolver + querier tests, retyped).

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/repquery/querier.go internal/repquery/resolver.go internal/repquery/querier_test.go internal/repquery/resolver_test.go
git add internal/repquery/querier.go internal/repquery/resolver.go internal/repquery/querier_test.go internal/repquery/resolver_test.go
git commit -m "feat(repquery): surface evidence subnets + resolver materialise callback (read-only)"
```

---

### Task 4: Node materialiser gate + wiring + integration test

**Files:**
- Modify: `internal/node/node.go`
- Test: `test/integration/materialise_test.go` (new)

**Interfaces:**
- Consumes: `Sink.BlockFor` (Task 2); `repquery.NewResolver(local, q, onFederated)` (Task 3); config knobs (Task 1); `n.neverblock.Contains`, `n.whitelist.Contains`, `n.sink`, `n.obs`.
- Produces: `func (n *Node) materialiseFederated(ip string, rec store.ScoreRecord, subnets int)`.

- [ ] **Step 1: Write the failing integration test**

Create `test/integration/materialise_test.go` (`package integration_test`). Build node A with materialise enabled + a mock sink, and an aggregator host B serving a diverse, block-worthy IP; drive A's federated read path (via the API point reader) and assert `BlockFor` was called; then assert a whitelisted IP and a low-diversity verdict are NOT materialised.

```go
package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/repquery"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/internal/transport"
)

// recSink records BlockFor calls (ip, ttl).
type recSink struct{ blockedFor []struct{ IP string; TTL time.Duration } }

func (r *recSink) Name() string                                   { return "rec" }
func (r *recSink) Start(context.Context) error                    { return nil }
func (r *recSink) Block(string) error                             { return nil }
func (r *recSink) BlockFor(ip string, ttl time.Duration) error    { r.blockedFor = append(r.blockedFor, struct{ IP string; TTL time.Duration }{ip, ttl}); return nil }
func (r *recSink) Unblock(string) error                           { return nil }
func (r *recSink) Close() error                                   { return nil }

func TestMaterialiseFederatedVerdict(t *testing.T) {
	ctx := context.Background()

	// Aggregator B: a diverse, block-worthy IP (high groups + many subnets).
	bHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("bHost: %v", err)
	}
	defer bHost.Close()
	blockworthy := store.ScoreRecord{
		Score: 90, LastSeen: time.Now(),
		Reasons:     []string{"ssh-auth-success"},
		Groups:      []string{"g1", "g2", "g3", "g4"},
		SubnetsSeen: []string{"s1", "s2", "s3", "s4"}, // 4 subnets ≥ floor 3
	}
	// storeStub serves 'blockworthy' for the target IP, empty otherwise.
	repquery.RegisterResponder(bHost, matStoreStub{ip: "203.0.113.90", rec: blockworthy}, allowAllAuth{})

	// Node A: materialise enabled, B configured as aggregator, mock sink.
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationMaterialize = true
	cfg.FederationAggregators = []string{aggMultiaddr(t, bHost)}
	trA := newMatTransport(t, ctx)
	n, err := node.New(cfg, trA)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.CloseStores()
	sink := &recSink{}
	n.SetSinkForTest(sink)

	// Drive A's federated read path for the IP (point lookup routes through the resolver).
	if _, err := n.ScoreViaPointReaderForTest("203.0.113.90"); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	// Allow the materialise call to complete (synchronous today, but be tolerant).
	if len(sink.blockedFor) != 1 || sink.blockedFor[0].IP != "203.0.113.90" {
		t.Fatalf("expected a materialised block for 203.0.113.90, got %+v", sink.blockedFor)
	}
	if sink.blockedFor[0].TTL != cfg.EffectiveFederationBlockTTL() {
		t.Errorf("materialised TTL = %v, want %v", sink.blockedFor[0].TTL, cfg.EffectiveFederationBlockTTL())
	}
}
```

The test needs three small local helpers in the same file (`matStoreStub` with `GetScore`, `allowAllAuth` — the same fakes used by `repquery_test.go`; if they are unexported in another `integration_test` file they are reusable here since it is the same package — otherwise define local copies), `aggMultiaddr(t, host)` returning `host.Addrs()[0]+"/p2p/"+host.ID()`, `newMatTransport(t, ctx)` (a `transport.New(ctx, transport.Options{ListenAddrs: [...loopback...]})`, mirroring the existing bridge/repquery integration setup), and — **new production seam** — `Node.ScoreViaPointReaderForTest(ip)` that routes through the API point reader (add it as a test helper on `*Node` alongside the existing `SelfID()`/`CloseStores()`/`SetSinkForTest`, calling the same resolver the DNSBL/API use; if `n.api.PointLookupForTest` already exists from Step 1, expose `func (n *Node) ScoreViaPointReaderForTest(ip string) (store.ScoreRecord, error) { return n.api.PointLookupForTest(ip) }`).

- [ ] **Step 2: Run to verify failure**

Run: `go test ./test/integration/ -run TestMaterialiseFederatedVerdict -v`
Expected: FAIL — `materialiseFederated` not wired / `ScoreViaPointReaderForTest` undefined.

- [ ] **Step 3: Add the materialiser method**

In `internal/node/node.go`, add (near the other `*Node` methods):
```go
// materialiseFederated is the callback the resolver invokes on a federated hit.
// It applies the federated block gate (design 2026-07-13 §4) and, on pass,
// pushes a TTL-bounded block. Read of n.sink is deferred so SetSinkForTest works.
func (n *Node) materialiseFederated(ip string, rec store.ScoreRecord, subnets int) {
	if !n.cfg.FederationMaterialize {
		return
	}
	if n.neverblock.Contains(ip) || n.whitelist.Contains(ip) {
		return // never-block / whitelist always win
	}
	if rec.Score < n.cfg.FederationBlockThreshold || subnets < n.cfg.FederationBlockMinSubnets {
		return // not block-worthy or insufficient diversity
	}
	ttl := n.cfg.EffectiveFederationBlockTTL()
	if err := n.sink.BlockFor(ip, ttl); err != nil {
		log.Printf("node: materialise block %s: %v", ip, err)
		return
	}
	log.Printf("node: materialised federated block %s (score=%.1f subnets=%d ttl=%s)", ip, rec.Score, subnets, ttl)
	n.obs.RecordBlock(ip, "federated-materialise", rec.Score, rec.FirstSeen, rec.Corroboration)
}
```

- [ ] **Step 4: Wire the callback into the resolver**

In `internal/node/node.go` `New`, the resolver is currently built as `resolver = repquery.NewResolver(s, q)`. Change to pass `nil` first (the `*Node` does not exist yet), then set the callback after `n` is constructed. Two edits:

Where the resolver is built (inside the aggregator-gated block):
```go
			resolver = repquery.NewResolver(s, q, nil)
```
After `n := &Node{...}` is constructed (near the end of `New`, before `return n, nil`):
```go
	if resolver != nil && cfg.FederationMaterialize {
		resolver.SetMaterialiser(n.materialiseFederated)
	}
```
Add a setter to `internal/repquery/resolver.go`:
```go
// SetMaterialiser installs the federated-hit callback after construction
// (the node needs a fully-built *Node to form the closure). nil-safe.
func (r *Resolver) SetMaterialiser(fn func(ip string, rec store.ScoreRecord, subnets int)) {
	r.onFederated = fn
}
```
(Import `store` in node.go if not already — it is.)

- [ ] **Step 5: Add the point-reader test helper on Node**

In `internal/node/node.go` (test helpers area):
```go
// ScoreViaPointReaderForTest routes an IP through the API point reader (the same
// resolver the DNSBL/API use), so tests can drive the federated read+materialise
// path. Test-only.
func (n *Node) ScoreViaPointReaderForTest(ip string) (store.ScoreRecord, error) {
	return n.api.PointLookupForTest(ip)
}
```
(`api.Server.PointLookupForTest` was added in Step 1 of the repquery-hardening feature — confirm it exists; if not, add a one-line pass-through on `*api.Server` returning `s.pointReader.GetScore(ip)`.)

Also add a direct gate seam for the adversarial task (Task 5), which drives the gate with crafted inputs instead of a full two-host setup:
```go
// MaterialiseForTest drives the federated materialise gate directly with a
// crafted verdict, bypassing the resolver wiring. Test-only.
func (n *Node) MaterialiseForTest(ip string, rec store.ScoreRecord, subnets int) {
	n.materialiseFederated(ip, rec, subnets)
}
```

- [ ] **Step 6: Run the integration + node + full regression**

Run: `go build ./... && go test ./test/integration/ -run TestMaterialiseFederatedVerdict -v && go test ./internal/node/... ./internal/repquery/... -race 2>&1 | tail -20`
Expected: PASS. (The known `TestStarTopologyGossipSymmetric` gossip flake is unrelated — rerun the integration suite once if only it fires.)

- [ ] **Step 7: Commit**

```bash
gofmt -w internal/node/node.go internal/repquery/resolver.go test/integration/materialise_test.go
git add internal/node/node.go internal/repquery/resolver.go test/integration/materialise_test.go
git commit -m "feat(node): materialise diversity-gated federated verdicts as TTL-bounded blocks"
```

---

### Task 5: Adversarial + never-block/whitelist coverage + docs + full gate

**Files:**
- Create: `test/adversarial/materialise_test.go`
- Modify: `docs/config.md`, `docs/spec.md` (§12a), `docs/roadmap.md`, `docs/architecture.md`, `docs/threat-model.md`

**Interfaces:**
- Consumes: `Node.materialiseFederated` path via the integration harness, or a direct unit on the gate.

- [ ] **Step 1: Write the adversarial test**

Create `test/adversarial/materialise_test.go`. It builds one node per case via `node.New(cfg, nil)` (no transport needed — it drives the gate directly through `n.MaterialiseForTest`, the seam from Task 4), injects the package's existing `mockSink` (which gained `BlockFor`/`blockedFor` in Task 2), and asserts each gate condition is load-bearing.

```go
//go:build adversarial

package adversarial

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/store"
)

// matNode builds a materialise-enabled node with a mock sink and optional
// never-block entries. neverBlock IPs go through cfg.Enforce.ExtraWhitelist,
// which n.neverblock.Contains checks (same precedence the gate uses).
func matNode(t *testing.T, neverBlock []string) (*node.Node, *mockSink) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationMaterialize = true // gate enabled
	cfg.Enforce.ExtraWhitelist = neverBlock
	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n.CloseStores() })
	sink := &mockSink{}
	n.SetSinkForTest(sink)
	return n, sink
}

func blockWorthy() store.ScoreRecord {
	return store.ScoreRecord{Score: 90, FirstSeen: time.Now().Add(-time.Hour), LastSeen: time.Now(), Reasons: []string{"ssh-auth-success"}}
}

func TestMaterialiseGateIsLoadBearing(t *testing.T) {
	// Positive control: diverse (4 subnets), high score, not whitelisted → 1 block.
	n, sink := matNode(t, nil)
	n.MaterialiseForTest("203.0.113.90", blockWorthy(), 4)
	if len(sink.blockedFor) != 1 || sink.blockedFor[0].IP != "203.0.113.90" {
		t.Fatalf("block-worthy diverse verdict must materialise; got %+v", sink.blockedFor)
	}

	// (a) Forged: many groups but only 1 subnet (< floor 3) → 0 blocks.
	n2, sink2 := matNode(t, nil)
	n2.MaterialiseForTest("203.0.113.91", blockWorthy(), 1)
	if len(sink2.blockedFor) != 0 {
		t.Errorf("single-subnet verdict must NOT materialise; got %+v", sink2.blockedFor)
	}

	// (b) Whitelisted (never-block) IP, otherwise block-worthy → 0 blocks.
	n3, sink3 := matNode(t, []string{"203.0.113.92"})
	n3.MaterialiseForTest("203.0.113.92", blockWorthy(), 4)
	if len(sink3.blockedFor) != 0 {
		t.Errorf("never-block IP must NOT materialise; got %+v", sink3.blockedFor)
	}

	// (c) Below-threshold score (< 80), diverse → 0 blocks.
	n4, sink4 := matNode(t, nil)
	low := blockWorthy()
	low.Score = 50
	n4.MaterialiseForTest("203.0.113.93", low, 4)
	if len(sink4.blockedFor) != 0 {
		t.Errorf("below-threshold verdict must NOT materialise; got %+v", sink4.blockedFor)
	}

	// (d) Disabled feature → 0 blocks even when block-worthy.
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationMaterialize = false
	n5, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n5.CloseStores() })
	sink5 := &mockSink{}
	n5.SetSinkForTest(sink5)
	n5.MaterialiseForTest("203.0.113.94", blockWorthy(), 4)
	if len(sink5.blockedFor) != 0 {
		t.Errorf("disabled materialise must be a no-op; got %+v", sink5.blockedFor)
	}
}
```

(Confirm the `mockSink` type name and that `blockedFor` is the field added in Task 2; if the enforce config field for the never-block list differs from `Enforce.ExtraWhitelist`, use the actual field — `enforce.NewNeverBlockList(cfg.Enforce.ExtraWhitelist)` is how node.New builds `n.neverblock`.)

- [ ] **Step 2: Run it + the whole adversarial suite**

Run: `go test -tags adversarial ./test/adversarial/ -run TestMaterialiseGate -v && go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3`
Expected: PASS; suite green.

- [ ] **Step 3: Docs — config.md**

In `docs/config.md`, add a `federation_materialize` section:
```markdown
### `federation_materialize`, `federation_block_threshold`, `federation_block_min_subnets`, `federation_block_ttl`

When **enabled** (`federation_materialize: true`, default **false**), a
block-worthy federated verdict for an IP that contacts a protected service is
pushed into the firewall as a **provisional, TTL-bounded** block (default 1h,
`federation_block_ttl`), so subsequent packets drop O(1). It materialises only
when the locally-recomputed score ≥ `federation_block_threshold` (default 80)
AND the evidence spans ≥ `federation_block_min_subnets` distinct subnets
(default 3) — diversity is the Sybil gate. never-block and whitelist always
win. Local (anchored) blocks are unchanged and permanent; federated blocks
self-expire and re-materialise if the evidence persists. Off by default: an
operator must consciously enable remote-sourced kernel drops.
```

- [ ] **Step 4: Docs — spec §12a + roadmap + architecture + threat-model**

- `docs/spec.md` §12a: update the §11.4 row to `DONE — read path (E3) + diversity-gated TTL materialise (Step 4)`; if there is a §4.4/materialise row, mark it DONE (Step 4).
- `docs/roadmap.md`: mark Step 4 done — heading `### Step 4 — materialise-on-verdict (A5) ✅ done 2026-07-13`; annotate the A5 row `✅ resolved — diversity-gated, TTL-bounded, opt-in`.
- `docs/architecture.md`: one line — the federated query read path can now materialise a provisional, diversity-gated, TTL-bounded block (opt-in), completing "pull discovers, push enforces".
- `docs/threat-model.md`: add a bullet — remote-sourced enforcement is opt-in, provisional (TTL self-expiry), diversity-gated (≥N subnets) + high-threshold, never-block/whitelist-respecting; a forged low-diversity aggregate cannot materialise; defederation is containment.

- [ ] **Step 5: Full gate**

Run: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/ && go test ./... 2>&1 | tail -5 && go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3 && go test -tags integration ./test/integration/... 2>&1 | tail -3`
Expected: build/vet clean, `gofmt -l` empty, all suites PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w test/adversarial/materialise_test.go
git add test/adversarial/materialise_test.go docs/config.md docs/spec.md docs/roadmap.md docs/architecture.md docs/threat-model.md
git commit -m "test+docs: adversarial materialise gate; §11.4 traceability, config, roadmap Step 4 done"
```
