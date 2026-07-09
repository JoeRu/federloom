# Federated On-Demand Reputation Query (E3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On a local reputation miss, a node fetches an IP's reputation on demand from configured, trusted aggregator peers over a libp2p request/response protocol, caches it, and serves it through the existing DNSBL + point-lookup score API — without touching the L3 push-to-firewall path.

**Architecture:** A new `internal/repquery` package provides a libp2p protocol `/federloom/repquery/v1`: a responder serving the local store as a `proto.ScoreEntry`, and a querier that fans out to configured aggregators. A `Resolver` decorator wraps the store with local-then-federated `GetScore` + a TTL cache; the DNSBL and score API consume the `Resolver` instead of the raw store. Empty aggregator config = feature off (byte-for-byte today's behaviour).

**Tech Stack:** Go 1.22, libp2p (host streams, first request/response protocol in the codebase; all prior comms are gossipsub), BadgerDB, `go test` (unit + integration).

## Global Constraints

- Go module `github.com/JoeRu/federloom`, Go 1.22. Conventional Commits.
- E3 is **read-only**: it must NOT mutate the local score store or the L3 enforcement (`ipset`/`nftables`) set, and must not change the gossip/ingest scoring paths. The batch-A anchored-corroboration block backstop stays untouched.
- Only **point-lookup** surfaces federate: the DNSBL handler and the per-IP score API endpoint (`internal/api/handler_score`). The blocklist **enumeration** endpoint (`internal/api/handler_blocklist`, `ScanScores`) stays local-only — never fetch a full list on demand.
- `pkg/proto` is the wire contract (additive change; follow `.claude/skills/wire-protocol`): add `RepQuery`; reuse the existing (reserved) `ScoreEntry` as the answer.
- Aggregators are explicitly configured and thus trusted (like anchors); their raw `ScoreEntry` is **advisory evidence** and the operator's own threshold governs (MVP score-scale simplification — spec §4, revisit at E2).
- Merge across aggregator answers = **max score** + union of reasons (MVP — spec §6, revisit at E2).
- DNSBL/score-API stay bound to the private/secured interface (batch A P0-5); the federated query rides authenticated libp2p, never DNS.
- Empty `federation.aggregators` ⇒ federation disabled ⇒ `Resolver.GetScore` is local-only.
- Query is synchronous with a tight timeout (default 150ms); results cached (default TTL 5m), negatives cached with a shorter TTL. On timeout, fall back to the local answer.
- Every reputation/trust/ingest/transport change adds or updates a test; `make adversarial` remains the CI gate.

---

### Task 1: Config — aggregators, timeouts, cache TTL

**Files:**
- Modify: `internal/config/config.go` (top-level `Config`)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `Config.FederationAggregators []string` (yaml `federation_aggregators`), `Config.FederationQueryTimeout Duration` (yaml `federation_query_timeout`), `Config.FederationQueryCacheTTL Duration` (yaml `federation_query_cache_ttl`); helpers `func (c *Config) EffectiveQueryTimeout() time.Duration` (default 150ms if unset) and `func (c *Config) EffectiveQueryCacheTTL() time.Duration` (default 5m if unset).

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestEffectiveQueryDefaults(t *testing.T) {
	c := &config.Config{} // unset
	if got := c.EffectiveQueryTimeout(); got != 150*time.Millisecond {
		t.Errorf("EffectiveQueryTimeout default = %v, want 150ms", got)
	}
	if got := c.EffectiveQueryCacheTTL(); got != 5*time.Minute {
		t.Errorf("EffectiveQueryCacheTTL default = %v, want 5m", got)
	}
	c2 := &config.Config{
		FederationQueryTimeout:  config.Duration{Duration: 300 * time.Millisecond},
		FederationQueryCacheTTL: config.Duration{Duration: 2 * time.Minute},
	}
	if got := c2.EffectiveQueryTimeout(); got != 300*time.Millisecond {
		t.Errorf("EffectiveQueryTimeout = %v, want 300ms", got)
	}
	if got := c2.EffectiveQueryCacheTTL(); got != 2*time.Minute {
		t.Errorf("EffectiveQueryCacheTTL = %v, want 2m", got)
	}
}
```

(`config.Duration` is the existing YAML duration wrapper in `config.go` — confirm its exact field name; it wraps `time.Duration` as `.Duration`.)

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/config/ -run TestEffectiveQueryDefaults -v`
Expected: FAIL — fields/methods undefined.

- [ ] **Step 3: Add the fields and helpers**

In `internal/config/config.go`, add to the top-level `Config` struct (near the other `Federation*` fields):

```go
	FederationAggregators   []string `yaml:"federation_aggregators"`    // aggregator peer multiaddrs to query on a local miss (empty = off)
	FederationQueryTimeout  Duration `yaml:"federation_query_timeout"`  // per-query deadline; default 150ms
	FederationQueryCacheTTL Duration `yaml:"federation_query_cache_ttl"`// cache TTL for federated answers; default 5m
```

Add the helpers (near the other `Config` methods):

```go
// EffectiveQueryTimeout returns the federated-query deadline, defaulting to 150ms.
func (c *Config) EffectiveQueryTimeout() time.Duration {
	if c.FederationQueryTimeout.Duration <= 0 {
		return 150 * time.Millisecond
	}
	return c.FederationQueryTimeout.Duration
}

// EffectiveQueryCacheTTL returns the federated-answer cache TTL, defaulting to 5m.
func (c *Config) EffectiveQueryCacheTTL() time.Duration {
	if c.FederationQueryCacheTTL.Duration <= 0 {
		return 5 * time.Minute
	}
	return c.FederationQueryCacheTTL.Duration
}
```

`Defaults()` needs no change (zero values → the defaults above; empty aggregators → off). Ensure `time` is imported (it is).

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/config/ -run TestEffectiveQueryDefaults -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/config/config.go internal/config/config_test.go
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add federation aggregators + query timeout/cache-ttl"
```

---

### Task 2: Wire type + ScoreEntry conversion helpers

**Files:**
- Modify: `pkg/proto/messages.go` (add `RepQuery`)
- Create: `internal/repquery/convert.go`
- Test: `internal/repquery/convert_test.go`

**Interfaces:**
- Produces: `proto.RepQuery{ IP string }`; `repquery.EntryFromRecord(ip string, r store.ScoreRecord) proto.ScoreEntry`; `repquery.RecordFromEntry(e proto.ScoreEntry) store.ScoreRecord`.

- [ ] **Step 1: Write the failing test**

Create `internal/repquery/convert_test.go`:

```go
package repquery

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/store"
)

func TestEntryRecordRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rec := store.ScoreRecord{
		Score:         42.5,
		Corroboration: 3,
		FirstSeen:     now.Add(-time.Hour),
		LastSeen:      now,
		Reasons:       []string{"ssh-probe", "smtp-auth-bruteforce"},
	}
	e := EntryFromRecord("1.2.3.4", rec)
	if e.IP != "1.2.3.4" || e.Score != 42.5 || e.Corroboration != 3 {
		t.Fatalf("EntryFromRecord lost fields: %+v", e)
	}
	back := RecordFromEntry(e)
	if back.Score != rec.Score || back.Corroboration != rec.Corroboration ||
		!back.LastSeen.Equal(rec.LastSeen) || !back.FirstSeen.Equal(rec.FirstSeen) ||
		len(back.Reasons) != len(rec.Reasons) {
		t.Errorf("round trip lost fields: got %+v want %+v", back, rec)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/repquery/ -run TestEntryRecordRoundTrip -v`
Expected: FAIL — package/symbols undefined.

- [ ] **Step 3: Add the wire type**

In `pkg/proto/messages.go`, add:

```go
// RepQuery is an on-demand request for one IP's reputation (spec §11.4, E3).
// The response reuses ScoreEntry.
type RepQuery struct {
	IP string `json:"ip"`
}
```

- [ ] **Step 4: Add the conversion helpers**

Create `internal/repquery/convert.go`:

```go
// Package repquery implements the on-demand federated reputation query protocol
// (spec §11.4, sub-project E3): a libp2p request/response so a node can fetch an
// IP's reputation from configured aggregator peers when it has no local record.
package repquery

import (
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// EntryFromRecord projects a local ScoreRecord onto the wire ScoreEntry (the
// answer). Tracking-only fields (ReporterIDs/Groups/StrangerContrib) are never
// shared. Disputes is 0 (not tracked yet).
func EntryFromRecord(ip string, r store.ScoreRecord) proto.ScoreEntry {
	return proto.ScoreEntry{
		IP:            ip,
		Score:         r.Score,
		Corroboration: r.Corroboration,
		FirstSeen:     r.FirstSeen,
		LastSeen:      r.LastSeen,
		Reasons:       r.Reasons,
	}
}

// RecordFromEntry projects a received ScoreEntry back onto a ScoreRecord so the
// DNSBL/API read path (which speaks ScoreRecord) can consume a federated answer.
func RecordFromEntry(e proto.ScoreEntry) store.ScoreRecord {
	return store.ScoreRecord{
		Score:         e.Score,
		Corroboration: e.Corroboration,
		FirstSeen:     e.FirstSeen,
		LastSeen:      e.LastSeen,
		Reasons:       e.Reasons,
	}
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/repquery/ -run TestEntryRecordRoundTrip -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w pkg/proto/messages.go internal/repquery/convert.go internal/repquery/convert_test.go
git add pkg/proto/messages.go internal/repquery/convert.go internal/repquery/convert_test.go
git commit -m "feat(repquery): add RepQuery wire type + ScoreEntry<->ScoreRecord conversion"
```

---

### Task 3: Responder — serve the local store over a libp2p stream

**Files:**
- Create: `internal/repquery/responder.go`
- Test: `internal/repquery/responder_test.go`

**Interfaces:**
- Consumes: `EntryFromRecord` (Task 2); a minimal store reader.
- Produces: `const ProtocolID = "/federloom/repquery/v1"`; `type Store interface { GetScore(ip string) (store.ScoreRecord, error) }`; `func RegisterResponder(h host.Host, s Store)`.

- [ ] **Step 1: Write the failing test**

Create `internal/repquery/responder_test.go`:

```go
package repquery

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// fakeStore returns a fixed record for one IP, empty otherwise.
type fakeStore struct{ ip string; rec store.ScoreRecord }

func (f fakeStore) GetScore(ip string) (store.ScoreRecord, error) {
	if ip == f.ip {
		return f.rec, nil
	}
	return store.ScoreRecord{}, nil
}

func TestResponderServesLocalScore(t *testing.T) {
	ctx := context.Background()
	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h1: %v", err)
	}
	defer h1.Close()
	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h2: %v", err)
	}
	defer h2.Close()

	RegisterResponder(h1, fakeStore{ip: "1.2.3.4", rec: store.ScoreRecord{Score: 88, Corroboration: 2, LastSeen: time.Now()}})

	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	s, err := h2.NewStream(ctx, h1.ID(), ProtocolID)
	if err != nil {
		t.Fatalf("newstream: %v", err)
	}
	defer s.Close()
	if err := json.NewEncoder(s).Encode(proto.RepQuery{IP: "1.2.3.4"}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var e proto.ScoreEntry
	if err := json.NewDecoder(s).Decode(&e); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e.IP != "1.2.3.4" || e.Score != 88 {
		t.Errorf("responder answer = %+v, want IP 1.2.3.4 score 88", e)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/repquery/ -run TestResponderServesLocalScore -v`
Expected: FAIL — `ProtocolID`/`RegisterResponder`/`Store` undefined.

- [ ] **Step 3: Implement the responder**

Create `internal/repquery/responder.go`:

```go
package repquery

import (
	"encoding/json"
	"log"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"

	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

// ProtocolID is the libp2p stream protocol for on-demand reputation queries.
const ProtocolID = "/federloom/repquery/v1"

// Store is the minimal reader the responder needs (the local BadgerStore satisfies it).
type Store interface {
	GetScore(ip string) (store.ScoreRecord, error)
}

// RegisterResponder installs the stream handler on h. Each stream is one
// RepQuery → one ScoreEntry, then closed. Read-only.
func RegisterResponder(h host.Host, s Store) {
	h.SetStreamHandler(ProtocolID, func(str network.Stream) {
		defer str.Close()
		var q proto.RepQuery
		if err := json.NewDecoder(str).Decode(&q); err != nil {
			log.Printf("repquery: bad request from %s: %v", str.Conn().RemotePeer(), err)
			return
		}
		rec, err := s.GetScore(q.IP)
		if err != nil {
			log.Printf("repquery: store error for %s: %v", q.IP, err)
			return
		}
		// Empty record → empty ScoreEntry (LastSeen zero) means "not found".
		if err := json.NewEncoder(str).Encode(EntryFromRecord(q.IP, rec)); err != nil {
			log.Printf("repquery: write answer for %s: %v", q.IP, err)
		}
	})
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/repquery/ -run TestResponderServesLocalScore -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/repquery/responder.go internal/repquery/responder_test.go
git add internal/repquery/responder.go internal/repquery/responder_test.go
git commit -m "feat(repquery): libp2p responder serving local reputation as ScoreEntry"
```

---

### Task 4: Querier + TTL cache

**Files:**
- Create: `internal/repquery/querier.go`
- Test: `internal/repquery/querier_test.go`

**Interfaces:**
- Consumes: `ProtocolID`, `proto.RepQuery`, `proto.ScoreEntry`.
- Produces: `type Querier struct{...}`; `func NewQuerier(h host.Host, aggregators []peer.AddrInfo, timeout, cacheTTL time.Duration) *Querier`; `func (q *Querier) Query(ctx context.Context, ip string) (proto.ScoreEntry, bool)` (merged max-score answer; `ok=false` if no aggregator answered a non-empty record); results cached by IP.

- [ ] **Step 1: Write the failing test**

Create `internal/repquery/querier_test.go`:

```go
package repquery

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/store"
)

func TestQuerierFetchesAndCaches(t *testing.T) {
	ctx := context.Background()
	// Aggregator host with a responder holding IP X.
	agg, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("agg: %v", err)
	}
	defer agg.Close()
	counter := &countStore{ip: "9.9.9.9", rec: store.ScoreRecord{Score: 70, Corroboration: 1, LastSeen: time.Now()}}
	RegisterResponder(agg, counter)

	client, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	q := NewQuerier(client, []peer.AddrInfo{{ID: agg.ID(), Addrs: agg.Addrs()}}, 2*time.Second, time.Minute)

	e, ok := q.Query(ctx, "9.9.9.9")
	if !ok || e.Score != 70 {
		t.Fatalf("Query = %+v ok=%v, want score 70 ok true", e, ok)
	}
	// Second query within TTL must hit the cache (no new responder call).
	before := counter.calls
	if _, ok := q.Query(ctx, "9.9.9.9"); !ok {
		t.Fatal("cached query lost the answer")
	}
	if counter.calls != before {
		t.Errorf("cache miss: responder called again (%d -> %d)", before, counter.calls)
	}

	// Unknown IP: no aggregator has it → ok false.
	if _, ok := q.Query(ctx, "8.8.8.8"); ok {
		t.Error("unknown IP should return ok=false")
	}
}

type countStore struct {
	ip    string
	rec   store.ScoreRecord
	calls int
}

func (c *countStore) GetScore(ip string) (store.ScoreRecord, error) {
	c.calls++
	if ip == c.ip {
		return c.rec, nil
	}
	return store.ScoreRecord{}, nil
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/repquery/ -run TestQuerierFetchesAndCaches -v`
Expected: FAIL — `NewQuerier`/`Query` undefined.

- [ ] **Step 3: Implement the querier + cache**

Create `internal/repquery/querier.go`:

```go
package repquery

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/pkg/proto"
)

// Querier fetches reputation from configured aggregators on demand and caches
// the merged answer per IP.
type Querier struct {
	host        host.Host
	aggregators []peer.AddrInfo
	timeout     time.Duration
	cacheTTL    time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	entry proto.ScoreEntry
	ok    bool
	at    time.Time
}

// NewQuerier builds a Querier. aggregators is the trusted set to ask.
func NewQuerier(h host.Host, aggregators []peer.AddrInfo, timeout, cacheTTL time.Duration) *Querier {
	return &Querier{host: h, aggregators: aggregators, timeout: timeout, cacheTTL: cacheTTL, cache: map[string]cacheEntry{}}
}

// Query returns the merged (max-score) reputation for ip across aggregators.
// ok is false if no aggregator returned a non-empty record. Cached by IP; a
// negative result is cached for a fraction of the TTL to avoid hammering.
func (q *Querier) Query(ctx context.Context, ip string) (proto.ScoreEntry, bool) {
	now := time.Now()
	q.mu.Lock()
	if c, hit := q.cache[ip]; hit {
		ttl := q.cacheTTL
		if !c.ok {
			ttl = q.cacheTTL / 5 // shorter negative TTL
		}
		if now.Sub(c.at) < ttl {
			q.mu.Unlock()
			return c.entry, c.ok
		}
	}
	q.mu.Unlock()

	merged, ok := q.fanout(ctx, ip)

	q.mu.Lock()
	q.cache[ip] = cacheEntry{entry: merged, ok: ok, at: now}
	q.mu.Unlock()
	return merged, ok
}

// fanout asks every aggregator concurrently within the timeout and merges by max score.
func (q *Querier) fanout(ctx context.Context, ip string) (proto.ScoreEntry, bool) {
	qctx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	type res struct {
		e  proto.ScoreEntry
		ok bool
	}
	ch := make(chan res, len(q.aggregators))
	for _, agg := range q.aggregators {
		go func(a peer.AddrInfo) {
			e, ok := q.ask(qctx, a, ip)
			ch <- res{e, ok}
		}(agg)
	}

	var merged proto.ScoreEntry
	merged.IP = ip
	found := false
	reasons := map[string]bool{}
	for range q.aggregators {
		r := <-ch
		if !r.ok {
			continue
		}
		found = true
		if r.e.Score > merged.Score {
			merged.Score = r.e.Score
			merged.Corroboration = r.e.Corroboration
			merged.FirstSeen = r.e.FirstSeen
			merged.LastSeen = r.e.LastSeen
		}
		for _, rs := range r.e.Reasons {
			reasons[rs] = true
		}
	}
	for rs := range reasons {
		merged.Reasons = append(merged.Reasons, rs)
	}
	return merged, found
}

// ask opens a stream to one aggregator, sends the query, reads the answer.
func (q *Querier) ask(ctx context.Context, a peer.AddrInfo, ip string) (proto.ScoreEntry, bool) {
	if q.host.Network().Connectedness(a.ID) != network.Connected {
		_ = q.host.Connect(ctx, a)
	}
	s, err := q.host.NewStream(ctx, a.ID, ProtocolID)
	if err != nil {
		return proto.ScoreEntry{}, false
	}
	defer s.Close()
	if err := json.NewEncoder(s).Encode(proto.RepQuery{IP: ip}); err != nil {
		return proto.ScoreEntry{}, false
	}
	var e proto.ScoreEntry
	if err := json.NewDecoder(s).Decode(&e); err != nil {
		return proto.ScoreEntry{}, false
	}
	// Empty answer (LastSeen zero) means the aggregator has no record.
	if e.LastSeen.IsZero() {
		return proto.ScoreEntry{}, false
	}
	return e, true
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/repquery/ -run TestQuerierFetchesAndCaches -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/repquery/querier.go internal/repquery/querier_test.go
git add internal/repquery/querier.go internal/repquery/querier_test.go
git commit -m "feat(repquery): querier with max-score merge + TTL cache"
```

---

### Task 5: Resolver — local-then-federated GetScore, wired into DNSBL + score API

**Files:**
- Create: `internal/repquery/resolver.go`
- Test: `internal/repquery/resolver_test.go`
- Modify: `internal/api/server.go` (accept a `GetScore` reader for point lookups)
- Modify: `internal/api/handler_score.go` (use the resolver)

**Interfaces:**
- Consumes: `Querier` (Task 4), `RecordFromEntry` (Task 2), `Store` (Task 3).
- Produces: `type Resolver struct{...}`; `func NewResolver(local Store, q *Querier) *Resolver`; `func (r *Resolver) GetScore(ip string) (store.ScoreRecord, error)` (local hit → local; miss + querier → federated, converted; miss + no querier → empty). `Resolver` satisfies the DNSBL's `StoreReader` and the score API's point-lookup reader.

- [ ] **Step 1: Write the failing test**

Create `internal/repquery/resolver_test.go`:

```go
package repquery

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/store"
)

// localMiss always misses; localHit returns a record.
type fixedStore struct{ rec store.ScoreRecord }

func (f fixedStore) GetScore(string) (store.ScoreRecord, error) { return f.rec, nil }

func TestResolverLocalHitSkipsFederation(t *testing.T) {
	local := fixedStore{rec: store.ScoreRecord{Score: 50, LastSeen: time.Now()}}
	r := NewResolver(local, nil) // nil querier: if it tried to federate it'd panic
	got, err := r.GetScore("1.1.1.1")
	if err != nil || got.Score != 50 {
		t.Fatalf("local hit not returned: %+v err=%v", got, err)
	}
}

func TestResolverMissNoQuerierReturnsEmpty(t *testing.T) {
	r := NewResolver(fixedStore{}, nil) // local miss (zero record), no federation
	got, _ := r.GetScore("2.2.2.2")
	if !got.LastSeen.IsZero() {
		t.Errorf("expected empty record on miss with no querier, got %+v", got)
	}
}
```

(The federated-miss path is covered end-to-end by the Task 6 integration test, which has a real querier.)

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/repquery/ -run TestResolver -v`
Expected: FAIL — `NewResolver`/`Resolver` undefined.

- [ ] **Step 3: Implement the Resolver**

Create `internal/repquery/resolver.go`:

```go
package repquery

import (
	"context"

	"github.com/JoeRu/federloom/internal/store"
)

// Resolver answers point reputation lookups: the local store first, then (on a
// miss) the configured aggregators via the querier. It is the single read path
// the DNSBL and the point-lookup score API consume. Read-only.
type Resolver struct {
	local Store
	q     *Querier // nil = federation disabled
}

// NewResolver wraps a local store; q may be nil (federation off).
func NewResolver(local Store, q *Querier) *Resolver {
	return &Resolver{local: local, q: q}
}

// GetScore returns the local record if present, else a federated answer
// (converted to a ScoreRecord), else an empty record. Never errors on the
// federated path — a miss/timeout degrades to the local (empty) answer.
func (r *Resolver) GetScore(ip string) (store.ScoreRecord, error) {
	rec, err := r.local.GetScore(ip)
	if err != nil {
		return rec, err
	}
	if !rec.LastSeen.IsZero() || r.q == nil {
		return rec, nil // local hit, or federation disabled
	}
	if e, ok := r.q.Query(context.Background(), ip); ok {
		return RecordFromEntry(e), nil
	}
	return rec, nil // federated miss → the (empty) local record
}
```

- [ ] **Step 4: Run the Resolver tests**

Run: `go test ./internal/repquery/ -run TestResolver -v`
Expected: PASS.

- [ ] **Step 5: Route the score API through a point-lookup reader**

In `internal/api/server.go`, the `Server` currently holds a concrete store. Add a narrow point-lookup interface and field so a `Resolver` can be injected without disturbing the enumeration path:

```go
// scoreReader is the point-lookup surface for the per-IP score endpoint. The
// concrete store satisfies it; a repquery.Resolver injects federated fallback.
type scoreReader interface {
	GetScore(ip string) (store.ScoreRecord, error)
}
```

Add a `pointReader scoreReader` field to `Server`. In `api.New(...)`, default it to the passed store (`srv.pointReader = s`); add a setter `func (s *Server) SetPointReader(r scoreReader) { s.pointReader = r }` for the node to inject the Resolver. In `internal/api/handler_score.go`, change `rec, err := s.store.GetScore(ip)` to `rec, err := s.pointReader.GetScore(ip)`. The blocklist enumeration handler keeps using `s.store` (unchanged — local only).

- [ ] **Step 6: Run the API + repquery suites**

Run: `go test ./internal/api/... ./internal/repquery/... && go build ./...`
Expected: PASS; build clean (default `pointReader = store` preserves today's behaviour when no Resolver is injected).

- [ ] **Step 7: Commit**

```bash
gofmt -w internal/repquery/resolver.go internal/repquery/resolver_test.go internal/api/server.go internal/api/handler_score.go
git add internal/repquery/resolver.go internal/repquery/resolver_test.go internal/api/server.go internal/api/handler_score.go
git commit -m "feat(repquery): Resolver (local-then-federated GetScore) + score API point-lookup seam"
```

---

### Task 6: Node wiring + integration test

**Files:**
- Modify: `internal/node/node.go` (build querier/resolver from config+transport; register responder; inject Resolver into DNSBL + API)
- Test: `test/integration/repquery_test.go` (new)

**Interfaces:**
- Consumes: `repquery.NewQuerier`, `repquery.NewResolver`, `repquery.RegisterResponder` (Tasks 3-5); `cfg.FederationAggregators`, `cfg.EffectiveQueryTimeout()`, `cfg.EffectiveQueryCacheTTL()` (Task 1); `dnsbl.New`, `api.New`, `transport.Node.Host()`.

- [ ] **Step 1: Write the failing integration test**

Create `test/integration/repquery_test.go` (`package integration_test`, no build tag — matches `cluster_test.go`, runs under `go test ./test/integration/...`). Two nodes: aggregator B has IP X scored, querier A does not; `A`'s Resolver fetches X from B.

```go
package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/repquery"
	"github.com/JoeRu/federloom/internal/store"
)

// storeStub is a minimal repquery.Store for the integration test.
type storeStub struct{ m map[string]store.ScoreRecord }

func (s storeStub) GetScore(ip string) (store.ScoreRecord, error) { return s.m[ip], nil }

func TestFederatedLookupFetchesFromAggregator(t *testing.T) {
	ctx := context.Background()

	// Aggregator B: has 203.0.113.9 scored, serves the responder.
	bHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("bHost: %v", err)
	}
	defer bHost.Close()
	repquery.RegisterResponder(bHost, storeStub{m: map[string]store.ScoreRecord{
		"203.0.113.9": {Score: 92, Corroboration: 4, LastSeen: time.Now()},
	}})

	// Querier A: empty local store, B configured as aggregator.
	aHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("aHost: %v", err)
	}
	defer aHost.Close()
	q := repquery.NewQuerier(aHost, []peer.AddrInfo{{ID: bHost.ID(), Addrs: bHost.Addrs()}}, 2*time.Second, time.Minute)
	resolver := repquery.NewResolver(storeStub{m: map[string]store.ScoreRecord{}}, q)

	// A resolves an IP it does not hold → fetched from B.
	rec, err := resolver.GetScore("203.0.113.9")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if rec.LastSeen.IsZero() || rec.Score != 92 {
		t.Errorf("federated lookup = %+v, want score 92", rec)
	}

	// An IP nobody has → empty.
	if rec, _ := resolver.GetScore("203.0.113.10"); !rec.LastSeen.IsZero() {
		t.Errorf("unknown IP should stay empty, got %+v", rec)
	}
}
```

- [ ] **Step 2: Run it to verify it fails/passes appropriately**

Run: `go test ./test/integration/ -run TestFederatedLookupFetchesFromAggregator -v`
Expected: this test exercises Tasks 2-5 directly; it should PASS once those are implemented (it does not need the node wiring). If it FAILS, fix the querier/resolver before proceeding.

- [ ] **Step 3: Wire the node**

In `internal/node/node.go` `New`, after the transport/store are available and before constructing DNSBL/API, build the federated read path when a transport and aggregators exist:

```go
	var resolver *repquery.Resolver
	if t != nil && len(cfg.FederationAggregators) > 0 {
		repquery.RegisterResponder(t.Host(), s) // serve our local store
		aggs := parseAggregators(cfg.FederationAggregators)
		q := repquery.NewQuerier(t.Host(), aggs, cfg.EffectiveQueryTimeout(), cfg.EffectiveQueryCacheTTL())
		resolver = repquery.NewResolver(s, q)
	}
```

Add a helper in `node.go`:

```go
// parseAggregators turns configured multiaddrs into libp2p AddrInfos, skipping bad ones.
func parseAggregators(addrs []string) []peer.AddrInfo {
	var out []peer.AddrInfo
	for _, a := range addrs {
		info, err := peer.AddrInfoFromString(a)
		if err != nil {
			log.Printf("node: bad federation aggregator %q: %v", a, err)
			continue
		}
		out = append(out, *info)
	}
	return out
}
```

(Import `"github.com/libp2p/go-libp2p/core/peer"` and `"github.com/JoeRu/federloom/internal/repquery"` in node.go.)

Then pass the Resolver to the read surfaces. The DNSBL already takes a `StoreReader` (`GetScore` only) — pass the resolver when present, else the store:

```go
	var dnsblReader dnsbl.StoreReader = s
	if resolver != nil {
		dnsblReader = resolver
	}
	dnsblSrv := dnsbl.New(cfg.DNSBL, dnsblReader, cfg.Reputation)
```

For the API, inject the Resolver as the point reader after construction:

```go
	apiSrv := api.New(cfg.API, s, cfg.Reputation)
	if resolver != nil {
		apiSrv.SetPointReader(resolver)
	}
```

(Confirm `dnsbl.StoreReader` is the exported interface name; if it is unexported, either export it or pass the resolver directly since Go structural typing lets `*repquery.Resolver` satisfy the parameter type.)

- [ ] **Step 4: Run build + the integration + node suites**

Run: `go build ./... && go test ./test/integration/ -run TestFederatedLookupFetchesFromAggregator -v && go test ./internal/node/... ./internal/dnsbl/... ./internal/api/...`
Expected: PASS. A node with no aggregators configured builds no resolver and behaves exactly as today.

- [ ] **Step 5: Run the full adversarial + integration regression**

Run: `go test ./... && go test -tags adversarial ./test/adversarial/... && go test -tags integration ./test/integration/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/node/node.go test/integration/repquery_test.go
git add internal/node/node.go test/integration/repquery_test.go
git commit -m "feat(node): wire federated reputation query into DNSBL + score API"
```

---

### Task 7: Docs + final verification

**Files:**
- Modify: `docs/config.md` (federation aggregators/query config + the architecture note)
- Modify: `docs/architecture.md` (add the query-path plane)
- Modify: `docs/spec.md` (§12a traceability: §11.4 + §7.2)

- [ ] **Step 1: Document the config**

In `docs/config.md`, add (near the federation config):

```markdown
### `federation_aggregators`, `federation_query_timeout`, `federation_query_cache_ttl`

When a reputation lookup (DNSBL or the per-IP score API) misses the local store,
the node queries these trusted aggregator peers on demand over libp2p and caches
the answer. `federation_aggregators` is a list of aggregator multiaddrs (empty =
feature off). `federation_query_timeout` (default `150ms`) bounds each query;
`federation_query_cache_ttl` (default `5m`) caches answers.

Aggregators are trusted like anchors — their answer is advisory evidence and
your own threshold decides "listed". The DNSBL/API stay on the private interface;
the query itself rides authenticated libp2p. Push-to-firewall (L3) is unchanged;
the blocklist *list* endpoint is never federated (point lookups only).
```

- [ ] **Step 2: Document the architecture**

In `docs/architecture.md`, add a short note: reputation has a **push** enforcement path (engine → ipset, L3, unchanged) and a **query** read path (DNSBL/API → local store → federated aggregators on a miss, E3). The query path is read-only and does not materialise into the firewall in this MVP (that lands with E2's scale-free evidence).

- [ ] **Step 3: Update spec traceability**

In `docs/spec.md` §12a, update:

```markdown
| §7.2 | ScoreEntry aggregate | `pkg/proto`, `internal/repquery` | DONE — exchanged as the on-demand query answer (E3) |
| §11.4 | On-demand query / pull transport | `internal/repquery` | PARTIAL — read path via configured aggregators (E3); DHT/bloom + materialise-on-verdict PLANNED |
```

- [ ] **Step 4: Full gate**

Run: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/ && go test ./... && go test -tags adversarial ./test/adversarial/... && go test -tags integration ./test/integration/...`
Expected: builds; vet clean; `gofmt -l` prints nothing; all suites PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/config.md docs/architecture.md docs/spec.md
git commit -m "docs: federated reputation query config, architecture, traceability (E3)"
```
