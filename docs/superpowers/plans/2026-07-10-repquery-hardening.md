# Repquery Hardening (Roadmap Step 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the E3 review findings: the repquery responder answers only trust-anchored, non-blocked peers (fail closed) and serves whenever the node is federated; the querier cache is bounded with in-flight de-dup; plus the B5 polish items.

**Architecture:** `RegisterResponder` gains an `Authorizer` interface that `*trust.Store` satisfies verbatim; authorization runs before any request byte is read, with `str.Reset()` on rejection. Responder registration moves from the aggregator-gated block to the plain `t != nil` path in `node.New`. The querier gets a bounded cache (dedupCache eviction pattern), `singleflight` around the fan-out, and peerstore-seeded addresses replacing the per-ask `Connect`.

**Tech Stack:** Go 1.22, libp2p (streams, peerstore), `golang.org/x/sync/singleflight` (already in go.sum, promoted to direct).

## Global Constraints

- Go module `github.com/JoeRu/federloom`, Go 1.22. Conventional Commits.
- **Fail closed:** a `nil` Authorizer rejects every peer; authorization runs BEFORE the request is decoded.
- **Authorization rule:** answer iff `anchored && !IsBlocked` for the connecting peer ID. Strangers and defederated peers get `str.Reset()`.
- **No new config keys.** Serve role = automatic when `t != nil`; client role stays gated on `federation_aggregators` exactly as today.
- **Read-only preserved:** repquery never mutates the score store or the enforcement set. No change to gossip, ingest, or enforce paths.
- Cache bound: `maxCacheEntries = 65536` (package var so tests can shrink it, mirroring the existing `responderStreamTimeout` precedent).
- Every task keeps `go build ./...` green and its commit self-contained.
- Full gate at the end: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/` (empty) + unit + `-tags adversarial` + `-tags integration` suites.

---

### Task 1: Responder authorization (B1)

**Files:**
- Modify: `internal/repquery/responder.go`
- Test: `internal/repquery/responder_test.go`
- Modify (keep build green — signature change ripples to all callers):
  `internal/repquery/querier_test.go`, `test/integration/repquery_test.go`,
  `internal/node/wiring_repquery_test.go`, `internal/node/node.go`

**Interfaces:**
- Consumes: `trust.Store.Resolve(peerID string) (weight float64, group string, anchored bool)` and `trust.Store.IsBlocked(peerID string) bool` (existing, unchanged).
- Produces: `type Authorizer interface { Resolve(peerID string) (weight float64, group string, anchored bool); IsBlocked(peerID string) bool }`; new signature `func RegisterResponder(h host.Host, s Store, auth Authorizer)`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/repquery/responder_test.go`:

```go
// fakeAuth is a test Authorizer: anchored/blocked are fixed answers.
type fakeAuth struct {
	anchored bool
	blocked  bool
}

func (f fakeAuth) Resolve(string) (float64, string, bool) { return 0.9, "test", f.anchored }
func (f fakeAuth) IsBlocked(string) bool                  { return f.blocked }

// queryOnce opens a stream to h1 from h2, sends a RepQuery for ip and returns
// the decode result of the answer.
func queryOnce(t *testing.T, ctx context.Context, h2 host.Host, id peer.ID, addrs []multiaddr.Multiaddr, ip string) (proto.ScoreEntry, error) {
	t.Helper()
	if err := h2.Connect(ctx, peer.AddrInfo{ID: id, Addrs: addrs}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	s, err := h2.NewStream(ctx, id, ProtocolID)
	if err != nil {
		t.Fatalf("newstream: %v", err)
	}
	defer s.Close()
	if err := json.NewEncoder(s).Encode(proto.RepQuery{IP: ip}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var e proto.ScoreEntry
	err = json.NewDecoder(s).Decode(&e)
	return e, err
}

func TestResponderAuthorization(t *testing.T) {
	ctx := context.Background()
	rec := store.ScoreRecord{Score: 88, Corroboration: 2, LastSeen: time.Now()}

	cases := []struct {
		name    string
		auth    Authorizer
		wantErr bool
	}{
		{"anchored peer answered", fakeAuth{anchored: true}, false},
		{"stranger reset", fakeAuth{anchored: false}, true},
		{"blocked anchored peer reset", fakeAuth{anchored: true, blocked: true}, true},
		{"nil authorizer rejects all", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
			RegisterResponder(h1, fakeStore{ip: "1.2.3.4", rec: rec}, tc.auth)

			e, err := queryOnce(t, ctx, h2, h1.ID(), h1.Addrs(), "1.2.3.4")
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected reset/decode error for unauthorized peer, got answer %+v", e)
				}
				return
			}
			if err != nil {
				t.Fatalf("authorized query failed: %v", err)
			}
			if e.Score != 88 {
				t.Errorf("answer score = %v, want 88", e.Score)
			}
		})
	}
}
```

New imports needed in `responder_test.go`: `github.com/multiformats/go-multiaddr`, `github.com/libp2p/go-libp2p/core/host` (check what is already imported; `context`, `encoding/json`, `libp2p`, `peer`, `store`, `proto`, `time` exist).

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/repquery/ -run TestResponderAuthorization -v`
Expected: FAIL to compile — `RegisterResponder` takes 2 args, `Authorizer` undefined.

- [ ] **Step 3: Implement authorization in the responder**

Replace `RegisterResponder` in `internal/repquery/responder.go` and add the interface:

```go
// Authorizer decides which peers may query this node's reputation
// (design 2026-07-10 §3: anchored AND not blocked; nil = reject all).
// *trust.Store satisfies it verbatim.
type Authorizer interface {
	Resolve(peerID string) (weight float64, group string, anchored bool)
	IsBlocked(peerID string) bool
}

// RegisterResponder installs the stream handler on h. Each stream is one
// RepQuery → one ScoreEntry, then closed. Read-only. Only peers authorized
// by auth are answered; unauthorized streams are reset before the request
// is read (fail closed: a nil auth rejects everyone).
func RegisterResponder(h host.Host, s Store, auth Authorizer) {
	h.SetStreamHandler(ProtocolID, func(str network.Stream) {
		peerID := str.Conn().RemotePeer().String()
		if auth == nil {
			log.Printf("repquery: reject %s: no authorizer configured", peerID)
			_ = str.Reset()
			return
		}
		if auth.IsBlocked(peerID) {
			log.Printf("repquery: reject blocked peer %s", peerID)
			_ = str.Reset()
			return
		}
		if _, _, anchored := auth.Resolve(peerID); !anchored {
			log.Printf("repquery: reject unanchored peer %s", peerID)
			_ = str.Reset()
			return
		}
		defer str.Close()
		if err := str.SetDeadline(time.Now().Add(responderStreamTimeout)); err != nil {
			log.Printf("repquery: set deadline for %s: %v", peerID, err)
		}
		var q proto.RepQuery
		if err := json.NewDecoder(str).Decode(&q); err != nil {
			log.Printf("repquery: bad request from %s: %v", peerID, err)
			_ = str.Reset()
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

Notes: `str.Reset()` before `defer str.Close()` is deliberate on the reject paths (abort, no graceful close); the decode-error path now also uses `Reset` (B5); the `SetDeadline` error is now logged (B5).

- [ ] **Step 4: Update all existing callers (build stays green)**

- `internal/repquery/responder_test.go`: existing `TestResponderServesLocalScore`, `TestResponderUnknownIPIsEmpty`, `TestResponderStreamDeadlineClosesIdleStream` → pass `fakeAuth{anchored: true}` as third arg.
- `internal/repquery/querier_test.go`: every `RegisterResponder(agg, …)` call → add `fakeAuth{anchored: true}` (the type lives in the same package's test files).
- `test/integration/repquery_test.go` (`package integration_test` — needs its own fake since `fakeAuth` is internal to repquery's tests):

```go
type allowAllAuth struct{}

func (allowAllAuth) Resolve(string) (float64, string, bool) { return 1, "test", true }
func (allowAllAuth) IsBlocked(string) bool                  { return false }
```

  and pass `allowAllAuth{}` to the `repquery.RegisterResponder` call.
- `internal/node/wiring_repquery_test.go` (`package node`): define the same `allowAllAuth` fake locally and pass it to the raw aggregator-host `repquery.RegisterResponder` call.
- `internal/node/node.go` (in-place only — the wiring MOVE is Task 2): change the call inside the aggregator-gated block to `repquery.RegisterResponder(t.Host(), s, ts)` (`ts` is the `*trust.Store` created earlier in `New`).

- [ ] **Step 5: Run the affected suites**

Run: `go build ./... && go test ./internal/repquery/... -race -v 2>&1 | tail -20 && go test ./internal/node/... && go test ./test/integration/ -run TestFederatedLookup -v`
Expected: all PASS. (The existing wiring test keeps passing: its aggregator is a raw host now registered with `allowAllAuth{}`, and nothing queries the node's own responder yet — that behavior lands in Task 2.)

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/repquery/responder.go internal/repquery/responder_test.go internal/repquery/querier_test.go test/integration/repquery_test.go internal/node/wiring_repquery_test.go internal/node/node.go
git add -A internal/repquery test/integration/repquery_test.go internal/node/wiring_repquery_test.go internal/node/node.go
git commit -m "feat(repquery): trust-store peer authorization on the responder (fail closed)"
```

---

### Task 2: Serve-role wiring — responder always-on when federated

**Files:**
- Modify: `internal/node/node.go` (wiring block, currently ~lines 151-162)
- Test: `internal/node/wiring_repquery_test.go`

**Interfaces:**
- Consumes: `repquery.RegisterResponder(h, s, auth)` (Task 1); `ts *trust.Store`; `identity.GeneratePersonKey`, `identity.EncodePub`, `identity.PersonPub`, `identity.IssueCert`, `trust.SaveAnchors`, `trust.SaveCerts` (all existing).
- Produces: responder registered whenever `t != nil`, authorized by the node's trust store; querier/resolver gating unchanged.

- [ ] **Step 1: Write the failing test**

Add to `internal/node/wiring_repquery_test.go` (reuse the file's existing helpers for hosts/config; `filepath`, `identity`, `trust`, `multiaddr` imports may need adding — mirror `node_test.go`'s vouched-reporter test for the identity/trust calls):

```go
// TestResponderServeRoleAuthz: a federated node (transport, NO aggregators)
// registers the responder; an anchored client is answered, a stranger is reset.
func TestResponderServeRoleAuthz(t *testing.T) {
	ctx := context.Background()

	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	// NO cfg.FederationAggregators — pure serve role.

	// Anchor a person and vouch the client host's peer ID BEFORE node.New,
	// so the trust store loads both at construction.
	client, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()
	priv, err := identity.GeneratePersonKey(filepath.Join(t.TempDir(), "p.key"))
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), []trust.Anchor{{
		Person: "p", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "test",
	}}); err != nil {
		t.Fatalf("save anchors: %v", err)
	}
	cert := identity.IssueCert(priv, client.ID().String(), time.Now().Add(time.Hour))
	if err := trust.SaveCerts(cfg.TrustCertsFile(), []proto.PeerCert{cert}); err != nil {
		t.Fatalf("save certs: %v", err)
	}

	tr := newTestTransport(t, ctx) // use/extract the transport construction already in this file
	n, err := New(cfg, tr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	// Anchored client: stream completes, decodes an (empty) ScoreEntry.
	if err := client.Connect(ctx, peer.AddrInfo{ID: tr.Host().ID(), Addrs: tr.Host().Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	s, err := client.NewStream(ctx, tr.Host().ID(), repquery.ProtocolID)
	if err != nil {
		t.Fatalf("anchored newstream: %v", err)
	}
	if err := json.NewEncoder(s).Encode(proto.RepQuery{IP: "203.0.113.50"}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var e proto.ScoreEntry
	if err := json.NewDecoder(s).Decode(&e); err != nil {
		t.Fatalf("anchored client should get an answer, got: %v", err)
	}
	_ = s.Close()

	// Stranger: stream is reset before an answer.
	stranger, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("stranger: %v", err)
	}
	defer stranger.Close()
	if err := stranger.Connect(ctx, peer.AddrInfo{ID: tr.Host().ID(), Addrs: tr.Host().Addrs()}); err != nil {
		t.Fatalf("stranger connect: %v", err)
	}
	s2, err := stranger.NewStream(ctx, tr.Host().ID(), repquery.ProtocolID)
	if err != nil {
		t.Fatalf("stranger newstream: %v", err)
	}
	_ = json.NewEncoder(s2).Encode(proto.RepQuery{IP: "203.0.113.50"})
	var e2 proto.ScoreEntry
	if err := json.NewDecoder(s2).Decode(&e2); err == nil {
		t.Errorf("stranger should be reset, got answer %+v", e2)
	}
	_ = s2.Close()
}
```

(If the wiring test file builds its transport inline rather than via a helper, extract or repeat that construction — `transport.New(ctx, transport.Options{ListenAddrs: …})` exactly as the existing test does.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/node/ -run TestResponderServeRoleAuthz -v`
Expected: FAIL — the anchored client's stream errors, because the responder is only registered when aggregators are configured (this node has none).

- [ ] **Step 3: Move the registration in `node.New`**

In `internal/node/node.go`, restructure the wiring block:

```go
	if t != nil {
		// Serve role (design 2026-07-10 §4): always answer anchored,
		// non-blocked peers when federated. Defederation (blocked_peers)
		// is the per-peer off switch.
		repquery.RegisterResponder(t.Host(), s, ts)
	}

	var resolver *repquery.Resolver
	if t != nil && len(cfg.FederationAggregators) > 0 {
		aggs := parseAggregators(cfg.FederationAggregators)
		if len(aggs) == 0 {
			log.Printf("node: federation_aggregators set but none parsed to a valid peer; federated query disabled")
		} else {
			q := repquery.NewQuerier(t.Host(), aggs, cfg.EffectiveQueryTimeout(), cfg.EffectiveQueryCacheTTL())
			resolver = repquery.NewResolver(s, q)
		}
	}
```

(The `RegisterResponder` call is removed from the inner block — it must appear exactly once.)

- [ ] **Step 4: Run node + integration suites**

Run: `go build ./... && go test ./internal/node/... -race && go test ./test/integration/ -v -run 'TestFederatedLookup|TestNodeWiring|TestResponderServeRole' 2>&1 | tail -15`
Expected: PASS, including the pre-existing `TestNodeWiringFederatesBothReadSurfaces` (its client-role node now also registers a responder — harmless) and the new serve-role test.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/node/node.go internal/node/wiring_repquery_test.go
git add internal/node/node.go internal/node/wiring_repquery_test.go
git commit -m "feat(node): register repquery responder whenever federated (serve role decoupled from client role)"
```

---

### Task 3: Bounded querier cache (B3a)

**Files:**
- Modify: `internal/repquery/querier.go`
- Test: `internal/repquery/querier_test.go`

**Interfaces:**
- Produces: package var `maxCacheEntries = 65536`; eviction inside `Query`'s cache-write path. No exported API change.

- [ ] **Step 1: Write the failing test**

Add to `internal/repquery/querier_test.go`:

```go
func TestQuerierCacheBounded(t *testing.T) {
	old := maxCacheEntries
	maxCacheEntries = 3
	defer func() { maxCacheEntries = old }()

	// No aggregators: every Query is an instant negative, exercising only the cache.
	q := NewQuerier(nil, nil, 100*time.Millisecond, time.Minute)
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	for _, ip := range ips {
		q.Query(context.Background(), ip)
	}
	q.mu.Lock()
	size := len(q.cache)
	_, oldestPresent := q.cache["10.0.0.1"]
	q.mu.Unlock()
	if size > 3 {
		t.Errorf("cache size = %d, want <= 3", size)
	}
	if oldestPresent {
		t.Error("oldest entry should have been evicted")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/repquery/ -run TestQuerierCacheBounded -v`
Expected: FAIL — `maxCacheEntries` undefined (compile error).

- [ ] **Step 3: Implement the bound**

In `internal/repquery/querier.go`, add near the top:

```go
// maxCacheEntries bounds the per-IP answer cache. Package var so tests can
// shrink it (same precedent as responderStreamTimeout).
var maxCacheEntries = 65536
```

In `Query`, replace the cache write with a bounded insert:

```go
	q.mu.Lock()
	if len(q.cache) >= maxCacheEntries {
		q.evictLocked(now)
	}
	q.cache[ip] = cacheEntry{entry: merged, ok: ok, at: now}
	q.mu.Unlock()
```

Add the eviction helper (mirrors `internal/node/dedup.go` `evictOldestLocked`: expired first, then single oldest):

```go
// evictLocked drops expired entries first, then the single oldest if still at
// capacity. Caller holds q.mu. Negative entries expire at cacheTTL/5, positive
// at cacheTTL (same rule the read path applies).
func (q *Querier) evictLocked(now time.Time) {
	for k, c := range q.cache {
		ttl := q.cacheTTL
		if !c.ok {
			ttl = q.cacheTTL / 5
		}
		if now.Sub(c.at) >= ttl {
			delete(q.cache, k)
		}
	}
	if len(q.cache) < maxCacheEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	first := true
	for k, c := range q.cache {
		if first || c.at.Before(oldest) {
			oldest, oldestKey, first = c.at, k, false
		}
	}
	if oldestKey != "" {
		delete(q.cache, oldestKey)
	}
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/repquery/ -race -run TestQuerier -v`
Expected: PASS (all querier tests, old and new).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/repquery/querier.go internal/repquery/querier_test.go
git add internal/repquery/querier.go internal/repquery/querier_test.go
git commit -m "fix(repquery): bound the querier answer cache (evict expired, then oldest)"
```

---

### Task 4: Singleflight de-dup + peerstore seeding (B3b, B5)

**Files:**
- Modify: `internal/repquery/querier.go`, `go.mod` (promote `golang.org/x/sync`)
- Test: `internal/repquery/querier_test.go`

**Interfaces:**
- Consumes: `golang.org/x/sync/singleflight` (`Group.Do(key string, fn func() (interface{}, error)) (interface{}, error, bool)`); `github.com/libp2p/go-libp2p/core/peerstore` (`peerstore.PermanentAddrTTL`).
- Produces: no exported API change. `NewQuerier` seeds the host peerstore; `ask` no longer calls `Connect`.

- [ ] **Step 1: Write the failing test**

Add to `internal/repquery/querier_test.go`:

```go
func TestQuerierSingleflight(t *testing.T) {
	ctx := context.Background()
	agg, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("agg: %v", err)
	}
	defer agg.Close()
	counter := &countStore{ip: "6.6.6.6", rec: store.ScoreRecord{Score: 60, LastSeen: time.Now()}}
	RegisterResponder(agg, counter, fakeAuth{anchored: true})

	client, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	q := NewQuerier(client, []peer.AddrInfo{{ID: agg.ID(), Addrs: agg.Addrs()}}, 2*time.Second, time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := q.Query(ctx, "6.6.6.6"); !ok {
				t.Error("concurrent query lost the answer")
			}
		}()
	}
	wg.Wait()
	if counter.calls != 1 {
		t.Errorf("responder called %d times for one IP, want 1 (singleflight)", counter.calls)
	}
}
```

(`countStore.calls` is written from the aggregator's handler goroutine and read after `wg.Wait()`; the existing `countStore` has no mutex. Under `-race`, guard it: give `countStore` a `sync.Mutex` around `calls` in `GetScore` and add a `callCount()` accessor; update the existing tests that read `.calls` accordingly.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/repquery/ -race -run TestQuerierSingleflight -v`
Expected: FAIL — `counter.calls` is 8 (every goroutine fans out; no de-dup yet).

- [ ] **Step 3: Implement singleflight + peerstore seeding**

`go get golang.org/x/sync@v0.20.0` (promotes the existing indirect entry to a direct requirement — run `go mod tidy` after).

In `internal/repquery/querier.go`:

1. Imports: add `"golang.org/x/sync/singleflight"` and `"github.com/libp2p/go-libp2p/core/peerstore"`; drop `"github.com/libp2p/go-libp2p/core/network"` (only used by the `Connect` check being removed).
2. Struct: add field `sf singleflight.Group` to `Querier`.
3. `NewQuerier`: seed addresses once (replaces per-ask `Connect`):

```go
// NewQuerier builds a Querier. aggregators is the trusted set to ask; their
// addresses are seeded into the host peerstore so NewStream can dial them
// without an explicit Connect per query.
func NewQuerier(h host.Host, aggregators []peer.AddrInfo, timeout, cacheTTL time.Duration) *Querier {
	if h != nil {
		for _, a := range aggregators {
			h.Peerstore().AddAddrs(a.ID, a.Addrs, peerstore.PermanentAddrTTL)
		}
	}
	return &Querier{host: h, aggregators: aggregators, timeout: timeout, cacheTTL: cacheTTL, cache: map[string]cacheEntry{}}
}
```

4. `Query`: wrap the miss path in singleflight — the fan-out AND the cache write happen inside `Do`, so followers share the result and do not rewrite the cache:

```go
	type qres struct {
		entry proto.ScoreEntry
		ok    bool
	}
	v, _, _ := q.sf.Do(ip, func() (interface{}, error) {
		merged, ok := q.fanout(ctx, ip)
		q.mu.Lock()
		if len(q.cache) >= maxCacheEntries {
			q.evictLocked(time.Now())
		}
		q.cache[ip] = cacheEntry{entry: merged, ok: ok, at: time.Now()}
		q.mu.Unlock()
		return qres{merged, ok}, nil
	})
	r := v.(qres)
	return r.entry, r.ok
```

(The `now := time.Now()` captured before the cache-read stays for the read path only; the write path timestamps at write time — this also fixes the "cache entry timestamped pre-fanout" minor from the E3 final review.)

5. `ask`: delete the two `Connect` lines:

```go
	// removed:
	// if q.host.Network().Connectedness(a.ID) != network.Connected {
	// 	_ = q.host.Connect(ctx, a)
	// }
```

`NewStream(ctx, a.ID, ProtocolID)` dials using the peerstore addresses seeded in `NewQuerier`.

- [ ] **Step 4: Run the full repquery suite (regression: no-Connect dialing)**

Run: `go test ./internal/repquery/ -race -v 2>&1 | tail -25 && go build ./... && go vet ./internal/repquery/...`
Expected: all PASS — `TestQuerierFetchesAndCaches` et al. now dial purely via seeded peerstore addresses, which IS the no-explicit-Connect regression test.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/repquery/querier.go internal/repquery/querier_test.go
git add internal/repquery/querier.go internal/repquery/querier_test.go go.mod go.sum
git commit -m "fix(repquery): singleflight in-flight de-dup + peerstore seeding instead of per-ask Connect"
```

---

### Task 5: Multi-bridge echo test + adversarial Sybil-querier scenario

**Files:**
- Test: `test/integration/bridge_test.go` (add one test)
- Test: `test/adversarial/repquery_sybil_test.go` (new; match the build tag + package clause of the existing files in `test/adversarial/` — check with `head -5 test/adversarial/*.go`)

**Interfaces:**
- Consumes: `node.New(cfg, nil)`, `node.Node.ProcessRemote`, `node.Node.GetScore` (exported); `identity.SignEvent`, `identity.PeerIDFromPrivKey`; `libp2pcrypto.GenerateEd25519Key`; `repquery.RegisterResponder(h, s, auth)`.

- [ ] **Step 1: Write the multi-bridge echo-suppression test**

Add to `test/integration/bridge_test.go` (imports to add: `crypto/rand`, `libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"`, `"github.com/JoeRu/federloom/internal/identity"`):

```go
// TestMultiBridgeEchoScoredOnce: a node reachable via TWO bridges receives two
// copies of the same origin event (identical signed content, different
// OriginTrace last hop). The dedup cache must score it exactly once.
// E1 design §4: first-seen wins; ledger minor "echo-suppression only
// single-bridge tested" closed here.
func TestMultiBridgeEchoScoredOnce(t *testing.T) {
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationSubnet = "b"
	c, err := node.New(cfg, nil) // leaf in subnet b; ProcessRemote driven directly
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer c.CloseStores()

	// A signed origin event. The signature covers IP|Reason|Timestamp|ReporterID
	// — NOT OriginTrace — so both bridged copies carry the same valid signature.
	priv, _, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	origID, err := identity.PeerIDFromPrivKey(priv)
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}
	base := proto.Event{
		IP:         "198.51.100.88",
		Reason:     "ssh-probe",
		ReporterID: origID,
		Timestamp:  time.Now().UTC(),
	}
	if err := identity.SignEvent(&base, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	copy1 := base
	copy1.OriginTrace = []string{origID, "12D3KooWbridge1"}
	copy2 := base
	copy2.OriginTrace = []string{origID, "12D3KooWbridge2"}

	c.ProcessRemote(transport.ReceivedEvent{Event: copy1, From: "12D3KooWbridge1", Subnet: "b"})
	rec1, err := c.GetScore("198.51.100.88")
	if err != nil || rec1.LastSeen.IsZero() {
		t.Fatalf("first bridged copy was not scored: %+v err=%v", rec1, err)
	}

	c.ProcessRemote(transport.ReceivedEvent{Event: copy2, From: "12D3KooWbridge2", Subnet: "b"})
	rec2, _ := c.GetScore("198.51.100.88")
	if rec2.Score != rec1.Score || rec2.Corroboration != rec1.Corroboration {
		t.Errorf("second copy via other bridge changed the record: %+v -> %+v (dedup failed)", rec1, rec2)
	}
}
```

- [ ] **Step 2: Run it**

Run: `go test ./test/integration/ -run TestMultiBridgeEchoScoredOnce -v`
Expected: PASS (dedup already keys on ReporterID|IP|Reason|Timestamp — this closes the coverage gap). If it FAILS, that is a real E1 bug: STOP and escalate rather than adjusting the assertion.

- [ ] **Step 3: Write the adversarial Sybil-querier scenario**

Create `test/adversarial/repquery_sybil_test.go`. First check the existing convention: `head -5 test/adversarial/*.go` — use the same `//go:build adversarial` tag and package clause. Content:

```go
//go:build adversarial

package adversarial_test // match the actual package name found above

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/repquery"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

type denyAllAuth struct{}

func (denyAllAuth) Resolve(string) (float64, string, bool) { return 0, "", false }
func (denyAllAuth) IsBlocked(string) bool                  { return false }

type sybilStore struct{ rec store.ScoreRecord }

func (s sybilStore) GetScore(string) (store.ScoreRecord, error) { return s.rec, nil }

// TestSybilStrangerQueriersGainNothing: a wave of stranger peers hammering the
// repquery responder is reset every time — no data served, no crash, and the
// served store is never mutated (read-only + fail-closed authorization).
func TestSybilStrangerQueriersGainNothing(t *testing.T) {
	ctx := context.Background()
	srv, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("srv: %v", err)
	}
	defer srv.Close()
	repquery.RegisterResponder(srv, sybilStore{rec: store.ScoreRecord{Score: 99, LastSeen: time.Now()}}, denyAllAuth{})

	for i := 0; i < 5; i++ {
		sybil, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		if err != nil {
			t.Fatalf("sybil %d: %v", i, err)
		}
		if err := sybil.Connect(ctx, peer.AddrInfo{ID: srv.ID(), Addrs: srv.Addrs()}); err != nil {
			t.Fatalf("sybil %d connect: %v", i, err)
		}
		s, err := sybil.NewStream(ctx, srv.ID(), repquery.ProtocolID)
		if err != nil {
			sybil.Close()
			continue // stream refused outright is also a pass
		}
		_ = json.NewEncoder(s).Encode(proto.RepQuery{IP: "1.2.3.4"})
		var e proto.ScoreEntry
		if err := json.NewDecoder(s).Decode(&e); err == nil {
			t.Errorf("sybil %d received an answer: %+v (authorization bypassed)", i, e)
		}
		_ = s.Close()
		sybil.Close()
	}
}
```

- [ ] **Step 4: Run both**

Run: `go test -tags adversarial ./test/adversarial/ -run TestSybilStrangerQueriersGainNothing -v && go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3`
Expected: PASS, whole adversarial suite green.

- [ ] **Step 5: Commit**

```bash
gofmt -w test/integration/bridge_test.go test/adversarial/repquery_sybil_test.go
git add test/integration/bridge_test.go test/adversarial/repquery_sybil_test.go
git commit -m "test: multi-bridge echo suppression + adversarial Sybil stranger-querier scenario"
```

---

### Task 6: Docs + roadmap check-off + full verification gate

**Files:**
- Modify: `docs/config.md` (federation section), `docs/threat-model.md`, `docs/roadmap.md`

- [ ] **Step 1: Update `docs/config.md`**

In the `federation_aggregators` section, append:

```markdown
**Serving queries (no config needed):** every federated node (i.e. with a
transport) answers `/federloom/repquery/v1` queries — but only from peers
that are **anchored** in its trust store and **not** on its `blocked_peers`
list. Strangers are rejected before their request is read. Defederation
(adding a peer to `blocked_peers`) is the per-peer off switch; a node with
no trust anchors answers nobody.
```

- [ ] **Step 2: Update `docs/threat-model.md`**

Add under the federation/transport threats (match the file's existing style):

```markdown
- **Reputation-oracle abuse (repquery):** the on-demand query responder
  authorizes per peer — anchored ∧ not blocked, fail closed — so strangers
  and defederated peers cannot read reputation data (closes the E3 review
  finding). Streams carry a deadline (slowloris-bounded); a Sybil stranger
  wave gains nothing (adversarial: `repquery_sybil_test.go`).
```

- [ ] **Step 3: Check off roadmap Step 1**

In `docs/roadmap.md`: mark Step 1 done, e.g. change the Step 1 heading line to
`### Step 1 — Repquery hardening (small, security) → B1, B3, B5 ✅ done 2026-07-10`
and in Part 2 table B, annotate B1 (`✅ resolved — trust-store authz, fail closed`), B3 (`✅ resolved — bounded cache + singleflight`), B5 (`✅ resolved — Reset/deadline-log/peerstore-seeding; multi-bridge echo test added; lowest-hop re-scoring stays parked`).

- [ ] **Step 4: Full gate**

Run: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/ && go test ./... 2>&1 | tail -5 && go test -tags adversarial ./test/adversarial/... 2>&1 | tail -3 && go test -tags integration ./test/integration/... 2>&1 | tail -3`
Expected: build/vet clean, `gofmt -l` prints nothing, all suites PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/config.md docs/threat-model.md docs/roadmap.md
git commit -m "docs: repquery serve-role authorization, threat-model note, roadmap Step 1 done"
```
