# Subnet-Bridge Forwarding + Functional Origin-Tracing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce per-subnet gossip topics and bridge nodes that re-emit events across subnet boundaries with a hop appended, so the previously-inert `FederationDiscount` and A→B→A loop guard become active (and correct), backed by an app-level dedup cache.

**Architecture:** The home subnet maps to the existing topic (default unchanged); bridge nodes additionally join their `bridge_subnets` topics and re-emit received events onto the other bridged topics with `selfID` appended to `OriginTrace`. A first-seen dedup cache keyed by event identity prevents amplification and double-scoring. The discount exponent is corrected to `len(OriginTrace)-1` (bridge hops), so a same-subnet direct event is not discounted.

**Tech Stack:** Go 1.22, libp2p gossipsub (multi-topic), `net/netip`, `go test` (unit + `adversarial` tag).

## Global Constraints

- Go module `github.com/JoeRu/federloom`, Go 1.22. Conventional Commits.
- `internal/transport`, `internal/node` touched here are security/behaviour-sensitive: surgical, conservative.
- Backward compatibility: a node with no `federation_subnet` / `federation_bridge_subnets` joins exactly the existing `DefaultTopic` (`federloom/events/v0`) and behaves as today (leaf, single topic).
- The home subnet `""` or `"default"` maps to the base topic (no suffix); a named subnet `s` maps to `base + "/" + s`.
- Each unique event `(ReporterID, IP, Reason, Timestamp)` is processed exactly once per node (first-seen dedup); first-seen wins (strict lowest-hop re-scoring is OUT of scope).
- `OriginTrace` is NOT part of the signed `eventMessage` (`internal/identity/sign.go` signs `IP|Reason|Timestamp|ReporterID` only), so appending a hop preserves the originator's signature — do not re-sign.
- Discount = `FederationDiscount ^ (len(OriginTrace) - 1)` for non-anchored reporters (bridge hops; excludes the originator). Anchored reporters are never discounted. `FederationDiscount` default = 0.5, lives at `cfg.Trust.FederationDiscount`.
- `maxOriginTraceLen` (existing constant, 8) caps trace growth; a bridge does not re-emit at or above the cap.
- Every reputation/trust/ingest/transport change adds or updates a test; `make adversarial` is the CI gate.

---

### Task 1: Config — `federation_subnet` + `federation_bridge_subnets`

**Files:**
- Modify: `internal/config/config.go` (top-level `Config` struct + a validation helper)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `Config.FederationSubnet string` (yaml `federation_subnet`), `Config.FederationBridgeSubnets []string` (yaml `federation_bridge_subnets`); `func (c *Config) EffectiveBridgeSubnets() []string` returning bridge subnets with any entry equal to the home subnet removed.

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestEffectiveBridgeSubnets(t *testing.T) {
	c := &config.Config{
		FederationSubnet:        "a",
		FederationBridgeSubnets: []string{"a", "b", "c"},
	}
	got := c.EffectiveBridgeSubnets()
	want := []string{"b", "c"} // "a" == home subnet is dropped
	if len(got) != len(want) {
		t.Fatalf("EffectiveBridgeSubnets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestEffectiveBridgeSubnetsEmpty(t *testing.T) {
	c := &config.Config{}
	if got := c.EffectiveBridgeSubnets(); len(got) != 0 {
		t.Errorf("expected no bridge subnets, got %v", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/config/ -run TestEffectiveBridgeSubnets -v`
Expected: FAIL — fields/method undefined.

- [ ] **Step 3: Add the fields and helper**

In `internal/config/config.go`, add to the top-level `Config` struct (right after `FederationMode`):

```go
	FederationMode           string   `yaml:"federation_mode"`
	FederationSubnet         string   `yaml:"federation_subnet"`         // home trust domain; "" or "default" = base topic
	FederationBridgeSubnets  []string `yaml:"federation_bridge_subnets"` // subnets this node bridges (empty = leaf)
```

Add the helper (near the `Config` methods):

```go
// EffectiveBridgeSubnets returns the configured bridge subnets minus any entry
// that equals the home subnet (bridging to yourself is meaningless).
func (c *Config) EffectiveBridgeSubnets() []string {
	out := make([]string, 0, len(c.FederationBridgeSubnets))
	for _, s := range c.FederationBridgeSubnets {
		if s == c.FederationSubnet {
			continue
		}
		out = append(out, s)
	}
	return out
}
```

`Defaults()` needs no change (zero value `""` / `nil` = leaf on the base topic).

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/config/ -run TestEffectiveBridgeSubnets -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/config/config.go internal/config/config_test.go
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add federation_subnet and federation_bridge_subnets"
```

---

### Task 2: Transport — multi-topic (SubnetTopic, join/publish per subnet, ReceivedEvent.Subnet)

**Files:**
- Modify: `internal/transport/options.go` (Options fields + `SubnetTopic`)
- Modify: `internal/transport/gossip.go` (multi-topic Node, `Publish(ctx, e, subnet)`, per-sub readLoop, `ReceivedEvent.Subnet`, Close)
- Modify: `internal/node/node.go` (the single `Publish` caller, ~line 296)
- Modify: `cmd/federloomd/main.go` (populate `Options.Subnet` / `Options.BridgeSubnets` from config)
- Test: `internal/transport/options_test.go` (SubnetTopic)

**Interfaces:**
- Consumes: `config.Config.FederationSubnet`, `config.Config.EffectiveBridgeSubnets()` (Task 1).
- Produces: `Options.Subnet string`, `Options.BridgeSubnets []string`; `func SubnetTopic(base, subnet string) string`; `ReceivedEvent.Subnet string` (arrival subnet); `func (n *Node) Publish(ctx context.Context, e proto.Event, subnet string) error`.

- [ ] **Step 1: Write the failing SubnetTopic test**

Add to `internal/transport/options_test.go`:

```go
func TestSubnetTopic(t *testing.T) {
	base := DefaultTopic
	cases := []struct{ subnet, want string }{
		{"", base},
		{"default", base},
		{"acme", base + "/acme"},
	}
	for _, c := range cases {
		if got := SubnetTopic(base, c.subnet); got != c.want {
			t.Errorf("SubnetTopic(%q, %q) = %q, want %q", base, c.subnet, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/transport/ -run TestSubnetTopic -v`
Expected: FAIL — `SubnetTopic` undefined.

- [ ] **Step 3: Add Options fields + SubnetTopic**

In `internal/transport/options.go`, add to `Options`:

```go
	// Subnet is this node's home trust domain. "" or "default" = the base topic.
	Subnet string
	// BridgeSubnets are additional subnets this node joins and relays between.
	BridgeSubnets []string
```

Add the helper (package-level, in `options.go`):

```go
// SubnetTopic returns the gossipsub topic for a subnet. "" or "default" maps to
// the base topic (backward compatible); a named subnet s maps to base+"/"+s.
func SubnetTopic(base, subnet string) string {
	if subnet == "" || subnet == "default" {
		return base
	}
	return base + "/" + subnet
}
```

- [ ] **Step 4: Make the transport Node multi-topic**

In `internal/transport/gossip.go`, replace the single `topic`/`sub` fields on `Node` and their wiring with a per-subnet map. Change the `Node` struct:

```go
type Node struct {
	host     host.Host
	ps       *pubsub.PubSub
	dht      *dht.IpfsDHT
	topics   map[string]*topicHandle // keyed by subnet name (canonical config string)
	events   chan ReceivedEvent
	stopLoop context.CancelFunc
}

// topicHandle bundles a joined topic + its subscription for one subnet.
type topicHandle struct {
	subnet string
	topic  *pubsub.Topic
	sub    *pubsub.Subscription
}
```

Add `Subnet` to `ReceivedEvent`:

```go
type ReceivedEvent struct {
	Event  proto.Event
	From   string
	Subnet string // subnet whose topic delivered this copy
}
```

Rewrite `New` so it joins the home subnet plus every bridge subnet. Replace the topic/subscribe block and the `Node{...}` construction with:

```go
	base := opts.Topic
	if base == "" {
		base = DefaultTopic
	}

	// Join the home subnet + each bridge subnet (deduplicated by subnet name).
	subnets := []string{opts.Subnet}
	seen := map[string]bool{opts.Subnet: true}
	for _, s := range opts.BridgeSubnets {
		if !seen[s] {
			seen[s] = true
			subnets = append(subnets, s)
		}
	}

	loopCtx, stopLoop := context.WithCancel(ctx)
	n := &Node{
		host:     h,
		ps:       ps,
		dht:      d,
		topics:   make(map[string]*topicHandle, len(subnets)),
		events:   make(chan ReceivedEvent, 64),
		stopLoop: stopLoop,
	}
	for _, s := range subnets {
		t, err := ps.Join(SubnetTopic(base, s))
		if err != nil {
			return nil, fmt.Errorf("transport: join subnet %q: %w", s, err)
		}
		sub, err := t.Subscribe()
		if err != nil {
			return nil, fmt.Errorf("transport: subscribe subnet %q: %w", s, err)
		}
		h := &topicHandle{subnet: s, topic: t, sub: sub}
		n.topics[s] = h
		go n.readLoop(loopCtx, h)
	}
	ok = true
	return n, nil
```

(Delete the old single `t, err := ps.Join(...)` / `sub, err := t.Subscribe()` block and the old `Node{...}` literal it fed.)

Rewrite `Publish` to target a subnet:

```go
// Publish JSON-encodes e and publishes it to the given subnet's topic. The node
// must be joined to that subnet (home or a bridge subnet), else an error.
func (n *Node) Publish(ctx context.Context, e proto.Event, subnet string) error {
	h, ok := n.topics[subnet]
	if !ok {
		return fmt.Errorf("transport: not joined to subnet %q", subnet)
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("transport: marshal event: %w", err)
	}
	return h.topic.Publish(ctx, data)
}
```

Rewrite `readLoop` to take a handle and tag the arrival subnet:

```go
func (n *Node) readLoop(ctx context.Context, h *topicHandle) {
	for {
		msg, err := h.sub.Next(ctx)
		if err != nil {
			return
		}
		if msg.GetFrom() == n.host.ID() {
			continue // skip our own messages
		}
		var e proto.Event
		if err := json.Unmarshal(msg.Data, &e); err != nil {
			continue
		}
		select {
		case n.events <- ReceivedEvent{Event: e, From: msg.GetFrom().String(), Subnet: h.subnet}:
		case <-ctx.Done():
			return
		}
	}
}
```

(Note: the old `readLoop` closed `n.events` via `defer`. With multiple loops, do NOT close the channel from any single loop. Remove the `defer close(n.events)`; the channel is left to be GC'd after Close cancels the loops — consumers select on it and on ctx.Done.)

Rewrite `Close` to tear down every topic/sub:

```go
func (n *Node) Close() error {
	n.stopLoop()
	for _, h := range n.topics {
		h.sub.Cancel()
		_ = h.topic.Close()
	}
	_ = n.dht.Close()
	return n.host.Close()
}
```

- [ ] **Step 5: Update the Publish caller and main wiring**

In `internal/node/node.go` (~line 296), change:
```go
		if err := n.transport.Publish(ctx, e); err != nil {
```
to publish to the node's home subnet:
```go
		if err := n.transport.Publish(ctx, e, n.cfg.FederationSubnet); err != nil {
```

In `cmd/federloomd/main.go`, where `transport.Options{...}` is populated, add the two fields from config:
```go
		Subnet:        cfg.FederationSubnet,
		BridgeSubnets: cfg.EffectiveBridgeSubnets(),
```
(Match the existing Options literal; if the file builds Options field-by-field, add the two assignments alongside `Mode`/`Topic`.)

The `Publish` signature change also breaks two existing test callers in `test/integration/cluster_test.go` (lines ~64 and ~94, `leaves[i].Publish(ctx, want)`). Update both to publish to the default subnet:
```go
	if err := leaves[0].Publish(ctx, want, ""); err != nil {
```
```go
	if err := leaves[2].Publish(ctx, want, ""); err != nil {
```
(These nodes use the default subnet `""` → base topic, so behaviour is unchanged.)

- [ ] **Step 6: Run transport + build**

Run: `go test ./internal/transport/ -run TestSubnetTopic -v && go build ./...`
Expected: PASS; build clean (the Publish signature change compiles with the updated caller).

- [ ] **Step 7: Run transport + node suites (regression)**

Run: `go test ./internal/transport/... ./internal/node/...`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
gofmt -w internal/transport/options.go internal/transport/options_test.go internal/transport/gossip.go internal/node/node.go cmd/federloomd/main.go
git add internal/transport/options.go internal/transport/options_test.go internal/transport/gossip.go internal/node/node.go cmd/federloomd/main.go
git commit -m "feat(transport): multi-topic subnets (SubnetTopic, per-subnet publish, arrival tagging)"
```

---

### Task 3: Dedup cache

**Files:**
- Create: `internal/node/dedup.go`
- Test: `internal/node/dedup_test.go`

**Interfaces:**
- Produces: `func dedupKey(reporterID, ip, reason string, ts time.Time) string`; `type dedupCache`; `func newDedupCache(max int, ttl time.Duration) *dedupCache`; `func (d *dedupCache) Seen(key string, now time.Time) bool` (marks-and-reports: true if already present).

- [ ] **Step 1: Write the failing test**

Create `internal/node/dedup_test.go`:

```go
package node

import (
	"testing"
	"time"
)

func TestDedupSeenFirstThenRepeat(t *testing.T) {
	d := newDedupCache(100, time.Minute)
	now := time.Now()
	k := dedupKey("peerA", "1.2.3.4", "ssh-probe", now)
	if d.Seen(k, now) {
		t.Error("first Seen must return false (not seen before)")
	}
	if !d.Seen(k, now) {
		t.Error("second Seen must return true (already seen)")
	}
}

func TestDedupDistinctKeys(t *testing.T) {
	d := newDedupCache(100, time.Minute)
	now := time.Now()
	if d.Seen(dedupKey("peerA", "1.2.3.4", "ssh-probe", now), now) {
		t.Error("distinct key A wrongly seen")
	}
	if d.Seen(dedupKey("peerB", "1.2.3.4", "ssh-probe", now), now) {
		t.Error("distinct key B (different reporter) wrongly seen")
	}
}

func TestDedupTTLEviction(t *testing.T) {
	d := newDedupCache(100, time.Minute)
	t0 := time.Now()
	k := dedupKey("peerA", "1.2.3.4", "ssh-probe", t0)
	d.Seen(k, t0)
	// After the TTL window, the key is expired and treated as new again.
	if d.Seen(k, t0.Add(2*time.Minute)) {
		t.Error("key past TTL must be treated as not-seen")
	}
}

func TestDedupBoundEviction(t *testing.T) {
	d := newDedupCache(2, time.Hour)
	now := time.Now()
	d.Seen(dedupKey("p1", "1.1.1.1", "r", now), now)
	d.Seen(dedupKey("p2", "2.2.2.2", "r", now), now)
	d.Seen(dedupKey("p3", "3.3.3.3", "r", now), now) // triggers eviction of oldest
	if d.len() > 2 {
		t.Errorf("cache exceeded bound: len=%d, want <= 2", d.len())
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/node/ -run TestDedup -v`
Expected: FAIL — dedup symbols undefined.

- [ ] **Step 3: Implement the dedup cache**

Create `internal/node/dedup.go`:

```go
package node

import (
	"sync"
	"time"
)

// dedupKey identifies an event by the fields the originator's signature covers,
// so a re-emitted copy (which only differs in OriginTrace) yields the same key.
func dedupKey(reporterID, ip, reason string, ts time.Time) string {
	return reporterID + "|" + ip + "|" + reason + "|" + ts.UTC().Format(time.RFC3339Nano)
}

// dedupCache is a bounded, TTL'd set of event keys. Seen marks a key and reports
// whether it was already present. First-seen wins: the caller processes and
// (on a bridge) re-emits only when Seen returns false.
type dedupCache struct {
	mu   sync.Mutex
	max  int
	ttl  time.Duration
	seen map[string]time.Time // key -> insertion time
}

func newDedupCache(max int, ttl time.Duration) *dedupCache {
	return &dedupCache{max: max, ttl: ttl, seen: make(map[string]time.Time)}
}

// Seen returns true if key was already present (and unexpired); otherwise it
// inserts key and returns false. Expired entries are treated as absent.
func (d *dedupCache) Seen(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if at, ok := d.seen[key]; ok && now.Sub(at) < d.ttl {
		return true
	}
	// Insert (or refresh an expired entry). Evict if over bound.
	if len(d.seen) >= d.max {
		d.evictOldestLocked(now)
	}
	d.seen[key] = now
	return false
}

// evictOldestLocked drops expired entries first, then the single oldest if still
// at capacity. Caller holds d.mu.
func (d *dedupCache) evictOldestLocked(now time.Time) {
	for k, at := range d.seen {
		if now.Sub(at) >= d.ttl {
			delete(d.seen, k)
		}
	}
	if len(d.seen) < d.max {
		return
	}
	var oldestKey string
	var oldest time.Time
	first := true
	for k, at := range d.seen {
		if first || at.Before(oldest) {
			oldest, oldestKey, first = at, k, false
		}
	}
	if oldestKey != "" {
		delete(d.seen, oldestKey)
	}
}

func (d *dedupCache) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/node/ -run TestDedup -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/node/dedup.go internal/node/dedup_test.go
git add internal/node/dedup.go internal/node/dedup_test.go
git commit -m "feat(node): app-level event dedup cache (bounded, TTL)"
```

---

### Task 4: Discount exponent fix (bridge hops = len(OriginTrace)-1)

Correct the federation discount so the originator is not counted as a hop. This lands independently: with no bridges, `OriginTrace` is length 1, so the discount becomes a no-op (a same-subnet direct event is no longer halved). Strangers remain capped and non-corroborating, so the change is safe.

**Files:**
- Modify: `internal/node/node.go` (`ProcessRemote` discount loop, ~lines 366-380)
- Test: `test/adversarial/injection_test.go` (add a discount-exponent scenario)

**Interfaces:**
- Consumes: existing `cfg.Trust.FederationDiscount`; `newNodeWithRules`, `mockSink` test helpers.

- [ ] **Step 1: Write the failing test**

Add to `test/adversarial/injection_test.go`:

```go
// TestFederationDiscountPerBridgeHop verifies the discount is applied per bridge
// hop = len(OriginTrace)-1: a direct (len 1) stranger event is NOT discounted,
// and each extra hop multiplies by FederationDiscount. Score after one stranger
// event = stranger_weight * reasonWeight * discount^(hops), read via GetScore.
func TestFederationDiscountPerBridgeHop(t *testing.T) {
	// Two IPs, same reason/weight; one arrives direct (len 1), one via 2 hops (len 3).
	n, _, _ := newNodeWithRules(t, injectionRules)

	direct := transport.ReceivedEvent{
		Event: proto.Event{IP: "203.0.113.40", Reason: "ssh-probe", ReporterID: "strangerD", OriginTrace: []string{"strangerD"}},
		From:  "strangerD",
	}
	twoHop := transport.ReceivedEvent{
		Event: proto.Event{IP: "203.0.113.41", Reason: "ssh-probe", ReporterID: "strangerH", OriginTrace: []string{"strangerH", "bridge1", "bridge2"}},
		From:  "strangerH",
	}
	n.ProcessRemote(direct)
	n.ProcessRemote(twoHop)

	rd, _ := n.GetScore("203.0.113.40")
	rh, _ := n.GetScore("203.0.113.41")
	// Direct event: no discount. Two-bridge event: discount^2 (0.25 with default 0.5).
	// So the direct score must be strictly greater than the two-hop score.
	if !(rd.Score > rh.Score) {
		t.Errorf("direct (len 1) score %.4f must exceed two-hop (len 3) score %.4f", rd.Score, rh.Score)
	}
	// And the two-hop score must be positive (event still recorded, just discounted).
	if rh.Score <= 0 {
		t.Errorf("two-hop event should still record a positive score, got %.4f", rh.Score)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test -tags adversarial ./test/adversarial/ -run TestFederationDiscountPerBridgeHop -v`
Expected: FAIL — with the current `len(OriginTrace)` exponent, the direct event is discounted once (×0.5) and the two-hop event ×0.5³, but the relationship/values differ from the corrected formula; more importantly the direct event is wrongly discounted. (If it happens to pass by luck of ordering, Step 4's assertion on the exact no-discount-for-len-1 still drives the change.)

- [ ] **Step 3: Fix the exponent**

In `internal/node/node.go`, `ProcessRemote`, replace the discount block:

```go
	weight, group, anchored := n.trust.Resolve(e.ReporterID)
	// Federation discount: non-anchored reporters lose weight per hop (spec §5.2).
	// Anchored reporters are exempt — their trust is explicitly established.
	// NOTE: gossipsub forwards raw bytes without appending relay hops to OriginTrace,
	// so len(OriginTrace) is always 1 (set by the originator in processLocal) and the
	// cross-node A→B→A feedback-loop guard above is not yet active at runtime. Both
	// become effective when the forwarding path appends selfID before re-broadcast.
	if !anchored && len(e.OriginTrace) > 0 {
		discount := n.cfg.Trust.FederationDiscount
		if discount <= 0 || discount > 1 {
			discount = 0.5 // safe fallback for misconfigured values
		}
		for i := 0; i < len(e.OriginTrace); i++ {
			weight *= discount
		}
	}
```

with the corrected per-bridge-hop version:

```go
	weight, group, anchored := n.trust.Resolve(e.ReporterID)
	// Federation discount: a non-anchored reporter loses weight per BRIDGE hop —
	// bridgeHops = len(OriginTrace)-1 (the originator itself is not a hop), so a
	// same-subnet direct event (len 1) is NOT discounted, and each subnet crossing
	// multiplies by FederationDiscount (spec §5.2). Anchored reporters are exempt.
	if bridgeHops := len(e.OriginTrace) - 1; !anchored && bridgeHops > 0 {
		discount := n.cfg.Trust.FederationDiscount
		if discount <= 0 || discount > 1 {
			discount = 0.5 // safe fallback for misconfigured values
		}
		for i := 0; i < bridgeHops; i++ {
			weight *= discount
		}
	}
```

- [ ] **Step 4: Run the new test + the adversarial suite**

Run: `go test -tags adversarial ./test/adversarial/ -run TestFederationDiscountPerBridgeHop -v && go test -tags adversarial ./test/adversarial/...`
Expected: the new test PASSES; the existing sybil/stranger scenarios still PASS (stranger score is now un-halved at len 1 but still bounded by `strangerCap`, so caps hold).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/node/node.go test/adversarial/injection_test.go
git add internal/node/node.go test/adversarial/injection_test.go
git commit -m "fix(node): discount per bridge hop (len(OriginTrace)-1), not per trace entry"
```

---

### Task 5: Originator subnet stamping + dedup wiring

Stamp the home subnet on published events and wire the dedup cache into both event paths so each unique event is processed once.

**Files:**
- Modify: `internal/node/node.go` (`Node` struct + `New` add the cache; `processLocal` stamp + dedup; `ProcessRemote` dedup)
- Test: `test/adversarial/injection_test.go` (duplicate remote event scored once)

**Interfaces:**
- Consumes: `newDedupCache`, `dedupKey` (Task 3); `cfg.FederationSubnet` (Task 1).
- Produces: `Node.dedup *dedupCache` field.

- [ ] **Step 1: Write the failing test**

Add to `test/adversarial/injection_test.go`:

```go
// TestDuplicateRemoteEventScoredOnce verifies the dedup cache: the same event
// delivered twice (e.g. via two topology paths) is recorded once, not twice.
func TestDuplicateRemoteEventScoredOnce(t *testing.T) {
	n, dir, _ := newNodeWithRules(t, injectionRules)
	_ = dir
	ts := time.Now().UTC()
	ev := transport.ReceivedEvent{
		Event: proto.Event{IP: "203.0.113.50", Reason: "ssh-probe", ReporterID: "strangerX", Timestamp: ts, OriginTrace: []string{"strangerX"}},
		From:  "strangerX",
	}
	n.ProcessRemote(ev)
	first, _ := n.GetScore("203.0.113.50")
	n.ProcessRemote(ev) // identical event (same reporter/ip/reason/timestamp)
	second, _ := n.GetScore("203.0.113.50")

	if second.Score != first.Score {
		t.Errorf("duplicate event changed score: first=%.4f second=%.4f (want equal — deduped)", first.Score, second.Score)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test -tags adversarial ./test/adversarial/ -run TestDuplicateRemoteEventScoredOnce -v`
Expected: FAIL — the second ProcessRemote re-scores the IP (no dedup yet), so `second.Score > first.Score`.

- [ ] **Step 3: Add the dedup cache to the Node**

In `internal/node/node.go`, add the field to `Node`:

```go
	dedup       *dedupCache
```

In `New`, initialise it (near the other subsystem construction, before the `return &Node{...}`):

```go
	dedup := newDedupCache(100_000, 10*time.Minute)
```

and add `dedup: dedup,` to the returned `&Node{...}` literal.

- [ ] **Step 4: Stamp the subnet and dedup local events in `processLocal`**

In `processLocal`, after `e.ReporterID = n.selfID` and the `OriginTrace` set, add the subnet stamp; and after normalization but before recording, insert into the dedup cache so a bridged copy that loops back is recognised. Specifically, set the subnet where `ReporterID`/`OriginTrace` are set:

```go
	e.ReporterID = n.selfID
	e.Vouch = n.vouch
	e.SubnetID = n.cfg.FederationSubnet
	if n.selfID != "" {
		e.OriginTrace = []string{n.selfID}
	}
```

and after `e.IP = key` (the normalized key) and before `n.rep.Record(...)`, mark it seen:

```go
	_ = n.dedup.Seen(dedupKey(e.ReporterID, e.IP, e.Reason, e.Timestamp), time.Now())
```

(Local events are always processed; the insert exists so a re-emitted copy returning to us is deduped.)

- [ ] **Step 5: Dedup remote events in `ProcessRemote`**

In `ProcessRemote`, after `e.IP = key` (the normalized key) and after the feedback-loop guard, drop duplicates before scoring:

```go
	if n.dedup.Seen(dedupKey(e.ReporterID, e.IP, e.Reason, e.Timestamp), time.Now()) {
		return // already processed this exact event via another path
	}
```

Place this immediately before `weight, group, anchored := n.trust.Resolve(...)`.

- [ ] **Step 6: Run the dedup test + regression**

Run: `go test -tags adversarial ./test/adversarial/ -run 'TestDuplicateRemoteEventScoredOnce|TestStrangerCannotInject|TestAnchored' -v && go test ./internal/node/...`
Expected: the new test PASSES; the existing injection/anchored scenarios still PASS.

- [ ] **Step 7: Commit**

```bash
gofmt -w internal/node/node.go test/adversarial/injection_test.go
git add internal/node/node.go test/adversarial/injection_test.go
git commit -m "feat(node): stamp home subnet on events + dedup each unique event once"
```

---

### Task 6: Bridge re-emission + topology integration test

A bridge re-emits accepted remote events onto its other bridged subnet topics with `selfID` appended, guarded by the loop check, trace cap, and dedup.

**Files:**
- Modify: `internal/node/node.go` (`ProcessRemote` re-emission tail)
- Test: `test/integration/bridge_test.go` (new) — 3-node topology

**Interfaces:**
- Consumes: `transport.ReceivedEvent.Subnet` (Task 2), `transport.Node.Publish(ctx, e, subnet)` (Task 2), `transport.New` with `Options.Subnet`/`BridgeSubnets` (Task 2), `node.New(cfg *config.Config, t *transport.Node) (*node.Node, error)`, `(*node.Node).ProcessRemote`, `(*node.Node).SelfID() string`, `(*node.Node).CloseStores()` (existing exported node API), `cfg.FederationSubnet`, `cfg.EffectiveBridgeSubnets()` (Task 1), `maxOriginTraceLen` (existing).

- [ ] **Step 1: Write the failing integration test**

Create `test/integration/bridge_test.go` (package `integration_test`, no build tag — matching the sibling `cluster_test.go` so it runs under `go test ./test/integration/...`). It builds a **bridge** `node.Node` on a real transport (home subnet `a`, bridging into `b`), a plain **observer** transport on subnet `b`, connects them, drives `ProcessRemote` on the bridge with an event that arrived on subnet `a`, and asserts the observer on `b` receives the re-emitted copy with the bridge's id appended to `OriginTrace`:

```go
package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

func newLocalAddr(t *testing.T) multiaddr.Multiaddr {
	t.Helper()
	m, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("addr: %v", err)
	}
	return m
}

func TestBridgeReemitsAcrossSubnets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Bridge transport: home subnet "a", bridges into "b".
	bridgeTr, err := transport.New(ctx, transport.Options{
		ListenAddrs:   []multiaddr.Multiaddr{newLocalAddr(t)},
		Subnet:        "a",
		BridgeSubnets: []string{"b"},
	})
	if err != nil {
		t.Fatalf("bridge transport: %v", err)
	}
	defer bridgeTr.Close()

	// Observer transport on subnet "b" (stands in for a node C in subnet b).
	obsB, err := transport.New(ctx, transport.Options{
		ListenAddrs: []multiaddr.Multiaddr{newLocalAddr(t)},
		Subnet:      "b",
	})
	if err != nil {
		t.Fatalf("observer transport: %v", err)
	}
	defer obsB.Close()

	// Connect them so the subnet-"b" gossipsub mesh forms.
	if err := obsB.Host().Connect(ctx, peer.AddrInfo{ID: bridgeTr.Host().ID(), Addrs: bridgeTr.Host().Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Bridge node.Node on the bridge transport.
	cfg := config.Defaults()
	cfg.Store.Dir = t.TempDir()
	cfg.FederationSubnet = "a"
	cfg.FederationBridgeSubnets = []string{"b"}
	bridge, err := node.New(cfg, bridgeTr)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer bridge.CloseStores()

	// A stranger event that arrived on subnet "a" (origin A).
	re := transport.ReceivedEvent{
		Event: proto.Event{
			IP:          "198.51.100.77",
			Reason:      "ssh-probe",
			ReporterID:  "origA",
			Timestamp:   time.Now().UTC(),
			OriginTrace: []string{"origA"},
		},
		From:   "origA",
		Subnet: "a",
	}

	// The bridge scores it and re-emits onto subnet "b".
	bridge.ProcessRemote(re)

	select {
	case got := <-obsB.Subscribe():
		if got.Event.IP != re.Event.IP {
			t.Errorf("observer got IP %q, want %q", got.Event.IP, re.Event.IP)
		}
		if got.Subnet != "b" {
			t.Errorf("re-emit arrived on subnet %q, want b", got.Subnet)
		}
		want := []string{"origA", bridge.SelfID()}
		if len(got.Event.OriginTrace) != len(want) {
			t.Fatalf("OriginTrace = %v, want %v", got.Event.OriginTrace, want)
		}
		for i := range want {
			if got.Event.OriginTrace[i] != want[i] {
				t.Errorf("OriginTrace[%d] = %q, want %q", i, got.Event.OriginTrace[i], want[i])
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("observer on subnet b did not receive the bridged event within 3s")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./test/integration/ -run TestBridgeReemitsAcrossSubnets -v`
Expected: FAIL — the bridge does not re-emit yet, so the observer times out at 3s.

- [ ] **Step 3: Implement bridge re-emission**

In `internal/node/node.go`, at the END of `ProcessRemote` (after the event has been scored/enforced and `n.api.Broadcast(...)`), append the re-emission. Add a helper and call it:

```go
	n.reemitIfBridge(re)
}

// reemitIfBridge re-publishes an accepted remote event onto the other subnets
// this node bridges, appending selfID to OriginTrace. Leaves (no bridge subnets)
// and loop/cap conditions are no-ops. The originator's signature is preserved
// (OriginTrace is not signed).
func (n *Node) reemitIfBridge(re transport.ReceivedEvent) {
	if n.transport == nil || n.selfID == "" {
		return
	}
	bridges := n.cfg.EffectiveBridgeSubnets()
	if len(bridges) == 0 {
		return // leaf
	}
	e := re.Event
	// Loop guard: never re-emit an event that already passed through us.
	for _, hop := range e.OriginTrace {
		if hop == n.selfID {
			return
		}
	}
	if len(e.OriginTrace) >= maxOriginTraceLen {
		return
	}
	out := e
	out.OriginTrace = append(append([]string{}, e.OriginTrace...), n.selfID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, sn := range bridges {
		if sn == re.Subnet {
			continue // don't echo back onto the subnet it arrived from
		}
		if err := n.transport.Publish(ctx, out, sn); err != nil {
			log.Printf("node: bridge re-emit to subnet %q failed: %v", sn, err)
		}
	}
}
```

Ensure `ProcessRemote` returns via reaching this tail on the success path (the existing early returns for drops/dedup/loop stay as-is; only fully-processed events reach `reemitIfBridge`).

- [ ] **Step 4: Run the integration test + full suites**

Run: `go test ./test/integration/ -run TestBridgeReemitsAcrossSubnets -v`
Expected: PASS — the observer on subnet `b` receives A's event with `OriginTrace=["origA", <bridge>]`.

Run: `go test ./... && go test -tags adversarial ./test/adversarial/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/node/node.go test/integration/bridge_test.go
git add internal/node/node.go test/integration/bridge_test.go
git commit -m "feat(node): bridge nodes re-emit events across subnets with hop append"
```

---

### Task 7: Docs + final verification

**Files:**
- Modify: `docs/config.md` (federation subnet/bridge config + security note)
- Modify: `docs/threat-model.md` (bridge trust-sensitivity)
- Modify: `docs/architecture.md` (replace the "origin-tracing inert" caveat)
- Modify: `docs/spec.md` (§12a traceability: §5.2 origin-trace/discount now active)

- [ ] **Step 1: Document the config**

In `docs/config.md`, add (near the federation/trust config):

```markdown
### `federation_subnet` and `federation_bridge_subnets`

`federation_subnet` names this node's home trust domain (gossip topic). Empty or
`default` uses the single base topic (the default — a flat federation). A named
subnet joins a dedicated topic `federloom/events/v0/<subnet>`.

`federation_bridge_subnets` lists other subnets this node **bridges**: it joins
their topics and re-emits events between them, appending its own id to the
event's origin trace so downstream nodes apply the per-hop `federation_discount`.
Leave empty for a normal leaf node.

**Security:** a bridge can drop, delay, or inject events between subnets. It
cannot force a downstream block (that still requires anchored corroboration) and
imported events are scored by the originator's trust, not the bridge's. Bridge
only subnets you trust; stop bridging a subnet to defederate it.
```

- [ ] **Step 2: Document the threat-model + architecture caveat**

In `docs/threat-model.md`, add a short "Bridge nodes" entry: a bridge is trust-sensitive; containment is the anchored-corroboration block backstop, per-hop discount, and defederation (stop bridging).

In `docs/architecture.md`, replace the "Federation … origin-tracing inert at runtime" caveat (added in batch B) with: origin-tracing and the per-bridge-hop discount are **active** under the subnet-bridge forwarding model (a bridge appends its id on re-emit); flat single-subnet deployments have no hops and thus no discount, which is correct.

- [ ] **Step 3: Update the spec traceability**

In `docs/spec.md`, §12a table, change the §5.2 row from `PARTIAL — discount + defederation present; origin-trace inert at runtime (E)` to:

```markdown
| §5.2 | Federation import / discount / origin-trace | `internal/node`, `internal/transport`, `internal/trust` | PARTIAL — subnet-bridge forwarding makes origin-trace + per-hop discount active (E1); evidence-aggregate import PLANNED (E2) |
```

- [ ] **Step 4: Full gate**

Run: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/ && go test ./... && go test -tags adversarial ./test/adversarial/... && go test -tags integration ./test/integration/...`
Expected: builds; vet clean; `gofmt -l` prints nothing; all unit, adversarial, and integration tests PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/config.md docs/threat-model.md docs/architecture.md docs/spec.md
git commit -m "docs: subnet-bridge forwarding config, threat-model, architecture, traceability"
```
