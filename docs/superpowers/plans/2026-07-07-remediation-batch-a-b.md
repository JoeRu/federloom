# Remediation Batch A+B Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the live remote-block-injection holes (P0-1/P0-2/P0-3/P0-4), bump the vulnerable dependency, harden the DNSBL default binding, and make the docs/spec match reality (P2/P3) — shipped as one batch.

**Architecture:** Two surgical control-plane changes make blocks require *anchored* corroboration (strangers no longer inflate corroboration; strangers no longer feed the burst window), plus an additive data-plane never-block default and new adversarial tests that drive `Node.ProcessRemote` through an injected mock sink. The rest is documentation.

**Tech Stack:** Go 1.22, BadgerDB, libp2p, `go test` with the `adversarial` build tag, YAML rules.

## Global Constraints

- Go module path is `github.com/JoeRu/federloom`; Go 1.22.
- `internal/enforce` and reputation/trust changes are security-critical: conservative defaults, extra review (CLAUDE.md invariant 7).
- Every reputation/trust/ingest change MUST add or update an adversarial scenario in `test/adversarial/` — it is the CI gate (`make adversarial`).
- Invariant 1: every changed default stays locally overridable (rules.yaml, config).
- Invariant 8 (spec Leitprinzip 8): no imported/remote signal may *force* a block; remote strangers may raise score (capped) and trigger `watch`, never `block`.
- `pkg/proto` is the wire contract — this batch only edits *comments* there, no field add/remove.
- Conventional Commits. Adversarial tests use `//go:build adversarial` as the first line.
- `strangerScoreCap` default = 15; `min_score` fallback rule = 75 (strangers can never reach it — do not change either).
- Never-block always-on ranges must keep existing RFC1918/loopback/CGNAT/link-local/multicast/ULA entries; additions are only public-resolver `/32`s.

---

### Task 1: Engine corroboration gate (A1)

Strangers must stop counting toward `Corroboration`. Only distinct anchored Person groups count. This makes `min_corroboration:N` mean N anchored voucher-groups, so a lone stranger (Corroboration 0) cannot satisfy `min_corroboration:1` block rules. Score behaviour and the stranger cap are unchanged.

**Files:**
- Modify: `internal/reputation/engine.go:86-93`
- Test: `internal/reputation/engine_test.go` (add cases; file exists)
- Update: `test/adversarial/sybil_ingest_test.go:47-48,85-86`, `test/adversarial/vouch_test.go:70-71` (existing assertions encode the OLD "strangers = 1 vote" semantics and must flip to 0)

**Interfaces:**
- Consumes: `store.ScoreRecord` fields `Groups []string`, `StrangerSeen bool` (unchanged).
- Produces: after `Record`, `rec.Corroboration == len(rec.Groups)` exactly; `StrangerSeen` still set for strangers but no longer affects `Corroboration`.

- [ ] **Step 1: Write the failing engine tests**

Add to `internal/reputation/engine_test.go`:

```go
func TestStrangerDoesNotCountAsCorroboration(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	eng := New(s, 7*24*time.Hour, 15)

	// One un-anchored (stranger) report: anchored=false, group="".
	if _, err := eng.Record("203.0.113.7", "ssh-post-auth-command", "stranger-1", 0.3, "", false); err != nil {
		t.Fatalf("Record: %v", err)
	}
	rec, err := eng.GetRecord("203.0.113.7")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Corroboration != 0 {
		t.Errorf("stranger must not corroborate: Corroboration=%d, want 0", rec.Corroboration)
	}
	if !rec.StrangerSeen {
		t.Error("StrangerSeen should still be true after a stranger report")
	}
}

func TestAnchoredGroupsCountAsCorroboration(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	eng := New(s, 7*24*time.Hour, 15)

	// Two distinct anchored groups + a stranger on the same IP.
	_, _ = eng.Record("203.0.113.8", "ssh-probe", "peerA", 0.9, "alice", true)
	_, _ = eng.Record("203.0.113.8", "ssh-probe", "peerB", 0.9, "bob", true)
	_, _ = eng.Record("203.0.113.8", "ssh-probe", "peerC", 0.3, "", false)

	rec, err := eng.GetRecord("203.0.113.8")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Corroboration != 2 {
		t.Errorf("two anchored groups (+1 stranger) must yield Corroboration=2, got %d", rec.Corroboration)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/reputation/ -run 'TestStrangerDoesNotCountAsCorroboration|TestAnchoredGroupsCountAsCorroboration' -v`
Expected: FAIL — `TestStrangerDoesNotCountAsCorroboration` gets `Corroboration=1` (old stranger bump), and the anchored case gets `3` instead of `2`.

- [ ] **Step 3: Remove the stranger corroboration bump**

In `internal/reputation/engine.go`, replace lines 86-93:

```go
	// Corroboration: distinct anchored Person groups + at most one stranger vote.
	if anchored && group != "" && !containsString(rec.Groups, group) {
		rec.Groups = append(rec.Groups, group)
	}
	rec.Corroboration = len(rec.Groups)
	if rec.StrangerSeen {
		rec.Corroboration++
	}
```

with:

```go
	// Corroboration counts distinct ANCHORED Person groups only. Strangers are
	// deliberately excluded so a single un-anchored remote reporter can never
	// satisfy a min_corroboration block rule (spec Leitprinzip 8; batch A P0-1).
	// StrangerSeen/StrangerContrib still bound the stranger *score* (cap 15).
	if anchored && group != "" && !containsString(rec.Groups, group) {
		rec.Groups = append(rec.Groups, group)
	}
	rec.Corroboration = len(rec.Groups)
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `go test ./internal/reputation/ -run 'TestStrangerDoesNotCountAsCorroboration|TestAnchoredGroupsCountAsCorroboration' -v`
Expected: PASS.

- [ ] **Step 5: Update the existing adversarial assertions to the new semantics**

These three assertions encode the old "strangers = 1 corroboration vote" behaviour and are now wrong. In `test/adversarial/sybil_ingest_test.go` change **both** occurrences (lines ~47 and ~85):

```go
	if rec.Corroboration != 0 {
		t.Errorf("corroboration: strangers must not corroborate, got %d (want 0)", rec.Corroboration)
	}
```

In `test/adversarial/vouch_test.go` change the occurrence at ~line 70:

```go
	if rec.Corroboration != 0 {
		t.Errorf("corroboration = %d, want 0 (strangers never corroborate)", rec.Corroboration)
	}
```

- [ ] **Step 6: Run the full reputation + adversarial suites**

Run: `go test ./internal/reputation/... && go test -tags adversarial ./test/adversarial/...`
Expected: PASS (all existing scenarios green under the new semantics).

- [ ] **Step 7: Commit**

```bash
git add internal/reputation/engine.go internal/reputation/engine_test.go test/adversarial/sybil_ingest_test.go test/adversarial/vouch_test.go
git commit -m "fix(reputation): strangers no longer count as corroboration (P0-1)"
```

---

### Task 2: Test-only sink injection hook

`Node` builds its `enforce.Sink` internally with no injection point, so the Task 3 injection tests cannot observe `Block` calls. Add a minimal test hook mirroring the existing `SetTrustReloadInterval` pattern.

**Files:**
- Modify: `internal/node/node.go` (add method near `SetTrustReloadInterval`, ~line 430-434)

**Interfaces:**
- Produces: `func (n *Node) SetSinkForTest(s enforce.Sink)` — replaces the node's sink; call after `node.New`, before driving `ProcessRemote`.

- [ ] **Step 1: Add the hook**

In `internal/node/node.go`, after the `SetTrustReloadInterval` method (~line 434), add:

```go
// SetSinkForTest replaces the enforce sink. Test-only: lets adversarial tests
// observe Block/Unblock decisions through a mock sink without touching a real
// firewall. Not called in production paths.
func (n *Node) SetSinkForTest(s enforce.Sink) { n.sink = s }
```

`enforce` is already imported in `node.go` (line 19).

- [ ] **Step 2: Verify it compiles**

Run: `go build ./...`
Expected: builds cleanly.

- [ ] **Step 3: Commit**

```bash
git add internal/node/node.go
git commit -m "test(node): add SetSinkForTest hook for adversarial block observation"
```

---

### Task 3: Burst gate + adversarial injection scenarios (A2, A4)

Remote strangers currently feed the `BurstStore`, so 15 stranger events trip `ssh-brute-burst → block`. Gate `burst.Record` on `anchored` in `ProcessRemote`. Then add the four injection scenarios that assert the full P0 contract end-to-end through `ProcessRemote`.

**Files:**
- Modify: `internal/node/node.go:385` (the `n.burst.Record` call inside `ProcessRemote`)
- Create: `test/adversarial/injection_test.go`

**Interfaces:**
- Consumes: `node.New(cfg *config.Config, t *transport.Node) (*node.Node, error)`; `(*node.Node).ProcessRemote(transport.ReceivedEvent)`; `(*node.Node).SetSinkForTest(enforce.Sink)` (Task 2); `(*node.Node).SetTrustReloadInterval(time.Duration)`; `transport.ReceivedEvent{Event proto.Event; From string}`; `identity.GeneratePersonKey(path) (ed25519.PrivateKey, error)`, `identity.PersonPub(ed25519.PrivateKey) ed25519.PublicKey`, `identity.EncodePub(ed25519.PublicKey) string`, `identity.IssueCert(priv ed25519.PrivateKey, peerID string, validUntil time.Time) proto.PeerCert`; `trust.SaveAnchors(path string, []trust.Anchor) error`; existing package-local `mockSink` (defined in `poisoning_test.go`, has `blocked []string`).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the failing injection tests**

Create `test/adversarial/injection_test.go`:

```go
//go:build adversarial

package adversarial

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/internal/trust"
	"github.com/JoeRu/federloom/pkg/proto"
)

// injectionRules is a minimal rule file exercising the two block paths a remote
// stranger could previously abuse: a corroboration:1 block and a burst block.
const injectionRules = `
- name: honeypot-shell-exec
  reason: ssh-post-auth-command
  min_corroboration: 1
  action: block
- name: ssh-brute-burst
  reason: ssh-auth-bruteforce
  min_burst: 15
  burst_window: 10m
  action: block
`

// newInjectionNode builds a solo Node with injectionRules loaded and a mock
// sink installed so Block calls are observable. Returns the node, its data dir,
// and the mock sink.
func newInjectionNode(t *testing.T) (*node.Node, string, *mockSink) {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(injectionRules), 0o644); err != nil {
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

// TestStrangerCannotInjectCorroborationBlock: a single un-anchored remote event
// matching a min_corroboration:1 block rule must NOT cause a block (P0-1).
func TestStrangerCannotInjectCorroborationBlock(t *testing.T) {
	n, _, sink := newInjectionNode(t)
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "203.0.113.10", Reason: "ssh-post-auth-command", ReporterID: "stranger-peer"},
		From:  "stranger-peer",
	})
	if len(sink.blocked) != 0 {
		t.Errorf("stranger triggered %d block(s) via min_corroboration:1; want 0", len(sink.blocked))
	}
}

// TestStrangerCannotInjectBurstBlock: 15 un-anchored remote events must NOT trip
// the burst block rule, because strangers no longer feed the burst window (P0-2).
func TestStrangerCannotInjectBurstBlock(t *testing.T) {
	n, _, sink := newInjectionNode(t)
	for i := 0; i < 15; i++ {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: "203.0.113.11", Reason: "ssh-auth-bruteforce", ReporterID: "stranger-peer"},
			From:  "stranger-peer",
		})
	}
	if len(sink.blocked) != 0 {
		t.Errorf("stranger burst triggered %d block(s); want 0", len(sink.blocked))
	}
}

// anchoredEvent builds a remote event whose reporter is vouched by an anchored
// Person, so ProcessRemote resolves it as anchored (weight 0.9, group "jo").
func anchoredEvent(t *testing.T, n *node.Node, dir, ip, reason string) transport.ReceivedEvent {
	t.Helper()
	priv, err := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	anchorsPath := filepath.Join(dir, "anchors.json")
	if err := trust.SaveAnchors(anchorsPath, []trust.Anchor{{
		Person:         "jo",
		IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight:         0.9,
		Source:         "self-added",
	}}); err != nil {
		t.Fatalf("save anchors: %v", err)
	}
	const peerID = "anchored-peer-1"
	cert := identity.IssueCert(priv, peerID, time.Now().Add(24*time.Hour))
	return transport.ReceivedEvent{
		Event: proto.Event{IP: ip, Reason: reason, ReporterID: peerID, Vouch: &cert},
		From:  peerID,
	}
}

// TestAnchoredReporterCanBlock: the legit federation path still works — an
// anchored remote reporter's ssh-post-auth-command IS blocked (regression).
func TestAnchoredReporterCanBlock(t *testing.T) {
	n, dir, sink := newInjectionNode(t)
	// SaveAnchors path must match cfg's TrustAnchorsFile; Defaults resolves it
	// under Store.Dir, and anchoredEvent writes anchors.json there.
	re := anchoredEvent(t, n, dir, "203.0.113.12", "ssh-post-auth-command")
	n.ProcessRemote(re)
	if len(sink.blocked) != 1 || sink.blocked[0] != "203.0.113.12" {
		t.Errorf("anchored reporter should block 203.0.113.12; got blocked=%v", sink.blocked)
	}
}

// TestAnchoredBurstStillBlocks: anchored reporters still feed the burst window,
// so 15 anchored ssh-auth-bruteforce events DO block (regression for A2).
func TestAnchoredBurstStillBlocks(t *testing.T) {
	n, dir, sink := newInjectionNode(t)
	// Build the anchored setup + cert ONCE (anchoredEvent generates the Person
	// key and writes anchors.json; calling it in the loop would regenerate the
	// key each iteration). Reuse the same event 15 times to fill the window.
	re := anchoredEvent(t, n, dir, "203.0.113.13", "ssh-auth-bruteforce")
	for i := 0; i < 15; i++ {
		n.ProcessRemote(re)
	}
	if len(sink.blocked) == 0 {
		t.Error("anchored burst of 15 must trip ssh-brute-burst; got 0 blocks")
	}
}
```

- [ ] **Step 2: Run the injection tests to verify the failing state**

Run: `go test -tags adversarial ./test/adversarial/ -run 'Injection|AnchoredReporterCanBlock|AnchoredBurstStillBlocks' -v`
Expected: `TestStrangerCannotInjectBurstBlock` FAILS (strangers still feed burst → 1 block). The two anchored tests should already PASS (Task 1 fixed corroboration), and `TestStrangerCannotInjectCorroborationBlock` should already PASS. This confirms the burst hole is the remaining gap.

- [ ] **Step 3: Gate the burst counter on `anchored`**

In `internal/node/node.go`, `ProcessRemote`, the block that currently reads (~line 381-385):

```go
	if _, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, weight, group, anchored); err != nil {
		log.Printf("node: record remote %s: %v", e.IP, err)
		return
	}
	n.burst.Record(e.IP, e.Reason, time.Now())
```

Change the burst line to record only anchored observations:

```go
	if _, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, weight, group, anchored); err != nil {
		log.Printf("node: record remote %s: %v", e.IP, err)
		return
	}
	// Only anchored reporters feed the burst window: an un-anchored remote peer
	// must not be able to trip a min_burst block rule (spec Leitprinzip 8; P0-2).
	if anchored {
		n.burst.Record(e.IP, e.Reason, time.Now())
	}
```

Leave `processLocal`'s `n.burst.Record` (line ~277) unchanged — local observations are always anchored evidence.

- [ ] **Step 4: Run the injection tests to verify they all pass**

Run: `go test -tags adversarial ./test/adversarial/ -run 'Injection|AnchoredReporterCanBlock|AnchoredBurstStillBlocks' -v`
Expected: all four PASS.

- [ ] **Step 5: Run the whole adversarial + node suites (regression)**

Run: `go test -tags adversarial ./test/adversarial/... && go test ./internal/node/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/node/node.go test/adversarial/injection_test.go
git commit -m "fix(node): only anchored reporters feed the burst window (P0-2) + injection tests (P0-4)"
```

---

### Task 4: Never-block public-resolver defaults (A3)

Add public-resolver `/32`s to the always-on never-block set so a hostile peer cannot get a receiving node to block `8.8.8.8` etc. Broad provider/CDN ranges are documented for operators (Task 7), not hardcoded (spec caveat N — avoid over-broad auto-whitelisting).

**Files:**
- Modify: `internal/enforce/neverblock.go:5-16` (`defaultNeverBlock`)
- Test: `internal/enforce/neverblock_test.go` (exists)

**Interfaces:**
- Consumes: `NewNeverBlockList(extra []string) *NeverBlockList`, `(*NeverBlockList).Contains(ip string) bool` (unchanged).
- Produces: the default list now also covers the six public-resolver addresses below.

- [ ] **Step 1: Write the failing test**

Add to `internal/enforce/neverblock_test.go`:

```go
func TestNeverBlockCoversPublicResolvers(t *testing.T) {
	nbl := NewNeverBlockList(nil)
	for _, ip := range []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"} {
		if !nbl.Contains(ip) {
			t.Errorf("public resolver %s must be never-blocked by default", ip)
		}
	}
	// Sanity: an ordinary public IP is still blockable (not in the set).
	if nbl.Contains("203.0.113.5") {
		t.Error("203.0.113.5 must NOT be in the never-block default set")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/enforce/ -run TestNeverBlockCoversPublicResolvers -v`
Expected: FAIL — `8.8.8.8` not covered.

- [ ] **Step 3: Add the resolver `/32`s to the default set**

In `internal/enforce/neverblock.go`, extend `defaultNeverBlock` (keep all existing entries, append these before the closing `}`):

```go
	"224.0.0.0/4",    // multicast
	"fc00::/7",       // IPv6 ULA
	"fe80::/10",      // IPv6 link-local
	// Public resolvers — safe default per spec §10; operator-removable by
	// editing this list. Broad provider/CDN ranges are documented in
	// docs/config.md for opt-in via extra_whitelist (spec caveat N).
	"8.8.8.8/32",         // Google DNS
	"8.8.4.4/32",         // Google DNS secondary
	"1.1.1.1/32",         // Cloudflare DNS
	"1.0.0.1/32",         // Cloudflare DNS secondary
	"9.9.9.9/32",         // Quad9
	"149.112.112.112/32", // Quad9 secondary
```

(The last three pre-existing entries are shown for placement; do not duplicate them.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/enforce/ -run TestNeverBlockCoversPublicResolvers -v`
Expected: PASS.

- [ ] **Step 5: Run the full enforce suite**

Run: `go test ./internal/enforce/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/enforce/neverblock.go internal/enforce/neverblock_test.go
git commit -m "fix(enforce): never-block public resolvers by default (P0-3)"
```

---

### Task 5: Dependency bump — golang.org/x/net (Dependabot #2)

Bump the indirect `golang.org/x/net` to the patched version clearing the HTML-parser DoS alert.

**Files:**
- Modify: `go.mod`, `go.sum`

**Interfaces:** none (dependency only).

- [ ] **Step 1: Bump and tidy**

Run:
```bash
go get golang.org/x/net@v0.55.0
go mod tidy
```
Expected: `go.mod` line for `golang.org/x/net` shows `v0.55.0` (still `// indirect`).

- [ ] **Step 2: Verify build and full test suite**

Run: `go build ./... && go test ./... && go test -tags adversarial ./test/adversarial/...`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore(deps): bump golang.org/x/net to v0.55.0 (Dependabot #2)"
```

---

### Task 6: DNSBL default binding hardening (P0-5)

The DNSBL is an open UDP responder. Bind it to the private (Tailscale) interface by default on the honeypot deployment, matching the metrics ports already restricted there. Config/deploy only — no Go change.

**Files:**
- Modify: `deploy/honeypot/docker-compose.yml:40`

**Interfaces:** none (deployment config).

- [ ] **Step 1: Restrict the published DNSBL port**

In `deploy/honeypot/docker-compose.yml`, change the DNSBL port publish (currently `- "5353:5353/udp"`) to bind the same private interface the metrics ports use (`100.71.239.1`):

```yaml
      - "100.71.239.1:5353:5353/udp"
```

- [ ] **Step 2: Verify the compose file parses**

Run: `docker compose -f deploy/honeypot/docker-compose.yml config >/dev/null && echo OK`
Expected: prints `OK` (no YAML/compose error). If `docker` is unavailable in the environment, instead confirm the line reads exactly `- "100.71.239.1:5353:5353/udp"` and matches the metrics-port pattern above it.

- [ ] **Step 3: Commit**

```bash
git add deploy/honeypot/docker-compose.yml
git commit -m "fix(deploy): bind honeypot DNSBL to private interface by default (P0-5)"
```

---

### Task 7: Documentation truth-up (B1, B2, B4, B5)

Fix the wrong README join path, add current-vs-target caveats to the architecture doc, mark the deprecated/reserved wire fields in comments, and document the API-auth exposure plus the recommended provider never-block additions. Doc-only.

**Files:**
- Modify: `README.md:34-47`
- Modify: `docs/architecture.md` (the "Why query instead of replicate" and "Federation" sections)
- Modify: `pkg/proto/messages.go:17,35-44`
- Modify: `docs/config.md`

**Interfaces:** none (docs).

- [ ] **Step 1: Fix the README federation-join path (B1, P3-1)**

The mailcow bootstrap (`deploy/mailcow/bootstrap-mailcow.sh`) rsyncs the whole repo — including `federation.invite` at the repo root — to the remote deploy dir; there is no `/opt/federloom` copy step. In `README.md`, replace the "Join this federation" code block (lines ~39-47) with a correct path and no false claim:

````markdown
```bash
# 1. Set up your own node first (see getting-started.md)
# 2. Verify the fingerprint out-of-band: 79bb d13a 114b 88fe

# From the deploy directory on your server (the bootstrap rsync placed
# federation.invite at the repo root, one level up from deploy/<stack>/):
docker compose cp ../../federation.invite federloom:/tmp/federation.invite
docker compose exec federloom federloomctl federation join /tmp/federation.invite \
    --config /etc/federloom/config.yaml
```
````

- [ ] **Step 2: Add current-vs-target caveats to architecture.md (B2, P3-2)**

In `docs/architecture.md`, under "Why query instead of replicate (scaling)", append:

```markdown
> **Current status (2026-07):** the running system push-replicates every event
> over gossipsub; the on-demand DHT query model and `EvidenceAggregate` import
> are the *target*, not yet implemented (see spec traceability table §7.5/§11.4).
```

Under "Federation (Mastodon model)", append:

```markdown
> **Current status (2026-07):** the per-hop `FederationDiscount` and A↔B loop
> guard are scaffolded but inert at runtime — gossipsub forwards raw bytes
> without appending relay hops, so `OriginTrace` stays length 1. Making origin
> tracing effective is tracked as remediation sub-project E.
```

- [ ] **Step 3: Mark deprecated/reserved wire fields (B4, P2-1/P2-2)**

In `pkg/proto/messages.go`, update the `PortClass` field comment (line 17) to:

```go
	PortClass   string    `json:"port_class"`      // DEPRECATED (spec §7.1): retained for v0/v1 wire compat, superseded by Reason/scenario; removal is a future wire-protocol cycle
```

Update the `Reason` field comment (line 15) to note the spec mapping:

```go
	Reason      string    `json:"reason"`          // attack scenario (spec §7.1 join-key `scenario`); e.g. "smtp-auth-bruteforce"
```

Update the `ScoreEntry` doc comment (line 35) to:

```go
// ScoreEntry is the aggregated reputation for one IP within a trust domain (spec §7.2).
// RESERVED: defined for the wire contract but not yet exchanged on the network —
// nodes currently gossip Event, not ScoreEntry. See remediation sub-project E.
```

- [ ] **Step 4: Document API-auth exposure and recommended never-block additions (B5, P3-3)**

In `docs/config.md`, add a short subsection (place near the API / observability config docs):

```markdown
### API authentication

The REST API (`api.addr`) is **unauthenticated unless `FEDERLOOM_API_TOKEN` is
set** in the daemon's environment; when set, all API requests require
`Authorization: Bearer <token>`. Bind the API to loopback/VPN for local use, and
**always set the token when the API is reachable off-host** — the blocklist
endpoints are sensitive.

### Recommended never-block additions

Public DNS resolvers (Google, Cloudflare, Quad9) are never-blocked by default.
Large mail/CDN provider ranges are **not** hardcoded (they are broad and change
often — see spec caveat N); add the ones relevant to you via
`enforce.extra_whitelist`, e.g.:

```yaml
enforce:
  extra_whitelist:
    - 35.190.247.0/24    # Google mail egress (example — verify current ranges)
    - 40.92.0.0/15       # Microsoft/Outlook (example — verify current ranges)
    - 104.16.0.0/13      # Cloudflare (example — verify current ranges)
```
Verify current provider ranges from their published SPF/IP lists before adding.
```

- [ ] **Step 5: Verify no broken internal links and commit**

Run: `grep -n "/opt/federloom" README.md`
Expected: no output (the stale path is gone).

```bash
git add README.md docs/architecture.md pkg/proto/messages.go docs/config.md
git commit -m "docs: truth-up README join path, architecture caveats, wire comments, API auth (B1/B2/B4/B5)"
```

---

### Task 8: Spec implementation traceability table (B3, P2-3/P2-4)

Add an English traceability table to `docs/spec.md` that maps spec sections to packages and honest status, superseding the stale §13 "Nächste Schritte" as the source of truth for what is live. The German status header was already updated by the maintainer; keep the German body.

**Files:**
- Modify: `docs/spec.md` (add a new subsection after §12 or before §13)

**Interfaces:** none (docs).

- [ ] **Step 1: Cross-check each row against the codebase**

Run: `ls internal/` and confirm presence of `reputation`, `trust`, `enforce`, `discovery`; confirm absence of any evidence-aggregate/applicability package.
Expected: the four exist; no `evidence`/`applicability`/`profile` package exists (confirms the PLANNED rows).

- [ ] **Step 2: Insert the traceability table**

In `docs/spec.md`, add this subsection (English, immediately before `## 13. Nächste Schritte`):

```markdown
## 12a. Implementation Traceability (2026-07)

Honest status of each design area in the current codebase. This table — not the
§13 "Nächste Schritte" list — is the source of truth for what is live.
`DONE` = implemented and tested · `PARTIAL` = present but incomplete/inert ·
`PLANNED` = designed, not yet built (remediation sub-project in parentheses).

| Spec § | Area | Package | Status |
|---|---|---|---|
| §4.1 | Ground-truth anchors | `internal/trust`, honeypot/spamtrap ingest | DONE |
| §4.2 | Diversity-weighted corroboration (ASN/geo) | — | PLANNED (D) |
| §4.3 | Asymmetric decay | `internal/reputation` | DONE |
| §4.4 | Dispute / anti-trust votes | — | PLANNED (E) |
| §4.5 | Applicability weighting | — | PLANNED (E) |
| §5.1 | Trust anchors (Person keys, peer certs) | `internal/trust`, `internal/identity` | DONE |
| §5.2 | Federation import / discount / origin-trace | `internal/node`, `internal/trust` | PARTIAL — discount + defederation present; origin-trace inert at runtime (E) |
| §7.1 | Event model | `pkg/proto` | DONE — `port_class` deprecated-retained |
| §7.1 | IPv6 `/64` prefix normalization | — | PLANNED (C) |
| §7.2 | ScoreEntry aggregate | `pkg/proto` | RESERVED — defined, not exchanged |
| §7.5 | EvidenceAggregate (federated import type) | — | PLANNED (E) |
| §7.6 | System profile / SBOM | — | PLANNED (E) |
| §8 | Score dynamics (logistic accumulation, decay) | `internal/reputation`, `internal/rules` | DONE |
| §9 | GDPR framing (cleartext IP, decay = deletion) | `internal/store` (TTL) | DONE |
| §10 | Never-block set | `internal/enforce` | DONE — incl. public resolvers |
| §11.3 | O(1) enforcement (ipset/nftables) | `internal/enforce` | DONE |
| §11.4 | On-demand query / pull transport | `internal/transport` | PLANNED (E) — current model is gossip push |
| §14 | Federation discovery (DHT + relay list) | `internal/discovery` | DONE |
```

- [ ] **Step 3: Verify the file still renders and commit**

Run: `grep -n "Implementation Traceability" docs/spec.md`
Expected: one match (the new subsection heading).

```bash
git add docs/spec.md
git commit -m "docs(spec): add implementation traceability table (B3, P2-3/P2-4)"
```

---

### Task 9: Final batch verification

Confirm the whole batch builds, all suites pass, and the security acceptance criteria hold.

**Files:** none (verification only).

- [ ] **Step 1: Full build + vet + format**

Run: `make build && make fmt lint`
Expected: builds; `gofmt`/`go vet` clean.

- [ ] **Step 2: Full unit + adversarial suites**

Run: `make test && make adversarial`
Expected: all PASS, including the new `injection_test.go` scenarios.

- [ ] **Step 3: Confirm the acceptance criteria explicitly**

Run: `go test -tags adversarial ./test/adversarial/ -run 'StrangerCannotInject|AnchoredReporterCanBlock|AnchoredBurstStillBlocks' -v`
Expected: `TestStrangerCannotInjectCorroborationBlock` PASS, `TestStrangerCannotInjectBurstBlock` PASS, `TestAnchoredReporterCanBlock` PASS, `TestAnchoredBurstStillBlocks` PASS — i.e. no un-anchored remote peer can force a block, while anchored/local evidence still blocks.

- [ ] **Step 4: Confirm the Dependabot bump landed**

Run: `grep 'golang.org/x/net' go.mod`
Expected: `golang.org/x/net v0.55.0 // indirect`.
