# Repquery Hardening (Roadmap Step 1)

**Status:** Design approved 2026-07-10
**Source:** [docs/roadmap.md](../../roadmap.md) Step 1 — items B1 (responder
authorization), B3 (querier cache bounding + in-flight de-dup), B5 (polish).
Origin of the findings: the E3 whole-branch final review and Task-4 review
(see roadmap Part 2 B).
**Prerequisite:** E3 (federated on-demand reputation query) merged to `main`.
**Spec refs:** §5.2 (defederation as containment), §11.4 (on-demand query),
Leitprinzip 8 (remote input advisory; secure defaults).

---

## 1. Problem

Three gaps shipped with the E3 MVP:

1. **B1 — the responder answers any peer.** `/federloom/repquery/v1` is
   registered on the shared transport host with no peer authorization.
   Enabling the *client* role (`federation_aggregators`) silently turns the
   node into an unauthenticated reputation oracle for the whole swarm.
2. **The serve role has no wiring of its own** (found during this design).
   The responder registers only when the node itself has aggregators
   configured — so a *pure aggregator* (the hub that only serves) registers
   nothing, and its leaves' queries fail. E3's tests passed because they
   called `RegisterResponder` on raw hosts directly.
3. **B3/B5 — querier debt:** unbounded per-IP cache (grows with every
   distinct IP, including negatives); no in-flight de-dup (concurrent misses
   for the same IP each fan out); plus small polish items (§5).

## 2. Scope

**In:** trust-store-based responder authorization; serve-role wiring fix;
bounded querier cache; singleflight de-dup; B5 polish incl. the E1
multi-bridge echo-suppression test.
**Out:** `EvidenceAggregate` / merge-semantics changes (roadmap Step 2);
materialise-on-verdict (Step 4); strict lowest-hop re-scoring (parked); any
change to gossip, ingest, enforcement, or the read-only property of repquery.

---

## 3. Responder authorization (B1) — trust-store based, fail closed

**Decision (user-selected):** authorize by the existing trust machinery, not
a new parallel allow-list. A peer may query us iff it is **anchored** in our
trust store (has a valid vouch cert from one of our anchors) **and not
blocked** (defederation list). Strangers and defederated peers get a stream
reset before any data is read or written.

**Mechanism.** `RegisterResponder` gains an authorizer parameter:

```go
// Authorizer decides which peers may query this node's reputation.
// *trust.Store satisfies it verbatim.
type Authorizer interface {
    Resolve(peerID string) (weight float64, group string, anchored bool)
    IsBlocked(peerID string) bool
}
```

Handler order: extract `str.Conn().RemotePeer().String()` → if
`auth == nil` OR `IsBlocked` OR `!anchored` → `str.Reset()`, log, return —
**before** decoding the request. A `nil` authorizer rejects everyone
(fail closed); tests pass a permissive fake.

**Properties:**
- Zero new config and zero new trust code — `*trust.Store` already exposes
  both methods, hot-reloads its files, and `blocked_peers` (defederation,
  spec §5.2) becomes the per-peer off switch.
- Cert propagation is the existing one: a peer becomes anchored in our store
  once its vouch cert arrives via gossip (`AddCert`) or is seeded in the
  `trust_certs` file. Until then its queries are reset — a graceful failure,
  because the querier falls back to its local answer.
- Rejected attempts are logged (peer ID + reason). A hostile peer can spam
  this log line; accepted for now (the stream deadline bounds the cost),
  noted as observability polish if it becomes a problem.

## 4. Serve-role wiring — always-on when federated

**Decision (user-selected):** register the responder whenever the node has a
transport (`t != nil`), authorized by the node's trust store. Rationale:
anchored peers already receive our raw events via gossip — serving them
aggregated scores adds no new data exposure — and federation "just works"
with zero extra config. A node with no anchors configured resolves nobody as
anchored, so the registered responder rejects all; harmless and
deadline-bounded.

In `internal/node/node.go` `New`: move `repquery.RegisterResponder(t.Host(),
s, ts)` out of the aggregator-gated block into the `t != nil` path. The
querier + resolver stay gated on `federation_aggregators` exactly as today
(client role unchanged). This decouples serve from ask and fixes the "pure
aggregator serves nothing" hole.

## 5. Querier hardening (B3) + polish (B5)

**Cache bound.** Constant `maxCacheEntries = 65536` (no config knob). On
insert when full: evict expired entries first; if still full, evict the
oldest by timestamp — mirroring the existing `dedupCache` pattern in
`internal/node`.

**In-flight de-dup.** Wrap `fanout` in a `golang.org/x/sync/singleflight`
`Group` keyed by IP: N concurrent `Query` calls for the same uncached IP
perform one fan-out and share the result. Promote `x/sync` from indirect to
direct dependency (already in `go.sum`).

**Peerstore seeding (corrects a review finding).** The E3 review called the
per-ask explicit `Connect` "redundant"; it is not — `NewStream` only dials
addresses already in the peerstore, and the per-ask `Connect(a)` is what
seeds them from the configured `AddrInfo`. Correct fix: in `NewQuerier`,
seed `h.Peerstore().AddAddrs(a.ID, a.Addrs, peerstore.PermanentAddrTTL)`
once per aggregator, then drop the per-ask `Connect`.

**Responder polish.** `str.Reset()` (abort) on unauthorized and on decode
error; graceful `Close()` only on the answer path. Log `SetDeadline` errors
instead of discarding them.

**E1 leftover (B5, test-only).** Add a multi-bridge echo-suppression test in
`test/integration` (alongside the existing E1 bridge test): a topology where a node is
reachable via two bridges must score the event once and produce no
re-emission storm. No production code change expected; if the test finds a
bug, that becomes its own escalation.

## 6. Security

- **Fail closed:** nil authorizer = reject all; authorization runs before
  any request byte is processed.
- **Read-only unchanged:** repquery still never mutates the store or the
  enforcement set; this change only narrows who can *read*.
- **Leitprinzip 8 preserved:** remote peers gain no new influence; the
  change strictly reduces exposure vs. shipped E3.
- **Stranger-block backstop, gossip, ingest, enforce: untouched.**
- Threat-model note: repquery serve surface = anchored peers only;
  defederation contains a misbehaving peer; the oracle risk from the E3
  review is closed.

## 7. Testing

- **Authz unit (`internal/repquery`):** anchored peer answered; stranger
  reset; blocked-but-anchored peer reset; nil authorizer rejects all. Fake
  authorizer struct; two real in-process libp2p hosts (existing pattern).
- **Node wiring (`internal/node`):** extend the existing
  `TestNodeWiringFederatesBothReadSurfaces` environment — the aggregator
  answers an anchored client; add a stranger host whose query is reset; a
  transport-bearing node with no aggregators still registers the responder.
- **Cache bound unit:** insert past `maxCacheEntries`; size stays ≤ bound;
  oldest evicted; expired preferred for eviction.
- **Singleflight unit:** counting responder + N concurrent `Query` for one
  uncached IP → exactly one responder call.
- **Peerstore-seeding regression:** querier reaches an aggregator without
  any explicit `Connect` call.
- **E1 echo test** per §5.
- **Full gate:** `make build test adversarial`, integration, `go vet`,
  `gofmt -l` clean. (Adversarial suite: authorization touches the trust
  path — add a scenario: a Sybil stranger querying the responder gains
  nothing and cannot influence anything.)

## 8. Compatibility

E3 shipped days ago, unreleased, off by default; no known deployment
configures `federation_aggregators`. Tightening the responder from "answers
anyone, only when client role active" to "answers anchored peers, always
when federated" is the intended fix, not a breaking change. Existing
`RegisterResponder` callers (tests) are updated for the new signature.

## 9. Docs (same PR)

- `docs/config.md`: serve role is automatic when federated; who may query
  (anchored ∧ not blocked); defederation as the off switch.
- `docs/threat-model.md`: repquery serve surface + closure of the E3
  oracle finding.
- `docs/roadmap.md`: check off Step 1 on merge.

## 10. Acceptance

An anchored, non-blocked peer's query is answered; a stranger's or
defederated peer's stream is reset before the request is read; a pure
aggregator (no `federation_aggregators` of its own) serves its leaves; the
querier cache never exceeds its bound; concurrent misses for one IP fan out
once; the querier works without per-ask `Connect`; all suites incl.
adversarial pass; repquery remains read-only.
