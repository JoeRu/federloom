# Federated On-Demand Reputation Query (Sub-project E3)

**Status:** Design approved 2026-07-09 (after an architecture debate — see §2)
**Source:** Remediation roadmap sub-project E, piece E3 (P1-1, "query not
replicate"). Spec §11.3 (bloom/threshold data-plane), §11.4 (on-demand DNSBL
lookup, relay-hierarchy), §5.2 (federated import, foreign score scales),
§7.2 (`ScoreEntry`).
**Prerequisite:** batches A+B, stranger-block guarantee, IPv6 normalization, E1
(subnet-bridge forwarding) — all merged to `main`.
**Unblocks:** E2 (`EvidenceAggregate` becomes the query payload) → D (diversity).

---

## 1. Problem

Today reputation is populated by gossiping every event to every node; a node
enforces from its own materialised store. The roadmap's scaling goal (§11) is to
stop replicating and instead **query reputation on demand** for IPs that actually
contact you. E3 builds the read path for that: a node-to-node query so a node can
fetch reputation it does not hold locally.

The first draft of E3 risked introducing a **second** on-demand surface parallel
to the existing DNSBL. The debate below rejected that. E3 is deliberately scoped
as the *backend of a single reputation-read path*, not a new feature.

---

## 2. Architecture decision (the debate outcome)

Three enforcement/query models exist; conflating them is the trap:

- **Push-to-firewall (current):** reputation engine → `ipset`/`nftables` set →
  kernel drops O(1). Correct for **L3** — you cannot ask a userspace service per
  SYN, and doing so worst under an attack wave violates §11.5 ("the protection
  must never become the performance problem"). Also covers *all* protocols
  (scans, floods, sshd), not just DNSBL-aware ones. **Kept, unchanged.**
- **Ask-per-connection (DNSBL):** an L7 service (Postfix/nginx) queries per
  connection. Correct for **L7** — latency-tolerant, wants L7 policy
  (reject-with-reason, greylist). **Kept.** The DNSBL is a *trusted southbound*
  interface, bound to a private/secured interface (already done, batch A P0-5),
  never internet-exposed, never a federation transport.
- **Federated pull (new, E3):** when a lookup misses locally, fetch reputation
  from configured, trusted aggregator peers over the authenticated libp2p
  channel.

**Rejected:** replacing push-to-firewall with firewall-asks-DNSBL. That moves
enforcement out of the kernel fast-path, becomes a bottleneck under load, and
drops non-L7 coverage. (Prior art: CrowdSec's bouncer does *pull-to-materialise*
— fetch the set, enforce O(1) locally — never ask-per-connection.)

**Adopted synthesis — "pull discovers, push enforces":**
- There is **one** southbound read interface for "reputation of IP X?" — the
  DNSBL (DNS framing) and the blocklist API (HTTP framing). Both call a single
  `Lookup(ip) → ScoreEntry` path.
- On a local miss, that path fans out east-west to configured aggregators via a
  libp2p protocol and returns the **same `ScoreEntry`** representation — so
  reputation is modelled once, framed three ways (DNS / HTTP / libp2p), not
  rebuilt twice.
- **Target** (beyond this MVP): a bad federated verdict for an IP that contacted
  you materialises a push into the firewall set, giving on-demand's minimal
  state *and* the kernel fast-path. This is **deferred** — see §8 — because safe
  cross-domain enforcement needs E2's scale-free `EvidenceAggregate`; E3 returns
  a raw `ScoreEntry`, which is advisory only.
- **Positioning note (documented, not built here):** FederLoom's primary role is
  a reputation *source* (DNSBL + CrowdSec-compatible list + API); standalone
  push-to-firewall stays as the "no external bouncer" convenience.

---

## 3. Scope

**In:** a single `Lookup` read path; a libp2p request/response query protocol
(backend); a querier with a TTL cache; a responder serving the local store;
DNSBL + API integration; config for aggregators/timeout/TTL.

**Out (explicit):** materialising a federated verdict into the firewall set
(§8, needs E2); the `EvidenceAggregate` payload and scale-free recompute (E2); a
distributed/federation bloom filter; DHT content routing; any change to the L3
push-to-firewall path or the gossip event path (both untouched).

---

## 4. The single read path

**New (or refactored) function**, e.g. `internal/reputation` or a small
`internal/lookup` unit: `Lookup(ctx, ip) (proto.ScoreEntry, bool)`.

1. Consult the local store (`GetScore`). If present (`!LastSeen.IsZero()`),
   return the local `ScoreEntry`, `found=true`.
2. On a local miss, if the federated query is enabled and aggregators are
   configured, call the querier (§6). Cache the result (§6). Return the merged
   `ScoreEntry` (§6 merge), `found` per whether any aggregator answered.
3. On miss with the feature disabled/no aggregators: return zero, `found=false`
   (exactly today's behaviour).

The **point-lookup** surfaces — the DNSBL handler and the per-IP score API
endpoint (`internal/api/handler_score`) — call `Lookup` instead of reading the
store directly, so they share one path and one representation. The operator's
local threshold still governs the "listed / blockworthy" decision (local
sovereignty preserved).

**Not federated:** the blocklist *enumeration* endpoint
(`internal/api/handler_blocklist`, which `ScanScores` over the whole local store)
stays local-only. You cannot fetch a full list on demand without materialising
the global set — the exact anti-pattern §11 rejects. On-demand federation is a
*point* query for an IP that contacted you, never a list dump.

**Score-scale caveat (§5.2):** a raw foreign `ScoreEntry` is scored in the
*aggregator's* trust domain, not yours; merging raw scores across domains is the
exact thing §5.2 warns about. For the MVP this is accepted as *advisory evidence
from a trusted, explicitly-configured aggregator* (like an anchor), and the
operator's own threshold is applied to the merged view. E2 replaces the payload
with `EvidenceAggregate` for scale-free local recompute — that is the proper
fix, deferred by design.

---

## 5. Wire types

`pkg/proto` (wire contract — treat as additive, follow `.claude/skills/wire-protocol`):
- `RepQuery{ IP string }` — the request.
- Response reuses the existing **`ScoreEntry`** (§7.2), which is currently
  *reserved/unused*; E3 activates it as the query answer (score, corroboration,
  first/last seen, reasons, disputes). A "not found" answer is an empty
  `ScoreEntry` (`LastSeen` zero).

No app-level signature on the answer: the libp2p secured stream authenticates
the responding peer, and the querier only asks peers it explicitly configured.

---

## 6. Querier, responder, cache

**Responder** (`internal/transport` or a new `internal/repquery`): register a
stream handler for protocol id `/federloom/repquery/v1` on the libp2p host. On a
`RepQuery`, decode the IP, `GetScore`, encode the `ScoreEntry`, write it back.
Read-only; serves the local store view. (This is the first libp2p
request/response protocol in the codebase — all prior comms are gossipsub.)

**Querier:** `Query(ctx, ip) []proto.ScoreEntry`. For each configured aggregator
peer: open a stream to `/federloom/repquery/v1`, send `RepQuery{ip}`, read the
`ScoreEntry`, close. Run concurrently with a per-query deadline
(`federation.query_timeout`, default 150ms). Collect the non-empty answers.

**Merge:** MVP takes the **max score** across answers (plus the union of
reasons) — "some trusted aggregator considers this bad". Deliberately simple;
E2's evidence-weighted recompute replaces it.

**Cache:** a bounded TTL cache keyed by IP (reuse the `dedupCache` pattern from
E1, or a small parallel unit): a miss triggers a `Query`; the merged result is
cached for `federation.query_cache_ttl` (default 5m) so repeated lookups for the
same IP don't refan out. Negative results (no answer) are cached too (shorter
TTL) to avoid hammering aggregators for unknown IPs.

**Latency:** the DNSBL/API lookup does a *synchronous* query with the tight
timeout; on timeout it falls back to the local-only answer. 150ms on a
spam-connection check is acceptable; the cache makes it a one-time cost per IP
per TTL. (Async cache-fill was considered and rejected: it always misses the
first, security-relevant lookup.)

---

## 7. Config

`internal/config`, federation area:
- `federation.aggregators []string` — multiaddrs of aggregator peers to query.
  Empty = feature OFF (backward compatible; `Lookup` behaves as today).
- `federation.query_timeout` (duration, default `150ms`).
- `federation.query_cache_ttl` (duration, default `5m`).

Document in `docs/config.md`: aggregators are trusted (their answers are
advisory evidence like an anchor's); the DNSBL/API remain private-interface-only;
enforcement is unchanged (push-to-firewall).

---

## 8. Deferred: materialise-on-verdict (the push half of the synthesis)

Once E2 provides scale-free `EvidenceAggregate`, the read path can, on a
block-worthy federated verdict for an IP that contacted you, call the enforce
sink to push the block into `ipset` (subject to never-block/whitelist and the
operator threshold) so subsequent packets drop O(1). This is intentionally NOT
in E3: doing it on a raw cross-domain `ScoreEntry` would push blocks off a score
scale that isn't yours. E3 stops at the advisory read; E2 makes the push safe.

---

## 9. Security

- The DNSBL/API stay bound to the private/secured interface (batch A P0-5) — the
  federated query does not change that; it is the *backend*, over authenticated
  libp2p, never DNS.
- Aggregators are explicitly configured and thus trusted (like anchors);
  `defederation` = remove an aggregator from the list.
- E3 is **read-only**: it does not mutate the local score store or the L3
  enforcement set, so the batch-A anchored-corroboration block backstop and the
  gossip/ingest scoring paths are untouched. The only enforcement effect is
  advisory (an enriched DNSBL/API answer the operator's own L7 service consumes
  against the operator's own threshold).
- Query amplification is bounded: only real southbound lookups (which the caller
  already rate-limits) trigger a fan-out, and the cache collapses repeats.

---

## 10. Testing

- **Responder unit** (`internal/repquery`): a stream handler returns the local
  store's `ScoreEntry` for a known IP and an empty one for an unknown IP.
- **Querier unit:** with a fake/in-memory responder (or two real libp2p hosts
  connected in-process, mirroring `test/integration/cluster_test.go`), `Query`
  returns the aggregator's `ScoreEntry`; merge takes the max across two
  aggregators; timeout yields no answer without hanging.
- **Cache unit:** a second `Lookup` within TTL does not refan out (assert via a
  counting fake responder); negative results cached.
- **Integration:** a two-node setup — aggregator B has IP X scored, querier A
  does not; `A.Lookup(X)` returns X's `ScoreEntry` from B; A's DNSBL/API then
  reports X per A's threshold. A with no aggregators behaves exactly as today.
- **Backward-compat:** empty `federation.aggregators` → `Lookup` is local-only;
  existing DNSBL/API/adversarial/integration suites still pass.
- **Full gate:** `make build test adversarial`, integration, `go vet`,
  `gofmt -l` clean.

---

## 11. Out-of-scope / follow-ups

- E2: `EvidenceAggregate` as the query payload + scale-free local recompute +
  `diversity_buckets` → then D (diversity-weighted corroboration).
- Materialise-on-verdict push into the firewall (§8), post-E2.
- Federation bloom distribution; DHT content routing; batch/multi-IP queries.
- After merge, update spec §12a traceability: §11.4 on-demand query → PARTIAL
  (read path via configured aggregators; DHT/bloom hardening PLANNED); §7.2
  `ScoreEntry` → DONE (now exchanged as the query answer).

## 12. Acceptance

A node that does not locally know IP X, but has a trusted aggregator configured,
answers a DNSBL/API lookup for X with reputation fetched on demand from that
aggregator (same `ScoreEntry` representation), cached with a TTL, within a tight
timeout, without mutating its firewall or score store. Push-to-firewall (L3) and
the gossip/ingest paths are unchanged. With no aggregators configured, behaviour
is byte-for-byte as today.
