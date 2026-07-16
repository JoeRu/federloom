# Architecture

Condensed from `spec.md` §11; read the spec for full reasoning.

## Three planes (kept separate in code)

```
                 ingest.Source plugins
   (mailcow logs, spamtrap, honeypot, crowdsec, fail2ban)
                          │  proto.Event
                          ▼
        ┌───────────────────────────────────┐
        │  CONTROL PLANE                      │
        │  reputation (score, decay,          │
        │     corroboration, dispute)         │
        │  trust (anchors, federation)        │
        │  store (BadgerDB + bloom + WL)      │
        │  transport (gossipsub + DHT)        │
        └───────────────┬───────────────────┘
                         │ blocked ScoreEntries (above local threshold)
                         ▼
        ┌───────────────────────────────────┐
        │  DATA PLANE — enforce.Sink          │
        │  ipset / nftables (O(1))            │
        │  or emit CrowdSec-compatible list   │
        └───────────────────────────────────┘

   OBSERVABILITY PLANE (opt-in, default OFF):
     firehose event stream + metrics — attack-wave monitoring
```

## Why query instead of replicate (scaling)

The global list is **not** materialised locally. Reputation is looked up
on-demand (DNSBL-style) via the DHT when an IP actually contacts you, fronted by a
compact in-memory **bloom filter** so the common "not suspicious" answer is
instant and local. The local **threshold** is the real filter — your active
enforcement set is thousands of IPs, not millions. **Decay** bounds the store and
serves as GDPR storage limitation.

> **Current status (2026-07):** the running system push-replicates every event
> over gossipsub; the on-demand DHT query model and materialize-on-verdict are the
> *target* (E2 `EvidenceAggregate` import via query path is DONE; federated query read path can now materialise a provisional, diversity-gated, TTL-bounded block (opt-in); see spec traceability table §7.5/§11.4).

## Reputation: push enforcement path vs query read path

Reputation has two paths: a **push** path where locally-sourced scoring events flow to the firewall (control plane → data plane, L3, engine to ipset, unchanged), and a **query** read path where DNSBL/API lookups miss the local store and consult federated aggregators on-demand over authenticated libp2p. The query path transports **evidence** (reporter diversity counts per IP) that your node recomputes into a score under your own rules, not foreign scores. The query path is read-only and advisory — the recomputed score feeds the operator's own threshold to decide listing. E3 shipped the query read path with opaque scores; E2 replaced that with scale-free evidence aggregates (federated answers never carry anchored corroboration, so they can raise an advisory score but cannot force a block). Materialise-on-verdict (flowing federated verdicts back into firewall decisions) is the next step.

Corroboration is **subnet-diversity weighted** — breadth across subnets outweighs volume from one (score only; the block gate stays anchored-Person). A report from a subnet that has already reported an IP counts for only a fraction (config `diversity_repeat_factor`, default 0.15) of a report from a new subnet, preventing single-subnet floods from buying breadth signals. Provenance (`SubnetID`) is signed as of v2; the federation discount rests on the signed origin subnet, preventing relay forgery of diversity keying.

**Disputes** (shared-vote whitelist entries) federate as diversity-weighted negative votes that can undo a materialized federated block when signatures from enough distinct subnets accumulate, but never touch local anchored blocks or local-only whitelist entries — preserving operator sovereignty (Invariant 1).

## Federation (Mastodon model)

Each subnet is a trust domain with its own roots and governance. Subnets run
isolated or federate — importing others' scores at a **trust discount**, with
**origin tracing** to prevent A↔B double-counting. A bad subnet is **defederated**.

> **Current status (2026-07):** origin-tracing and the per-bridge-hop discount are
> **active** under the subnet-bridge forwarding model — a bridge appends its id on
> re-emit. Flat single-subnet deployments have no hops and thus no discount, which
> is correct.

## Good-neighbour behaviour

The daemon runs under a CPU/bandwidth budget and **sheds load** under attack:
local protection takes priority over network contribution; it verifies foreign
signatures lazily/in batches and syncs later. The protection must never become the
performance problem.
