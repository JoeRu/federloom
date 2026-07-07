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
> over gossipsub; the on-demand DHT query model and `EvidenceAggregate` import
> are the *target*, not yet implemented (see spec traceability table §7.5/§11.4).

## Federation (Mastodon model)

Each subnet is a trust domain with its own roots and governance. Subnets run
isolated or federate — importing others' scores at a **trust discount**, with
**origin tracing** to prevent A↔B double-counting. A bad subnet is **defederated**.

> **Current status (2026-07):** the per-hop `FederationDiscount` and A↔B loop
> guard are scaffolded but inert at runtime — gossipsub forwards raw bytes
> without appending relay hops, so `OriginTrace` stays length 1. Making origin
> tracing effective is tracked as remediation sub-project E.

## Good-neighbour behaviour

The daemon runs under a CPU/bandwidth budget and **sheds load** under attack:
local protection takes priority over network contribution; it verifies foreign
signatures lazily/in batches and syncs later. The protection must never become the
performance problem.
