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

## Federation (Mastodon model)

Each subnet is a trust domain with its own roots and governance. Subnets run
isolated or federate — importing others' scores at a **trust discount**, with
**origin tracing** to prevent A↔B double-counting. A bad subnet is **defederated**.

## Good-neighbour behaviour

The daemon runs under a CPU/bandwidth budget and **sheds load** under attack:
local protection takes priority over network contribution; it verifies foreign
signatures lazily/in batches and syncs later. The protection must never become the
performance problem.
