# FederLoom ⇄ CrowdSec bridge (bidirectional, Docker)

Already running CrowdSec? This example bridges it to FederLoom in both
directions at once: FederLoom acts as a CrowdSec bouncer that ingests every
decision your CrowdSec instance makes, scores it, and enforces it in O(1) via
ipset — and FederLoom also serves its own reputation data back out as a
CrowdSec-CTI-compatible feed that any remote bouncer or firewall can pull.

## What you get

- **Ingest direction — FederLoom as a bouncer.** FederLoom registers with your
  CrowdSec's Local API (LAPI) using a bouncer key and polls
  `GET /v1/decisions/stream`. Every new "ban" decision your CrowdSec makes
  (from its own scenarios, or from `cscli decisions add`) becomes a FederLoom
  event: it is scored, corroboration-checked against `rules.yaml`, and — once
  a rule matches — pushed into the local `ipset` firewall set. Decisions
  sourced from the CrowdSec community blocklist (`origin: capi` or
  `origin: lists`) are skipped on purpose: redistributing someone else's
  third-party list through the swarm would break the independence assumption
  behind corroboration (spec §4.2).
- **Serve direction — FederLoom as a feed.** FederLoom exposes
  `GET /crowdsec/v1/decisions` on its local API: a plain-text list of
  currently-blocked IPs, one per line, in the same shape a CrowdSec bouncer
  expects from a CTI-style feed. Point any downstream firewall, edge proxy, or
  a *second* CrowdSec's bouncer at this endpoint to pull FederLoom's
  (locally-decided or federated) reputation data — no CrowdSec account or
  central API dependency required.
- `docker-compose.yml` — a CrowdSec sidecar (LAPI published on
  `127.0.0.1:18080`; host port 18080 so it never collides with a
  host-installed CrowdSec that already owns 8080) plus FederLoom
  (`network_mode: host`, so it can write the host firewall and reach the LAPI
  over loopback).
- Already running CrowdSec on this host? You can skip the sidecar entirely:
  set `ingest.crowdsec.lapi_url` in `config.yaml` to your existing LAPI
  (e.g. `http://127.0.0.1:8080`), register the bouncer key against it with
  `cscli bouncers add federloom --key <your-key>`, and delete the `crowdsec`
  service (and its volumes) from `docker-compose.yml`.
- `config.yaml` — the CrowdSec ingest adapter enabled, and the local score API
  bound to `127.0.0.1:9102`.
- `rules.yaml` — a single own-CrowdSec decision blocks immediately; three
  independent federated reporters agreeing is the federation dividend.

## Prerequisites

- Docker + Compose v2. Nothing else — CrowdSec itself ships as part of the
  compose file, so you do not need CrowdSec pre-installed on the host.

## Setup

1. Review both key files before starting — every threshold is yours to
   override, and the bouncer key pairing is the one thing you must keep in
   sync:

       cat examples/crowdsec/docker-compose.yml examples/crowdsec/config.yaml

   **Change `federloom-example-key` in BOTH files** if this host is shared
   with anyone else — it is the bouncer API key CrowdSec uses to authorise
   FederLoom, set via `BOUNCER_KEY_federloom` in `docker-compose.yml` and read
   back as `ingest.crowdsec.api_key` in `config.yaml`. The two values must
   always match exactly.

2. Start the stack:

       cd examples/crowdsec
       docker compose up -d

   On first start, CrowdSec auto-registers the `federloom` bouncer from the
   `BOUNCER_KEY_federloom` environment variable — no manual `cscli bouncers
   add` step needed.

3. This example ships with no CrowdSec log acquisition configured (`cscli
   decisions add` alone is enough to exercise the bridge — see *Verify it
   works* below). For a real deployment, install the collections and point
   CrowdSec at your actual logs, e.g.:

       docker compose exec crowdsec cscli collections install crowdsecurity/sshd
       docker compose exec crowdsec cscli collections install crowdsecurity/nginx
       docker compose restart crowdsec

   Then add the corresponding log source to CrowdSec's `acquis.yaml` (inside
   the `crowdsec-config` volume) so those collections have something to read.

## Verify it works

Inject a decision directly through `cscli` (standing in for a real detection)
and watch it cross both directions of the bridge:

    docker compose exec crowdsec cscli decisions add -i 203.0.113.99 -d 5m -R smoke-test
    curl -s http://127.0.0.1:9102/api/v1/score/203.0.113.99   # → JSON with score
    curl -s http://127.0.0.1:9102/crowdsec/v1/decisions | grep 203.0.113.99   # → serve feed lists it
    sudo ipset list federloom | grep 203.0.113.99              # → blocked in the set

Clean up the test entry:

    docker compose exec crowdsec cscli decisions delete -i 203.0.113.99
    sudo ipset del federloom 203.0.113.99 2>/dev/null || true

## Solo vs. join a federation

The config ships `federation_mode: solo`: everything stays on this host. To
federate, set `federation_mode: federated`, uncomment `bootstrap_peers` with a
peer you trust, and restart. See `docs/federation-guide.md` for anchors and
invites. Your local whitelist (own IPs, gateway, DNS) is never shared.

## Teardown

    docker compose down -v
    sudo ipset destroy federloom 2>/dev/null || true
