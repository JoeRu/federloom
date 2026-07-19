# FederLoom behind Traefik (CrowdSec sidecar, Docker)

A self-contained Traefik + CrowdSec + FederLoom stack: CrowdSec parses
Traefik's access log (the `crowdsecurity/traefik` collection) and turns
attacks against **any service routed through Traefik** into decisions;
FederLoom ingests those decisions as a CrowdSec bouncer, scores them, and
enforces the result in O(1) via ipset — blocking attackers in `DOCKER-USER`
before they ever reach Traefik, and therefore before they reach any backend
Traefik proxies to. One FederLoom node protects every routed service.

## What you get

- `docker-compose.yml` — `traefik:v3.1` (file-based access logging enabled,
  routing a demo `traefik/whoami` backend) behind a CrowdSec sidecar
  (`crowdsecurity/traefik` collection, LAPI published on `127.0.0.1:18080` so
  it never collides with a host-installed CrowdSec that already owns 8080)
  plus FederLoom (`network_mode: host`, so it can write the host firewall and
  reach the LAPI over loopback).
- `acquis.yaml` — points CrowdSec's traefik collection at the real access-log
  file shared with the `traefik` container via the `traefik-logs` volume.
- `config.yaml` — the CrowdSec ingest adapter enabled, and the local score API
  bound to `127.0.0.1:9102`.
- `rules.yaml` — a single own-CrowdSec decision blocks immediately; three
  independent federated reporters agreeing is the federation dividend.

FederLoom also exposes `GET /crowdsec/v1/decisions` (a plain-text feed any
downstream bouncer can pull) — that direction of the bridge is documented and
smoke-tested once, in `examples/crowdsec/`, and works identically here.

## Prerequisites

- Docker + Compose v2. Nothing else — Traefik, the demo `whoami` backend, and
  CrowdSec all ship as part of the compose file.

## Setup

1. Review both key files before starting — every threshold is yours to
   override, and the bouncer key pairing is the one thing you must keep in
   sync:

       cat examples/traefik/docker/docker-compose.yml examples/traefik/docker/config.yaml

   **Change `federloom-example-key` in BOTH files** if this host is shared
   with anyone else — it is the bouncer API key CrowdSec uses to authorise
   FederLoom, set via `BOUNCER_KEY_federloom` in `docker-compose.yml` and read
   back as `ingest.crowdsec.api_key` in `config.yaml`. The two values must
   always match exactly.

2. Start the stack:

       cd examples/traefik/docker
       docker compose up -d

   On first start, CrowdSec auto-registers the `federloom` bouncer from the
   `BOUNCER_KEY_federloom` environment variable and installs the
   `crowdsecurity/traefik` collection from the `COLLECTIONS` environment
   variable — no manual `cscli` setup needed.

### Add to your existing Traefik stack

You don't need this file's `traefik` or `whoami` services — just add the
bridge to your existing project:

1. Copy the `crowdsec` and `federloom` services from `docker-compose.yml`
   into your stack's compose file (plus the `crowdsec-config`,
   `crowdsec-data`, and `federloom-data` volumes).
2. Copy `acquis.yaml`, `config.yaml`, and `rules.yaml` alongside your compose
   file.
3. Point the shared log volume at your own Traefik's `--accesslog.filepath`:
   mount that same volume (or bind-mount the host path it writes to) into the
   `crowdsec` service at the path `acquis.yaml`'s `filenames:` entry
   references, and update `acquis.yaml` if your log file lives somewhere
   else. **Traefik must have file-based access logging enabled**
   (`--accesslog=true` plus `--accesslog.filepath=...`) — CrowdSec cannot
   parse an access log that only goes to stdout/Docker's log driver.
4. Keep the `BOUNCER_KEY_federloom` / `ingest.crowdsec.api_key` pairing
   change-me note from *Setup* above in mind — it applies here too.

## Verify it works

**Real-traffic path** (exercises the full stack: Traefik access log →
CrowdSec parser → scenario → decision → FederLoom bouncer → ipset). Run this
from an **external** host — CrowdSec's default parsers whitelist
private/RFC1918 source addresses, so requests from the Docker host itself or
another container on the same LAN will not trigger a decision:

    for i in $(seq 1 20); do curl -s -o /dev/null "http://<public-ip>:8081/wp-login.php"; done

After a few seconds this should trip `crowdsecurity/http-probing` and produce
a decision. Confirm with:

    docker compose exec crowdsec cscli decisions list
    curl -s http://127.0.0.1:9102/api/v1/score/<attacker-ip>   # → JSON with score
    sudo ipset list federloom | grep <attacker-ip>             # → blocked in the set

**No external host handy?** Inject a decision directly through `cscli`,
standing in for a real detection (this is exactly what `smoke.sh` does):

    docker compose exec crowdsec cscli decisions add -i 203.0.113.99 -d 5m -R smoke-test
    curl -s http://127.0.0.1:9102/api/v1/score/203.0.113.99   # → JSON with score
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
