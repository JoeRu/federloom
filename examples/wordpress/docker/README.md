# FederLoom for a dockerized WordPress (CrowdSec sidecar, Docker)

A self-contained WordPress + MariaDB + CrowdSec + FederLoom stack: CrowdSec
reads WordPress's Apache logs (via the Docker log-acquisition source, since
the official image logs to stdout instead of files) and turns attacks
(wp-login / xmlrpc brute force, bot search, HTTP probing, …) into decisions;
FederLoom ingests those decisions as a CrowdSec bouncer, scores them, and
enforces the result in O(1) via ipset — blocking attackers in `DOCKER-USER`
before they ever reach the `wordpress` container.

## What you get

- `docker-compose.yml` — `wordpress:latest` + `mariadb:11` behind a CrowdSec
  sidecar (`crowdsecurity/wordpress` collection, LAPI published on
  `127.0.0.1:18080` so it never collides with a host-installed CrowdSec that
  already owns 8080) plus FederLoom (`network_mode: host`, so it can write the
  host firewall and reach the LAPI over loopback).
- `acquis.yaml` — CrowdSec's **docker** log-acquisition source: it reads the
  `federloom-wordpress` container's stdout directly via the Docker socket
  (`/var/run/docker.sock:ro`), rather than a shared log-file volume. This is
  the pattern to reuse for any service that logs to stdout instead of files.
- `config.yaml` — the CrowdSec ingest adapter enabled, and the local score API
  bound to `127.0.0.1:9102`.
- `rules.yaml` — a single own-CrowdSec decision blocks immediately; three
  independent federated reporters agreeing is the federation dividend.

FederLoom also exposes `GET /crowdsec/v1/decisions` (a plain-text feed any
downstream bouncer can pull) — that direction of the bridge is documented and
smoke-tested once, in `examples/crowdsec/`, and works identically here.

## Prerequisites

- Docker + Compose v2. Nothing else — WordPress, MariaDB, and CrowdSec all
  ship as part of the compose file.

## Setup

1. Review the key files before starting — every threshold is yours to
   override, and two pairings you must keep in sync:

       cat examples/wordpress/docker/docker-compose.yml examples/wordpress/docker/config.yaml

   **Change `federloom-example-key` in BOTH `docker-compose.yml` and
   `config.yaml`** if this host is shared with anyone else — it is the
   bouncer API key CrowdSec uses to authorise FederLoom, set via
   `BOUNCER_KEY_federloom` in `docker-compose.yml` and read back as
   `ingest.crowdsec.api_key` in `config.yaml`. The two values must always
   match exactly.

   **Change `change-me-db-pass` in BOTH the `db` and `wordpress` services**
   in `docker-compose.yml` — it must match between `MARIADB_PASSWORD` and
   `WORDPRESS_DB_PASSWORD`, and it's the WordPress database password, so
   don't ship the example default to a real install.

2. Start the stack:

       cd examples/wordpress/docker
       docker compose up -d

   On first start, CrowdSec auto-registers the `federloom` bouncer from the
   `BOUNCER_KEY_federloom` environment variable and installs the
   `crowdsecurity/wordpress` collection from the `COLLECTIONS` environment
   variable — no manual `cscli` setup needed. WordPress's first boot (DB
   schema init) can take a little while; CrowdSec and FederLoom come up
   independently of that.

### Already have a WordPress compose stack?

You don't need this file's `wordpress` or `db` services — just add the
bridge to your existing project:

1. Copy the `crowdsec` and `federloom` services from `docker-compose.yml`
   into your stack's compose file (plus the `crowdsec-config`,
   `crowdsec-data`, and `federloom-data` volumes).
2. Copy `acquis.yaml`, `config.yaml`, and `rules.yaml` alongside your compose
   file.
3. In `acquis.yaml`, set `container_name` to your real WordPress container's
   name (not `federloom-wordpress`) — that's how CrowdSec's `docker` source
   picks up the right stdout stream.
4. If your WordPress container doesn't log Apache's combined format to
   stdout (e.g. you're on `wordpress:php-fpm` behind your own web server
   instead of the Apache-based image), point CrowdSec at that web server's
   own collection and log source instead of `crowdsecurity/wordpress` +
   `acquis.yaml`'s `type: apache2`.
5. Keep the `BOUNCER_KEY_federloom` / `ingest.crowdsec.api_key` pairing and
   the DB password change-me notes from *Setup* above in mind — they apply
   here too.

## Verify it works

Inject a decision directly through `cscli`, standing in for a real detection
(this is exactly what `smoke.sh` does):

    docker compose exec crowdsec cscli decisions add -i 203.0.113.99 -d 5m -R smoke-test
    curl -s http://127.0.0.1:9102/api/v1/score/203.0.113.99   # → JSON with score
    sudo ipset list federloom | grep 203.0.113.99              # → blocked in the set

**Real-traffic path** (exercises the full stack: WordPress Apache log →
CrowdSec parser → scenario → decision → FederLoom bouncer → ipset). Run this
from an **external** host — CrowdSec's default parsers whitelist
private/RFC1918 source addresses, so requests from the Docker host itself or
another container on the same LAN will not trigger a decision:

    for i in $(seq 1 20); do curl -s -o /dev/null "http://<public-ip>:8081/wp-login.php" -d "log=admin&pwd=wrong$i"; done

After a few requests this should trip a `crowdsecurity/wordpress` brute-force
scenario and produce a decision. Confirm with:

    docker compose exec crowdsec cscli decisions list
    curl -s http://127.0.0.1:9102/api/v1/score/<attacker-ip>   # → JSON with score
    sudo ipset list federloom | grep <attacker-ip>             # → blocked in the set

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
