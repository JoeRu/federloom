# FederLoom at the HAProxy edge (detect + consume, Docker)

A self-contained HAProxy + CrowdSec + FederLoom stack that shows **both**
directions of the FederLoom/CrowdSec bridge at once, at a reverse-proxy edge:
CrowdSec parses HAProxy's access log and turns attacks into decisions;
FederLoom ingests those decisions as a CrowdSec bouncer, scores them, and
enforces the result in O(1) via ipset on the host firewall — and HAProxy
*itself* also denies requests from FederLoom's own blocklist feed, refreshed
by a small `fetch-blocklist.sh` script, adding a second, proxy-layer line of
defence in front of the `app` backend.

## What you get

- `docker-compose.yml` — `haproxy:2.9-alpine` in front of a `whoami` backend,
  a CrowdSec sidecar (`crowdsecurity/haproxy` collection, LAPI published on
  `127.0.0.1:18080` so it never collides with a host-installed CrowdSec that
  already owns 8080), and FederLoom (`network_mode: host`, so it can write
  the host firewall and reach the LAPI over loopback).
- `haproxy.cfg` — HAProxy logs to stdout (read by CrowdSec's `docker` source)
  and denies any source IP listed in `acl/blocklist.acl` before it reaches
  the `app` backend.
- `acquis.yaml` — CrowdSec's **docker** log-acquisition source: it reads the
  `federloom-haproxy` container's stdout directly via the Docker socket
  (`/var/run/docker.sock:ro`), the same pattern used in
  `examples/wordpress/docker/`.
- `acl/blocklist.acl` — the HAProxy deny list, one IP per line. Committed as
  a placeholder; `fetch-blocklist.sh` overwrites it. The **whole `acl/`
  directory** is bind-mounted into the container (not the single file):
  `fetch-blocklist.sh` refreshes the list with an atomic rename, and a
  single-file bind mount stays pinned to the original inode across a
  rename — only a directory mount picks up the swap.
- `fetch-blocklist.sh` — pulls FederLoom's plain-text
  `GET /crowdsec/v1/decisions` feed, writes it to `acl/blocklist.acl`, and
  hot-reloads HAProxy (`docker compose kill -s HUP haproxy`) so the new list
  takes effect without dropping connections. Meant to run on a schedule (cron,
  systemd timer, …) from this directory.
- `config.yaml` — the CrowdSec ingest adapter enabled, and the local score API
  bound to `127.0.0.1:9102`.
- `rules.yaml` — a single own-CrowdSec decision blocks immediately; three
  independent federated reporters agreeing is the federation dividend.

## Prerequisites

- Docker + Compose v2. Nothing else — HAProxy, CrowdSec, and FederLoom all
  ship as part of the compose file.

## Setup

1. Review both key files before starting — every threshold is yours to
   override, and the bouncer key pairing is the one thing you must keep in
   sync:

       cat examples/haproxy/docker/docker-compose.yml examples/haproxy/docker/config.yaml

   **Change `federloom-example-key` in BOTH files** if this host is shared
   with anyone else — it is the bouncer API key CrowdSec uses to authorise
   FederLoom, set via `BOUNCER_KEY_federloom` in `docker-compose.yml` and read
   back as `ingest.crowdsec.api_key` in `config.yaml`. The two values must
   always match exactly.

2. Start the stack:

       cd examples/haproxy/docker
       docker compose up -d

   On first start, CrowdSec auto-registers the `federloom` bouncer from the
   `BOUNCER_KEY_federloom` environment variable and installs the
   `crowdsecurity/haproxy` collection from the `COLLECTIONS` environment
   variable — no manual `cscli` setup needed.

## Both directions

This example is the only one that exercises the bridge from both ends at
once, at the same edge:

- **Detect** — CrowdSec parses HAProxy's access log (via the Docker log
  source, since the official image logs to stdout) and raises decisions for
  scenarios like `crowdsecurity/http-probing`. FederLoom polls those
  decisions as a bouncer, scores them, and — once `rules.yaml` matches —
  writes them into the host's `federloom` ipset, enforced in `INPUT` and
  `DOCKER-USER`.
- **Consume** — FederLoom also serves its own reputation data (locally
  decided or federated) back out as a plain-text feed at
  `GET /crowdsec/v1/decisions`. `fetch-blocklist.sh` polls that feed and
  writes it to `acl/blocklist.acl`, which HAProxy's `frontend web` ACL checks
  on every request, denying matches with a 403 before they reach `app`.

The proxy-layer deny in `acl/blocklist.acl` is **defence in depth on top of
the host-firewall block**, not a replacement for it: an attacker already
blocked in the `federloom` ipset never reaches HAProxy at all, so the ACL
mostly matters for IPs FederLoom learned about from elsewhere (e.g.
federation, or a different local detector) faster than the firewall rule
propagated, or in setups where HAProxy runs on a host separate from
`federloomd` and cannot share its ipset — the ACL works over the network via
the feed, with no shared firewall required. Schedule `fetch-blocklist.sh` on
a cron or systemd timer (e.g. every 5 minutes) to keep `acl/blocklist.acl`
current.

## Verify it works

Inject a decision directly through `cscli`, standing in for a real detection
(this is exactly what `smoke.sh` does):

    docker compose exec crowdsec cscli decisions add -i 203.0.113.99 -d 5m -R smoke-test
    curl -s http://127.0.0.1:9102/api/v1/score/203.0.113.99   # → JSON with score
    sudo ipset list federloom | grep 203.0.113.99              # → blocked in the set

Then exercise the consume direction manually:

    ./fetch-blocklist.sh
    grep 203.0.113.99 acl/blocklist.acl                          # → the fetched ACL lists it

The host file matching is necessary but not sufficient: it only proves
`fetch-blocklist.sh` wrote the list, not that HAProxy is actually reading it.
Confirm the running container's own view has picked up the refresh (this is
exactly what `smoke.sh` asserts, and why `acl/` is mounted as a directory
rather than the file being mounted directly — see *What you get* above):

    docker compose exec haproxy grep 203.0.113.99 /usr/local/etc/haproxy/acl/blocklist.acl

Clean up the test entry:

    docker compose exec crowdsec cscli decisions delete -i 203.0.113.99
    sudo ipset del federloom 203.0.113.99 2>/dev/null || true
    git checkout -- acl/blocklist.acl

## Solo vs. join a federation

The config ships `federation_mode: solo`: everything stays on this host. To
federate, set `federation_mode: federated`, uncomment `bootstrap_peers` with a
peer you trust, and restart. See `docs/federation-guide.md` for anchors and
invites. Your local whitelist (own IPs, gateway, DNS) is never shared or
federated.

## Teardown

    docker compose down -v
    sudo ipset destroy federloom 2>/dev/null || true
