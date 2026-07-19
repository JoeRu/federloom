# FederLoom on Mailcow (non-invasive add-on)

Non-invasive integration, in the spirit of
[JoeRu/Mailcow-Crowdsec-Override](https://github.com/JoeRu/Mailcow-Crowdsec-Override):
everything lives in `docker-compose.override.yml`, so Mailcow's own files are
untouched and upgrades stay safe.

> **This example cannot be smoke-tested standalone** — it requires a live
> Mailcow install (Postfix/Dovecot containers to read logs from) and is
> therefore not covered by `smoke.sh` like the Docker examples. It is
> validated in CI by `make validate-examples`, which strict-decodes
> `federloom/config.yaml` and `federloom/rules.yaml` against the current
> schemas and confirms `docker-compose.override.yml` is valid Compose on its
> own (`docker compose -f docker-compose.override.yml config -q`).

## What you get

- `docker-compose.override.yml` — merges a `federloom` service into your
  existing Mailcow stack: reads Docker logs read-only, runs on the host
  network with `NET_ADMIN`/`NET_RAW` so it can write `ipset` rules directly.
- `federloom/config.yaml` — `ingest.mailcow_logs` enabled against Mailcow's
  default Postfix/Dovecot container names, `enforce` via `ipset` on
  `INPUT` and `DOCKER-USER`, and the local score API bound to
  `127.0.0.1:9102` with the mail taxonomy (`smtp-*`, `imap-*`, `pop3-*`).
- `federloom/rules.yaml` — local SMTP/IMAP brute-force detections block
  immediately; three independent federated reporters agreeing on anything
  else is the federation dividend.

## Relationship to CrowdSec

CrowdSec already detects attacks and shares intel with its **central**
community network. FederLoom is the **decentralised / federated** counterpart
and can:

- **consume** CrowdSec LAPI decisions as ingest (`internal/ingest/crowdsec.go`), and
- **emit** a CrowdSec-compatible blocklist (`internal/enforce/crowdsec.go`) so an
  existing `cs-firewall-bouncer` enforces FederLoom's federated reputation.

So you can run it *alongside* a CrowdSec override: CrowdSec for local
detection + enforcement, FederLoom for federated, trust-weighted intel
sharing. See `examples/crowdsec/` for that bridge.

## Prerequisites

- A running Mailcow install (`docker-compose.yml` in `/opt/mailcow-dockerized/`
  or wherever your project lives) with Postfix and Dovecot containers up.
- Docker + Compose v2 (already required by Mailcow itself).
- `ipset` on the host — FederLoom manages its own `federloom` set.

## Setup

1. Copy this example's contents into your Mailcow project directory (merge
   the `services:`/`volumes:` blocks if you already have another override
   there — e.g. one for CrowdSec):

       cp -r examples/mailcow/federloom /opt/mailcow-dockerized/
       cp examples/mailcow/docker-compose.override.yml /opt/mailcow-dockerized/

2. Run the install script to seed the **local-only** whitelist (own IP,
   gateway, DNS, Docker ranges) before enforcement goes live:

       scripts/install/install.sh

   This whitelist is `scope: local-only` and is never shared or federated —
   it stays on this node regardless of `federation_mode` (spec §6.2).

3. Check the container names in `/opt/mailcow-dockerized/federloom/config.yaml`
   (the copy you just made — that's the file that will actually be live)
   against your actual Mailcow project. FederLoom ships the stock defaults
   (`mailcowdockerized-postfix-mailcow-1`, `mailcowdockerized-dovecot-mailcow-1`),
   which match Mailcow's default `COMPOSE_PROJECT_NAME`. If your project
   directory or `COMPOSE_PROJECT_NAME` differs, adjust both values — find the
   real names with:

       docker ps | grep postfix
       docker ps | grep dovecot

4. Start it:

       cd /opt/mailcow-dockerized
       docker compose up -d federloom

   Because this only *adds* an override service, Mailcow's own
   `docker-compose.yml` and update process are completely untouched —
   `mailcow update` stays safe.

## Verify it works

    docker logs federloom

should show the mailcow_logs adapter picking up Postfix/Dovecot log lines.
Trigger a real failed login (e.g. a wrong IMAP password from a mail client,
or `openssl s_client` against port 587 with a bad `AUTH LOGIN`), then:

    curl -s http://127.0.0.1:9102/api/v1/score/<attacker-ip>   # → JSON with score
    sudo ipset list federloom | grep <attacker-ip>             # → blocked once corroboration is met

## Solo vs. join a federation

The config ships `federation_mode: solo`: everything stays on this host. To
federate, set `federation_mode: federated` and add `bootstrap_peers` with a
peer you trust, then restart. See `docs/federation-guide.md` for anchors and
invites. Your local whitelist (own IPs, gateway, DNS, Docker ranges) is never
shared regardless of federation mode.

Observability (Prometheus metrics, SQLite event history) and the embedded
DNSBL are both opt-in and off by default in this example — see
`docs/config.md` for the `observability` and `dnsbl` config sections if you
want either.

## Teardown

    cd /opt/mailcow-dockerized
    docker compose stop federloom
    docker compose rm -f federloom
    rm -rf federloom docker-compose.override.yml
    sudo ipset destroy federloom 2>/dev/null || true
