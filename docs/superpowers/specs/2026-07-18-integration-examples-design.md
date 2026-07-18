# Integration Examples (`examples/`) — Design

Date: 2026-07-18
Status: approved (brainstorm 2026-07-18)

## Goal

Make first contact with FederLoom a 5-minute copy-paste. A newcomer who runs
one of the covered tools finds one folder with everything needed, follows a
numbered README, and ends with a working, verifiable FederLoom integration.

Secondary goal: publicity. Each example targets a distinct audience:

| Audience | Entry point |
|---|---|
| VPS admins (bare-metal fail2ban) | `vps-fail2ban/`, `nginx/os/`, `apache/os/` |
| Docker / self-hosted community | `wordpress/`, `traefik/`, `haproxy/`, `nginx/docker/`, `apache/docker/` |
| Existing CrowdSec users | `crowdsec/` (bidirectional bridge) |
| Mailcow operators | `mailcow/` |
| Network admins (no agent at all) | `firewall-export/` (OPNsense/pfSense/MikroTik/FortiGate) |

## Relationship to `deploy/`

`examples/` is a new top-level folder for public consumption: generic,
copy-paste-ready, no personal environment assumptions. `deploy/` stays as-is
(personal SwarmGuard lab: pinned IPs, bootstrap scripts, `config.local.yaml`).
`examples/mailcow/` and `examples/wordpress/` are generalised from their
`deploy/` counterparts, not moves.

## Tree

```
examples/
  README.md            # chooser matrix: "I run X → go here"
  vps-fail2ban/        # hello-world: plain VPS, sshd jail (OS install)
  nginx/
    os/                # fail2ban web jails, bare-metal
    docker/            # nginx + CrowdSec sidecar + federloomd
  apache/
    os/
    docker/
  wordpress/docker/    # override for the canonical WordPress compose
  traefik/docker/
  haproxy/docker/      # detect via CrowdSec; also CONSUME blocklist into an ACL
  crowdsec/            # bidirectional bridge (bare-metal + docker notes)
  mailcow/             # docker-compose.override.yml, generalised from deploy/
  firewall-export/     # consume-side only: firewall alias/address-list URLs
```

## Per-example anatomy

Every folder is standalone (approach C: self-contained user-facing files,
shared CI harness — see Verification).

- `README.md` — fixed section order: What you get → Prerequisites → Setup
  (numbered) → Verify it works → Solo vs. join a federation → Teardown.
  Wherever a threshold/parameter appears, note that it is locally overridable
  (invariant 1: lists are aids, not law).
- Docker variants: `docker-compose.yml` — or `docker-compose.override.yml`
  where the upstream project has a canonical compose file (mailcow,
  wordpress) — plus federloom `config.yaml` and `rules.yaml` where needed.
- OS variants: config files (fail2ban `jail.d/` snippets, federloom
  `config.yaml`, systemd unit) plus exact commands in the README.

## Signal routing (what exists vs. what is added)

FederLoom ingests created bans/decisions, not raw web-server logs
(see `docs/backlog.md` B2 for the future direct access-log ingest).

- **vps-fail2ban**: sshd jail → fail2ban ingest in new `mode: local` (B1) →
  ipset enforce. The flagship "federate your fail2ban in 5 minutes".
- **nginx/os, apache/os**: fail2ban web jails (`nginx-http-auth`,
  `nginx-botsearch`; `apache-auth`, `apache-badbots`) → `mode: local`.
- **nginx/docker, apache/docker, wordpress, traefik, haproxy**: target
  service + CrowdSec sidecar with the matching collection + federloomd in one
  `docker compose up`.
- **haproxy** additionally consumes the blocklist: plain-text endpoint →
  periodic fetch into an ACL file → block at the edge proxy.
- **crowdsec**: bridge in both directions — ingest LAPI decisions/alerts;
  serve the bouncer-compatible plain-text feed (`GET /crowdsec/v1/decisions`).
- **mailcow**: generalised override (strip personal IPs/bootstrap from
  `deploy/mailcow`).
- **firewall-export**: no FederLoom agent on the firewall. OPNsense URL-table
  alias, pfSense, MikroTik address-list, FortiGate external feed, all
  fetching `GET /crowdsec/v1/decisions`. Mandatory security section: the API
  is network-trust-based — bind to a VPN/management interface, never
  `0.0.0.0` on WAN.

## Code change: B1 — fail2ban bare-metal mode

The only Go change in this wave. `Fail2BanConfig` gains
`mode: local | docker` (default `docker`, fully backward-compatible).
`local` runs `fail2ban-client banned` directly on the host instead of
`docker exec`. Jail→reason mapping unchanged. Unit tests via the existing
injectable fetcher. Adversarial suite reviewed: no scoring/trust change, so
no new scenario expected — confirm, don't assume.

## Verification (anti-rot gate)

- `make validate-examples`, run in CI on every PR:
  strict YAML decode of every `examples/**/config.yaml` and `rules.yaml`
  against the current schema (unknown keys = failure) + `docker compose
  config` on every compose file. This is the lesson from the v0.1.0
  truth-up: example configs rot silently without a strict gate.
- Shared smoke harness in `test/examples/`: for each docker example —
  `compose up` → scripted simulated attack (repeated auth failures) → poll
  `GET /api/v1/blocklist` until the attacker IP appears → `compose down`.
  Runs in CI on PRs touching `examples/` and nightly.
- OS variants cannot run in CI: hand-verified once, README carries a
  "Verified on Debian 12, YYYY-MM-DD" line.

## Docs integration

- Root `README.md`: "Integrations" matrix linking into `examples/`.
- `docs/getting-started.md`: point to `examples/vps-fail2ban/` as the
  fastest path.
- `docs/backlog.md`: B2 (direct access-log ingest) referenced from the web
  examples as the future upgrade; B1 closed by this wave.

## Build order (publicity-first)

1. B1 code change + `vps-fail2ban`
2. `crowdsec` bridge
3. `nginx` (docker, then os)
4. `wordpress`
5. `traefik`
6. `apache`
7. `haproxy`
8. `mailcow`
9. `firewall-export`
10. `examples/README.md` matrix + docs integration + CI harness (harness
    grows alongside from step 1)

## Out of scope (wave 2+)

- B2 direct access-log ingest plugin (nginx/apache/traefik/haproxy without
  fail2ban/CrowdSec).
- Caddy, Nextcloud, Vaultwarden, docker-mailserver/Mailu, Authelia/Authentik,
  Gitea/Forgejo, Proxmox examples.
- Vagrant/VM-automated verification of OS variants.
