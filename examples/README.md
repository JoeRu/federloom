# FederLoom integration examples

Copy-paste-ready integrations. Every folder is self-contained: copy it, follow
its README, done. Configs are CI-validated against the current schema; docker
examples are smoke-tested (simulated attack → IP appears in the blocklist API).

## I run … → go here

| You run | Example | Style | Detector |
|---|---|---|---|
| A plain VPS with fail2ban | [`vps-fail2ban/`](vps-fail2ban/) | OS install | fail2ban (`mode: local`) |
| nginx on the host | [`nginx/os/`](nginx/os/) | OS install | fail2ban web jails |
| nginx in Docker | [`nginx/docker/`](nginx/docker/) | Compose | CrowdSec sidecar |
| Apache on the host | [`apache/os/`](apache/os/) | OS install | fail2ban web jails |
| Apache in Docker | [`apache/docker/`](apache/docker/) | Compose | CrowdSec sidecar |
| WordPress | [`wordpress/docker/`](wordpress/docker/) | Compose | CrowdSec (wordpress collection) |
| Traefik | [`traefik/docker/`](traefik/docker/) | Compose | CrowdSec (traefik collection) |
| HAProxy | [`haproxy/docker/`](haproxy/docker/) | Compose | CrowdSec + edge ACL consume |
| CrowdSec already | [`crowdsec/`](crowdsec/) | Compose | bidirectional bridge |
| Mailcow | [`mailcow/`](mailcow/) | Compose override | native mailcow log ingest |
| OPNsense / pfSense / MikroTik / FortiGate | [`firewall-export/`](firewall-export/) | agentless | consumes the plain-text feed |

## How the docker examples are built

The pattern in most of them: your service + a CrowdSec sidecar (parses the
logs, publishes LAPI on `127.0.0.1:18080` host side; container-internal 8080
— the non-standard host port avoids colliding with a host-installed CrowdSec
that already owns 8080) + `federloomd` on the host network (ingests CrowdSec
decisions as a bouncer, maintains reputation, enforces via ipset in
`DOCKER-USER`/`INPUT`). Every threshold and rule is locally overridable —
lists are aids, not law.

Three examples don't fit that mould:

- **`haproxy/docker/`** additionally *consumes* FederLoom's own blocklist feed
  at the edge: a `fetch-blocklist.sh` script refreshes `acl/blocklist.acl`,
  which HAProxy denies against directly — a second, proxy-layer line of
  defence in front of the backend, alongside the usual ipset enforcement.
- **`firewall-export/`** is agentless: a single FederLoom container in
  `federation_mode: solo` with no ingest source, serving
  `GET /crowdsec/v1/decisions` as a plain-text feed for your perimeter
  firewall's native URL-fetch/Threat-Feed mechanism. Nothing to install on
  the firewall itself.
- **`mailcow/`** is a `docker-compose.override.yml` (JoeRu/Mailcow-Crowdsec-Override
  style) that reads Mailcow's own Postfix/Dovecot logs directly — no CrowdSec
  sidecar. It requires a live Mailcow install, so it isn't smoke-tested like
  the other Docker examples; `make validate-examples` still strict-decodes
  its config/rules and validates the override compose file on its own.

Web-server examples route detection through fail2ban/CrowdSec today; a direct
access-log ingest is planned (see `docs/backlog.md`, B2).
