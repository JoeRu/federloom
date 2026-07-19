# Backlog

Known gaps and planned work that is not yet scheduled into a release. Items
move from here into `roadmap.md` when they get a target milestone.

## Ingest signal paths

FederLoom today ingests **created bans/decisions** (fail2ban bans, CrowdSec
decisions/alerts) and a few tool-specific logs (mailcow, Cowrie, OpenCanary,
spamtrap). Two gaps block wider integration examples:

### B1 — fail2ban ingest: bare-metal (non-Docker) mode — DONE

Done: implemented as `ingest.fail2ban.mode: local | docker` (default docker).

### B2 — direct access-log ingest (nginx / apache / traefik / haproxy) — NOT RECOMMENDED

There is no ingest plugin that parses web-server access/error logs directly,
**and that is now deliberate policy** (see "Scope: what qualifies as an ingest
source" in `docs/plugins.md`): routing web-server signal through fail2ban or
CrowdSec as the detection layer is the supported path, and the `examples/`
wave ships working recipes for exactly that (nginx, apache, traefik, haproxy,
wordpress). Detection belongs to detectors; FederLoom consumes verdicts.

Reopen only on demonstrated demand, and then under strict adversarial
constraints: log lines are attacker-controlled input — spoofed-IP log
injection must not poison the reputation store.

### B3 — generic webhook/push ingest — TODO

One authenticated `POST` endpoint (schema `{ip, reason, timestamp}`) instead
of N SIEM adapters: Graylog, ELK/OpenSearch, Loki/Grafana, fluentd,
syslog-ng, SEC etc. all have alert webhooks/exec actions and integrate
themselves against a published contract. This caps adapter growth — FederLoom
publishes a contract rather than maintaining per-tool parsers.

Sketch: token auth, rate limiting, `reason` must come from the reason-code
catalog (spec §7.1), bind to localhost/management networks by default.
Adversarial note: a push endpoint is externally reachable input; events count
under the node's own `ReporterID`, so the operator vouches for whatever their
pipeline pushes — document this prominently.

### B4 — Wazuh / OSSEC adapter — TODO (post-MVP)

Consume only the active-response / alert output (finished verdicts, rule-ID →
reason mapping). Never hook into the Wazuh log pipeline itself, and ignore
host-internal signal (FIM, rootkit, compliance) — only IP-attributable events
map to the taxonomy.

### B5 — Suricata / Snort adapter — TODO (post-MVP)

EVE JSON alerts are structured verdicts from a network IDS. Needs a
signature-category → reason-taxonomy mapping. Same verdict-only rule as B4.

> B3–B5 complement what the spec already plans: MISP ingest is spec §13
> item 19; the future source-reputation layer (item 20) will address
> per-source weighting.

### B6 — mailcow container-name fallback mismatch — TODO (small)

`internal/ingest/mailcow_logs.go` falls back to `mailcowdockerized-postfix-1`
/ `mailcowdockerized-dovecot-1`, but real Mailcow projects (and our docs +
`examples/mailcow/`) use `mailcowdockerized-postfix-mailcow-1` /
`-dovecot-mailcow-1`. Align the code fallback with the documented default.
Harmless today because deploy and example configs pin the names explicitly.

### B7 — examples polish (final branch-review follow-ups) — TODO (small)

- OS-variant configs (`vps-fail2ban`, `nginx/os`, `apache/os`) omit the
  `block_threshold: 1` / `unblock_threshold: 0.5` override the docker examples
  carry — add the override or a one-line note explaining the difference.
- `examples/firewall-export/docker-compose.yml` keeps
  `cap_add: [NET_ADMIN, NET_RAW]` without saying why (ipset inside the
  container's own netns) — add a comment line.
- `tools/validate-examples` `isCandidate` prefix match also sweeps files like
  `configuration-notes.yaml` into strict decode (fails safe, but surprising).
- `examples/wordpress/docker/README.md` "existing stack" section could caveat
  `db-data` volume-name collisions.
