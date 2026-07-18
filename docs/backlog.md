# Backlog

Known gaps and planned work that is not yet scheduled into a release. Items
move from here into `roadmap.md` when they get a target milestone.

## Ingest signal paths

FederLoom today ingests **created bans/decisions** (fail2ban bans, CrowdSec
decisions/alerts) and a few tool-specific logs (mailcow, Cowrie, OpenCanary,
spamtrap). Two gaps block wider integration examples:

### B1 — fail2ban ingest: bare-metal (non-Docker) mode — DONE

Done: implemented as `ingest.fail2ban.mode: local | docker` (default docker).

### B2 — direct access-log ingest (nginx / apache / traefik / haproxy) — TODO

There is no ingest plugin that parses web-server access/error logs directly.
All web-server signal must currently pass through fail2ban or CrowdSec as the
detection layer.

Proposed: one generic `internal/ingest/accesslog.go` (combined log format +
configurable bad-path / auth-failure patterns) covering nginx, apache,
traefik and haproxy. Needs a rules schema and adversarial tests (log lines
are attacker-controlled input — spoofed-IP log injection must not poison the
reputation store).

Not required for the first examples wave (fail2ban/CrowdSec route works);
removes the extra moving part for users later.
