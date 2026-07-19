# Plugins: wrapping existing tools

FederLoom is built around two small interfaces so it can integrate existing
honeypots and security tooling instead of reinventing them.

## Scope: what qualifies as an ingest source

FederLoom's core competence is reputation aggregation, federation, and
enforcement — **not detection**. A SIEM collects, normalises, correlates, and
alerts on arbitrary logs; that is exactly what FederLoom must not become.
SIEM/TIP platforms are downstream *consumers* (via the STIX/TAXII egress and
the plain-text decisions feed), and alerting stacks (Graylog, ELK/OpenSearch,
Loki, fluentd, syslog-ng, SEC, …) will integrate as *producers* through one
generic webhook ingest (`docs/backlog.md`, B3) — not through per-tool adapters.

Existing sources fall into three classes:

1. **Own traps** (`spamtrap`, `honeypot`/Cowrie, `opencanary`) — never-used
   resources where any hit is hostile. Zero false positives, trivial parsing.
   These are FederLoom's ground-truth-anchor concept (spec §4.1), not a SIEM
   feature.
2. **Verdict wrappers** (`crowdsec`, `fail2ban`) — thin adapters that consume
   *finished decisions* (bans, alerts) from tools whose whole job is detection.
   The parsing/correlation know-how stays in those communities.
3. **Raw-log parsers** (`mailcow_logs`, and only it) — the founding use case,
   kept as a frozen exception. **New raw-log parsers are not accepted**; route
   the signal through a detector (class 2) instead.

Every proposed source must pass this four-point test:

1. **Verdict, not raw data.** The tool already emits a decision (ban, alert,
   trap hit). If FederLoom would have to detect — regex or correlation over raw
   logs — that is SIEM drift; the logic belongs in a detector, not here.
2. **Maps onto the reason taxonomy.** The signal translates to an abstract
   attack scenario (spec §7.1, the join key; no concrete ports).
3. **IP-centric.** The event is a statement about a remote IP misbehaving.
   Host-internal signals (file integrity, rootkits, compliance) are out of
   scope, even when the wrapped tool produces them.
4. **Adversarial cost.** Raw logs are attacker-controlled input; every parser
   FederLoom owns widens the poisoning surface, while verdict adapters inherit
   the detector's hardening. All local sources report under the node's own
   `ReporterID` — the node vouches for everything it ingests with its own
   reputation, and trust falls fast (spec §4.3).

Planned sources that pass the test (Wazuh/OSSEC active-response output,
Suricata/Snort EVE alerts, MISP, the generic webhook) are tracked in
`docs/backlog.md` and spec §13.

## `ingest.Source` — attack-signal producers

Defined in `internal/ingest/plugin.go`:

```go
type Source interface {
    Name() string
    Start(ctx context.Context) (<-chan proto.Event, error)
}
```

A Source watches some system and emits `proto.Event`s. Register it from `init()`
with `ingest.Register("name", factory)`.

**Shipped / planned adapters:**

| Adapter | Class | Wraps | Notes |
| --- | --- | --- | --- |
| `mailcow_logs` | raw-log parser (frozen exception) | Postfix/Dovecot/nginx Docker logs | SMTP-AUTH brute force, dict attacks, web probes |
| `spamtrap` | own trap | never-used mailboxes on a real system | honeypot semantics, zero-FP (spec §6.1) |
| `honeypot` | own trap | Cowrie, Dionaea, OpenCanary, T-Pot | dedicated honeypots → ground-truth anchors |
| `crowdsec` | verdict wrapper | CrowdSec LAPI decisions | federate what CrowdSec shares only centrally |
| `fail2ban` | verdict wrapper | Fail2Ban jails (docker or local mode) | reuse existing detectors as a source |

### Adding a honeypot tool

1. Create `internal/ingest/<tool>.go`, implement `Source`, map the tool's events
   to `proto.Event` (set `IP`, `Reason`, `Timestamp`; `ReporterID` is the node's
   own identity).
2. Honeypot/spamtrap sources should be wired as **ground-truth anchors** (high
   weight) — coordinate with `internal/trust`.
3. Add an adversarial test if the source affects scoring.

See `.claude/skills/add-ingest-plugin`.

## `enforce.Sink` — enforcement backends

Defined in `internal/enforce/plugin.go`:

```go
type Sink interface {
    Name() string
    Apply(blocked []proto.ScoreEntry) error // idempotent reconcile
}
```

**Backends:** `ipset`, `nftables` (both O(1)), and `crowdsec` (emit a
CrowdSec-compatible blocklist so an existing `cs-firewall-bouncer` enforces it —
the clean way to run alongside JoeRu/Mailcow-Crowdsec-Override).

> Enforcement is security-critical: backends must be idempotent, must honour the
> never-block set, and must never generate one rule per IP. See
> `.claude/skills/enforce-backend`.
