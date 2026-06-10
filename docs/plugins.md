# Plugins: wrapping existing tools

SwarmGuard is built around two small interfaces so it can integrate existing
honeypots and security tooling instead of reinventing them.

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

| Adapter | Wraps | Notes |
| --- | --- | --- |
| `mailcow_logs` | Postfix/Dovecot/nginx Docker logs | SMTP-AUTH brute force, dict attacks, web probes |
| `spamtrap` | never-used mailboxes on a real system | honeypot semantics, zero-FP (spec §6.1) |
| `honeypot` | Cowrie, Dionaea, OpenCanary, T-Pot | dedicated honeypots → ground-truth anchors |
| `crowdsec` | CrowdSec LAPI decisions | federate what CrowdSec shares only centrally |
| `fail2ban` | Fail2Ban jails | reuse existing detectors as a source |

### Adding a honeypot tool

1. Create `internal/ingest/<tool>.go`, implement `Source`, map the tool's events
   to `proto.Event` (set `Reason`, `PortClass`, `Timestamp`).
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
