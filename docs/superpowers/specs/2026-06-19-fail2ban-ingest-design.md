# Fail2Ban Ingest Plugin Design

**Feature:** `ingest.Fail2Ban` — Docker-native fail2ban ingest source  
**Date:** 2026-06-19  
**Status:** Approved

## Problem

SwarmGuard has no adapter for fail2ban, the most widely deployed intrusion prevention system on self-hosted Linux servers. Operators running fail2ban alongside Mailcow or WordPress already have local ban decisions that SwarmGuard cannot see or federate. Adding fail2ban as an ingest source lets SwarmGuard incorporate locally-observed ban events without requiring operators to replace their existing tooling.

## Goal

Add `internal/ingest/fail2ban.go` implementing `ingest.Source`. The adapter polls a fail2ban Docker container via `docker exec fail2ban-client banned`, diffs against a prior state to detect new bans, maps jail names to SwarmGuard reason codes, and emits `proto.Event`s — one per newly-banned IP.

Scope is Docker-first (matching the deployment model of all other SwarmGuard ingest adapters). Non-Docker fail2ban is out of scope.

---

## Config

New `Fail2BanConfig` in `IngestConfig`:

```go
type Fail2BanConfig struct {
    Enabled      bool              `yaml:"enabled"`
    Container    string            `yaml:"container"`     // default: "fail2ban"
    PollInterval Duration          `yaml:"poll_interval"` // default: 30s
    JailReasons  map[string]string `yaml:"jail_reasons"`  // operator overrides
}
```

Added to `IngestConfig` as `Fail2Ban Fail2BanConfig \`yaml:"fail2ban"\``.

Default values set in `Defaults()`:
- `Container`: `"fail2ban"`
- `PollInterval`: `30s`
- `Enabled`: `false` (opt-in, same pattern as all other adapters)

Example `config.yaml` snippet:

```yaml
ingest:
  fail2ban:
    enabled: true
    container: "fail2ban"
    poll_interval: "30s"
    jail_reasons:
      my-custom-jail: "http-wp-bruteforce"
```

---

## Data Model & Polling Logic

### Fetcher interface

```go
// fail2banFetcher retrieves the current ban set from a fail2ban container.
// Injectable so tests run without a Docker daemon.
type fail2banFetcher func(ctx context.Context, container string) ([]byte, error)

// dockerBanned is the production fetcher.
func dockerBanned(ctx context.Context, container string) ([]byte, error) {
    return exec.CommandContext(ctx,
        "docker", "exec", container, "fail2ban-client", "banned",
    ).Output()
}
```

`fail2ban-client banned` returns a JSON array of single-key objects:

```json
[{"sshd": ["1.2.3.4", "5.6.7.8"]}, {"postfix-sasl": ["9.9.9.9"]}]
```

### Struct

```go
type Fail2Ban struct {
    cfg     config.Fail2BanConfig
    selfID  string
    fetcher fail2banFetcher
}

func NewFail2Ban(cfg config.Fail2BanConfig, selfID string) *Fail2Ban
func NewFail2BanWithFetcher(cfg config.Fail2BanConfig, selfID string, f fail2banFetcher) *Fail2Ban
```

`NewFail2Ban` uses `dockerBanned`. `NewFail2BanWithFetcher` is the test constructor (same pattern as `NewMailcowWithFetcher`).

### Poll loop

State: `seen map[string]string` — IP → jail name — held in memory, not persisted.

On each tick:
1. Call fetcher, parse JSON into `current map[string]string` (IP → jail)
2. For each IP in `current` not in `seen`: emit event, add to `seen`
3. For each IP in `seen` not in `current`: remove from `seen` (unbanned — no event; score decays naturally)

On restart `seen` is empty, so all currently-banned IPs emit once. This is harmless — the reputation engine is idempotent and a score bump for an already-blocked IP has no practical effect.

---

## Reason Mapping

Resolution order: **config override (exact) → exact built-in → prefix built-in → fallback**. Operator `jail_reasons` entries are exact-match only; prefix patterns are built-in only.

### Built-in defaults

| Jail pattern | Reason |
|---|---|
| `sshd`, `ssh`, `sshd-*` | `ssh-auth-bruteforce` |
| `postfix`, `postfix-sasl`, `postfix-*` | `smtp-auth-bruteforce` |
| `dovecot`, `dovecot-*` | `imap-auth-bruteforce` |
| `nginx-http-auth`, `nginx-*` | `http-auth-bruteforce` |
| `apache-auth`, `apache-*` | `http-auth-bruteforce` |
| `wordpress`, `wp-*` | `http-wp-bruteforce` |
| `recidive` | `recidive` |

Prefix patterns (`sshd-*`) match jail names that start with the prefix, catching common variants like `sshd-aggressive` and `sshd-ddos`.

### Fallback

Unknown jails produce reason `"fail2ban-<jailname>"`. Events are still emitted and visible in `swarmctl status` and the API, so operators can discover what fail2ban is detecting before they classify it in `jail_reasons`.

### Implementation

```go
func (f *Fail2Ban) resolveReason(jail string) string {
    // 1. Operator config override (exact match)
    if r, ok := f.cfg.JailReasons[jail]; ok {
        return r
    }
    // 2. Built-in exact match
    if r, ok := builtinJailReasons[jail]; ok {
        return r
    }
    // 3. Built-in prefix match
    for prefix, r := range builtinJailPrefixes {
        if strings.HasPrefix(jail, prefix) {
            return r
        }
    }
    // 4. Fallback
    return "fail2ban-" + jail
}
```

---

## Trust Level

Fail2ban is a **locally-observed source**, not a ground-truth honeypot. Events are emitted with the standard reporter weight — the same treatment as CrowdSec decisions. They are not wired as trust anchors (that treatment is reserved for Cowrie/spamtrap where any connection is definitionally malicious).

---

## Wire-up

### `internal/node/node.go`

In the source-construction block alongside existing adapters:

```go
if cfg.Ingest.Fail2Ban.Enabled {
    sources = append(sources, ingest.NewFail2Ban(cfg.Ingest.Fail2Ban, selfID))
}
```

---

## Testing

Four test cases in `internal/ingest/fail2ban_test.go` using a stub fetcher:

| Test | Setup | Assert |
|---|---|---|
| `TestFail2Ban_NewBan` | Stub returns `[{"sshd": ["1.2.3.4"]}]` | Event emitted with reason `ssh-auth-bruteforce` |
| `TestFail2Ban_NoDuplicate` | Same stub called twice | Event emitted only on first poll |
| `TestFail2Ban_Reban` | IP appears, disappears, re-appears | Event emitted on first and third poll, not second |
| `TestFail2Ban_UnknownJail` | Stub returns `[{"my-jail": ["2.2.2.2"]}]` | Reason is `"fail2ban-my-jail"` |

No adversarial test: fail2ban is a local-only source. Poisoning it requires compromising the local Docker daemon, which is outside SwarmGuard's threat model.

---

## File Map

| File | Action | What changes |
|---|---|---|
| `internal/ingest/fail2ban.go` | Create | `Fail2Ban` struct, fetcher, poll loop, reason mapping |
| `internal/ingest/fail2ban_test.go` | Create | 4 unit tests with stub fetcher |
| `internal/config/config.go` | Modify | Add `Fail2BanConfig`, wire into `IngestConfig` and `Defaults()` |
| `internal/node/node.go` | Modify | Instantiate and register `Fail2Ban` when enabled |

---

## Out of Scope

- Non-Docker fail2ban (systemd service, bare-metal)
- Unban events triggering score reduction (score decays naturally via half-life)
- Persisting `seen` state across restarts
- Nginx/Apache access log ingest (separate plugin, separate brainstorm)
