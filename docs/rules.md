# Rules Reference

`rules.yaml` is a list of named rules that determine what FederLoom does when
an IP is observed. Rules give operators fine-grained control beyond a simple
score threshold: block on a single high-confidence event, require corroboration
from multiple peers, or trigger on a burst of events within a sliding time window.

## File location and loading

Set `reputation.rules_file` in `config.yaml` to an absolute path. If unset,
FederLoom auto-discovers `<store.dir>/rules.yaml`. If that file is also absent,
FederLoom falls back to **legacy mode**: block when score ≥ `reputation.block_threshold`.

The daemon watches the file's mtime and size and reloads automatically on change —
no restart required. If a reload fails (parse error, missing file after a
successful first load), the last-good ruleset is kept and a warning is logged.

## Evaluation semantics

- Rules are evaluated **top-to-bottom; the first matching rule wins**.
- All conditions within a rule are **AND**ed. Omitting a field skips that check entirely.
- A rule with no conditions (only `name` and `action`) always matches — useful as a catch-all at the end of the list.
- Misconfigured rules are **dropped at load time** with a log warning:
  - `min_burst` set without `burst_window`
  - Unknown `action` value (typos such as `bloc` instead of `block`)

## Field reference

Each entry in `rules.yaml` is a rule object. All fields except `name` and
`action` are optional.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique identifier. Appears in logs and metrics when the rule fires. |
| `action` | enum | yes | `block` — add IP to blocklist. `watch` — track score but don't block. `ignore` — suppress scoring for this event entirely. |
| `reason` | string | no | Reason code to match. Exact string or prefix wildcard ending in `*` (e.g. `smtp-*` matches any reason starting with `smtp-`). Omit to match any reason. |
| `min_score` | float64 | no | Minimum cumulative reputation score. Rule skipped when score is below this value. |
| `min_corroboration` | int | no | Minimum number of distinct reporters (peers or local adapters) that have seen this IP. |
| `anchored_only` | bool | no | When `true`, skip this rule if any stranger (un-vouched reporter) contributed to the record. Default `false`. |
| `min_burst` | int | no | Minimum number of events within `burst_window`. Must be paired with `burst_window`. Burst state resets on daemon restart. |
| `burst_window` | duration | no | Sliding time window for burst detection, e.g. `10m`, `1h`. Required when `min_burst` is set. |

### Reason pattern matching

The `reason` field supports two matching modes:

- **Exact match:** `reason: smtp-auth-bruteforce` matches only that string.
- **Prefix wildcard:** `reason: smtp-*` matches any reason starting with `smtp-`, such as `smtp-auth-bruteforce` or `smtp-spamtrap`.

Omitting `reason` matches every event regardless of reason code.

## Reason code catalogue

The table below lists all reason codes currently emitted by FederLoom's ingest
adapters. Use these values in the `reason` field of your rules.

### Honeypot (Cowrie)

| Reason code | Cowrie event | Meaning |
|-------------|-------------|---------|
| `ssh-probe` | `cowrie.session.connect` | TCP connection to the honeypot — no auth attempted. |
| `ssh-auth-bruteforce` | `cowrie.login.failed` | Failed login attempt. |
| `ssh-auth-success` | `cowrie.login.success` | Attacker authenticated to the honeypot shell. High-confidence signal. |
| `ssh-post-auth-command` | `cowrie.command.input` | Attacker ran a command inside the honeypot. Highest-confidence signal. |
| `ssh-unknown` | (all other event IDs) | Fallback for unrecognised Cowrie event types. |

### OpenCanary (multi-protocol honeypot)

| Reason code | Logtype | Meaning |
|-------------|---------|---------|
| `ssh-new-connection` | 4000 | New SSH TCP connection. |
| `ssh-remote-version` | 4001 | SSH client sent its version banner. |
| `ssh-login-attempt` | 4002 | SSH login attempt. |
| `ftp-login-attempt` | 2000 | FTP login attempt. |
| `ftp-auth-attempt` | 2001 | FTP auth attempt. |
| `http-probe` | 3000 | HTTP/HTTPS GET request (fires for both port 80 and 443). |
| `http-post-login` | 3001 | HTTP login form POST attempt. |
| `http-unimplemented` | 3002 | Unsupported HTTP method. |
| `http-redirect` | 3003 | HTTP redirect triggered. |
| `http-proxy-login` | 7001 | HTTP proxy login attempt. |
| `smb-file-open` | 5000 | SMB file open event. |
| `telnet-login-attempt` | 6001 | Telnet login attempt. |
| `mysql-login-attempt` | 8001 | MySQL login attempt. |
| `opencanary-unknown` | (other) | Fallback for OpenCanary logtypes not in the standard map. |

### Mailcow logs (Postfix + Dovecot)

| Reason code | Log source | Meaning |
|-------------|-----------|---------|
| `smtp-auth-bruteforce` | Postfix | Failed SMTP AUTH attempt. |
| `imap-auth-bruteforce` | Dovecot | Failed IMAP login. |
| `pop3-auth-bruteforce` | Dovecot | Failed POP3 login. |

### Spamtrap

| Reason code | Meaning |
|-------------|---------|
| `smtp-spamtrap` | Mail delivered to a spamtrap address — zero-false-positive signal. |

### CrowdSec LAPI

CrowdSec scenarios are mapped to reason codes as follows:

| CrowdSec scenario | Reason code |
|-------------------|-------------|
| `crowdsecurity/ssh-bf`, `crowdsecurity/ssh-slow-bf`, `crowdsecurity/ssh-bf-wordpress` | `ssh-auth-bruteforce` |
| `crowdsecurity/http-probing`, `crowdsecurity/http-bf` | `http-probe` |
| `crowdsecurity/smtp-bf` | `smtp-auth-bruteforce` |
| Any other scenario | Vendor prefix stripped: `crowdsecurity/custom-rule` → `custom-rule` |

For unknown CrowdSec scenarios, the vendor prefix is stripped and the remainder
becomes the reason code. For example, `crowdsecurity/http-sensitive-files` becomes
`http-sensitive-files`. Use prefix wildcards on the stripped name (e.g. `http-*`)
to match entire families of scenarios.

### Fail2ban

Reason codes are resolved from jail names. Built-in mappings (exact and prefix):

| Jail name (or prefix) | Reason code |
|-----------------------|-------------|
| `sshd`, `ssh`, `sshd-*` | `ssh-auth-bruteforce` |
| `postfix`, `postfix-sasl`, `postfix-*` | `smtp-auth-bruteforce` |
| `dovecot`, `dovecot-*` | `imap-auth-bruteforce` |
| `nginx-http-auth`, `nginx-*` | `http-auth-bruteforce` |
| `apache-auth`, `apache-*` | `http-auth-bruteforce` |
| `wordpress`, `wp-*` | `http-wp-bruteforce` |
| `recidive` | `recidive` |
| (any other jail) | `fail2ban-<jailname>` automatically (e.g. `proftpd` → `fail2ban-proftpd`). Override via `ingest.fail2ban.jail_reasons` in `config.yaml`. Use `fail2ban-*` as a wildcard pattern to match all auto-mapped codes. |

## Deployment recipes

The recipes below illustrate rule ordering for four common node archetypes.
The ordering principle is the same in all cases: **high-confidence single-event
rules first, multi-corroboration rules next, score-based fallback last.**

### Sensor / honeypot node

A sensor attracts attackers and feeds intelligence to peers. Its own
`reputation.block_threshold` is set high (e.g. `1000`) so the score-based
fallback never fires locally. Only block IPs that achieved interactive access;
watch everything else to maximise data collection.

```yaml
# Block IPs that achieved shell access — they got what they wanted; no data loss from blocking.
- name: honeypot-shell-exec
  reason: ssh-post-auth-command
  min_corroboration: 1
  action: block

- name: honeypot-auth-success
  reason: ssh-auth-success
  min_corroboration: 1
  action: block

# Watch all other events — keep the sensor visible and maximise feed quality.
- name: watch-all
  min_corroboration: 1
  action: watch
```

### Mail server (Mailcow)

Mail servers care about SMTP/IMAP/POP3. Block spamtrap hits immediately
(zero false-positive rate); block brute-force when corroborated; catch
everything else with a score fallback.

```yaml
# Spamtrap — zero-FP; block on single local event.
- name: spamtrap-hit
  reason: smtp-spamtrap
  min_corroboration: 1
  action: block

# Honeypot shell commands federated from peer nodes.
- name: honeypot-shell-exec
  reason: ssh-post-auth-command
  min_corroboration: 1
  action: block

- name: honeypot-auth-success
  reason: ssh-auth-success
  min_corroboration: 1
  action: block

# SMTP/IMAP/POP3 brute-force confirmed by 2+ reporters.
- name: smtp-brute-consensus
  reason: smtp-auth-bruteforce
  min_corroboration: 2
  action: block

- name: imap-brute-consensus
  reason: imap-auth-bruteforce
  min_corroboration: 2
  action: block

- name: pop3-brute-consensus
  reason: pop3-auth-bruteforce
  min_corroboration: 2
  action: block

# SSH burst — local fail2ban / honeypot data.
- name: ssh-brute-burst
  reason: ssh-auth-bruteforce
  min_burst: 15
  burst_window: 10m
  action: block

# Score fallback — catches anything not matched above.
- name: score-fallback
  min_score: 75
  action: block
```

### Web server (WordPress)

Web servers see HTTP scanning and WordPress probing. Use wildcard prefixes
to catch all CrowdSec HTTP/WordPress scenarios without enumerating them.

```yaml
# CrowdSec HTTP bans — covers http-probe, http-bf, and custom HTTP scenarios.
- name: crowdsec-http-ban
  reason: http-*
  min_corroboration: 1
  action: block

# CrowdSec WordPress bans.
- name: crowdsec-wordpress-ban
  reason: wordpress-*
  min_corroboration: 1
  action: block

# Honeypot shell access federated from peers.
- name: honeypot-shell-exec
  reason: ssh-post-auth-command
  min_corroboration: 1
  action: block

- name: honeypot-auth-success
  reason: ssh-auth-success
  min_corroboration: 1
  action: block

# HTTP probe corroborated by 2+ federation peers.
- name: http-probe-consensus
  reason: http-probe
  min_corroboration: 2
  action: block

# SSH burst seen by honeypot or fail2ban.
- name: ssh-brute-burst
  reason: ssh-auth-bruteforce
  min_burst: 15
  burst_window: 10m
  action: block

# Score fallback.
- name: score-fallback
  min_score: 75
  action: block
```

### General-purpose / solo node

A balanced ruleset for a node with no specialised role. Requires corroboration
for most signals; relies on score accumulation for the long tail.

```yaml
# Honeypot shell access — highest confidence from any peer.
- name: honeypot-shell-exec
  reason: ssh-post-auth-command
  min_corroboration: 1
  action: block

- name: honeypot-auth-success
  reason: ssh-auth-success
  min_corroboration: 1
  action: block

# SSH brute force burst — rapid local detection.
- name: ssh-brute-burst
  reason: ssh-auth-bruteforce
  min_burst: 15
  burst_window: 10m
  action: block

# Any threat type confirmed by 3+ independent reporters.
- name: multi-reporter-consensus
  min_corroboration: 3
  action: block

# SSH/SMTP brute force confirmed by 2 reporters.
- name: ssh-brute-consensus
  reason: ssh-auth-bruteforce
  min_corroboration: 2
  action: block

- name: smtp-brute-consensus
  reason: smtp-auth-bruteforce
  min_corroboration: 2
  action: block

# Watch single-reporter events — accumulate score before blocking.
- name: watch-singles
  min_corroboration: 1
  action: watch

# Score fallback — block when accumulated score is high enough.
- name: score-fallback
  min_score: 75
  action: block
```
