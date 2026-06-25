# Rules Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Write `docs/rules.md` — a complete reference document covering the `rules.yaml` schema, evaluation semantics, all known reason codes, and deployment recipes for the four main node archetypes.

**Architecture:** Single Markdown file mirroring the pattern of `docs/config.md`. Prose at top (overview, file location, evaluation semantics). Field reference table. Reason code catalogue. Four annotated YAML deployment recipes.

**Tech Stack:** Markdown. Source of truth for schema: `internal/rules/rule.go`. Source of truth for reason codes: `internal/ingest/*.go` adapter files. No code changes — docs only.

## Global Constraints

- All field names and validation rules MUST be verified against `internal/rules/rule.go`.
- Reason codes MUST be derived from the adapter source files in `internal/ingest/` — not from the deploy example files, which may contain stale reason codes.
- The `crowdsec-decision` reason code appears in some example files but is NOT emitted by the current code. Do not include it as a documented reason code; document the actual `mapScenario` fallback behaviour instead.
- Duration values use Go notation: `10m`, `1h`, `500ms` — no `d` suffix.
- Do not document `config.yaml` fields — that is `docs/config.md`'s scope.

---

### Task 1: Write docs/rules.md

**Files:**
- Create: `docs/rules.md`
- Reference: `internal/rules/rule.go` (Rule struct, validateRules, matchReason)
- Reference: `internal/ingest/honeypot.go` (cowrieReasons map)
- Reference: `internal/ingest/opencanary.go` (openCanaryReasons map)
- Reference: `internal/ingest/crowdsec.go` (scenarioMap, mapScenario)
- Reference: `internal/ingest/mailcow_logs.go` (dovecot reason generation)
- Reference: `internal/ingest/fail2ban.go` (builtinJailReasons, builtinJailPrefixes)
- Reference: `internal/ingest/spamtrap.go` (hardcoded smtp-spamtrap reason)

**Interfaces:**
- Produces: `docs/rules.md` — complete, verified document.

- [ ] **Step 1: Write `docs/rules.md`**

Write the following content exactly to `docs/rules.md`:

```markdown
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
becomes the reason code. Use prefix wildcards (e.g. `crowdsecurity-*` or the
stripped name prefix) to match entire families of scenarios.

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
| (any other jail) | operator-defined via `ingest.fail2ban.jail_reasons` in `config.yaml` |

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
```

- [ ] **Step 2: Verify all 7 Rule struct fields appear in the field reference table**

Run:
```bash
grep 'yaml:"' /root/federloom/internal/rules/rule.go | sed 's/.*yaml:"\([^"]*\)".*/\1/' | sort
```

Expected output:
```
action
anchored_only
burst_window
min_burst
min_corroboration
min_score
name
reason
```

Each must appear as a row in the `## Field reference` table in `docs/rules.md`. Fix any gaps.

- [ ] **Step 3: Verify all YAML snippets are syntactically valid**

```bash
python3 -c "
import re, sys, yaml
text = open('docs/rules.md').read()
blocks = re.findall(r'\`\`\`yaml\n(.*?)\`\`\`', text, re.DOTALL)
ok = True
for i, b in enumerate(blocks):
    try:
        yaml.safe_load(b)
        print(f'block {i}: OK')
    except yaml.YAMLError as e:
        print(f'block {i}: ERROR — {e}')
        ok = False
sys.exit(0 if ok else 1)
"
```

Fix any YAML errors reported before continuing.

- [ ] **Step 4: Commit**

```bash
git add docs/rules.md
git commit -m "docs: add rules.yaml reference (docs/rules.md)"
```

---

### Task 2: Coverage check

**Files:**
- Modify: `docs/rules.md` (fix any gaps found)

**Interfaces:**
- Consumes: `docs/rules.md` from Task 1
- Produces: `docs/rules.md` verified complete

- [ ] **Step 1: Cross-check reason codes against adapter source files**

Verify each reason code in the catalogue is actually emitted by the listed adapter:

```bash
# Cowrie reasons
grep -o '"ssh-[^"]*"\|"ssh-probe"\|"ssh-auth-\|"ssh-post' /root/federloom/internal/ingest/honeypot.go

# OpenCanary reasons
grep -o '"[a-z-]*"' /root/federloom/internal/ingest/opencanary.go | sort -u

# CrowdSec scenario map
grep -A20 'scenarioMap' /root/federloom/internal/ingest/crowdsec.go

# Mailcow reasons
grep 'Reason\|reason' /root/federloom/internal/ingest/mailcow_logs.go

# Spamtrap reason
grep 'Reason' /root/federloom/internal/ingest/spamtrap.go

# Fail2ban builtin reasons
grep -A20 'builtinJailReasons\|builtinJailPrefixes' /root/federloom/internal/ingest/fail2ban.go
```

For any reason code in the adapter source that is missing from `docs/rules.md`, add it.

- [ ] **Step 2: Commit if any fixes were needed**

```bash
git add docs/rules.md
git commit -m "docs: fix rules reference gaps found in coverage check"
```

If no changes were needed, skip this commit.
