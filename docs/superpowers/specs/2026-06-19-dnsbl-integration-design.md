# DNSBL Integration Guide Design

**Feature:** `docs/dnsbl-integration.md` — operator guide for integrating FederLoom's embedded DNSBL with external tools  
**Date:** 2026-06-19  
**Status:** Approved

---

## Problem

FederLoom's DNSBL server is fully implemented but has no operator-facing documentation. Operators who want to wire Postfix, Rspamd, nginx, or fail2ban against it have to read the source and the design spec to figure out the query format, response semantics, and tool-specific config. This creates unnecessary friction, especially for Docker-based deployments where the DNSBL address is not `127.0.0.1`.

## Goal

A single `docs/dnsbl-integration.md` that takes a Linux-literate operator (familiar with server administration but not necessarily with each tool's config format) from zero to working integration for each supported tool, including Docker networking scenarios.

---

## Document Structure

File: `docs/dnsbl-integration.md`

Sections, in order:

1. Overview
2. Setup
3. Testing with dig
4. Tool: Postfix
5. Tool: Rspamd
6. Tool: nginx
7. Tool: fail2ban
8. Docker Networking

Each tool section is independently readable. Operators using only Postfix do not need to read the Rspamd section.

---

## Section: Overview

Covers:

- **Query format**: reversed IPv4 dotted-quad + zone suffix. `4.3.2.1.dnsbl.your.zone` looks up `1.2.3.4`.
- **Response semantics**:
  - Listed (score ≥ threshold): `NOERROR` with `A 127.0.0.2` + TXT record
  - Unlisted or below threshold: `NXDOMAIN`
- **TXT record content**: `score=87.3 reasons=smtp-auth-bruteforce,imap-auth-bruteforce` — human-readable, useful for logging and debugging
- **TTL**: 60 seconds (fixed — scores decay over time, long TTLs would produce stale results)
- **IPv4 only**: IPv6 DNSBL queries are not supported

---

## Section: Setup

### Config fields

```yaml
dnsbl:
  addr: ":5353"                   # listen address; "" = disabled
  zone: "dnsbl.federloom.mail."  # your DNSBL zone name; trailing dot optional
  # min_score: 0                  # 0 = use reputation.block_threshold
```

All three fields are required when enabling DNSBL. `min_score: 0` (the default) inherits `reputation.block_threshold`.

### Port 53 redirect (optional)

Some tools cannot point at a non-standard port. To make the DNSBL available on port 53 without running federloomd as root:

```bash
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5353
```

To persist across reboots, save with `iptables-save` or add to the host's firewall management tool.

---

## Section: Testing with dig

Before configuring any tool, verify the DNSBL is reachable and returning the expected responses.

**A query (listed IP):**
```bash
dig +short A 4.3.2.1.dnsbl.your.zone @127.0.0.1 -p 5353
# Expected: 127.0.0.2
```

**TXT query (score details):**
```bash
dig +short TXT 4.3.2.1.dnsbl.your.zone @127.0.0.1 -p 5353
# Expected: "score=87.3 reasons=smtp-auth-bruteforce"
```

**Unlisted IP:**
```bash
dig +short A 1.1.1.1.dnsbl.your.zone @127.0.0.1 -p 5353
# Expected: (empty — NXDOMAIN)
```

If the DNSBL address differs (Docker scenario), substitute the appropriate IP and port.

---

## Section: Tool: Postfix

Postfix has native DNSBL support via `reject_rbl_client` in `smtpd_recipient_restrictions`.

### Config

In `/etc/postfix/main.cf`, add to `smtpd_recipient_restrictions`:

```
smtpd_recipient_restrictions =
    ...
    reject_rbl_client dnsbl.your.zone=127.0.0.2,
    ...
```

The `=127.0.0.2` qualifier restricts rejection to responses matching that exact address, following standard DNSBL practice. Without the qualifier, Postfix rejects on any A response, which can cause false positives if the DNSBL zone is ever misconfigured.

### Apply changes

```bash
postfix reload
```

### Verify

Send a test message from a listed IP and check `/var/log/mail.log` for a line like:
```
reject: RCPT ... 554 5.7.1 Service unavailable; Client host [1.2.3.4] blocked using dnsbl.your.zone
```

To test without sending mail:
```bash
postmap -q 1.2.3.4 cidr:/dev/stdin <<< "0.0.0.0/0 DUNNO"
```
or use `postfix/dnslookup` directly:
```bash
postfix/dnslookup 1.2.3.4.dnsbl.your.zone A
```

---

## Section: Tool: Rspamd

Rspamd queries DNSBL zones natively via its RBL module and applies the result as a weighted score contribution rather than a hard reject — more flexible than Postfix for environments with mixed signal quality.

### Config

Create or edit `/etc/rspamd/local.d/rbl.conf`:

```ucl
rbls {
  federloom {
    symbol = "RBL_SWARMGUARD";
    rbl = "dnsbl.your.zone";
    ipv4 = true;
    ipv6 = false;
    returncodes {
      RBL_FEDERLOOM_LISTED = "127.0.0.2";
    }
  }
}
```

Assign a score to the symbol in `/etc/rspamd/local.d/scores.conf`:

```ucl
RBL_FEDERLOOM_LISTED = 5.0;
```

Adjust the score to match your rejection threshold. A score of 5.0 is a strong signal without being an automatic rejection for borderline cases.

### Apply changes

```bash
rspamadm control reload
```

### Verify

```bash
rspamc symbols 1.2.3.4
# Look for RBL_FEDERLOOM_LISTED in the output
```

---

## Section: Tool: nginx

nginx has no native per-request DNSBL support. The practical approach is a short script run by cron that queries FederLoom's HTTP API blocklist, writes an nginx `deny` include file, and reloads nginx. This is faster and more reliable than polling the DNSBL for thousands of IPs individually.

### Setup

1. Create `/etc/nginx/conf.d/federloom-blocklist.conf` (nginx will include it automatically):

```nginx
# Auto-generated by /usr/local/bin/federloom-blocklist-update
# Do not edit manually — overwritten every 5 minutes
```

2. Create `/usr/local/bin/federloom-blocklist-update`:

```bash
#!/bin/bash
set -euo pipefail

API="http://127.0.0.1:9102"
OUT="/etc/nginx/conf.d/federloom-blocklist.conf"
TMP="$(mktemp)"

curl -sf "$API/api/v1/blocklist" \
  | jq -r '.[] | "deny \(.ip);"' \
  > "$TMP"

echo "# Auto-generated $(date -u +%Y-%m-%dT%H:%M:%SZ)" | cat - "$TMP" > "$OUT"
rm "$TMP"

nginx -s reload
```

Make it executable:
```bash
chmod +x /usr/local/bin/federloom-blocklist-update
```

3. Add to cron (every 5 minutes):

```
*/5 * * * * root /usr/local/bin/federloom-blocklist-update 2>/dev/null
```

### Purpose filter (optional)

To restrict the blocklist to web attackers only:

```bash
curl -sf "$API/api/v1/blocklist?purpose=web"
```

### Notes

- Requires FederLoom's HTTP API (`api.addr`) to be enabled alongside the DNSBL.
- nginx reload is fast (< 1s, no dropped connections), so a 5-minute cron is safe.
- The generated file will be empty on startup until the first cron run. Add `include /etc/nginx/conf.d/federloom-blocklist.conf;` inside a `http {}` block if not already auto-included.

---

## Section: Tool: fail2ban

Two integration patterns are documented: **preemptive ban** (check reputation before counting failures) and **extended ban** (check reputation at ban time, apply a longer ban for known-bad IPs).

### Pattern 1: Extended ban duration for known-bad IPs

Uses `ipset` with per-entry timeout so known-bad IPs get a 7-day ban and unknown IPs get the default 1 hour. Requires `ipset` installed on the host.

Create `/etc/fail2ban/action.d/federloom-dnsbl.conf`:

```ini
[Definition]
actionstart = ipset create f2b-<name> hash:ip timeout 3600 2>/dev/null || true
              iptables -I INPUT -m set --match-set f2b-<name> src -j DROP

actionstop = iptables -D INPUT -m set --match-set f2b-<name> src -j DROP
             ipset destroy f2b-<name> 2>/dev/null || true

actionban = listed=$(dig +short A $(echo <ip> | awk -F. '{print $4"."$3"."$2"."$1}').dnsbl.your.zone @127.0.0.1 -p 5353 2>/dev/null)
            if [ "$listed" = "127.0.0.2" ]; then
              ipset add -exist f2b-<name> <ip> timeout 604800
            else
              ipset add -exist f2b-<name> <ip> timeout 3600
            fi

actionunban = ipset del -exist f2b-<name> <ip>
```

Enable it in your jail config (`/etc/fail2ban/jail.local`):

```ini
[sshd]
action = federloom-dnsbl[name=sshd]
```

IPs already known to FederLoom receive a 7-day ban; first-time offenders get the default 1-hour ban.

### Pattern 2: Log enrichment (score + reasons in ban log)

A lighter-weight option that doesn't change ban duration but adds FederLoom reputation data to the fail2ban log:

```ini
[Definition]
actionban = zone="dnsbl.your.zone"
            server="127.0.0.1"
            port="5353"
            txt=$(dig +short TXT $(echo <ip> | awk -F. '{print $4"."$3"."$2"."$1}').$zone @$server -p $port 2>/dev/null | tr -d '"')
            if [ -n "$txt" ]; then
              logger -t fail2ban "federloom: <ip> — $txt"
            fi
            iptables -I INPUT -s <ip> -j DROP

actionunban = iptables -D INPUT -s <ip> -j DROP
```

This logs a line like `federloom: 1.2.3.4 — score=87.3 reasons=ssh-auth-bruteforce` alongside the standard fail2ban ban log entry.

---

## Section: Docker Networking

The DNSBL address depends on where FederLoom and the querying tool are running. Three scenarios:

### Scenario 1: Tool on host, FederLoom in Docker

FederLoom's compose file publishes the DNSBL port:

```yaml
ports:
  - "5353:5353/udp"
  - "5353:5353/tcp"
```

Tools on the host use `127.0.0.1:5353`. This is the simplest case.

### Scenario 2: Tool in Docker, FederLoom in Docker (separate stacks)

`127.0.0.1` inside a container refers to the container itself, not the host. Two options:

**Option A — Docker bridge gateway IP:**

Find the gateway:
```bash
docker network inspect bridge | jq -r '.[0].IPAM.Config[0].Gateway'
# Typically: 172.17.0.1
```

Point the tool at `172.17.0.1:5353`. Works without any network changes but the IP can differ per host — check it after each Docker Engine upgrade.

**Option B — Shared external network (more robust):**

```bash
docker network create federloom-net
```

Add to FederLoom's `docker-compose.yml`:

```yaml
networks:
  federloom-net:
    external: true
```

Add to the tool's compose file:

```yaml
networks:
  federloom-net:
    external: true
```

Tools can then reach the DNSBL at `federloom:5353` (using the FederLoom container's service name).

### Scenario 3: Mailcow (recommended setup)

Mailcow's Postfix and Rspamd containers run on the `mailcow-network` Docker network. Attach FederLoom to the same network so containers can reach it by service name.

In FederLoom's `docker-compose.override.yml` (alongside Mailcow):

```yaml
services:
  federloom:
    networks:
      - mailcowdockerized_mailcow-network

networks:
  mailcowdockerized_mailcow-network:
    external: true
```

Postfix and Rspamd configs then use `federloom:5353` as the DNSBL address (no port redirect needed).

In `deploy/mailcow/config.yaml`:
```yaml
dnsbl:
  addr: ":5353"
  zone: "dnsbl.federloom.mail."
```

### Quick reference

| Tool location | FederLoom location | DNSBL address |
|---|---|---|
| Host | Docker (port published) | `127.0.0.1:5353` |
| Docker | Docker (separate stack) | `172.17.0.1:5353` or shared network |
| Mailcow container | Mailcow network | `federloom:5353` |

---

## File Map

| File | Action |
|---|---|
| `docs/dnsbl-integration.md` | Create — full operator guide |
| `docs/getting-started.md` | Modify — add one-line pointer to dnsbl-integration.md in the "Next steps" section |

No code changes. No config changes. Documentation only.

---

## Out of Scope

- IPv6 DNSBL queries (not supported by the server)
- DNS-over-TLS / DNS-over-HTTPS
- SpamAssassin (low priority for the Mailcow/WordPress operator base)
- Automated testing of the doc examples
