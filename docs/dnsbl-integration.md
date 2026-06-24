# FederLoom DNSBL Integration

FederLoom's embedded DNSBL server lets any tool that understands DNS blocklists query your node's local reputation data with a single DNS lookup — no custom API integration required.

**Table of contents**
- [Overview](#overview)
- [Setup](#setup)
- [Testing with dig](#testing-with-dig)
- [Tool: Postfix](#tool-postfix)
- [Tool: Rspamd](#tool-rspamd)
- [Tool: nginx](#tool-nginx)
- [Tool: fail2ban](#tool-fail2ban)
- [Docker Networking](#docker-networking)

---

## Overview

### Query format

DNSBL queries use the standard reversed-IP format: reverse the four octets of the IPv4 address and append your zone name.

To look up `1.2.3.4` against zone `dnsbl.federloom.mail.`:
```
A query: 4.3.2.1.dnsbl.federloom.mail.
```

### Response semantics

| Condition | DNS response |
|---|---|
| IP not in store | `NXDOMAIN` |
| IP score below threshold | `NXDOMAIN` |
| IP score ≥ threshold | `NOERROR` with `A 127.0.0.2` + TXT |

A `NXDOMAIN` response means "not listed" — the IP is either unknown or below your configured threshold. An `A 127.0.0.2` response means "listed".

### TXT record

Listed responses include a TXT record on the same name with the score and reasons:

```
"score=87.3 reasons=smtp-auth-bruteforce,imap-auth-bruteforce"
```

Useful for logging and for tools that can act on reason codes.

### TTL

All responses have a 60-second TTL. Scores decay over time, so longer TTLs would produce stale results.

### IPv4 only

IPv6 DNSBL queries are not supported. The reputation store is IPv4-only.

---

## Setup

### Enable DNSBL in config.yaml

Add a `dnsbl:` section to your `config.yaml`:

```yaml
dnsbl:
  addr: ":5353"                    # listen address; "" = disabled
  zone: "dnsbl.federloom.mail."  # your DNSBL zone name; trailing dot recommended, omitting accepted
  # min_score: 0                  # 0 = use reputation.block_threshold
```

All three fields are needed when enabling DNSBL:
- `addr` — the address and port federloomd listens on. `:5353` is the recommended default (unprivileged port).
- `zone` — the DNS zone name your tools will query. Pick something that reflects your node's role, e.g. `dnsbl.federloom.mail.` for a mail node or `dnsbl.federloom.web.` for a web node.
- `min_score` — minimum score to list an IP. Omit or set to `0` to use `reputation.block_threshold`.

Restart federloomd after changing this config.

### Port 53 redirect (optional)

Some tools cannot query a non-standard port. If you need the DNSBL to appear on port 53, redirect at the firewall (federloomd does not need to run as root):

```bash
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5353
```

To persist across reboots, save with `iptables-save` or add to your host's firewall management tool (e.g. `/etc/iptables/rules.v4` on Debian/Ubuntu).

If you redirect port 53, tools use `127.0.0.1` (no port) instead of `127.0.0.1:5353`.

---

## Testing with dig

Before configuring any tool, verify the DNSBL is reachable and returning the expected responses.

Replace `4.3.2.1` with a reversed IP you expect to be listed (one that FederLoom has scored above threshold), and `dnsbl.federloom.mail.` with your actual zone name.

**A query — expect `127.0.0.2` for a listed IP:**
```bash
dig +short A 4.3.2.1.dnsbl.federloom.mail. @127.0.0.1 -p 5353
# Expected output: 127.0.0.2
```

**TXT query — get score and reasons:**
```bash
dig +short TXT 4.3.2.1.dnsbl.federloom.mail. @127.0.0.1 -p 5353
# Expected output: "score=87.3 reasons=smtp-auth-bruteforce"
```

**Unlisted IP — expect empty output (NXDOMAIN):**
```bash
dig +short A 1.0.0.1.dnsbl.federloom.mail. @127.0.0.1 -p 5353
# Expected output: (empty)
```

If you get no output for listed IPs, check:
- Is federloomd running? (`ps aux | grep federloomd`)
- Is the `dnsbl.addr` port open? (`ss -ulnp | grep 5353`)
- Does the IP have a score above `block_threshold`? (check with `curl http://127.0.0.1:9102/api/v1/score/1.2.3.4` if the API is enabled)

---

## Tool: Postfix

Postfix has native DNSBL support via `reject_rbl_client` in `smtpd_recipient_restrictions`. It queries the DNSBL for every incoming connection's IP and rejects if listed.

### Config

In `/etc/postfix/main.cf`, add `reject_rbl_client` to `smtpd_recipient_restrictions`:

```
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_rbl_client dnsbl.federloom.mail.=127.0.0.2,
    permit
```

The `=127.0.0.2` qualifier tells Postfix to reject only when the A response matches `127.0.0.2` exactly. This is standard DNSBL practice — it prevents false positives if the zone is misconfigured and returns an unexpected address.

If you redirected port 53, use `dnsbl.federloom.mail.` without a port. If you're querying `:5353` directly, Postfix cannot specify a non-standard port in `reject_rbl_client` — use the port-53 redirect for Postfix.

### Apply

```bash
postfix reload
```

### Verify

Send a test message from a listed IP (or use `swaks` to simulate one). Check `/var/log/mail.log`:

```
reject: RCPT from unknown[1.2.3.4]: 554 5.7.1 Service unavailable;
  Client host [1.2.3.4] blocked using dnsbl.federloom.mail.; from=<...>
```

---

## Tool: Rspamd

Rspamd's RBL module queries DNSBL zones and adds the result as a weighted score contribution rather than a hard reject. This is more flexible than Postfix — a listed IP increases the spam score but doesn't automatically block the message.

### Config

Create or edit `/etc/rspamd/local.d/rbl.conf`:

```ucl
rbls {
  federloom {
    symbol = "RBL_SWARMGUARD";
    rbl = "dnsbl.federloom.mail.";
    ipv4 = true;
    ipv6 = false;
    returncodes {
      RBL_FEDERLOOM_LISTED = "127.0.0.2";
    }
  }
}
```

Set the symbol score in `/etc/rspamd/local.d/scores.conf`:

```ucl
RBL_FEDERLOOM_LISTED = 5.0;
```

Adjust the score to suit your rejection threshold. A value of 5.0 makes a FederLoom hit a strong but not automatic rejection signal in combination with other Rspamd checks.

> **Rspamd and non-standard ports:** Like Postfix, Rspamd's RBL module sends DNS queries to the system resolver. If federloomd is on `:5353`, use the port-53 iptables redirect and configure `rbl = "dnsbl.federloom.mail."` without a port. Alternatively, configure the system resolver (`/etc/resolv.conf` or `systemd-resolved`) to delegate the zone to `127.0.0.1:5353` using a split-horizon resolver like `dnsmasq`.

### Apply

```bash
rspamadm control reload
```

### Verify

```bash
rspamc -h 127.0.0.1:11333 symbols 1.2.3.4
```

Look for `RBL_FEDERLOOM_LISTED` in the output for a listed IP.

---

## Tool: nginx

nginx does not perform real-time DNS lookups per request — there is no native DNSBL support equivalent to Postfix's `reject_rbl_client`. The practical approach is a short script run by cron that queries FederLoom's HTTP API, writes `deny` directives to an nginx include file, and reloads nginx.

> This requires FederLoom's HTTP API to be enabled. Add to `config.yaml` if not already present:
> ```yaml
> api:
>   addr: ":9102"
> ```
> Restart federloomd after enabling.

### Setup

**1. Create the include file** (nginx will include it; start with an empty file so nginx starts cleanly before the first cron run):

```bash
touch /etc/nginx/conf.d/federloom-blocklist.conf
```

**2. Add the include to your nginx `http {}` block** (usually in `/etc/nginx/nginx.conf`):

```nginx
http {
    include /etc/nginx/conf.d/federloom-blocklist.conf;
    # ... rest of your config
}
```

**3. Create the update script** at `/usr/local/bin/federloom-blocklist-update`:

```bash
#!/bin/bash
set -euo pipefail

API="http://127.0.0.1:9102"
OUT="/etc/nginx/conf.d/federloom-blocklist.conf"
TMP="$(mktemp)"

curl -sf "$API/api/v1/blocklist" \
  | jq -r '.[] | "deny \(.ip);"' \
  > "$TMP"

printf "# Auto-generated %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | cat - "$TMP" > "$OUT"
rm "$TMP"

nginx -s reload
```

Make it executable:

```bash
chmod +x /usr/local/bin/federloom-blocklist-update
```

**4. Add to cron** (every 5 minutes):

Create `/etc/cron.d/federloom-blocklist`:

```
*/5 * * * * root /usr/local/bin/federloom-blocklist-update 2>/dev/null
```

### Purpose filter (optional)

To restrict the blocklist to web attackers only, change the `curl` line to:

```bash
curl -sf "$API/api/v1/blocklist?purpose=web" \
```

### Verify

Run the script manually and check the output file:

```bash
/usr/local/bin/federloom-blocklist-update
cat /etc/nginx/conf.d/federloom-blocklist.conf
```

Expected output (for a node with listed IPs):
```
# Auto-generated 2026-06-19T12:00:00Z
deny 1.2.3.4;
deny 5.6.7.8;
```

Test that nginx rejects a listed IP:
```bash
curl -v --interface 1.2.3.4 http://your-server/
# Expected: HTTP 403
```

---

## Tool: fail2ban

Two integration patterns: **extended ban** (known-bad IPs get a longer ban) and **log enrichment** (adds FederLoom reputation data to the fail2ban log without changing ban behavior).

### Pattern 1: Extended ban duration for known-bad IPs

Uses `ipset` with per-entry timeout. IPs already known to FederLoom receive a 7-day ban; unknown IPs get the default 1 hour.

**Requires:** `ipset` installed on the host (`apt install ipset` / `yum install ipset`).

Create `/etc/fail2ban/action.d/federloom-dnsbl.conf`:

```ini
[Definition]
actionstart = ipset create f2b-<name> hash:ip timeout 3600 2>/dev/null || true
              iptables -I INPUT -m set --match-set f2b-<name> src -j DROP

actionstop = iptables -D INPUT -m set --match-set f2b-<name> src -j DROP
             ipset destroy f2b-<name> 2>/dev/null || true

actionban = listed=$(dig +short A $(echo <ip> | awk -F. '{print $4"."$3"."$2"."$1}').dnsbl.federloom.mail. @127.0.0.1 -p 5353 2>/dev/null)
            if [ "$listed" = "127.0.0.2" ]; then
              ipset add -exist f2b-<name> <ip> timeout 604800
            else
              ipset add -exist f2b-<name> <ip> timeout 3600
            fi

actionunban = ipset del -exist f2b-<name> <ip>
```

> If you applied the optional port-53 iptables redirect, remove `-p 5353` from the `actionban` dig command.

Enable in your jail config (`/etc/fail2ban/jail.local`):

```ini
[sshd]
action = federloom-dnsbl[name=sshd]
```

Reload fail2ban:

```bash
fail2ban-client reload
```

### Pattern 2: Log enrichment (lightweight, no ban logic change)

Logs FederLoom score and reasons alongside the standard fail2ban ban entry. Works with any existing action — add it as a second action entry.

Create `/etc/fail2ban/action.d/federloom-log.conf`:

```ini
[Definition]
actionban = txt=$(dig +short TXT $(echo <ip> | awk -F. '{print $4"."$3"."$2"."$1}').dnsbl.federloom.mail. @127.0.0.1 -p 5353 2>/dev/null | tr -d '"')
            [ -n "$txt" ] && logger -t fail2ban "federloom: <ip> $txt" || true
```

Enable alongside your existing action:

```ini
[sshd]
action = %(action_)s
         federloom-log
```

This adds a syslog line like:
```
fail2ban: federloom: 1.2.3.4 score=87.3 reasons=ssh-auth-bruteforce
```

No changes to ban duration or firewall rules.

---

## Docker Networking

The DNSBL address depends on where FederLoom and the querying tool are running. Three scenarios:

### Scenario 1: Tool on host, FederLoom in Docker

The simplest case. FederLoom's compose file publishes the DNSBL port:

```yaml
# docker-compose.yml or docker-compose.override.yml
services:
  federloom:
    ports:
      - "5353:5353/udp"
      - "5353:5353/tcp"
```

Tools on the host use `127.0.0.1` port `5353`. All the tool configs above work as-is.

### Scenario 2: Tool in Docker, FederLoom in Docker (separate stacks)

`127.0.0.1` inside a container refers to the container itself, not the host.

**Option A — Docker bridge gateway IP**

Find the gateway IP:
```bash
docker network inspect bridge | jq -r '.[0].IPAM.Config[0].Gateway'
# Typically: 172.17.0.1
```

Use `172.17.0.1:5353` as the DNSBL address. This works without network changes but the IP can differ between hosts — verify it after Docker Engine upgrades.

**Option B — Shared external Docker network (more robust)**

Create a shared network:
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

Tools can then reach the DNSBL at `federloom:5353` using the FederLoom container's service name. Use this as the zone server address in tool configs.

### Scenario 3: Mailcow (recommended setup)

Mailcow runs Postfix and Rspamd inside the `mailcowdockerized_mailcow-network` Docker network. Attach FederLoom to that network so those containers can reach it by service name.

In FederLoom's `docker-compose.override.yml` (place this file alongside Mailcow's compose files):

```yaml
services:
  federloom:
    networks:
      - mailcowdockerized_mailcow-network

networks:
  mailcowdockerized_mailcow-network:
    external: true
```

Apply:
```bash
docker compose up -d federloom
```

Postfix and Rspamd configs then use `federloom` as the DNSBL server hostname and port `5353` — no iptables redirect needed.

In `deploy/mailcow/config.yaml` the `dnsbl.addr` stays `:5353` — the port does not need to be published to the host since Mailcow containers reach it directly on the internal network.

### Quick reference

| Tool location | FederLoom location | DNSBL address |
|---|---|---|
| Host | Docker (port published) | `127.0.0.1:5353` |
| Docker (separate stack) | Docker (separate stack) | `172.17.0.1:5353` or shared network + service name |
| Mailcow container | Mailcow Docker network | `federloom:5353` |
