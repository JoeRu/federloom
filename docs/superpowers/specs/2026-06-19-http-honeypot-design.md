# HTTP Honeypot (OpenCanary HTTP/HTTPS) Design

**Goal:** Enable OpenCanary's built-in HTTP and HTTPS modules on the honeypot node so that web scanners and credential stuffers are captured alongside the existing SSH/SMTP/IMAP sensors, and their IPs are federated into the swarm with `http-*` reason codes.

---

## Scope

Three small, contained changes — no new containers, no new Go packages:

1. `deploy/honeypot/opencanary.json` — enable HTTP (port 80) and HTTPS (port 443)
2. `deploy/honeypot/docker-compose.yml` — expose ports 80 and 443 on the opencanary service
3. `internal/ingest/opencanary.go` — add HTTP/HTTPS logtypes to `openCanaryReasons`

---

## Changes

### `deploy/honeypot/opencanary.json`

Add six keys to the existing JSON config:

```json
"http.enabled": true,
"http.port": 80,
"http.banner": "Apache/2.2.22 (Ubuntu)",
"https.enabled": true,
"https.port": 443,
"https.banner": "Apache/2.2.22 (Ubuntu)"
```

### `deploy/honeypot/docker-compose.yml`

Add two ports to the `opencanary` service's `ports:` block:

```yaml
- "80:80"
- "443:443"
```

### `internal/ingest/opencanary.go`

Extend `openCanaryReasons` with HTTP/HTTPS logtypes. The exact integer logtype values must be verified against the running container before coding:

```bash
docker exec opencanary grep -r "logtype\|LOGGER" \
  /usr/local/lib/python*/dist-packages/opencanary/modules/http*.py
```

Expected reason code mapping:

| OpenCanary logtype | Reason code |
|---|---|
| HTTP GET/HEAD (probe) | `http-probe` |
| HTTP POST (login attempt) | `http-login-attempt` |
| HTTPS GET/HEAD | `https-probe` |
| HTTPS POST | `https-login-attempt` |

All four reason codes match the existing `"web": {"http-*"}` entry in `DefaultTaxonomy` — no taxonomy changes needed.

---

## Data flow

```
attacker → port 80/443
         → opencanary container
         → /var/log/opencanary/opencanary.log (existing shared volume)
         → ingest/opencanary.go tail loop (existing)
         → proto.Event{Reason: "http-probe", Trust: 1.0}
         → swarmguard reputation store
         → federated to mailcow + wordpress (matches "web" taxonomy)
```

The existing shared volume `opencanary-logs` already bridges the opencanary container and the swarmguard container. No new volumes or mounts needed.

---

## Verification

After deploying:

```bash
# Confirm HTTP responds (expect 200 or redirect, not connection refused)
curl -si http://swarmguard.jru.me/ | head -5

# Confirm HTTPS responds
curl -sik https://swarmguard.jru.me/ | head -5

# After ~1 poll interval, check swarmguard metrics for http events
curl -s http://167.233.115.41:9101/metrics \
  | grep 'swarmguard_events_received_total.*http'
```

---

## Security note

Ports 80 and 443 are exposed publicly. OpenCanary's HTTP module serves a static decoy page and logs all requests — it does not proxy or forward traffic. No TLS certificates are needed for the HTTPS module (OpenCanary uses a self-signed cert internally).
