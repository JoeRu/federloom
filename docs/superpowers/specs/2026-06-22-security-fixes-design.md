# Security Fixes Design — 2026-06-22

Fixes for three confirmed vulnerabilities identified in the FederLoom security review.

---

## Vulnerabilities Addressed

| # | ID | Severity | Root Cause |
|---|----|----------|------------|
| 1 | CIDR injection → nftables block-all | HIGH | No `net.ParseIP` gate before `sink.Block()` |
| 2 | Unauthenticated API on public IP | HIGH | No auth middleware; port published to `0.0.0.0` |
| 3 | Newline injection in CrowdSec CTI export | MEDIUM | No `net.ParseIP` gate before store write or CTI output |

Vulns 1 and 3 share the same root cause and are fixed by the same change.

---

## Fix 1 & 3 — IP Validation Gate

### Architecture

A single authoritative guard is placed at the top of both processing entry points in `internal/node/node.go`. All ingest paths (local honeypot, opencanary, gossip peers) converge at these two functions, so one change covers all sources.

A second guard in the CTI output handler sanitizes any malformed keys already present in the store from before the fix.

### Changes

**`internal/node/node.go` — `processLocal` and `ProcessRemote`**

At the very top of each function, before any reputation recording or sink call, add:

```go
if net.ParseIP(e.IP) == nil {
    log.Printf("node: drop event with invalid IP %q", e.IP)
    return
}
```

Rejects: CIDR notation (`0.0.0.0/0`), newline-embedded strings (`"1.2.3.4\n5.6.7.8"`), hostnames, empty strings — anything that is not a bare IPv4 or IPv6 address.

**`internal/api/handler_blocklist.go` — `handleCrowdSecCTI`**

Inside the `ScanScores` callback, skip keys that fail `net.ParseIP`:

```go
if net.ParseIP(ip) == nil {
    return nil
}
fmt.Fprintln(w, ip)
```

### Tests

- `internal/node/node_test.go`: CIDR string, newline-embedded string, hostname, and empty string are all silently dropped by `processLocal` and `ProcessRemote`. Valid IPv4 and IPv6 addresses pass through.
- `test/adversarial/`: add scenario — a remote peer publishing `IP: "0.0.0.0/0"` must never reach `sink.Block`. Assert the nftables/ipset sink receives zero calls for that event.

---

## Fix 2 — API Auth + Tailscale Binding

### Architecture

Two independent layers of protection:

1. **Network layer** — Docker port bindings restrict API and Prometheus to the host's Tailscale interface (`100.71.239.1`), making both endpoints invisible to the public internet.
2. **Application layer** — Bearer token middleware in `internal/api/server.go` rejects unauthenticated requests with `401 Unauthorized`, protecting against compromise of a Tailscale peer.

```
internet → [blocked by Docker binding]
Tailscale peer → 100.71.239.1:9102 → tokenMiddleware → mux → handler
                                           ↑
                               FEDERLOOM_API_TOKEN env var
```

### Changes

**`deploy/honeypot/docker-compose.yml`**

Bind Prometheus and API ports to Tailscale interface only. Keep libp2p (7700) and DNSBL (5353) public by design:

```yaml
ports:
  - "7700:7700"
  - "100.71.239.1:9101:9101"
  - "100.71.239.1:9102:9102"
  - "5353:5353/udp"
env_file:
  - .env
```

`api.addr` in `config.yaml` stays `:9102` — the container listens on all interfaces internally; Docker controls what is exposed on the host.

**`internal/api/server.go` — bearer token middleware**

`Start()` reads `os.Getenv("FEDERLOOM_API_TOKEN")` at startup:

- If set and non-empty: wrap the mux with a middleware that checks `Authorization: Bearer <token>`. Requests missing or with wrong token → `401 Unauthorized`. Log a startup message confirming auth is active.
- If unset or empty: skip middleware, log a startup warning (`api: FEDERLOOM_API_TOKEN not set — API is unauthenticated`). Backward-compatible: existing deployments without the var configured keep working.

Middleware is implemented as a closure wrapping `http.Handler` — no new dependencies, no interface changes.

**Secret management**

- `deploy/honeypot/.env` — gitignored, contains `FEDERLOOM_API_TOKEN=<secret>`. Created by operator on first deploy.
- `deploy/honeypot/.env.example` — committed, contains `FEDERLOOM_API_TOKEN=changeme` as a placeholder.
- Add `**/.env` to `.gitignore` (currently absent — `.env` files are not covered).

### Tests

`internal/api/server_test.go`:

- `FEDERLOOM_API_TOKEN` set, request without `Authorization` header → `401`
- `FEDERLOOM_API_TOKEN` set, request with wrong token → `401`
- `FEDERLOOM_API_TOKEN` set, request with correct `Bearer <token>` → `200`
- `FEDERLOOM_API_TOKEN` unset → all requests pass through (no 401)

---

## Out of Scope

- Secrets management beyond `.env` (flagged as a future concern — a secret store or vault integration is a separate project).
- Adding auth to Prometheus (`9101`) — Prometheus is internal-pull only and Tailscale-bound; bearer token adds marginal value there.
- IP validation at individual ingest sources (`opencanary.go`, `honeypot.go`) — all paths converge at `node.go`; per-source validation would be redundant.

---

## Invariants Preserved

- **Invariant 1 (local override):** The bearer token is operator-configured via env var; operators can disable it by leaving `FEDERLOOM_API_TOKEN` unset.
- **Invariant 4 (enforcement is O(1)):** IP validation adds one `net.ParseIP` call per event — no change to the firewall write path's complexity.
- **Invariant 7 (`internal/enforce` is security-critical):** The validation gate lives in `internal/node`, upstream of `internal/enforce`. The enforce package itself remains unchanged.
