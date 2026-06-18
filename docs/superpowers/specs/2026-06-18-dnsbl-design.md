# DNSBL Server Design

**Feature:** DHT on-demand IP lookup / DNSBL mode (Feature 5)
**Date:** 2026-06-18
**Status:** Approved

## Problem

External tools (Postfix, nginx, fail2ban, etc.) cannot query SwarmGuard's reputation data using standard interfaces. They either need the full gossip stream (too heavy) or custom HTTP API integration (non-standard). A DNSBL interface lets any tool query "is this IP blocked?" with a single DNS lookup — the same protocol used by every major spam/abuse blocklist.

## Goal

Embed a DNS DNSBL server in swarmd that answers `A` and `TXT` queries from the local reputation store. Answers are local-only (no fan-out to the swarm). The server is opt-in (disabled when `dnsbl.addr == ""`). External tools configure SwarmGuard's DNS port as their DNSBL source.

## Design

### Config (`internal/config/config.go`)

```go
// DNSBLConfig controls the optional embedded DNSBL DNS server.
// Disabled when Addr is empty (zero value).
type DNSBLConfig struct {
    Addr     string  `yaml:"addr"`      // e.g. ":5353"; "" = disabled
    Zone     string  `yaml:"zone"`      // e.g. "dnsbl.mail.example.com." — trailing dot optional
    MinScore float64 `yaml:"min_score"` // 0 = use reputation.block_threshold
}
```

Added to `Config` as:
```go
DNSBL DNSBLConfig `yaml:"dnsbl"`
```

`Defaults()` leaves all fields zero (disabled by default).

**Port note:** Port 53 requires root. Operators should configure `:5353` (or any unprivileged port) and use an iptables PREROUTING redirect if they need port 53 visible to external tools:

```bash
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5353
```

### DNSBL Server (`internal/dnsbl/server.go`)

```go
package dnsbl

// StoreReader is the minimal store interface the DNSBL server needs.
// Narrower than api.StoreReader (no ScanScores) — only point lookups are required.
type StoreReader interface {
    GetScore(ip string) (store.ScoreRecord, error)
}

type Server struct {
    cfg    config.DNSBLConfig
    store  StoreReader
    repCfg config.ReputationConfig
    srv    *dns.Server
}

func New(cfg config.DNSBLConfig, s StoreReader, repCfg config.ReputationConfig) *Server

// Start registers the DNS handler and starts the server on both UDP and TCP.
// No-op when cfg.Addr == "".
func (s *Server) Start(ctx context.Context)
```

**Dependency:** `github.com/miekg/dns` — the standard Go DNS library (used by CoreDNS, k8s). Added via `go get`.

### Query Format

Standard DNSBL format: reversed IPv4 dotted quad + zone suffix.

```
Query:  A  4.3.2.1.dnsbl.mail.example.com.   ← means "look up 1.2.3.4"
```

The server normalises `cfg.Zone` to a fully-qualified name (appends `.` if missing, lowercases) before registering `dns.HandleFunc`. The handler:

1. Strips the zone suffix from `qname` to extract the reversed IP.
2. Reverses the octets to get the real IP (e.g. `4.3.2.1` → `1.2.3.4`).
3. Calls `store.GetScore(ip)`.
4. Determines the effective `minScore`: `cfg.MinScore` if > 0, else `repCfg.BlockThreshold`.

### Response Logic

| Condition | DNS Response |
|---|---|
| IP not in store | `NXDOMAIN` |
| Score < minScore | `NXDOMAIN` |
| Score ≥ minScore | `NOERROR` with A + TXT |

**Listed response (A record):**
```
1.2.3.4.dnsbl.mail.example.com.  60  IN  A  127.0.0.2
```

**TXT record (same name, same response):**
```
1.2.3.4.dnsbl.mail.example.com.  60  IN  TXT  "score=87.3 reasons=smtp-auth-bruteforce,imap-auth-bruteforce"
```

- TTL is 60 seconds (fixed — scores decay over time, so long TTLs would produce stale results).
- Only `A` and `TXT` query types produce the listed response. Other types (`AAAA`, `MX`, etc.) return `NOERROR` with no answer section.
- IPv6 addresses: out of scope (reputation store is IPv4-only currently).

### Startup / Shutdown

`Start(ctx)` launches `srv.ListenAndServe()` in a goroutine (both UDP and TCP on the same addr). When ctx is cancelled, `srv.Shutdown()` is called. Identical lifecycle pattern to `api.Server.Start`.

### Node Wiring (`internal/node/node.go`)

Add field:
```go
dnsbl *dnsbl.Server  // nil-safe; all methods no-op when cfg.DNSBL.Addr == ""
```

In `New()`:
```go
dnsblSrv := dnsbl.New(cfg.DNSBL, s, cfg.Reputation)
```

In `Run()` alongside existing servers:
```go
n.dnsbl.Start(ctx)
```

### Deploy Config (`deploy/mailcow/config.yaml`)

```yaml
dnsbl:
  addr: ":5353"
  zone: "dnsbl.swarmguard.mail."
  # min_score: 0   # defaults to reputation.block_threshold
```

Same pattern for `deploy/wordpress/config.yaml` with zone `dnsbl.swarmguard.web.`.

### Testing

Unit test in `internal/dnsbl/server_test.go`:
- Seed a test store with known IPs and scores
- Start server on a random port (`:0` with listener)
- Send `dns.Msg` A and TXT queries using `miekg/dns` client
- Assert: listed IPs → A `127.0.0.2` + TXT with score; unlisted IPs → NXDOMAIN

No mocking needed — the DNS client/server round-trip is fast and deterministic.

## Out of Scope

- IPv6 DNSBL queries
- Fan-out to swarm when IP is unknown locally
- DNS-over-HTTPS or DNS-over-TLS
- Authoritative NS/SOA records (not needed for DNSBL-only use)
- `swarmctl query` CLI command (existing `/api/v1/score/{ip}` HTTP endpoint covers node queries)

## Files Changed

| File | Action |
|---|---|
| `internal/config/config.go` | Add `DNSBLConfig` type + `DNSBL` field to `Config` |
| `internal/dnsbl/server.go` | New — DNS server, handler, response logic |
| `internal/dnsbl/server_test.go` | New — unit tests with live DNS round-trip |
| `internal/node/node.go` | Add `dnsbl *dnsbl.Server` field; wire in `New()` and `Run()` |
| `deploy/mailcow/config.yaml` | Add `dnsbl:` section |
| `deploy/wordpress/config.yaml` | Add `dnsbl:` section |
| `go.mod` / `go.sum` | Add `github.com/miekg/dns` |
