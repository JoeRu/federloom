# IP Normalization Design

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Guarantee that every IP string inside SwarmGuard is in canonical `net/netip` form before it touches any store, bloom filter, whitelist, signature, or enforcement call.

**Architecture:** Normalization happens at the two mandatory entry points in `node.go` (local and remote event handlers). All other callsites that hold parsed IP/CIDR state migrate from `net.IP`/`net.IPNet` to `netip.Addr`/`netip.Prefix`. IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are collapsed to their IPv4 form via `.Unmap()`.

**Tech Stack:** Go 1.22, `net/netip` (stdlib since Go 1.18), no new dependencies.

## Global Constraints

- Use `net/netip` exclusively — do not introduce a wrapper package.
- `netip.Addr.Unmap()` must be called on every parsed address before use or storage.
- IPv4-mapped IPv6 (`::ffff:x.x.x.x`) always collapses to IPv4 (`x.x.x.x`).
- `spamtrap.go` remains IPv4-only; express the constraint with `addr.Unmap().Is4()`.
- `dnsbl/server.go` remains IPv4-only by design (DNSBL standard); same constraint.
- No behaviour changes beyond normalization — block thresholds, decay, trust are untouched.
- All existing tests must pass; add tests for the normalization and IPv4-mapped cases.

---

## Callsite Inventory

### Entry points (correctness — must fix)

| File | Line | Current | After |
|------|------|---------|-------|
| `internal/node/node.go` | 250 | `net.ParseIP(e.IP) == nil` | `netip.ParseAddr(e.IP)` + `e.IP = addr.Unmap().String()` |
| `internal/node/node.go` | 326 | `net.ParseIP(e.IP) == nil` | `netip.ParseAddr(e.IP)` + `e.IP = addr.Unmap().String()` |

After normalization, `e.IP` is canonical for all downstream calls on that path (whitelist, neverblock, bloom, store, sign, broadcast).

### Internal type migrations (correctness — must fix)

| File | Change |
|------|--------|
| `internal/enforce/neverblock.go` | `[]*net.IPNet` → `[]netip.Prefix`; `net.ParseCIDR` → `netip.ParsePrefix(s).Masked()`; `net.ParseIP` → `netip.ParseAddr(ip).Unmap()` |
| `internal/store/whitelist.go` | Re-parse entries on `Contains` using `netip.ParseAddr` + `Unmap()` and `netip.ParsePrefix` + `Masked()`; exact-match via `.Compare()==0` |
| `internal/dnsbl/server.go` | `net.ParseIP(ip).To4() == nil` → `netip.ParseAddr(ip).Unmap().Is4()` (IPv4-only constraint preserved) |
| `internal/api/handler_blocklist.go` | `net.ParseIP(ip) == nil` → `netip.ParseAddr(ip)` error check |

### Ingest hardening (defence-in-depth — should fix)

| File | Change |
|------|--------|
| `internal/ingest/spamtrap.go` | `net.ParseIP(line) == nil \|\| !strings.Contains(line, ".")` → `netip.ParseAddr(line)` err check + `!addr.Unmap().Is4()` |
| `internal/ingest/crowdsec.go` | Validate `a.Source.IP` with `netip.ParseAddr` before emitting event; log and skip on error |

---

## Entry-Point Normalization (detail)

Both local and remote event handlers in `node.go` follow this pattern:

```go
addr, err := netip.ParseAddr(e.IP)
if err != nil {
    log.Printf("node: drop event with invalid IP %q", e.IP)
    return
}
e.IP = addr.Unmap().String()
```

This replaces the existing `if net.ParseIP(e.IP) == nil { ... return }` guard. The normalised string is written back to `e.IP` before any further processing — whitelist check, neverblock check, bloom lookup, reputation record, signing, and broadcast all see the canonical form.

---

## Internal Type Migration (detail)

### `internal/enforce/neverblock.go`

Replace `nets []*net.IPNet` with `prefixes []netip.Prefix`.

Building:
```go
prefix, err := netip.ParsePrefix(cidr)
if err != nil {
    continue
}
prefixes = append(prefixes, prefix.Masked())
```

Contains:
```go
func (l *NeverBlockList) Contains(ip string) bool {
    addr, err := netip.ParseAddr(ip)
    if err != nil {
        return false
    }
    addr = addr.Unmap()
    for _, p := range l.prefixes {
        if p.Contains(addr) {
            return true
        }
    }
    return false
}
```

### `internal/store/whitelist.go`

`Contains` re-parses each entry on lookup (list is small; no caching needed):

```go
func (w *WhitelistStore) Contains(ip string) bool {
    addr, err := netip.ParseAddr(ip)
    if err != nil {
        return false
    }
    addr = addr.Unmap()
    w.mu.RLock()
    defer w.mu.RUnlock()
    for _, entry := range w.entries {
        if entryAddr, err := netip.ParseAddr(entry.IPOrRange); err == nil {
            if entryAddr.Unmap().Compare(addr) == 0 {
                return true
            }
            continue
        }
        if prefix, err := netip.ParsePrefix(entry.IPOrRange); err == nil {
            if prefix.Masked().Contains(addr) {
                return true
            }
        }
    }
    return false
}
```

---

## Data Compatibility

**BadgerDB and bloom filter require no code changes.** Keys are plain strings; after node.go normalization all new entries use canonical `netip` form. IPv4 canonical form is identical between `net.IP.String()` and `netip.Addr.String()`, so all existing IPv4 store data survives the migration intact.

Any pre-existing non-canonical IPv6 store entries (e.g., a key stored as `"2001:0db8::0001"` before this change) become unreachable after migration — canonical lookups will miss them in both bloom and BadgerDB. This is acceptable: such entries are negligible in current deployments and will decay naturally via BadgerDB TTL. No data migration is required.

## Testing Requirements

New tests cover:

1. **Canonical form**: `netip.ParseAddr("2001:0db8:0000:0000:0000:0000:0000:0001").Unmap().String()` == `"2001:db8::1"`
2. **IPv4-mapped collapse**: `netip.ParseAddr("::ffff:1.2.3.4").Unmap().String()` == `"1.2.3.4"`
3. **Split-reputation prevention**: two events with IPs `"::ffff:1.2.3.4"` and `"1.2.3.4"` must land on the same store key after node.go normalization
4. **NeverBlock with IPv6 loopback**: `::1` is blocked by the `::1/128` default entry
5. **Whitelist with IPv4-mapped**: whitelist entry `"1.2.3.4"` must match an incoming `"::ffff:1.2.3.4"` event after normalization
6. **Spamtrap rejects IPv6**: an IPv6 address emitted by the spamtrap source is dropped before reaching node.go

Tests 1–2 belong in `internal/node/node_test.go` (or a dedicated normalization test). Tests 3–5 can be inline with the changed packages. Test 6 belongs in `internal/ingest/spamtrap_test.go`.
