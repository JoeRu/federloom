# IPv6 Prefix Normalization (Sub-project C)

**Status:** Design approved 2026-07-07
**Source:** Remediation roadmap sub-project C (batch A+B design §1); critique P1-4;
spec §7.1 and Problem V ("IPv6 `/128` reputation useless — attacker owns 2^64
per `/64`", currently marked solved but unimplemented).
**Prerequisite:** batches A+B and the stranger-block guarantee are merged.

---

## 1. Problem

`processLocal` (`internal/node/node.go:255`) and `ProcessRemote` (`node.go:333`)
store an event's IP as `addr.Unmap().String()` — no prefix masking. An IPv6
attacker owning a `/64` therefore presents up to 2^64 distinct `/128` keys:
reputation never accumulates, corroboration never fires, decay resets per
address. Problem V is real and open.

**Fix:** normalize IPv6 addresses to a configurable prefix (default `/64`) as an
explicit CIDR key, keyed and enforced per prefix, so an attacker's whole
allocation rolls up to one reputation entry and one firewall entry. IPv4 is
unchanged (per single address). The user decision (2026-07-07): block the `/64`
**range** (symmetric block/unblock), key represented as an **explicit CIDR**
(`2001:db8:1:2::/64`), prefix **configurable** (default 64; `/56` is common for
router allocations).

**Non-goals:** changing the trust/scoring math, the on-demand pull transport
(that is sub-project E), or IPv4 behaviour. The `pkg/proto` wire *struct* does
not change — only the string *value* in `Event.IP` becomes a normalized CIDR for
IPv6.

---

## 2. Architecture

The change has four layers, each independently testable:

- **Config** — `internal/config`: a new `reputation.ipv6_prefix` knob.
- **Normalization** — new `internal/netutil.NormalizeIP`: the single pure
  function that maps any address/CIDR to the canonical key form.
- **Node wiring** — `internal/node`: both event paths call `NormalizeIP` in
  place of `addr.Unmap().String()`.
- **Consumers of the key** — enforce sinks (ipset, nftables, crowdsec) block the
  `/64` range; never-block / whitelist / API validation accept a CIDR-or-address
  key.

Key invariant introduced: **a reputation key is either a bare IPv4 address
(`1.2.3.4`, implicitly `/32`) or an IPv6 CIDR at the configured prefix
(`2001:db8:1:2::/64`).** Every consumer that parses a key must accept both forms.

---

## 3. Config — `reputation.ipv6_prefix`

**File:** `internal/config/config.go`.

- Add `IPv6Prefix int \`yaml:"ipv6_prefix"\`` to `ReputationConfig`.
- `Defaults()` sets `IPv6Prefix: 64`.
- Validation (in the config load/validate path): if unset (0) → treat as 64; if
  outside `[1,128]` → log a warning and clamp to 64. Document `/56` as the common
  alternative for router-sized allocations.

Only `reputation.ipv6_prefix` is added; no other config field changes.

---

## 4. Normalization — `internal/netutil.NormalizeIP`

**New file:** `internal/netutil/netutil.go` (new tiny package, one pure
function; unit-testable without node/store).

```go
// NormalizeIP canonicalises an observed IP string into a reputation key.
//   - IPv4 (or IPv4-mapped IPv6): returned as the bare, unmapped address
//     (e.g. "1.2.3.4") — IPv4 is keyed per single address.
//   - IPv6: masked to ipv6Prefix and returned as an explicit CIDR
//     (e.g. "2001:db8:1:2::/64").
// Accepts input already in CIDR form (from a peer that normalized): the base
// address is extracted and re-masked to THIS node's ipv6Prefix, so each node
// enforces its own configured prefix (local sovereignty). ipv6Prefix must be
// 1..128; callers pass the validated config value.
func NormalizeIP(s string, ipv6Prefix int) (string, error)
```

Behaviour:
1. Try `netip.ParseAddr(s)`. On success, `addr = addr.Unmap()`.
2. If that fails, try `netip.ParsePrefix(s)` (already-CIDR input from a
   normalizing peer). Take `addr = prefix.Addr().Unmap()`, but **only if
   `addr.Is6()`** — an IPv4 address in CIDR form (e.g. `0.0.0.0/0`) is malformed
   on the wire and is rejected (return an error → caller drops the event). This
   preserves the existing CIDR-injection guard (§5). For an IPv6 CIDR the base is
   re-masked below, so even a deliberately wide CIDR (`::/0`, `2000::/3`)
   collapses to a single `/ipv6Prefix` key — the re-masking is itself the guard.
3. If both parses fail → return an error (caller drops the event, as today).
4. If `addr.Is4()` → return `addr.String()` (bare IPv4 address).
5. If `addr.Is6()` → `p, _ := addr.Prefix(ipv6Prefix)` and return
   `p.Masked().String()` (canonical CIDR, e.g. `2001:db8:1:2::/64`).

**Cross-prefix federation note (documented limitation):** if this node's
`ipv6_prefix` is *wider* than a peer's (e.g. local `/56` vs peer `/64`),
re-masking widens coverage — safe (superset). If *narrower* (local `/72` vs peer
`/64`), the imported `/64` collapses to only its `/72` base, under-covering the
range. Narrower-than-`/64` is unusual; documented, not fixed here.

---

## 5. Node wiring

**File:** `internal/node/node.go`.

In both `processLocal` (~line 250-255) and `ProcessRemote` (~line 328-333),
replace:

```go
	addr, err := netip.ParseAddr(e.IP)
	if err != nil {
		log.Printf("node: drop event with invalid IP %q", e.IP)
		return
	}
	e.IP = addr.Unmap().String()
```

with a call through `netutil.NormalizeIP(e.IP, n.cfg.Reputation.IPv6Prefix)`,
dropping the event on error exactly as the current `ParseAddr` failure does. The
normalized CIDR/address then flows unchanged through scoring, rules, enforce, the
API broadcast, and (for `processLocal`) the published `Event.IP`.

The CIDR-injection guard (`TestCIDRInjectionNeverRecorded`) still holds
unchanged: a raw attacker string like `0.0.0.0/0` is an IPv4 CIDR, which
`NormalizeIP` rejects (§4 step 2) → the event is dropped and never recorded,
exactly as today. Only bare IPv4 addresses and IPv6 (address or CIDR) are
accepted.

---

## 6. Enforcement — block the `/64` range

The score key for IPv6 is now a CIDR, so each sink receives it directly. Block
and unblock use the **same** key (symmetry — the decay/unblock loop in
`runDecay` scans score keys and calls `sink.Unblock(key)`).

**6.1 ipset** (`internal/enforce/ipset.go`) — default backend, primary:
- IPv6 set type becomes `hash:net` (was `hash:ip`); IPv4 set stays `hash:ip`.
- `Block`/`Unblock` pass the key verbatim — a CIDR `2001:db8:1:2::/64` is exactly
  what `hash:net` accepts; a bare IPv4 goes to the `hash:ip` set. The existing
  `ipSet()` router (`strings.Contains(ip, ":")` → IPv6 set) still selects
  correctly (IPv6 CIDRs contain `:`).
- **Migration on `Start`:** if `<set>6` already exists with type `hash:ip`,
  delete its ip6tables rule, `ipset destroy <set>6`, then create `hash:net` and
  reinstall the rule. Fresh installs just create `hash:net`. (Detect type via
  `ipset list <set>6 -t`; destroy requires the referencing rule be removed first.)

**6.2 nftables** (`internal/enforce/nftables.go`) — currently IPv6-broken (only a
`type ipv4_addr` set exists):
- Add a parallel IPv6 set `{ type ipv6_addr; flags interval; }` and an
  `ip6 saddr @<set6> drop` rule in `Start`. `flags interval` supports CIDR
  ranges, so `2001:db8:1:2::/64` blocks natively.
- `Block`/`Unblock` route by address family: IPv6 CIDR → the ipv6 set, IPv4 → the
  ipv4 set. This also fixes the pre-existing "IPv6 never blocked" gap.

**6.3 crowdsec** (`internal/enforce/crowdsec.go`):
- When the value is a CIDR (contains `/`), emit `Scope: "Range"` instead of
  `Scope: "Ip"`. Bare IPv4 keeps `Scope: "Ip"`. `Unblock` already deletes by
  `value=`, which works for the CIDR string unchanged.

**Collateral:** blocking a `/64` blocks every address in it — intended for
attacker allocations. The never-block set (§7) protects infra ranges; operators
can whitelist a specific `/64`/`/48` to override (invariant 1).

---

## 7. Consumers of the key — accept CIDR-or-address

Because the key may now be an IPv6 CIDR, three query sites must accept it. Each
change is a "parse as address, else parse as prefix" widening.

**7.1 never-block** (`internal/enforce/neverblock.go`): `Contains(ip string)`
currently does `netip.ParseAddr(ip)`. Widen: if `ParseAddr` fails, `ParsePrefix`
and test the prefix's **base address** against each never-block prefix
(`nbPrefix.Contains(base)`, where `base = queriedPrefix.Addr()`). A `/64` key is
thus never-blocked when its base falls in a never-block range (e.g. a whitelisted
`/48`, or `fe80::/10`).

**7.2 whitelist** (`internal/store/whitelist.go`): `Contains(ip)` at line 46
does `netip.ParseAddr(ip)` and compares against entries. Apply the same
address-or-prefix widening for the queried key so a normalized `/64` can match a
whitelist entry.

**7.3 API validation** (`internal/api/handler_blocklist.go:134`): the
`netip.ParseAddr(ip)` validation must also accept a CIDR key (address-or-prefix),
so normalized IPv6 keys aren't rejected as malformed.

**Unaffected (confirmed):** DNSBL (`internal/dnsbl/server.go`) is IPv4-only via
its `Is4()` guard — IPv6 keys never reach it. `pkg/proto` structs are unchanged
(only the `Event.IP` string value format changes). The reputation store keys on
the string as-is — mixed IPv4-address / IPv6-CIDR keys coexist fine.

---

## 8. Data flow summary

```
ingest / remote event  IP="2001:db8:1:2:aaaa::1"  (a /128)
        │
        ▼  netutil.NormalizeIP(ip, 64)
   key = "2001:db8:1:2::/64"   ← scored, corroborated, decayed, published, enforced
        │
        ├─ store: GetScore/PutScore keyed by the /64 CIDR
        ├─ neverblock/whitelist: base 2001:db8:1:2:: checked (address-or-prefix)
        ├─ rules.Evaluate: on the /64's aggregate record
        └─ sink.Block("2001:db8:1:2::/64")  → ipset hash:net / nft interval / crowdsec Range
                    decay → sink.Unblock("2001:db8:1:2::/64")  (same key)
```

A second `/128` in the same `/64` (`2001:db8:1:2:ffff::9`) normalizes to the
**same** key → its report corroborates the existing entry instead of creating a
new one. Problem V solved.

---

## 9. Testing

**`netutil.NormalizeIP` unit** (`internal/netutil/netutil_test.go`):
- IPv4 `"1.2.3.4"` → `"1.2.3.4"` (unchanged).
- IPv4-mapped `"::ffff:1.2.3.4"` → `"1.2.3.4"`.
- IPv6 `"2001:db8:1:2:aaaa::1"` prefix 64 → `"2001:db8:1:2::/64"`.
- Two distinct `/128`s in one `/64` → identical output; a `/128` in another
  `/64` → different output.
- Custom prefix 56 → `"2001:db8:1::/56"`; prefix 128 → the full `/128` CIDR.
- Already-CIDR input `"2001:db8:1:2::/64"` at prefix 56 → `"2001:db8:1::/56"`
  (re-masked to local prefix).
- Wide IPv6 CIDR `"2000::/3"` at prefix 64 → `"2000::/64"` (re-masking contains
  the width to a single key).
- Invalid `"not-an-ip"` → error.
- IPv4 CIDR `"0.0.0.0/0"` → **error** (rejected; the existing
  `TestCIDRInjectionNeverRecorded` still asserts it is never recorded).

**Node adversarial** (`test/adversarial/injection_test.go` or a new file):
- Two remote events with different `/128`s in one `/64` → `GetScore` on the `/64`
  key shows a single aggregated record with corroboration reflecting both (per
  the anchored/stranger rules already in place); a `/128` in a different `/64`
  scores separately.

**Enforce sink command construction** (new `internal/enforce/ipset_test.go`,
`nftables_test.go`): make the exec function injectable (replace the `run`
method / `exec.CommandContext` call with a small overridable field) so a unit
test asserts, without root: IPv6 key → `hash:net` set + the CIDR added verbatim;
IPv4 key → `hash:ip` set + bare address. crowdsec test: CIDR value → `Scope:
"Range"`, IPv4 → `Scope: "Ip"` (extend `crowdsec_test.go`).

**Never-block / whitelist** (extend existing `_test.go`): a `/64` CIDR key whose
base is inside a never-block/whitelist range is matched; one outside is not.

**Full acceptance:** `make build test adversarial`, `go vet`, `gofmt -l` clean.

---

## 10. Out of scope / follow-ups

- On-demand pull transport and `EvidenceAggregate` `/64` sharing → sub-project E.
- Narrower-than-peer local prefix under-coverage (§4) → documented limitation.
- After merge, update spec §12a traceability: §7.1 IPv6 `/64` normalization
  DONE; and Problem V may be marked genuinely solved.

## 11. Acceptance

Two IPv6 addresses in the same configured prefix produce one reputation key and
one firewall entry; an attacker rotating within their `/64` can no longer dilute
reputation or evade the block. IPv4 behaviour is byte-for-byte unchanged. All
three enforce backends block the `/64` range (ipset `hash:net`, nftables
interval set, crowdsec `Range`); never-block, whitelist, and API accept the CIDR
key; DNSBL and the wire struct are untouched. The prefix is operator-configurable
(default 64).
