# IP Normalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Guarantee every IP string inside FederLoom is in canonical `net/netip` form — with IPv4-mapped IPv6 collapsed to IPv4 — before it touches any store, bloom filter, whitelist, signature, or enforcement call.

**Architecture:** Normalization is enforced at the two mandatory entry points in `node.go` (local and remote event handlers). All packages that parse IPs or CIDRs independently migrate from `net.IP`/`net.IPNet` to `netip.Addr`/`netip.Prefix` so that IPv4-mapped forms and non-canonical representations are handled uniformly at every callsite.

**Tech Stack:** Go 1.22, `net/netip` (stdlib since Go 1.18), no new dependencies.

## Global Constraints

- Use `net/netip` exclusively — do not introduce a wrapper package.
- `netip.Addr.Unmap()` must be called on every parsed address before use or storage.
- IPv4-mapped IPv6 (`::ffff:x.x.x.x`) always collapses to IPv4 (`x.x.x.x`).
- `spamtrap.go` remains IPv4-only; express the constraint with `addr.Unmap().Is4()`.
- `dnsbl/server.go` remains IPv4-only by design; same constraint.
- No behaviour changes beyond normalization — block thresholds, decay, trust are untouched.
- All existing tests must pass after every task; add new tests as specified per task.

---

### Task 1: Migrate `neverblock.go` to `net/netip`

**Files:**
- Modify: `internal/enforce/neverblock.go`
- Test: `internal/enforce/neverblock_test.go`

**Interfaces:**
- Produces: `NeverBlockList.Contains(ip string) bool` — unchanged signature, new implementation using `netip.Prefix`

- [ ] **Step 1: Write failing tests**

Add to the bottom of `internal/enforce/neverblock_test.go`:

```go
func TestNeverBlockIPv6Loopback(t *testing.T) {
	nbl := enforce.NewNeverBlockList(nil)
	if !nbl.Contains("::1") {
		t.Error("::1 should be in neverblock (::1/128 default entry)")
	}
}

func TestNeverBlockIPv4MappedRFC1918(t *testing.T) {
	nbl := enforce.NewNeverBlockList(nil)
	// ::ffff:10.0.0.1 is IPv4-mapped RFC1918 — Unmap() must reveal 10.0.0.1
	if !nbl.Contains("::ffff:10.0.0.1") {
		t.Error("::ffff:10.0.0.1 (IPv4-mapped RFC1918) should be caught by 10.0.0.0/8")
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```
go test ./internal/enforce/... -run "TestNeverBlockIPv6Loopback|TestNeverBlockIPv4Mapped" -v
```

Expected: both tests FAIL (current code doesn't call `Unmap()`, so `::ffff:10.0.0.1` is not matched by the IPv4 `10.0.0.0/8` entry).

- [ ] **Step 3: Replace `neverblock.go` with the `net/netip` implementation**

Replace the entire content of `internal/enforce/neverblock.go`:

```go
package enforce

import "net/netip"

// defaultNeverBlock contains CIDRs that must never be blocked (spec §6.2, invariant 3).
var defaultNeverBlock = []string{
	"127.0.0.0/8",    // loopback
	"::1/128",        // IPv6 loopback
	"10.0.0.0/8",     // RFC1918
	"172.16.0.0/12",  // RFC1918
	"192.168.0.0/16", // RFC1918
	"100.64.0.0/10",  // CGNAT (RFC6598)
	"169.254.0.0/16", // link-local
	"224.0.0.0/4",    // multicast
	"fc00::/7",       // IPv6 ULA
	"fe80::/10",      // IPv6 link-local
}

// NeverBlockList is an immutable set of CIDRs that must never be blocked.
type NeverBlockList struct {
	prefixes []netip.Prefix
}

// NewNeverBlockList builds a NeverBlockList from the default RFC1918 ranges plus any
// operator-provided extra CIDRs. Invalid entries in extra are silently skipped.
func NewNeverBlockList(extra []string) *NeverBlockList {
	all := append(defaultNeverBlock, extra...)
	var prefixes []netip.Prefix
	for _, cidr := range all {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return &NeverBlockList{prefixes: prefixes}
}

// Contains returns true if ip is covered by any CIDR in the list.
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

- [ ] **Step 4: Run all enforce tests**

```
go test ./internal/enforce/... -v
```

Expected: all tests PASS including the two new ones.

- [ ] **Step 5: Commit**

```bash
git add internal/enforce/neverblock.go internal/enforce/neverblock_test.go
git commit -m "feat(enforce): migrate NeverBlockList to net/netip; handle IPv4-mapped addresses"
```

---

### Task 2: Migrate `whitelist.go` `Contains` to `net/netip`

**Files:**
- Modify: `internal/store/whitelist.go`
- Test: `internal/store/whitelist_test.go`

**Interfaces:**
- Consumes: `proto.WhitelistEntry.IPOrRange string` — unchanged
- Produces: `WhitelistStore.Contains(ip string) bool` — unchanged signature, new implementation

- [ ] **Step 1: Write failing test**

Add to `internal/store/whitelist_test.go`:

```go
func TestWhitelistContains_IPv4MappedMatchesV4Entry(t *testing.T) {
	dir := t.TempDir()
	wl, err := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	if err := wl.Add(proto.WhitelistEntry{IPOrRange: "1.2.3.4", Scope: "local-only", Source: "manual"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// IPv4-mapped form of the same address must also match after Unmap()
	if !wl.Contains("::ffff:1.2.3.4") {
		t.Error("whitelist entry 1.2.3.4 must match incoming ::ffff:1.2.3.4 after Unmap()")
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```
go test ./internal/store/... -run TestWhitelistContains_IPv4MappedMatchesV4Entry -v
```

Expected: FAIL — current code compares `net.ParseIP("::ffff:1.2.3.4")` with `net.ParseIP("1.2.3.4")` using `Equal`, but `net.IP.Equal` does handle IPv4-mapped... actually let me check: `net.IP.Equal` does handle this case. So the test may not fail with the current code.

Actually: `net.ParseIP("::ffff:1.2.3.4")` returns a 16-byte IPv6 form, and `net.ParseIP("1.2.3.4")` returns a 4-byte IPv4 form. `net.IP.Equal` normalises both to 16-byte for comparison and they DO equal. So the old code already handles this case by accident.

The failing case for the old code is: whitelist entry `"1.2.3.4/32"` (as a CIDR) vs incoming `"::ffff:1.2.3.4"`. The CIDR `net.ParseCIDR("1.2.3.4/32")` produces an IPv4 net, and `ipNet.Contains(net.ParseIP("::ffff:1.2.3.4"))` — `net.IPNet.Contains` does NOT normalise IPv4-mapped, so this would return false.

Update the test to use a CIDR entry:

```go
func TestWhitelistContains_IPv4MappedMatchesV4CIDREntry(t *testing.T) {
	dir := t.TempDir()
	wl, err := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	if err := wl.Add(proto.WhitelistEntry{IPOrRange: "1.2.3.0/24", Scope: "local-only", Source: "manual"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// IPv4-mapped form of a host in 1.2.3.0/24 must match after Unmap()
	if !wl.Contains("::ffff:1.2.3.4") {
		t.Error("whitelist CIDR 1.2.3.0/24 must match incoming ::ffff:1.2.3.4 after Unmap()")
	}
}
```

- [ ] **Step 3: Run test to confirm it fails**

```
go test ./internal/store/... -run TestWhitelistContains_IPv4MappedMatchesV4CIDREntry -v
```

Expected: FAIL — `net.IPNet.Contains` does not unmask IPv4-mapped addresses.

- [ ] **Step 4: Replace `Contains` in `whitelist.go`**

In `internal/store/whitelist.go`, change the import block to add `"net/netip"` and remove `"net"`:

```go
import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"github.com/JoeRu/federloom/pkg/proto"
)
```

Replace the `Contains` method body:

```go
// Contains returns true if ip is covered by any entry in the store.
// Handles exact IP matches, CIDR containment, IPv4 and IPv6, and IPv4-mapped IPv6.
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

- [ ] **Step 5: Run all store tests**

```
go test ./internal/store/... -v
```

Expected: all tests PASS including the new one.

- [ ] **Step 6: Commit**

```bash
git add internal/store/whitelist.go internal/store/whitelist_test.go
git commit -m "feat(store): migrate WhitelistStore.Contains to net/netip; handle IPv4-mapped CIDRs"
```

---

### Task 3: Normalize IPs at `node.go` entry points

**Files:**
- Modify: `internal/node/node.go`
- Test: `internal/node/node_test.go`

**Interfaces:**
- Consumes: `proto.Event.IP string` — raw from ingest or federation
- Produces: `proto.Event.IP string` — canonical `netip` form written back before any downstream call

- [ ] **Step 1: Write failing tests**

Add to `internal/node/node_test.go` (file is `package node`, so private fields/methods are accessible):

```go
func TestProcessLocalNormalizesIPv6(t *testing.T) {
	n, _ := testNode(t)
	ctx := context.Background()

	n.processLocal(ctx, proto.Event{IP: "2001:0db8::0001", Reason: "test"})

	rec, err := n.rep.GetRecord("2001:db8::1")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Score == 0 {
		t.Error("expected non-zero score stored under canonical key 2001:db8::1")
	}
}

func TestProcessLocalCollapsesIPv4Mapped(t *testing.T) {
	n, _ := testNode(t)
	ctx := context.Background()

	n.processLocal(ctx, proto.Event{IP: "::ffff:1.2.3.4", Reason: "test"})

	rec, err := n.rep.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Score == 0 {
		t.Error("expected non-zero score under key 1.2.3.4 after IPv4-mapped event")
	}
	recMapped, _ := n.rep.GetRecord("::ffff:1.2.3.4")
	if recMapped.Score != 0 {
		t.Error("key ::ffff:1.2.3.4 must be empty — event should be stored as 1.2.3.4")
	}
}

func TestProcessLocalSplitReputationPrevention(t *testing.T) {
	n, _ := testNode(t)
	ctx := context.Background()

	n.processLocal(ctx, proto.Event{IP: "::ffff:1.2.3.4", Reason: "test"})
	n.processLocal(ctx, proto.Event{IP: "1.2.3.4", Reason: "test"})

	rec, err := n.rep.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Score < 2 {
		t.Errorf("expected combined score ≥ 2 (both events merged), got %.1f", rec.Score)
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```
go test ./internal/node/... -run "TestProcessLocalNormalizes|TestProcessLocalCollapses|TestProcessLocalSplit" -v
```

Expected: all three FAIL — current code stores the raw IP string without normalizing.

- [ ] **Step 3: Update `node.go` imports**

In `internal/node/node.go`, change the import block: remove `"net"`, add `"net/netip"`:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/JoeRu/federloom/internal/api"
	// ... rest of imports unchanged
)
```

- [ ] **Step 4: Replace the local-event guard (line 250)**

In `processLocal`, replace:

```go
	if net.ParseIP(e.IP) == nil {
		log.Printf("node: drop event with invalid IP %q", e.IP)
		return
	}
```

With:

```go
	addr, err := netip.ParseAddr(e.IP)
	if err != nil {
		log.Printf("node: drop event with invalid IP %q", e.IP)
		return
	}
	e.IP = addr.Unmap().String()
```

- [ ] **Step 5: Replace the remote-event guard (line 326)**

In the remote event handler, replace:

```go
	if net.ParseIP(e.IP) == nil {
		log.Printf("node: drop event with invalid IP %q", e.IP)
		return
	}
```

With:

```go
	addr, err := netip.ParseAddr(e.IP)
	if err != nil {
		log.Printf("node: drop event with invalid IP %q", e.IP)
		return
	}
	e.IP = addr.Unmap().String()
```

- [ ] **Step 6: Run all node tests**

```
go test ./internal/node/... -v
```

Expected: all tests PASS including the three new ones.

- [ ] **Step 7: Run full test suite to catch any regressions**

```
go test ./...
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/node/node.go internal/node/node_test.go
git commit -m "feat(node): normalize IPs to canonical net/netip form at entry points; collapse IPv4-mapped"
```

---

### Task 4: Ingest hardening — `spamtrap.go` and `crowdsec.go`

**Files:**
- Modify: `internal/ingest/spamtrap.go`
- Modify: `internal/ingest/crowdsec.go`
- Test: `internal/ingest/spamtrap_test.go`

**Interfaces:**
- Produces: `proto.Event.IP string` — canonical form emitted from both ingest sources

- [ ] **Step 1: Write failing spamtrap test**

Add to `internal/ingest/spamtrap_test.go`:

```go
func TestSpamtrapRejectsIPv6(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "spamtrap.log")

	cfg := config.SpamtrapConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	s := ingest.NewSpamtrap(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// First line: IPv6 (must be rejected). Second line: valid IPv4 (must pass).
	writeLines(t, logPath, []string{"2001:db8::1", "198.51.100.5"})

	var got []string
	for {
		select {
		case e := <-ch:
			got = append(got, e.IP)
		case <-ctx.Done():
			goto done
		}
	}
done:
	if len(got) != 1 || got[0] != "198.51.100.5" {
		t.Errorf("expected only [198.51.100.5], got %v", got)
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```
go test ./internal/ingest/... -run TestSpamtrapRejectsIPv6 -v
```

Expected: FAIL — current guard `!strings.Contains(line, ".")` passes IPv6 addresses that contain dots (e.g. `::ffff:1.2.3.4`) or, for `2001:db8::1`, the condition is `!strings.Contains("2001:db8::1", ".")` which is `true` so it IS rejected. Actually `2001:db8::1` contains no dot, so the current code does reject it. But `::ffff:1.2.3.4` contains dots and would slip through.

Update the test to use an IPv4-mapped IPv6 address that the current code would let through:

```go
func TestSpamtrapRejectsIPv6(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "spamtrap.log")

	cfg := config.SpamtrapConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	s := ingest.NewSpamtrap(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// ::ffff:198.51.100.5 contains dots so the old guard passes it through as if IPv4.
	// The new guard must reject it (Is4() returns false for IPv4-mapped IPv6 before Unmap).
	// 198.51.100.5 is a valid IPv4 that must pass.
	writeLines(t, logPath, []string{"::ffff:198.51.100.5", "198.51.100.5"})

	var got []string
	for {
		select {
		case e := <-ch:
			got = append(got, e.IP)
		case <-ctx.Done():
			goto done
		}
	}
done:
	if len(got) != 1 || got[0] != "198.51.100.5" {
		t.Errorf("expected only [198.51.100.5], got %v", got)
	}
}
```

- [ ] **Step 3: Run test to confirm it fails**

```
go test ./internal/ingest/... -run TestSpamtrapRejectsIPv6 -v
```

Expected: FAIL — `::ffff:198.51.100.5` passes `strings.Contains(line, ".")` so the current code lets it through, emitting two events instead of one.

- [ ] **Step 4: Update `spamtrap.go`**

In `internal/ingest/spamtrap.go`, change the import block: remove `"net"`, add `"net/netip"`. Remove `"strings"` if it's only used for the dot-check (verify first — it may be used elsewhere in the file).

Replace the guard:

```go
				addr, err := netip.ParseAddr(line)
				if err != nil || !addr.Unmap().Is4() {
					log.Printf("ingest/spamtrap: invalid IPv4 %q in %s — skipping", line, s.cfg.LogFile)
					continue
				}
```

- [ ] **Step 5: Update `crowdsec.go` ingest**

In `internal/ingest/crowdsec.go`, add `"net/netip"` to the import block.

Replace the alert-emission loop body (currently starting at `if a.Source.IP == ""`):

```go
		if a.Source.IP == "" {
			continue
		}
		addr, err := netip.ParseAddr(a.Source.IP)
		if err != nil {
			log.Printf("crowdsec: invalid IP %q in alert — skipping", a.Source.IP)
			continue
		}
		reason := mapScenario(a.Scenario)
		ts, err := time.Parse(time.RFC3339, a.StartAt)
		if err != nil {
			ts = pollTime
		}
		select {
		case ch <- proto.Event{
			IP:         addr.Unmap().String(),
			Reason:     reason,
			Timestamp:  ts,
			ReporterID: c.selfID,
		}:
		case <-ctx.Done():
			return
		}
```

- [ ] **Step 6: Run all ingest tests**

```
go test ./internal/ingest/... -v
```

Expected: all tests PASS including the new spamtrap test.

- [ ] **Step 7: Commit**

```bash
git add internal/ingest/spamtrap.go internal/ingest/crowdsec.go internal/ingest/spamtrap_test.go
git commit -m "feat(ingest): harden IP validation with net/netip; reject IPv4-mapped in spamtrap"
```

---

### Task 5: Remaining callsites — `dnsbl/server.go` and `api/handler_blocklist.go`

**Files:**
- Modify: `internal/dnsbl/server.go`
- Modify: `internal/api/handler_blocklist.go`

**Interfaces:**
- No new interfaces; these are drop-in guard replacements.

- [ ] **Step 1: Update `dnsbl/server.go`**

In `internal/dnsbl/server.go`, add `"net/netip"` to the import block. Keep `"net"` — it is still needed for `net.ParseIP("127.0.0.2").To4()` on the A-record line.

Replace line 120:

```go
	if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
```

With:

```go
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Unmap().Is4() {
```

- [ ] **Step 2: Update `api/handler_blocklist.go`**

In `internal/api/handler_blocklist.go`, change the import block: remove `"net"`, add `"net/netip"`.

Replace line 134:

```go
		if net.ParseIP(ip) == nil {
			return nil
		}
```

With:

```go
		if _, err := netip.ParseAddr(ip); err != nil {
			return nil
		}
```

- [ ] **Step 3: Run full test suite**

```
go test ./...
```

Expected: all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/dnsbl/server.go internal/api/handler_blocklist.go
git commit -m "feat(dnsbl,api): replace net.ParseIP guards with net/netip"
```
