# IPv6 Prefix Normalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Normalize IPv6 addresses to a configurable prefix (default `/64`) as an explicit CIDR key so an attacker's `/64` rolls up to one reputation entry and one firewall entry (spec Problem V), leaving IPv4 unchanged.

**Architecture:** A pure `netutil.NormalizeIP` produces the canonical key (bare IPv4 address, or IPv6 CIDR at the configured prefix). Both node event paths call it; the three enforce sinks block the `/64` range (ipset `hash:net`, nftables interval set, crowdsec `Range`); never-block/whitelist/API accept a CIDR-or-address key. Tasks are ordered so the behaviour flip (node wiring) lands last, after every consumer already handles CIDR keys.

**Tech Stack:** Go 1.22, `net/netip`, BadgerDB, `ipset`/`nftables` shell-outs, `go test` (unit + `adversarial` tag).

## Global Constraints

- Go module `github.com/JoeRu/federloom`, Go 1.22. Conventional Commits.
- `internal/enforce` is security-critical: conservative, extra care; the ipset IPv6-set migration must not error a fresh install.
- A reputation key is EITHER a bare IPv4 address (`1.2.3.4`) OR an IPv6 CIDR at the configured prefix (`2001:db8:1:2::/64`). Every consumer that parses a key accepts both.
- IPv4 behaviour is unchanged (per single address, `hash:ip`, `Scope: "Ip"`).
- Default IPv6 prefix = 64; valid range 1..128; `/56` is a supported alternative (router allocations).
- `NormalizeIP` accepts bare IPv4, bare/`/128` IPv6, and IPv6 CIDR input; it REJECTS IPv4-in-CIDR (e.g. `0.0.0.0/0`) so the existing `TestCIDRInjectionNeverRecorded` guard still holds. A wide IPv6 CIDR is re-masked to a single `/prefix` key.
- No `pkg/proto` struct change (only the `Event.IP` string value format changes for IPv6). DNSBL is IPv4-only and untouched.
- Every reputation/trust/ingest/enforce change adds or updates a test; `make adversarial` is the CI gate.

---

### Task 1: Config knob `reputation.ipv6_prefix`

**Files:**
- Modify: `internal/config/config.go` (`ReputationConfig`, `Defaults`, add `EffectiveIPv6Prefix`)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `ReputationConfig.IPv6Prefix int` (yaml `ipv6_prefix`); `func (c ReputationConfig) EffectiveIPv6Prefix() int` returning a clamped prefix in `[1,128]`, defaulting to 64 when unset (0) or out of range.

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestEffectiveIPv6Prefix(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, 64},    // unset → default
		{64, 64},   // valid
		{56, 56},   // router allocation
		{128, 128}, // single host
		{-1, 64},   // out of range → default
		{129, 64},  // out of range → default
	}
	for _, c := range cases {
		got := config.ReputationConfig{IPv6Prefix: c.in}.EffectiveIPv6Prefix()
		if got != c.want {
			t.Errorf("EffectiveIPv6Prefix(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestDefaultsIPv6Prefix(t *testing.T) {
	if got := config.Defaults().Reputation.IPv6Prefix; got != 64 {
		t.Errorf("default IPv6Prefix = %d, want 64", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/config/ -run 'TestEffectiveIPv6Prefix|TestDefaultsIPv6Prefix' -v`
Expected: FAIL — `IPv6Prefix` / `EffectiveIPv6Prefix` undefined.

- [ ] **Step 3: Add the field, default, and method**

In `internal/config/config.go`, add the field to `ReputationConfig` (after `RulesFile`):

```go
	RulesFile        string   `yaml:"rules_file"` // empty = legacy threshold mode
	IPv6Prefix       int      `yaml:"ipv6_prefix"` // IPv6 reputation/enforcement prefix; default 64
```

In `Defaults()`, in the `Reputation:` literal, add `IPv6Prefix: 64,`.

Add the method (near `ReputationConfig`):

```go
// EffectiveIPv6Prefix returns the IPv6 normalization prefix, clamped to [1,128]
// with 64 as the default for unset (0) or out-of-range values.
func (c ReputationConfig) EffectiveIPv6Prefix() int {
	if c.IPv6Prefix < 1 || c.IPv6Prefix > 128 {
		return 64
	}
	return c.IPv6Prefix
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/config/ -run 'TestEffectiveIPv6Prefix|TestDefaultsIPv6Prefix' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/config/config.go internal/config/config_test.go
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add reputation.ipv6_prefix knob (default 64)"
```

---

### Task 2: `internal/netutil.NormalizeIP`

**Files:**
- Create: `internal/netutil/netutil.go`
- Test: `internal/netutil/netutil_test.go`

**Interfaces:**
- Produces: `func NormalizeIP(s string, ipv6Prefix int) (string, error)`.

- [ ] **Step 1: Write the failing test**

Create `internal/netutil/netutil_test.go`:

```go
package netutil

import "testing"

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		name, in string
		prefix   int
		want     string
		wantErr  bool
	}{
		{"ipv4 bare", "1.2.3.4", 64, "1.2.3.4", false},
		{"ipv4-mapped", "::ffff:1.2.3.4", 64, "1.2.3.4", false},
		{"ipv6 128 to 64", "2001:db8:1:2:aaaa::1", 64, "2001:db8:1:2::/64", false},
		{"ipv6 other 128 same 64", "2001:db8:1:2:ffff::9", 64, "2001:db8:1:2::/64", false},
		{"ipv6 different 64", "2001:db8:1:3::1", 64, "2001:db8:1:3::/64", false},
		{"ipv6 prefix 56", "2001:db8:1:2:aaaa::1", 56, "2001:db8:1::/56", false},
		{"ipv6 prefix 128", "2001:db8:1:2::5", 128, "2001:db8:1:2::5/128", false},
		{"ipv6 cidr input remask 56", "2001:db8:1:2::/64", 56, "2001:db8:1::/56", false},
		{"wide ipv6 cidr contained", "2000::/3", 64, "2000::/64", false},
		{"invalid", "not-an-ip", 64, "", true},
		{"ipv4 cidr rejected", "0.0.0.0/0", 64, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormalizeIP(c.in, c.prefix)
			if c.wantErr {
				if err == nil {
					t.Fatalf("NormalizeIP(%q) = %q, want error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeIP(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("NormalizeIP(%q, %d) = %q, want %q", c.in, c.prefix, got, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/netutil/ -v`
Expected: FAIL — package/function does not exist.

- [ ] **Step 3: Implement the function**

Create `internal/netutil/netutil.go`:

```go
// Package netutil holds small, pure network-address helpers shared across
// FederLoom. It has no dependencies on other internal packages.
package netutil

import (
	"fmt"
	"net/netip"
)

// NormalizeIP canonicalises an observed IP string into a reputation key:
//   - IPv4 (or IPv4-mapped IPv6): the bare, unmapped address ("1.2.3.4").
//   - IPv6: masked to ipv6Prefix and returned as an explicit CIDR
//     ("2001:db8:1:2::/64").
//
// Input may already be an IPv6 CIDR (from a peer that normalized): its base is
// re-masked to THIS node's ipv6Prefix. IPv4 in CIDR form (e.g. "0.0.0.0/0") is
// rejected so a malformed/attacker CIDR is dropped by the caller. A wide IPv6
// CIDR ("::/0") collapses to a single /ipv6Prefix key — the re-masking is the
// guard. ipv6Prefix must be 1..128 (callers pass a validated value).
func NormalizeIP(s string, ipv6Prefix int) (string, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		// Maybe an already-CIDR input from a normalizing peer.
		p, perr := netip.ParsePrefix(s)
		if perr != nil {
			return "", fmt.Errorf("netutil: parse %q: %w", s, err)
		}
		base := p.Addr().Unmap()
		if !base.Is6() {
			// IPv4-in-CIDR is malformed on the wire; reject (preserves the
			// CIDR-injection guard).
			return "", fmt.Errorf("netutil: reject IPv4 CIDR %q", s)
		}
		addr = base
	} else {
		addr = addr.Unmap()
	}

	if addr.Is4() {
		return addr.String(), nil
	}
	p, err := addr.Prefix(ipv6Prefix)
	if err != nil {
		return "", fmt.Errorf("netutil: mask %q to /%d: %w", s, ipv6Prefix, err)
	}
	return p.Masked().String(), nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/netutil/ -v`
Expected: PASS (all subtests).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/netutil/netutil.go internal/netutil/netutil_test.go
git add internal/netutil/netutil.go internal/netutil/netutil_test.go
git commit -m "feat(netutil): add NormalizeIP for IPv6 /64 prefix keys"
```

---

### Task 3: ipset `hash:net` for IPv6 + migration + injectable runner

**Files:**
- Modify: `internal/enforce/ipset.go`
- Test: `internal/enforce/ipset_test.go` (new)

**Interfaces:**
- Consumes: `Sink` interface (`Name/Start/Block/Unblock/Close`).
- Produces: `IpsetSink` with an injectable `run func(ctx, name, args...) error` field (test-settable); IPv6 set is `hash:net`, IPv6 blocks pass the CIDR key verbatim.

- [ ] **Step 1: Write the failing test**

Create `internal/enforce/ipset_test.go`:

```go
package enforce

import (
	"context"
	"testing"
)

// captureRun records ipset/iptables invocations for assertion.
func captureRun(calls *[][]string) func(ctx context.Context, name string, args ...string) error {
	return func(ctx context.Context, name string, args ...string) error {
		*calls = append(*calls, append([]string{name}, args...))
		return nil
	}
}

func hasCall(calls [][]string, want ...string) bool {
	for _, c := range calls {
		if len(c) != len(want) {
			continue
		}
		match := true
		for i := range c {
			if c[i] != want[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestIpsetIPv6BlocksAsHashNet(t *testing.T) {
	var calls [][]string
	s := NewIpset("federloom", []string{"INPUT"})
	s.run = captureRun(&calls)

	if err := s.Block("2001:db8:1:2::/64"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !hasCall(calls, "ipset", "add", "federloom6", "2001:db8:1:2::/64", "-exist") {
		t.Errorf("IPv6 CIDR must be added to the hash:net set federloom6; calls=%v", calls)
	}
}

func TestIpsetIPv4BlocksBareAddress(t *testing.T) {
	var calls [][]string
	s := NewIpset("federloom", []string{"INPUT"})
	s.run = captureRun(&calls)

	if err := s.Block("1.2.3.4"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !hasCall(calls, "ipset", "add", "federloom", "1.2.3.4", "-exist") {
		t.Errorf("IPv4 must be added to the hash:ip set federloom; calls=%v", calls)
	}
}

func TestIpsetStartCreatesHashNetIPv6Set(t *testing.T) {
	var calls [][]string
	s := NewIpset("federloom", []string{"INPUT"})
	s.run = captureRun(&calls)

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !hasCall(calls, "ipset", "create", "federloom6", "hash:net", "family", "inet6", "-exist") {
		t.Errorf("IPv6 set must be created as hash:net; calls=%v", calls)
	}
	if !hasCall(calls, "ipset", "create", "federloom", "hash:ip", "family", "inet", "-exist") {
		t.Errorf("IPv4 set must stay hash:ip; calls=%v", calls)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/enforce/ -run 'TestIpset' -v`
Expected: FAIL — `s.run` field does not exist (compile error) / IPv6 set is `hash:ip`.

- [ ] **Step 3: Add the injectable runner field**

In `internal/enforce/ipset.go`, change the struct and constructor, and delete the old `run` method:

```go
type IpsetSink struct {
	setName string
	chains  []string
	run     func(ctx context.Context, name string, args ...string) error
}
```

In `NewIpset`, before `return`, set the default runner:

```go
	s := &IpsetSink{setName: setName, chains: chains}
	s.run = func(ctx context.Context, name string, args ...string) error {
		return exec.CommandContext(ctx, name, args...).Run()
	}
	return s
}
```

Delete the old method:

```go
func (s *IpsetSink) run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}
```

(All existing `s.run(ctx, ...)` calls now invoke the field — no other change needed there.)

- [ ] **Step 4: Make the IPv6 set `hash:net` with migration**

In `Start`, replace the IPv6 set creation line:

```go
	// IPv6 set — best-effort; ip6tables may not be present on all hosts
	if err := s.run(ctx, "ipset", "create", s.setName+"6", "hash:ip", "family", "inet6", "-exist"); err != nil {
		log.Printf("enforce/ipset: IPv6 set creation failed (ip6tables may be unavailable): %v", err)
	}
```

with the `hash:net` version plus in-place migration of a pre-existing `hash:ip` set:

```go
	// IPv6 set is hash:net so a whole /64 (or configured prefix) blocks as one
	// entry. Migrate a pre-existing hash:ip set: -exist errors on a type
	// mismatch, which we use as the migration trigger. Best-effort (IPv6 may be
	// unavailable on some hosts).
	set6 := s.setName + "6"
	if err := s.run(ctx, "ipset", "create", set6, "hash:net", "family", "inet6", "-exist"); err != nil {
		// Likely a stale hash:ip set from a prior version. Drop referencing
		// ip6tables rules so the set can be destroyed, then recreate as hash:net.
		for _, chain := range s.chains {
			_ = s.run(ctx, "ip6tables", "-D", chain, "-m", "set", "--match-set", set6, "src", "-j", "DROP")
		}
		_ = s.run(ctx, "ipset", "destroy", set6)
		if err2 := s.run(ctx, "ipset", "create", set6, "hash:net", "family", "inet6", "-exist"); err2 != nil {
			log.Printf("enforce/ipset: IPv6 hash:net set creation failed (ip6tables may be unavailable): %v", err2)
		}
	}
```

The `Block`/`Unblock`/`ipSet` methods are unchanged — a CIDR like `2001:db8:1:2::/64` contains `:` so it routes to `set6`, and `hash:net` accepts the CIDR verbatim.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/enforce/ -run 'TestIpset' -v && go build ./...`
Expected: all three PASS; build clean.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/enforce/ipset.go internal/enforce/ipset_test.go
git add internal/enforce/ipset.go internal/enforce/ipset_test.go
git commit -m "feat(enforce/ipset): block IPv6 /64 ranges via hash:net (+migration, testable runner)"
```

---

### Task 4: nftables IPv6 interval set + crowdsec `Range` scope

**Files:**
- Modify: `internal/enforce/nftables.go`
- Modify: `internal/enforce/crowdsec.go`
- Test: `internal/enforce/nftables_test.go` (new), `internal/enforce/crowdsec_test.go` (extend)

**Interfaces:**
- Produces: `NftablesSink` with an injectable `run func(ctx, name, args...) error` field and an IPv6 `ipv6_addr` interval set; crowdsec emits `Scope: "Range"` for CIDR values.

- [ ] **Step 1: Write the failing nftables test**

Create `internal/enforce/nftables_test.go`:

```go
package enforce

import "testing"

func TestNftablesIPv6BlocksInV6Set(t *testing.T) {
	var calls [][]string
	s := NewNftables("blocked", "input")
	s.run = captureRun(&calls) // captureRun/hasCall defined in ipset_test.go (same package)

	if err := s.Block("2001:db8:1:2::/64"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	// IPv6 CIDR goes to the v6 set (blocked6), added as an interval element.
	if !hasCall(calls, "nft", "add", "element", "inet", "federloom", "blocked6", "{", "2001:db8:1:2::/64", "}") {
		t.Errorf("IPv6 CIDR must be added to blocked6; calls=%v", calls)
	}
}

func TestNftablesIPv4BlocksInV4Set(t *testing.T) {
	var calls [][]string
	s := NewNftables("blocked", "input")
	s.run = captureRun(&calls)

	if err := s.Block("1.2.3.4"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !hasCall(calls, "nft", "add", "element", "inet", "federloom", "blocked", "{", "1.2.3.4", "}") {
		t.Errorf("IPv4 must be added to the v4 set; calls=%v", calls)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/enforce/ -run 'TestNftables' -v`
Expected: FAIL — `s.run` field does not exist; IPv6 goes nowhere valid.

- [ ] **Step 3: Refactor nftables to an injectable runner + IPv6 set**

Rewrite `internal/enforce/nftables.go` so all shell-outs go through an injectable `run` field, add the IPv6 interval set and rule in `Start`, and route by family in `Block`/`Unblock`:

```go
package enforce

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

const nftTable = "federloom"
const nftSetName = "blocked"

// NftablesSink enforces blocks via nftables. Shells out to /sbin/nft. Requires root.
type NftablesSink struct {
	setName string // IPv4 set; IPv6 set is setName+"6"
	hook    string // "input" (host traffic) or "forward" (Docker/routed)
	run     func(ctx context.Context, name string, args ...string) error
}

// NewNftables creates a NftablesSink. hook should be "forward" in Docker environments.
func NewNftables(setName, hook string) *NftablesSink {
	if setName == "" {
		setName = nftSetName
	}
	if hook == "" {
		hook = "input"
	}
	s := &NftablesSink{setName: setName, hook: hook}
	s.run = func(ctx context.Context, name string, args ...string) error {
		return exec.CommandContext(ctx, name, args...).Run()
	}
	return s
}

func (s *NftablesSink) Name() string { return "nftables" }

func (s *NftablesSink) set6() string { return s.setName + "6" }

// nftSet selects the IPv4 or IPv6 set for ip (CIDR or address).
func (s *NftablesSink) nftSet(ip string) string {
	if strings.Contains(ip, ":") {
		return s.set6()
	}
	return s.setName
}

// Start creates the nftables table, both sets (v4 addr + v6 addr interval),
// chain, and drop rules (all idempotent — errors ignored).
func (s *NftablesSink) Start(ctx context.Context) error {
	if s.hook == "input" {
		log.Printf("INFO enforce/nftables: hook=input covers host traffic only; use hook=forward for Docker environments")
	}
	cmds := [][]string{
		{"nft", "add", "table", "inet", nftTable},
		{"nft", "add", "set", "inet", nftTable, s.setName, "{ type ipv4_addr; flags interval; }"},
		{"nft", "add", "set", "inet", nftTable, s.set6(), "{ type ipv6_addr; flags interval; }"},
		{"nft", "add", "chain", "inet", nftTable, s.hook, fmt.Sprintf("{ type filter hook %s priority 0; }", s.hook)},
		{"nft", "add", "rule", "inet", nftTable, s.hook, "ip", "saddr", "@" + s.setName, "drop"},
		{"nft", "add", "rule", "inet", nftTable, s.hook, "ip6", "saddr", "@" + s.set6(), "drop"},
	}
	for _, args := range cmds {
		_ = s.run(ctx, args[0], args[1:]...)
	}
	return nil
}

// Block adds ip (IPv4 address or IPv6 CIDR) to the matching set.
func (s *NftablesSink) Block(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.run(ctx, "nft", "add", "element", "inet", nftTable, s.nftSet(ip), "{", ip, "}"); err != nil {
		return fmt.Errorf("enforce/nftables: block %s: %w", ip, err)
	}
	return nil
}

// Unblock removes ip from the matching set.
func (s *NftablesSink) Unblock(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.run(ctx, "nft", "delete", "element", "inet", nftTable, s.nftSet(ip), "{", ip, "}"); err != nil {
		return fmt.Errorf("enforce/nftables: unblock %s: %w", ip, err)
	}
	return nil
}

// Close is a no-op: the nftables rules persist across daemon restarts.
func (s *NftablesSink) Close() error { return nil }

// Compile-time interface check.
var _ Sink = (*NftablesSink)(nil)
```

- [ ] **Step 4: Run the nftables tests to verify they pass**

Run: `go test ./internal/enforce/ -run 'TestNftables' -v`
Expected: both PASS.

- [ ] **Step 5: Write the failing crowdsec Range test**

Add to `internal/enforce/crowdsec_test.go`:

```go
func TestCrowdSecScopeForValue(t *testing.T) {
	if got := csScopeFor("1.2.3.4"); got != "Ip" {
		t.Errorf("IPv4 scope = %q, want Ip", got)
	}
	if got := csScopeFor("2001:db8:1:2::/64"); got != "Range" {
		t.Errorf("IPv6 CIDR scope = %q, want Range", got)
	}
}
```

- [ ] **Step 6: Run it to verify it fails**

Run: `go test ./internal/enforce/ -run 'TestCrowdSecScopeForValue' -v`
Expected: FAIL — `csScopeFor` undefined.

- [ ] **Step 7: Add `csScopeFor` and use it in the decision + source**

In `internal/enforce/crowdsec.go`, add `"strings"` to the imports if not present, add the helper (package-level):

```go
// csScopeFor returns the CrowdSec decision scope for a reputation key: "Range"
// for a CIDR (IPv6 /prefix), "Ip" for a bare address.
func csScopeFor(value string) string {
	if strings.Contains(value, "/") {
		return "Range"
	}
	return "Ip"
}
```

In the alert construction, replace the two hardcoded `Scope: "Ip",` (in `csDecision` and `csSource`) with `Scope: csScopeFor(ip),`.

- [ ] **Step 8: Run all enforce tests to verify they pass**

Run: `go test ./internal/enforce/... && go build ./...`
Expected: PASS; build clean.

- [ ] **Step 9: Commit**

```bash
gofmt -w internal/enforce/nftables.go internal/enforce/nftables_test.go internal/enforce/crowdsec.go internal/enforce/crowdsec_test.go
git add internal/enforce/nftables.go internal/enforce/nftables_test.go internal/enforce/crowdsec.go internal/enforce/crowdsec_test.go
git commit -m "feat(enforce): nftables IPv6 interval set + crowdsec Range scope for /64"
```

---

### Task 5: CIDR-aware key consumers (never-block, whitelist, API)

**Files:**
- Modify: `internal/enforce/neverblock.go` (`Contains`)
- Modify: `internal/store/whitelist.go` (`Contains`)
- Modify: `internal/api/handler_blocklist.go` (the `ParseAddr` filter ~line 134)
- Test: `internal/enforce/neverblock_test.go`, `internal/store/whitelist_test.go`

**Interfaces:**
- Produces: a shared parse helper so all three accept a bare address or a CIDR key. Add `func KeyAddr(s string) (netip.Addr, bool)` (exported — used across packages) in `internal/netutil` (Task 2 package) returning the address to test (the address itself, or a CIDR's base) and ok=false on parse failure.

- [ ] **Step 1: Write the failing helper + never-block tests**

Add to `internal/netutil/netutil_test.go`:

```go
func TestKeyAddr(t *testing.T) {
	a, ok := KeyAddr("1.2.3.4")
	if !ok || a.String() != "1.2.3.4" {
		t.Errorf("KeyAddr(1.2.3.4) = %v,%v", a, ok)
	}
	a, ok = KeyAddr("2001:db8:1:2::/64")
	if !ok || a.String() != "2001:db8:1:2::" {
		t.Errorf("KeyAddr(/64) base = %v,%v, want 2001:db8:1:2::", a, ok)
	}
	if _, ok := KeyAddr("nonsense"); ok {
		t.Error("KeyAddr(nonsense) ok=true, want false")
	}
}
```

Add to `internal/enforce/neverblock_test.go`:

```go
func TestNeverBlockAcceptsCIDRKey(t *testing.T) {
	nbl := NewNeverBlockList([]string{"2001:db8:1::/48"})
	if !nbl.Contains("2001:db8:1:2::/64") {
		t.Error("/64 whose base is in a whitelisted /48 must be never-blocked")
	}
	if nbl.Contains("2001:db8:9:9::/64") {
		t.Error("/64 outside all never-block ranges must be blockable")
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/netutil/ ./internal/enforce/ -run 'TestKeyAddr|TestNeverBlockAcceptsCIDRKey' -v`
Expected: FAIL — `KeyAddr` undefined; never-block returns false for the CIDR key.

- [ ] **Step 3: Add `KeyAddr` to netutil**

In `internal/netutil/netutil.go`, add:

```go
// KeyAddr returns the address to test for a reputation key: the address itself
// for a bare IP, or the base address for a CIDR key. ok is false if s parses as
// neither. Used by never-block/whitelist/API to match a normalized CIDR key.
func KeyAddr(s string) (addr netip.Addr, ok bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}
```

- [ ] **Step 4: Use `KeyAddr` in never-block**

In `internal/enforce/neverblock.go`, add the import `"github.com/JoeRu/federloom/internal/netutil"` and change `Contains`:

```go
// Contains returns true if ip (a bare address or CIDR key) is covered by any
// CIDR in the list. For a CIDR key, its base address is tested.
func (l *NeverBlockList) Contains(ip string) bool {
	addr, ok := netutil.KeyAddr(ip)
	if !ok {
		return false
	}
	for _, p := range l.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
```

(Delete the old `netip.ParseAddr`+`Unmap` lines; `net/netip` may become unused in the file body except the `prefixes` field type — keep the import since `NewNeverBlockList` still uses `netip.ParsePrefix`.)

- [ ] **Step 5: Use `KeyAddr` in whitelist**

In `internal/store/whitelist.go`, add the `netutil` import and change the top of `Contains` from:

```go
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
```

to:

```go
	addr, ok := netutil.KeyAddr(ip)
	if !ok {
		return false
	}
```

(The rest of `Contains` — entry address/prefix comparison — is unchanged.)

- [ ] **Step 6: Accept CIDR keys in the blocklist API**

In `internal/api/handler_blocklist.go` (~line 134), change the filter so CIDR keys pass validation:

```go
		if _, ok := netutil.KeyAddr(ip); !ok {
			return nil
		}
```

Add the `netutil` import; drop `netip` from this file's imports if it becomes unused (verify with `go build`).

- [ ] **Step 7: Run the tests + build**

Run: `go test ./internal/netutil/ ./internal/enforce/ ./internal/store/ ./internal/api/ && go build ./...`
Expected: PASS; build clean.

- [ ] **Step 8: Commit**

```bash
gofmt -w internal/netutil/netutil.go internal/netutil/netutil_test.go internal/enforce/neverblock.go internal/enforce/neverblock_test.go internal/store/whitelist.go internal/api/handler_blocklist.go
git add internal/netutil/ internal/enforce/neverblock.go internal/enforce/neverblock_test.go internal/store/whitelist.go internal/api/handler_blocklist.go
git commit -m "feat: accept IPv6 CIDR reputation keys in never-block/whitelist/API"
```

---

### Task 6: Node wiring — activate IPv6 normalization

This flips the behaviour: both event paths now key IPv6 per prefix. Lands after all consumers handle CIDR keys.

**Files:**
- Modify: `internal/node/node.go` (`processLocal`, `ProcessRemote`)
- Test: `test/adversarial/injection_test.go` (extend) — aggregation + CIDR-injection regression

**Interfaces:**
- Consumes: `netutil.NormalizeIP(s string, ipv6Prefix int) (string, error)` (Task 2); `config.ReputationConfig.EffectiveIPv6Prefix() int` (Task 1); existing `node.New`, `ProcessRemote`, `GetScore`, `newInjectionNode`/`newNodeWithRules` helpers.

- [ ] **Step 1: Write the failing adversarial test**

Add to `test/adversarial/injection_test.go`:

```go
// TestIPv6AddressesAggregatePer64: two different /128s in the same /64 collapse
// to one reputation key; a /128 in a different /64 stays separate.
func TestIPv6AddressesAggregatePer64(t *testing.T) {
	n, _, _ := newNodeWithRules(t, injectionRules)
	send := func(ip string) {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: ip, Reason: "ssh-probe", ReporterID: "stranger-peer"},
			From:  "stranger-peer",
		})
	}
	send("2001:db8:1:2:aaaa::1")
	send("2001:db8:1:2:ffff::9") // same /64
	send("2001:db8:1:3::1")      // different /64

	rec64, _ := n.GetScore("2001:db8:1:2::/64")
	if rec64.LastSeen.IsZero() {
		t.Fatal("expected an aggregated record under the /64 key")
	}
	if len(rec64.ReporterIDs) == 0 || rec64.Score <= 0 {
		t.Errorf("aggregated /64 record looks empty: %+v", rec64)
	}
	// The raw /128s must NOT be separate keys.
	if r, _ := n.GetScore("2001:db8:1:2:aaaa::1"); !r.LastSeen.IsZero() {
		t.Error("raw /128 must not be recorded as its own key")
	}
	// A different /64 is a distinct key.
	if r, _ := n.GetScore("2001:db8:1:3::/64"); r.LastSeen.IsZero() {
		t.Error("a /128 in another /64 should score under that /64 key")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test -tags adversarial ./test/adversarial/ -run TestIPv6AddressesAggregatePer64 -v`
Expected: FAIL — the raw `/128`s are recorded as separate keys; the `/64` key is empty.

- [ ] **Step 3: Wire `NormalizeIP` into both node paths**

In `internal/node/node.go`, add the import `"github.com/JoeRu/federloom/internal/netutil"`. In `processLocal` replace:

```go
	addr, err := netip.ParseAddr(e.IP)
	if err != nil {
		log.Printf("node: drop event with invalid IP %q", e.IP)
		return
	}
	e.IP = addr.Unmap().String()
```

with:

```go
	key, err := netutil.NormalizeIP(e.IP, n.cfg.Reputation.EffectiveIPv6Prefix())
	if err != nil {
		log.Printf("node: drop event with invalid IP %q: %v", e.IP, err)
		return
	}
	e.IP = key
```

Apply the identical replacement in `ProcessRemote` (the second occurrence, ~line 328-333). If `netip` becomes unused in `node.go`, drop it from the imports (verify with `go build`).

- [ ] **Step 4: Run the aggregation test + CIDR-injection regression**

Run: `go test -tags adversarial ./test/adversarial/ -run 'TestIPv6AddressesAggregatePer64|TestCIDRInjectionNeverRecorded' -v`
Expected: both PASS — IPv6 aggregates per `/64`; `0.0.0.0/0` is still rejected and never recorded (NormalizeIP rejects IPv4-in-CIDR).

- [ ] **Step 5: Run the full adversarial + node suites (regression)**

Run: `go test -tags adversarial ./test/adversarial/... && go test ./internal/node/...`
Expected: PASS — all batch A+B and stranger-block tests still green (IPv4 events unaffected).

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/node/node.go test/adversarial/injection_test.go
git add internal/node/node.go test/adversarial/injection_test.go
git commit -m "feat(node): normalize IPv6 events to the configured /64 prefix key"
```

---

### Task 7: Final verification + docs

**Files:**
- Modify: `docs/config.md` (document `reputation.ipv6_prefix`)
- Modify: `docs/spec.md` (§12a traceability: IPv6 `/64` → DONE)

- [ ] **Step 1: Document the config knob**

In `docs/config.md`, under the reputation config section, add:

```markdown
### `reputation.ipv6_prefix`

IPv6 reputation and enforcement granularity (default `64`). IPv6 addresses are
normalized to this prefix, so an attacker's whole allocation aggregates to one
reputation entry and blocks as one firewall range. Use `56` for router-sized
allocations. IPv4 is always keyed per single address. Valid range `1`–`128`;
out-of-range values fall back to `64`.
```

- [ ] **Step 2: Update the spec traceability table**

In `docs/spec.md`, §12a table, change the IPv6 row status from `PLANNED (C)` to `DONE`:

```markdown
| §7.1 | IPv6 `/64` prefix normalization | `internal/netutil`, `internal/node`, `internal/enforce` | DONE |
```

- [ ] **Step 3: Full build, vet, format, suites**

Run: `go build ./... && go vet ./... && gofmt -l internal/ pkg/ cmd/ test/ && go test ./... && go test -tags adversarial ./test/adversarial/...`
Expected: builds; vet clean; `gofmt -l` prints nothing; all unit + adversarial tests PASS.

- [ ] **Step 4: Confirm acceptance explicitly**

Run: `go test ./internal/netutil/ -v && go test -tags adversarial ./test/adversarial/ -run 'IPv6AddressesAggregatePer64|CIDRInjectionNeverRecorded' -v`
Expected: `NormalizeIP`/`KeyAddr` PASS; `TestIPv6AddressesAggregatePer64` PASS (two `/128`s in one `/64` aggregate); `TestCIDRInjectionNeverRecorded` PASS (IPv4 CIDR still dropped).

- [ ] **Step 5: Commit**

```bash
git add docs/config.md docs/spec.md
git commit -m "docs: document reputation.ipv6_prefix; mark IPv6 /64 normalization DONE"
```
