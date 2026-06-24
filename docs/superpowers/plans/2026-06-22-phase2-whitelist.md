# Phase 2 — Install Script + Local Whitelist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the local-only whitelist store, wire it into the node's scoring path, expose it through `federloomctl whitelist`, and complete the install script so it persists detected local-truth entries.

**Architecture:** A JSON-backed `WhitelistStore` lives in `internal/store/whitelist.go` — same package as `BadgerStore`, separate file. The store is loaded once at node startup (no hot-reload in this phase; YAGNI). Both `processLocal` and `ProcessRemote` in `node.go` check the whitelist immediately after the `neverblock` check — a whitelisted IP is silently dropped regardless of who reported it. `federloomctl whitelist add/remove/list` manipulates the JSON file on disk; `federloomd` must be restarted to pick up changes. `install.sh`'s dead TODO becomes a real loop that calls `federloomctl whitelist add --scope local-only`.

**Tech Stack:** Go 1.25, standard library (`encoding/json`, `net`, `os`, `sync`), bash (install.sh).

## Global Constraints

- Module: `github.com/JoeRu/federloom`, Go 1.25
- `proto.WhitelistEntry` is already defined in `pkg/proto/messages.go`: `{IPOrRange string, Scope string, Source string}`
- Valid `Scope` values: `"local-only"` | `"shared-vote"`
- Valid `Source` values: `"install-script"` | `"manual"` | `"federation"`
- Spec invariant 3 (CLAUDE.md): local-only entries must **never** be federated — whitelist check suppresses scoring only; no whitelist data is ever published to gossipsub
- Spec Leitprinzip 7: all whitelist behaviour is operator-overridable
- Conventional Commits + SemVer: `feat:`, `fix:`, `test:`, `chore:`
- Never commit secrets or filled-in config files

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `internal/store/whitelist.go` | `WhitelistStore` — JSON persistence, `Contains`, `Add`, `Remove`, `List` |
| Create | `internal/store/whitelist_test.go` | Unit tests for `WhitelistStore` |
| Modify | `internal/config/config.go` | Add `(*Config).WhitelistFile() string` helper |
| Modify | `internal/node/node.go` | Add `whitelist *store.WhitelistStore` field; load in `New()`; check in `processLocal` + `ProcessRemote` |
| Modify | `internal/node/node_test.go` | Test whitelist suppression via `ProcessRemote` |
| Create | `cmd/federloomctl/whitelist.go` | `cmdWhitelist`, `whitelistAdd`, `whitelistRemove`, `whitelistList` |
| Modify | `cmd/federloomctl/main.go` | Add `"whitelist"` case; update usage string |
| Modify | `scripts/install/install.sh` | Replace TODO with real `federloomctl whitelist add` loop |

---

## Task 1: WhitelistStore

**Files:**
- Create: `internal/store/whitelist.go`
- Create: `internal/store/whitelist_test.go`

**Interfaces:**
- Consumes: `pkg/proto.WhitelistEntry` (existing)
- Produces:
  - `store.LoadWhitelist(path string) (*WhitelistStore, error)` — missing file → empty store, not error
  - `(*WhitelistStore).Contains(ip string) bool` — CIDR containment + exact IP match
  - `(*WhitelistStore).Add(entry proto.WhitelistEntry) error` — idempotent on `IPOrRange`
  - `(*WhitelistStore).Remove(ipOrRange string) error` — no-op if missing
  - `(*WhitelistStore).List() []proto.WhitelistEntry` — returns a copy

- [ ] **Step 1: Write the failing tests**

Create `internal/store/whitelist_test.go`:

```go
package store_test

import (
	"path/filepath"
	"testing"

	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

func TestLoadWhitelist_MissingFile(t *testing.T) {
	wl, err := store.LoadWhitelist("/nonexistent/whitelist.json")
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if len(wl.List()) != 0 {
		t.Errorf("expected empty list, got %d entries", len(wl.List()))
	}
}

func TestWhitelistContains_CIDR(t *testing.T) {
	dir := t.TempDir()
	wl, err := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	if err := wl.Add(proto.WhitelistEntry{IPOrRange: "203.0.113.0/24", Scope: "local-only", Source: "manual"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if !wl.Contains("203.0.113.1") {
		t.Error("Contains should match IP inside CIDR")
	}
	if !wl.Contains("203.0.113.254") {
		t.Error("Contains should match last IP in CIDR")
	}
	if wl.Contains("203.0.114.1") {
		t.Error("Contains should not match IP outside CIDR")
	}
}

func TestWhitelistContains_ExactIP(t *testing.T) {
	dir := t.TempDir()
	wl, _ := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	_ = wl.Add(proto.WhitelistEntry{IPOrRange: "192.168.1.5", Scope: "local-only", Source: "manual"})

	if !wl.Contains("192.168.1.5") {
		t.Error("exact IP should match")
	}
	if wl.Contains("192.168.1.6") {
		t.Error("different IP should not match")
	}
}

func TestWhitelistAdd_Idempotent(t *testing.T) {
	dir := t.TempDir()
	wl, _ := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))

	e := proto.WhitelistEntry{IPOrRange: "1.2.3.4", Scope: "local-only", Source: "manual"}
	_ = wl.Add(e)
	_ = wl.Add(e)

	if len(wl.List()) != 1 {
		t.Errorf("second Add should be no-op: got %d entries", len(wl.List()))
	}
}

func TestWhitelistRemove(t *testing.T) {
	dir := t.TempDir()
	wl, _ := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	_ = wl.Add(proto.WhitelistEntry{IPOrRange: "1.2.3.4", Scope: "local-only", Source: "manual"})
	_ = wl.Add(proto.WhitelistEntry{IPOrRange: "5.6.7.8", Scope: "local-only", Source: "manual"})

	if err := wl.Remove("1.2.3.4"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if wl.Contains("1.2.3.4") {
		t.Error("removed entry should not match")
	}
	if !wl.Contains("5.6.7.8") {
		t.Error("other entry should still match")
	}
}

func TestWhitelistRemove_Missing(t *testing.T) {
	dir := t.TempDir()
	wl, _ := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	// Remove on empty list must not error
	if err := wl.Remove("9.9.9.9"); err != nil {
		t.Errorf("Remove of missing entry should return nil, got: %v", err)
	}
}

func TestWhitelistPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.json")

	wl1, _ := store.LoadWhitelist(path)
	_ = wl1.Add(proto.WhitelistEntry{IPOrRange: "10.0.0.1", Scope: "local-only", Source: "manual"})

	wl2, err := store.LoadWhitelist(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !wl2.Contains("10.0.0.1") {
		t.Error("persisted entry must survive a reload")
	}
}

func TestWhitelistList_ReturnsCopy(t *testing.T) {
	dir := t.TempDir()
	wl, _ := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	_ = wl.Add(proto.WhitelistEntry{IPOrRange: "1.1.1.1", Scope: "local-only", Source: "manual"})

	list1 := wl.List()
	list1[0].IPOrRange = "9.9.9.9" // mutate the returned slice
	list2 := wl.List()
	if list2[0].IPOrRange != "1.1.1.1" {
		t.Error("List must return a copy, not a reference to internal state")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/store/... -run 'TestLoadWhitelist|TestWhitelist' -v 2>&1 | head -20
```

Expected: FAIL — `store.LoadWhitelist` undefined.

- [ ] **Step 3: Implement whitelist.go**

Create `internal/store/whitelist.go`:

```go
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/JoeRu/federloom/pkg/proto"
)

// WhitelistStore is the local operator-managed IP/CIDR allowlist (spec §6.2 / §7.4).
// Loaded once at node startup from a JSON file; call Add/Remove to mutate the file.
// federloomd reads the file at startup only — no hot-reload in this phase.
type WhitelistStore struct {
	path    string
	mu      sync.RWMutex
	entries []proto.WhitelistEntry
}

// LoadWhitelist opens path and loads the whitelist. A missing file returns an
// empty store without error — the file is created on the first Add call.
func LoadWhitelist(path string) (*WhitelistStore, error) {
	w := &WhitelistStore{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return w, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read whitelist %s: %w", path, err)
	}
	if len(data) == 0 {
		return w, nil
	}
	if err := json.Unmarshal(data, &w.entries); err != nil {
		return nil, fmt.Errorf("store: parse whitelist %s: %w", path, err)
	}
	return w, nil
}

// Contains returns true if ip is covered by any entry in the store.
// Handles both exact IP matches and CIDR containment. IPv4 and IPv6 are both supported.
func (w *WhitelistStore) Contains(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, entry := range w.entries {
		if entryIP := net.ParseIP(entry.IPOrRange); entryIP != nil {
			if entryIP.Equal(parsed) {
				return true
			}
			continue
		}
		if _, ipNet, err := net.ParseCIDR(entry.IPOrRange); err == nil {
			if ipNet.Contains(parsed) {
				return true
			}
		}
	}
	return false
}

// Add appends entry to the store. If an entry with the same IPOrRange already
// exists it is not duplicated (idempotent). Persists the updated list to disk.
func (w *WhitelistStore) Add(entry proto.WhitelistEntry) error {
	w.mu.Lock()
	for _, e := range w.entries {
		if e.IPOrRange == entry.IPOrRange {
			w.mu.Unlock()
			return nil
		}
	}
	w.entries = append(w.entries, entry)
	snap := make([]proto.WhitelistEntry, len(w.entries))
	copy(snap, w.entries)
	w.mu.Unlock()
	return whitelistSave(w.path, snap)
}

// Remove deletes the entry with IPOrRange equal to ipOrRange. If no such entry
// exists it returns nil — not an error. Persists the updated list to disk.
func (w *WhitelistStore) Remove(ipOrRange string) error {
	w.mu.Lock()
	filtered := w.entries[:0]
	for _, e := range w.entries {
		if e.IPOrRange != ipOrRange {
			filtered = append(filtered, e)
		}
	}
	w.entries = filtered
	snap := make([]proto.WhitelistEntry, len(w.entries))
	copy(snap, w.entries)
	w.mu.Unlock()
	return whitelistSave(w.path, snap)
}

// List returns a copy of all entries.
func (w *WhitelistStore) List() []proto.WhitelistEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]proto.WhitelistEntry, len(w.entries))
	copy(out, w.entries)
	return out
}

// whitelistSave marshals entries and atomically writes them to path.
func whitelistSave(path string, entries []proto.WhitelistEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal whitelist: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("store: write whitelist tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("store: rename whitelist: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/store/... -v
```

Expected: all tests pass (existing BadgerStore tests + 8 new whitelist tests).

- [ ] **Step 5: Commit**

```bash
git add internal/store/whitelist.go internal/store/whitelist_test.go
git commit -m "feat(store): WhitelistStore — JSON-backed local IP/CIDR allowlist (spec §6.2)"
```

---

## Task 2: Node Integration

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/node/node.go`
- Modify: `internal/node/node_test.go`

**Interfaces:**
- Consumes: `store.LoadWhitelist` + `(*store.WhitelistStore).Contains` (Task 1), `(*config.Config).WhitelistFile()` (this task)
- Produces:
  - `(*config.Config).WhitelistFile() string` — returns `filepath.Join(c.Store.Dir, "whitelist.json")`
  - `node.Node.whitelist *store.WhitelistStore` — checked in `processLocal` and `ProcessRemote`

- [ ] **Step 1: Write the failing test**

Add to `internal/node/node_test.go`:

```go
func TestProcessRemoteRespectsWhitelist(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir

	// Pre-populate whitelist before node creation (no hot-reload in this phase).
	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	if err := wl.Add(proto.WhitelistEntry{
		IPOrRange: "203.0.113.1",
		Scope:     "local-only",
		Source:    "manual",
	}); err != nil {
		t.Fatalf("whitelist Add: %v", err)
	}

	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	// Whitelisted IP: ProcessRemote must not score it.
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:         "203.0.113.1",
			Reason:     "ssh-probe",
			ReporterID: "12D3KooWtestpeer",
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ := n.GetScore("203.0.113.1")
	if !rec.LastSeen.IsZero() {
		t.Error("whitelisted IP should not be scored")
	}

	// Non-whitelisted IP in same /24: must be scored normally.
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:         "203.0.113.2",
			Reason:     "ssh-probe",
			ReporterID: "12D3KooWtestpeer",
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ = n.GetScore("203.0.113.2")
	if rec.LastSeen.IsZero() {
		t.Error("non-whitelisted IP should be scored normally")
	}
}

func TestProcessRemoteRespectsWhitelistCIDR(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir

	wl, _ := store.LoadWhitelist(cfg.WhitelistFile())
	_ = wl.Add(proto.WhitelistEntry{
		IPOrRange: "198.51.100.0/24",
		Scope:     "local-only",
		Source:    "install-script",
	})

	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:         "198.51.100.42",
			Reason:     "smtp-auth",
			ReporterID: "12D3KooWtestpeer",
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ := n.GetScore("198.51.100.42")
	if !rec.LastSeen.IsZero() {
		t.Error("IP in whitelisted CIDR must not be scored")
	}
}
```

Also add the import `"github.com/JoeRu/federloom/internal/store"` to `node_test.go`'s import block.

- [ ] **Step 2: Run the failing tests**

```bash
go test ./internal/node/... -run 'TestProcessRemoteRespectsWhitelist' -v 2>&1 | head -20
```

Expected: FAIL — `cfg.WhitelistFile()` undefined (or import error on `store`).

- [ ] **Step 3: Add WhitelistFile() to config.go**

In `internal/config/config.go`, add after `TrustBlockedPeersFile()`:

```go
// WhitelistFile returns the path of the operator local-only whitelist JSON file.
func (c *Config) WhitelistFile() string {
	return filepath.Join(c.Store.Dir, "whitelist.json")
}
```

- [ ] **Step 4: Run tests again — expect compile error on node package**

```bash
go test ./internal/node/... -run 'TestProcessRemoteRespectsWhitelist' -v 2>&1 | head -20
```

Expected: FAIL — `n.GetScore` exists but tests still fail because `node.Node` has no `whitelist` field yet.

- [ ] **Step 5: Wire whitelist into node.go**

In `internal/node/node.go`, add `whitelist *store.WhitelistStore` to the `Node` struct after `neverblock`:

```go
neverblock *enforce.NeverBlockList
whitelist  *store.WhitelistStore // local-only allowlist; never nil (may be empty)
```

In `New()`, after the `nbl` construction and before building the return struct, add:

```go
wl, err := store.LoadWhitelist(cfg.WhitelistFile())
if err != nil {
    _ = s.Close()
    return nil, fmt.Errorf("node: load whitelist: %w", err)
}
```

Update the `return &Node{...}` to include `whitelist: wl`.

In `processLocal`, immediately after the `n.neverblock.Contains(e.IP)` early-return, add:

```go
if n.whitelist.Contains(e.IP) {
    return
}
```

In `ProcessRemote`, immediately after the `n.neverblock.Contains(e.IP)` early-return (around line 333), add:

```go
if n.whitelist.Contains(e.IP) {
    return
}
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
go test ./internal/node/... -v
go test ./internal/config/... -v
```

Expected: all tests pass, including the two new whitelist tests.

- [ ] **Step 7: Full suite check**

```bash
make build
go test ./...
```

Expected: all packages pass, both binaries build.

- [ ] **Step 8: Commit**

```bash
git add internal/config/config.go internal/node/node.go internal/node/node_test.go
git commit -m "feat(node): wire WhitelistStore into processLocal + ProcessRemote (spec §6.2)"
```

---

## Task 3: federloomctl whitelist

**Files:**
- Create: `cmd/federloomctl/whitelist.go`
- Modify: `cmd/federloomctl/main.go`

**Interfaces:**
- Consumes: `store.LoadWhitelist`, `(*store.WhitelistStore).Add/Remove/List` (Task 1), `(*config.Config).WhitelistFile()` (Task 2), `addConfigFlag` (existing in `cmd/federloomctl/common.go`)
- Produces: CLI commands `federloomctl whitelist add|remove|list`

**Commands:**
```
federloomctl whitelist add [--scope local-only] [--source manual] IP_OR_CIDR
federloomctl whitelist remove IP_OR_CIDR
federloomctl whitelist list
```

- [ ] **Step 1: Write the failing test**

In `cmd/federloomctl/`, check for an existing test file:

```bash
ls cmd/federloomctl/*test* 2>/dev/null || echo "no tests"
```

Add to `cmd/federloomctl/setup_test.go` (or create `cmd/federloomctl/whitelist_test.go`):

```go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWhitelistAddRemoveList(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("store:\n  dir: "+dir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Add an entry
	if err := cmdWhitelist([]string{"add", "--config", cfgPath, "203.0.113.0/24"}); err != nil {
		t.Fatalf("whitelist add: %v", err)
	}

	// Adding same entry again must be idempotent (no error)
	if err := cmdWhitelist([]string{"add", "--config", cfgPath, "203.0.113.0/24"}); err != nil {
		t.Fatalf("whitelist add (duplicate): %v", err)
	}

	// Remove the entry
	if err := cmdWhitelist([]string{"remove", "--config", cfgPath, "203.0.113.0/24"}); err != nil {
		t.Fatalf("whitelist remove: %v", err)
	}

	// Removing again must not error
	if err := cmdWhitelist([]string{"remove", "--config", cfgPath, "203.0.113.0/24"}); err != nil {
		t.Fatalf("whitelist remove (missing): %v", err)
	}
}

func TestWhitelistAdd_InvalidIP(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(cfgPath, []byte("store:\n  dir: "+dir+"\n"), 0o644)

	err := cmdWhitelist([]string{"add", "--config", cfgPath, "not-an-ip"})
	if err == nil {
		t.Fatal("expected error for invalid IP/CIDR, got nil")
	}
}

func TestWhitelistAdd_InvalidScope(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(cfgPath, []byte("store:\n  dir: "+dir+"\n"), 0o644)

	err := cmdWhitelist([]string{"add", "--scope", "bad-scope", "--config", cfgPath, "1.2.3.4"})
	if err == nil {
		t.Fatal("expected error for invalid scope, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./cmd/federloomctl/... -run 'TestWhitelist' -v 2>&1 | head -20
```

Expected: FAIL — `cmdWhitelist` undefined.

- [ ] **Step 3: Implement whitelist.go**

Create `cmd/federloomctl/whitelist.go`:

```go
package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/pkg/proto"
)

func cmdWhitelist(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: federloomctl whitelist add|remove|list ...")
	}
	switch args[0] {
	case "add":
		return whitelistAdd(args[1:])
	case "remove":
		return whitelistRemove(args[1:])
	case "list":
		return whitelistList(args[1:])
	default:
		return fmt.Errorf("unknown whitelist subcommand %q; use add, remove, or list", args[0])
	}
}

func whitelistAdd(args []string) error {
	fs := flag.NewFlagSet("whitelist add", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	scope := fs.String("scope", "local-only", `scope: "local-only" or "shared-vote"`)
	source := fs.String("source", "manual", `source: "manual", "install-script", or "federation"`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: federloomctl whitelist add [--scope local-only] IP_OR_CIDR")
	}
	ipOrRange := fs.Arg(0)
	if net.ParseIP(ipOrRange) == nil {
		if _, _, err := net.ParseCIDR(ipOrRange); err != nil {
			return fmt.Errorf("invalid IP or CIDR %q: %w", ipOrRange, err)
		}
	}
	if *scope != "local-only" && *scope != "shared-vote" {
		return fmt.Errorf("scope must be \"local-only\" or \"shared-vote\"")
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		return fmt.Errorf("load whitelist: %w", err)
	}
	if err := wl.Add(proto.WhitelistEntry{
		IPOrRange: ipOrRange,
		Scope:     *scope,
		Source:    *source,
	}); err != nil {
		return fmt.Errorf("add to whitelist: %w", err)
	}
	fmt.Printf("added %s (scope: %s) — restart federloomd to activate\n", ipOrRange, *scope)
	return nil
}

func whitelistRemove(args []string) error {
	fs := flag.NewFlagSet("whitelist remove", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: federloomctl whitelist remove IP_OR_CIDR")
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		return fmt.Errorf("load whitelist: %w", err)
	}
	if err := wl.Remove(fs.Arg(0)); err != nil {
		return fmt.Errorf("remove from whitelist: %w", err)
	}
	fmt.Printf("removed %s — restart federloomd to activate\n", fs.Arg(0))
	return nil
}

func whitelistList(args []string) error {
	fs := flag.NewFlagSet("whitelist list", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		return fmt.Errorf("load whitelist: %w", err)
	}
	entries := wl.List()
	if len(entries) == 0 {
		fmt.Println("no whitelist entries — see `federloomctl whitelist add`")
		return nil
	}
	fmt.Printf("%-40s %-12s %s\n", "IP/CIDR", "SCOPE", "SOURCE")
	for _, e := range entries {
		fmt.Printf("%-40s %-12s %s\n", e.IPOrRange, e.Scope, e.Source)
	}
	return nil
}
```

- [ ] **Step 4: Update main.go**

In `cmd/federloomctl/main.go`, add to the `switch` statement before `case "-h"`:

```go
case "whitelist":
    err = cmdWhitelist(os.Args[2:])
```

Update the `usage()` function string — add these lines after `federloomctl trust unblock PEER_ID`:

```
  federloomctl whitelist add [--scope local-only] [--source manual] IP_OR_CIDR
  federloomctl whitelist remove IP_OR_CIDR
  federloomctl whitelist list
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./cmd/federloomctl/... -run 'TestWhitelist' -v
```

Expected: all 3 whitelist tests pass.

- [ ] **Step 6: Full build and test**

```bash
make build
go test ./...
```

Expected: all packages pass, both binaries build.

- [ ] **Step 7: Smoke-test the binary**

```bash
dir=$(mktemp -d)
./bin/federloomctl whitelist add --config /dev/null "203.0.113.0/24" 2>&1 || true
# With a temp config:
cat > "$dir/config.yaml" << 'EOF'
store:
  dir: /tmp/sg-whitelist-smoke
EOF
mkdir -p /tmp/sg-whitelist-smoke
./bin/federloomctl whitelist add --config "$dir/config.yaml" "10.10.10.0/24"
./bin/federloomctl whitelist list --config "$dir/config.yaml"
./bin/federloomctl whitelist remove --config "$dir/config.yaml" "10.10.10.0/24"
./bin/federloomctl whitelist list --config "$dir/config.yaml"
rm -rf /tmp/sg-whitelist-smoke "$dir"
```

Expected output:
```
added 10.10.10.0/24 (scope: local-only) — restart federloomd to activate
IP/CIDR                                  SCOPE        SOURCE
10.10.10.0/24                            local-only   manual
removed 10.10.10.0/24 — restart federloomd to activate
no whitelist entries — see `federloomctl whitelist add`
```

- [ ] **Step 8: Commit**

```bash
git add cmd/federloomctl/whitelist.go cmd/federloomctl/main.go
git commit -m "feat(federloomctl): whitelist add/remove/list subcommand (spec §6.2)"
```

---

## Task 4: Complete install.sh

**Files:**
- Modify: `scripts/install/install.sh`

**Interfaces:**
- Consumes: `federloomctl whitelist add --scope local-only --source install-script` (Task 3, from PATH)
- Produces: install.sh with a working loop that persists detected local-truth entries

**Background:** `detect_local_truth.sh` outputs commentary headers (lines beginning with `#`) and actual IP/CIDR entries mixed together. The fix captures its output, prints it for review, then on operator confirmation filters to IP/CIDR lines and calls `federloomctl whitelist add` for each.

Line-by-line plan for the replacement:
1. Capture the full output of `detect_local_truth.sh` in a variable (so we can both print it and iterate over it without running the script twice)
2. Print the captured output for the operator to review
3. On `y|Y`: check `federloomctl` is in PATH; iterate over lines; skip blank lines and lines starting with `#` or `NOTE:`; call `federloomctl whitelist add` for each remaining line; count successes; report

- [ ] **Step 1: Read the current install.sh**

The current `scripts/install/install.sh` is:

```bash
#!/usr/bin/env bash
# FederLoom installer (scaffold). Seeds the local-only whitelist after explicit
# operator confirmation, then points at config. Conservative by design (spec §6.2).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== FederLoom install (scaffold) =="
echo "Step 1: detect local truth for the local-only whitelist"
"$HERE/detect_local_truth.sh"

echo
read -r -p "Write the confirmed entries to the local-only whitelist? [y/N] " ans
case "${ans:-N}" in
  y|Y) echo "TODO: persist confirmed entries via 'federloomctl whitelist add --scope local-only'";;
  *)   echo "Aborted — nothing written.";;
esac
echo "Next: edit config.yaml (see deploy/examples/) and start the daemon."
```

- [ ] **Step 2: Write the updated install.sh**

Replace the file content with:

```bash
#!/usr/bin/env bash
# FederLoom installer. Seeds the local-only whitelist after explicit operator
# confirmation (spec §6.2). Conservative by design: when in doubt, do NOT add.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== FederLoom install =="
echo "Step 1: detect local truth for the local-only whitelist"
echo

# Capture once so we can print for review AND iterate without re-running the script.
detected=$("$HERE/detect_local_truth.sh")
echo "$detected"
echo

read -r -p "Write the confirmed entries to the local-only whitelist? [y/N] " ans
case "${ans:-N}" in
  y|Y)
    if ! command -v federloomctl >/dev/null 2>&1; then
      echo "error: federloomctl not found in PATH — build and install it first:" >&2
      echo "  make build && cp bin/federloomctl /usr/local/bin/" >&2
      exit 1
    fi
    count=0
    while IFS= read -r line; do
      # Skip blank lines, comment/header lines (start with #), and NOTE: lines.
      [[ -z "$line" || "$line" == \#* || "$line" == NOTE:* ]] && continue
      if federloomctl whitelist add --scope local-only --source install-script "$line" 2>/dev/null; then
        count=$((count + 1))
      else
        printf "  warning: skipped %s (not a valid IP/CIDR)\n" "$line" >&2
      fi
    done <<< "$detected"
    echo "wrote $count entries to local-only whitelist"
    ;;
  *)
    echo "Aborted — nothing written."
    ;;
esac
echo "Next: edit config.yaml (see deploy/examples/) and start the daemon."
```

- [ ] **Step 3: Verify the script is syntactically valid**

```bash
bash -n scripts/install/install.sh && echo "syntax OK"
```

Expected: `syntax OK`

- [ ] **Step 4: Smoke-test the TODO replacement**

Verify the TODO line is gone and the correct pattern is in place:

```bash
grep -c "TODO" scripts/install/install.sh
```

Expected: `0` (grep exits with 1 since there are no matches — `grep -c` returns the count, so check the output is `0`, not the exit code)

```bash
grep "federloomctl whitelist add" scripts/install/install.sh
```

Expected: output contains `federloomctl whitelist add --scope local-only --source install-script "$line"`

- [ ] **Step 5: Build and run full tests**

```bash
make build
go test ./...
```

Expected: all tests pass (shell changes don't affect Go tests).

- [ ] **Step 6: Commit**

```bash
git add scripts/install/install.sh
git commit -m "feat(install): complete whitelist seeding — replace TODO with federloomctl loop (spec §6.2)"
```

---

## Self-Review

**Spec coverage check:**

| Requirement | Task |
|---|---|
| `WhitelistStore` — JSON-backed, human-readable | Task 1 |
| `Contains(ip string) bool` — CIDR + exact | Task 1 |
| `Add(entry proto.WhitelistEntry) error` — idempotent | Task 1 |
| `Remove(ipOrRange string) error` — no-op if missing | Task 1 |
| `List() []proto.WhitelistEntry` — copy | Task 1 |
| `(*Config).WhitelistFile() string` | Task 2 |
| Wire into `processLocal` (local ingest) | Task 2 |
| Wire into `ProcessRemote` (remote ingest) | Task 2 |
| Invariant 3: local-only never federated — whitelist not published | Task 2 (check suppresses scoring; no publish path added) |
| `federloomctl whitelist add --scope local-only CIDR_OR_IP` | Task 3 |
| `federloomctl whitelist add --scope shared-vote CIDR_OR_IP` | Task 3 |
| `federloomctl whitelist remove CIDR_OR_IP` | Task 3 |
| `federloomctl whitelist list` | Task 3 |
| Input validation: reject non-IP/non-CIDR | Task 3 |
| Input validation: reject invalid scope | Task 3 |
| `install.sh` TODO replaced with real federloomctl calls | Task 4 |
| `install.sh` sets `source: install-script` | Task 4 |
| `install.sh` checks federloomctl is in PATH before proceeding | Task 4 |

**Placeholder scan:** No TBDs. All code blocks are complete.

**Type consistency check:**
- `store.LoadWhitelist(path string) (*WhitelistStore, error)` — used in Task 2 (`store.LoadWhitelist(cfg.WhitelistFile())`) and Task 3 (`store.LoadWhitelist(cfg.WhitelistFile())`) ✅
- `(*WhitelistStore).Contains(ip string) bool` — used in `processLocal` and `ProcessRemote` with `n.whitelist.Contains(e.IP)` ✅
- `cfg.WhitelistFile()` returns `string` — passed directly to `store.LoadWhitelist` ✅
- `proto.WhitelistEntry{IPOrRange, Scope, Source}` — all three fields set in both `whitelistAdd` and in the test fixtures ✅
