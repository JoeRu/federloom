# Fail2Ban Ingest Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `internal/ingest/fail2ban.go` — a Docker-native ingest source that polls `fail2ban-client banned`, diffs against prior state to detect new bans, maps jail names to reason codes, and emits `proto.Event`s.

**Architecture:** Injectable fetcher pattern (identical to `mailcow_logs`): `NewFail2BanWithFetcher` accepts a stub for tests; `NewFail2Ban` uses `docker exec <container> fail2ban-client banned`. Poll loop diffs an in-memory `seen` set; no persistence needed. Reason mapping uses exact then prefix built-in defaults, with per-operator overrides in `config.yaml`.

**Tech Stack:** Go stdlib (`os/exec`, `encoding/json`, `strings`), `internal/config`, `pkg/proto`.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `internal/config/config.go` | Modify | Add `Fail2BanConfig` struct, field in `IngestConfig`, defaults in `Defaults()` |
| `internal/ingest/fail2ban.go` | Create | Adapter: fetcher, reason mapping, poll/diff loop, `proto.Event` emission |
| `internal/ingest/fail2ban_test.go` | Create | 4 unit tests with stub fetcher |
| `internal/node/node.go` | Modify | Wire `Fail2Ban` into the source-construction block |

---

## Task 1: Config — `Fail2BanConfig`

**Files:**
- Modify: `internal/config/config.go`

- [ ] **Step 1: Write the failing config test**

Add to `internal/config/config_test.go` inside `TestDefaultsAreValid`:

```go
func TestFail2BanDefaults(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Ingest.Fail2Ban.Container != "fail2ban" {
		t.Errorf("fail2ban container default: got %q, want \"fail2ban\"", cfg.Ingest.Fail2Ban.Container)
	}
	if cfg.Ingest.Fail2Ban.PollInterval.Duration != 30*time.Second {
		t.Errorf("fail2ban poll_interval default: got %v, want 30s", cfg.Ingest.Fail2Ban.PollInterval.Duration)
	}
	if cfg.Ingest.Fail2Ban.Enabled {
		t.Error("fail2ban must default to disabled")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/config/... -run TestFail2BanDefaults -v
```

Expected: `FAIL` — `cfg.Ingest.Fail2Ban` does not exist yet.

- [ ] **Step 3: Add `Fail2BanConfig` struct**

In `internal/config/config.go`, after the `SpamtrapConfig` struct (after line ~129), add:

```go
// Fail2BanConfig configures the fail2ban Docker ingest adapter.
// The adapter polls `docker exec <container> fail2ban-client banned` on each tick.
type Fail2BanConfig struct {
	Enabled      bool              `yaml:"enabled"`
	Container    string            `yaml:"container"`     // default: "fail2ban"
	PollInterval Duration          `yaml:"poll_interval"` // default: 30s
	JailReasons  map[string]string `yaml:"jail_reasons"`  // operator overrides (exact match only)
}
```

- [ ] **Step 4: Add field to `IngestConfig`**

In `internal/config/config.go`, in the `IngestConfig` struct (around line 77), add after the `Spamtrap` field:

```go
Fail2Ban     Fail2BanConfig   `yaml:"fail2ban"`
```

So `IngestConfig` reads:

```go
type IngestConfig struct {
	Honeypot    HoneypotConfig   `yaml:"honeypot"`
	OpenCanary  OpenCanaryConfig `yaml:"opencanary"`
	CrowdSec    CrowdSecConfig   `yaml:"crowdsec"`
	MailcowLogs MailcowConfig    `yaml:"mailcow_logs"`
	Spamtrap    SpamtrapConfig   `yaml:"spamtrap"`
	Fail2Ban    Fail2BanConfig   `yaml:"fail2ban"`
}
```

- [ ] **Step 5: Add defaults**

In `internal/config/config.go`, inside `Defaults()`, after the `Spamtrap` block (around line 212), add:

```go
Fail2Ban: Fail2BanConfig{
    Container:    "fail2ban",
    PollInterval: Duration{30 * time.Second},
    // Enabled: false (zero value — opt-in, same pattern as all adapters)
},
```

- [ ] **Step 6: Run test to verify it passes**

```bash
go test ./internal/config/... -run TestFail2BanDefaults -v
```

Expected: `PASS`.

- [ ] **Step 7: Verify full config suite still passes**

```bash
go test ./internal/config/... -v
```

Expected: all tests `PASS`.

- [ ] **Step 8: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add Fail2BanConfig for fail2ban ingest adapter"
```

---

## Task 2: Adapter — `internal/ingest/fail2ban.go`

**Files:**
- Create: `internal/ingest/fail2ban.go`
- Create: `internal/ingest/fail2ban_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/ingest/fail2ban_test.go`:

```go
package ingest_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/ingest"
)

func makeFail2BanCfg(poll time.Duration) config.Fail2BanConfig {
	return config.Fail2BanConfig{
		Enabled:      true,
		Container:    "test-fail2ban",
		PollInterval: config.Duration{Duration: poll},
	}
}

// TestFail2Ban_NewBan: a newly-banned IP emits one event with the correct reason.
func TestFail2Ban_NewBan(t *testing.T) {
	stub := func(_ context.Context, _ string) ([]byte, error) {
		return []byte(`[{"sshd": ["1.2.3.4"]}]`), nil
	}
	f := ingest.NewFail2BanWithFetcher(makeFail2BanCfg(50*time.Millisecond), "selfpeer", stub)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := f.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case e := <-ch:
		if e.IP != "1.2.3.4" {
			t.Errorf("IP: got %q, want 1.2.3.4", e.IP)
		}
		if e.Reason != "ssh-auth-bruteforce" {
			t.Errorf("Reason: got %q, want ssh-auth-bruteforce", e.Reason)
		}
		if e.ReporterID != "selfpeer" {
			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
		}
		if e.Timestamp.IsZero() {
			t.Error("Timestamp must not be zero")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

// TestFail2Ban_NoDuplicate: same IP present on every poll → only one event ever.
func TestFail2Ban_NoDuplicate(t *testing.T) {
	stub := func(_ context.Context, _ string) ([]byte, error) {
		return []byte(`[{"sshd": ["1.2.3.4"]}]`), nil
	}
	f := ingest.NewFail2BanWithFetcher(makeFail2BanCfg(50*time.Millisecond), "selfpeer", stub)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := f.Start(ctx)

	// Drain the first event.
	select {
	case <-ch:
	case <-ctx.Done():
		t.Fatal("timed out waiting for first event")
	}

	// Allow 3 more poll cycles; no second event should arrive.
	select {
	case e := <-ch:
		t.Errorf("unexpected duplicate event: IP=%s Reason=%s", e.IP, e.Reason)
	case <-time.After(200 * time.Millisecond):
		// correct — no duplicate
	}
}

// TestFail2Ban_Reban: IP unbanned then re-banned → event emitted again.
func TestFail2Ban_Reban(t *testing.T) {
	var mu sync.Mutex
	callN := 0
	stub := func(_ context.Context, _ string) ([]byte, error) {
		mu.Lock()
		n := callN
		callN++
		mu.Unlock()
		switch n {
		case 0:
			return []byte(`[{"sshd": ["1.2.3.4"]}]`), nil // banned
		case 1:
			return []byte(`[]`), nil // unbanned
		default:
			return []byte(`[{"sshd": ["1.2.3.4"]}]`), nil // re-banned
		}
	}
	f := ingest.NewFail2BanWithFetcher(makeFail2BanCfg(50*time.Millisecond), "selfpeer", stub)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := f.Start(ctx)

	// First ban event.
	select {
	case e := <-ch:
		if e.IP != "1.2.3.4" {
			t.Errorf("first ban: IP got %q, want 1.2.3.4", e.IP)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for first ban event")
	}

	// Re-ban event after unban cycle.
	select {
	case e := <-ch:
		if e.IP != "1.2.3.4" {
			t.Errorf("re-ban: IP got %q, want 1.2.3.4", e.IP)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for re-ban event")
	}
}

// TestFail2Ban_UnknownJail: unknown jail → reason is "fail2ban-<jailname>".
func TestFail2Ban_UnknownJail(t *testing.T) {
	stub := func(_ context.Context, _ string) ([]byte, error) {
		return []byte(`[{"my-custom-jail": ["2.2.2.2"]}]`), nil
	}
	f := ingest.NewFail2BanWithFetcher(makeFail2BanCfg(50*time.Millisecond), "selfpeer", stub)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := f.Start(ctx)

	select {
	case e := <-ch:
		if e.Reason != "fail2ban-my-custom-jail" {
			t.Errorf("Reason: got %q, want fail2ban-my-custom-jail", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/ingest/... -run "TestFail2Ban" -v
```

Expected: `FAIL` — `ingest.NewFail2BanWithFetcher` does not exist yet.

- [ ] **Step 3: Create the adapter**

Create `internal/ingest/fail2ban.go`:

```go
package ingest

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// fail2banFetcher retrieves the current ban set from a fail2ban container.
// Injectable so tests run without a Docker daemon.
type fail2banFetcher func(ctx context.Context, container string) ([]byte, error)

// dockerBanned is the production fetcher: runs `docker exec <container> fail2ban-client banned`.
func dockerBanned(ctx context.Context, container string) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", "exec", container, "fail2ban-client", "banned").Output()
}

// builtinJailReasons maps common fail2ban jail names (exact) to SwarmGuard reason strings.
var builtinJailReasons = map[string]string{
	"sshd":             "ssh-auth-bruteforce",
	"ssh":              "ssh-auth-bruteforce",
	"postfix":          "smtp-auth-bruteforce",
	"postfix-sasl":     "smtp-auth-bruteforce",
	"dovecot":          "imap-auth-bruteforce",
	"nginx-http-auth":  "http-auth-bruteforce",
	"apache-auth":      "http-auth-bruteforce",
	"wordpress":        "http-wp-bruteforce",
	"recidive":         "recidive",
}

// builtinJailPrefixes maps jail name prefixes to reason strings.
// Checked in order after exact matches; first match wins.
var builtinJailPrefixes = []struct{ prefix, reason string }{
	{"sshd-",    "ssh-auth-bruteforce"},
	{"postfix-", "smtp-auth-bruteforce"},
	{"dovecot-", "imap-auth-bruteforce"},
	{"nginx-",   "http-auth-bruteforce"},
	{"apache-",  "http-auth-bruteforce"},
	{"wp-",      "http-wp-bruteforce"},
}

// Fail2Ban polls a fail2ban Docker container for banned IPs and emits proto.Events.
type Fail2Ban struct {
	cfg     config.Fail2BanConfig
	selfID  string
	fetcher fail2banFetcher
}

// Compile-time check: Fail2Ban must implement Source.
var _ Source = (*Fail2Ban)(nil)

// NewFail2Ban creates a Fail2Ban adapter using the real Docker fetcher.
func NewFail2Ban(cfg config.Fail2BanConfig, selfID string) *Fail2Ban {
	return NewFail2BanWithFetcher(cfg, selfID, dockerBanned)
}

// NewFail2BanWithFetcher creates a Fail2Ban adapter with a custom fetcher.
// Use this in tests to inject a stub without a running Docker daemon.
func NewFail2BanWithFetcher(cfg config.Fail2BanConfig, selfID string, f fail2banFetcher) *Fail2Ban {
	if cfg.Container == "" {
		cfg.Container = "fail2ban"
	}
	return &Fail2Ban{cfg: cfg, selfID: selfID, fetcher: f}
}

func (f *Fail2Ban) Name() string { return "fail2ban" }

// Start launches the polling goroutine and returns the event channel.
func (f *Fail2Ban) Start(ctx context.Context) (<-chan proto.Event, error) {
	ch := make(chan proto.Event, 64)
	go f.run(ctx, ch)
	return ch, nil
}

func (f *Fail2Ban) run(ctx context.Context, ch chan<- proto.Event) {
	defer close(ch)

	pollInterval := f.cfg.PollInterval.Duration
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}

	seen := make(map[string]struct{})

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.poll(ctx, seen, ch)
		}
	}
}

func (f *Fail2Ban) poll(ctx context.Context, seen map[string]struct{}, ch chan<- proto.Event) {
	data, err := f.fetcher(ctx, f.cfg.Container)
	if err != nil {
		log.Printf("fail2ban: fetch banned: %v", err)
		return
	}

	current, err := parseBanned(data)
	if err != nil {
		log.Printf("fail2ban: parse banned: %v", err)
		return
	}

	// Emit events for newly-banned IPs.
	for ip, jail := range current {
		if _, alreadySeen := seen[ip]; alreadySeen {
			continue
		}
		select {
		case ch <- proto.Event{
			IP:         ip,
			Reason:     f.resolveReason(jail),
			Timestamp:  time.Now(),
			ReporterID: f.selfID,
		}:
		case <-ctx.Done():
			return
		}
		seen[ip] = struct{}{}
	}

	// Prune IPs that are no longer banned so a re-ban triggers a new event.
	for ip := range seen {
		if _, stillBanned := current[ip]; !stillBanned {
			delete(seen, ip)
		}
	}
}

// resolveReason maps a fail2ban jail name to a SwarmGuard reason string.
// Resolution order: operator config override → exact built-in → prefix built-in → fallback.
func (f *Fail2Ban) resolveReason(jail string) string {
	if r, ok := f.cfg.JailReasons[jail]; ok {
		return r
	}
	if r, ok := builtinJailReasons[jail]; ok {
		return r
	}
	for _, p := range builtinJailPrefixes {
		if strings.HasPrefix(jail, p.prefix) {
			return p.reason
		}
	}
	return "fail2ban-" + jail
}

// parseBanned parses the JSON output of `fail2ban-client banned`.
// Format: [{"jail1": ["ip1", "ip2"]}, {"jail2": ["ip3"]}]
// Returns a map of IP → jail name.
func parseBanned(data []byte) (map[string]string, error) {
	var raw []map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	result := make(map[string]string, len(raw))
	for _, jailMap := range raw {
		for jail, ips := range jailMap {
			for _, ip := range ips {
				result[ip] = jail
			}
		}
	}
	return result, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/ingest/... -run "TestFail2Ban" -v
```

Expected: all four `TestFail2Ban_*` tests `PASS`.

- [ ] **Step 5: Run full ingest suite to check no regressions**

```bash
go test ./internal/ingest/... -v
```

Expected: all tests `PASS`.

- [ ] **Step 6: Commit**

```bash
git add internal/ingest/fail2ban.go internal/ingest/fail2ban_test.go
git commit -m "feat(ingest): add fail2ban Docker ingest adapter"
```

---

## Task 3: Wire into node

**Files:**
- Modify: `internal/node/node.go`

- [ ] **Step 1: Add the source to the construction block**

In `internal/node/node.go`, find the source-construction block (the sequence of `if cfg.Ingest.X.Enabled { sources = append(...) }` blocks, ending after the `Spamtrap` block around line 108). Add immediately after the `Spamtrap` block:

```go
if cfg.Ingest.Fail2Ban.Enabled {
    sources = append(sources, ingest.NewFail2Ban(cfg.Ingest.Fail2Ban, selfID))
}
```

The full block then reads:

```go
var sources []ingest.Source
if cfg.Ingest.Honeypot.Enabled {
    sources = append(sources, ingest.NewHoneypot(cfg.Ingest.Honeypot, selfID))
}
if cfg.Ingest.OpenCanary.Enabled {
    sources = append(sources, ingest.NewOpenCanary(cfg.Ingest.OpenCanary, selfID))
}
if cfg.Ingest.CrowdSec.Enabled {
    sources = append(sources, ingest.NewCrowdSec(cfg.Ingest.CrowdSec, selfID))
}
if cfg.Ingest.MailcowLogs.Enabled {
    sources = append(sources, ingest.NewMailcow(cfg.Ingest.MailcowLogs, selfID))
}
if cfg.Ingest.Spamtrap.Enabled {
    sources = append(sources, ingest.NewSpamtrap(cfg.Ingest.Spamtrap, selfID))
}
if cfg.Ingest.Fail2Ban.Enabled {
    sources = append(sources, ingest.NewFail2Ban(cfg.Ingest.Fail2Ban, selfID))
}
```

- [ ] **Step 2: Build to verify**

```bash
make build
```

Expected: `bin/swarmd` and `bin/swarmctl` build without errors.

- [ ] **Step 3: Run full test suite**

```bash
make test
```

Expected: all tests `PASS`.

- [ ] **Step 4: Commit**

```bash
git add internal/node/node.go
git commit -m "feat(node): wire fail2ban ingest source"
```

---

## Verification

Enable in a test config and confirm events flow:

```yaml
# config.yaml excerpt
ingest:
  fail2ban:
    enabled: true
    container: "fail2ban"   # name of your fail2ban Docker container
    poll_interval: "30s"
    jail_reasons:
      recidive: "recidive"  # already in built-ins, but shows override syntax
```

Then:

```bash
# Confirm a currently-banned IP produces an event (check swarmd logs)
docker exec fail2ban fail2ban-client banned
# Should show banned IPs; swarmd log should show: "node: recorded event ip=X reason=ssh-auth-bruteforce"

# Check the API score for a banned IP
curl http://localhost:9102/api/v1/score/1.2.3.4
```
