# Mailcow Self-Sufficient Sensor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a Mailcow node a first-class attack sensor that generates its own events from Postfix/Dovecot container logs, adds a spamtrap adapter for zero-false-positive signals, and gives SMTP/IMAP events the correct scoring weights.

**Architecture:** Three independent additions: (1) add SMTP/IMAP entries to the existing `reportWeight` map in the reputation engine; (2) implement `MailcowLogs` — an ingest adapter that runs `docker logs --since=<timestamp>` against `mailcowdockerized-postfix-1` and `mailcowdockerized-dovecot-1` and parses auth-failure lines with regex; (3) implement `Spamtrap` — a file-tail adapter (same pattern as `Honeypot`) for a configurable log file that operators write one IPv4 per line to whenever a never-used mailbox receives a delivery attempt. All three wire into the existing `node.New()` / `config.IngestConfig` fan-in without touching the P2P or enforcement layers.

**Tech Stack:** Go stdlib `regexp`, `os/exec`, `bufio`, `net`; existing `ingest.Source` interface; existing `config.Duration` type; existing `store` / `reputation` engine.

---

## Context for implementers

Read these files before starting any task — they define the patterns everything must follow:

- `internal/ingest/honeypot.go` — canonical file-tail adapter (copy structure for Spamtrap)
- `internal/ingest/opencanary.go` — second example of the same pattern
- `internal/ingest/honeypot_test.go` — canonical adapter test (temp file + `writeLines` helper)
- `internal/reputation/engine.go` — `reportWeight` map location
- `internal/config/config.go` — `IngestConfig` struct and the `Duration` wrapper type
- `internal/node/node.go` lines 93–101 — how sources are wired

Key invariants from `CLAUDE.md`:
- Never commit secrets or `config.local.yaml`
- `internal/enforce` is security-critical — do **not** touch it in this plan
- Every new ingest source must implement the `Source` interface (`Name() string`, `Start(ctx) (<-chan proto.Event, error)`)

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `internal/reputation/engine.go` | Modify | Add SMTP/IMAP entries to `reportWeight` |
| `internal/reputation/engine_test.go` | Modify | Test that SMTP/IMAP weights are higher than the 2-point default |
| `internal/config/config.go` | Modify | Add `MailcowConfig`, `SpamtrapConfig`; extend `IngestConfig`; add defaults |
| `internal/config/config_test.go` | Modify | Test YAML parsing of new config types |
| `internal/ingest/mailcow_logs.go` | Replace stub | `MailcowLogs` adapter — Docker logs + regex parse |
| `internal/ingest/mailcow_logs_test.go` | Create | Unit tests via injectable `logFetcher` stub |
| `internal/ingest/spamtrap.go` | Replace stub | `Spamtrap` adapter — file tail |
| `internal/ingest/spamtrap_test.go` | Create | Tests using `t.TempDir()` temp file |
| `internal/node/node.go` | Modify | Wire `MailcowLogs` and `Spamtrap` into `New()` |
| `deploy/mailcow/config.yaml` | Modify | Add `mailcow_logs` and `spamtrap` sections |
| `deploy/mailcow/rules.yaml` | Replace | Fix stale `crowdsec-decision` reasons, add `smtp-spamtrap` rule |
| `deploy/mailcow/bootstrap-mailcow.sh` | Modify | Idempotent bouncer delete, fix `enable_alerts`, add `mailcow_logs`/`spamtrap` heredoc sections |

---

## Task 1: SMTP/IMAP reputation weights

**Files:**
- Modify: `internal/reputation/engine.go` (the `reportWeight` var, lines 12–17)
- Modify: `internal/reputation/engine_test.go` (append new test)

### Why these weights?

The existing SSH weights are: success=40, bruteforce=10, probe=2. SMTP/IMAP signals are analogous but SMTP is the primary attack vector on a mail server:

| Reason | Weight | Rationale |
|---|---|---|
| `smtp-auth-bruteforce` | 10 | Repeated SASL failures — same severity as SSH BF |
| `smtp-auth-success` | 40 | Auth on a honeypot — never legitimate, same as SSH success |
| `smtp-probe` | 2 | Connection without auth — same as SSH probe |
| `smtp-spamtrap` | 50 | Delivery to a never-used mailbox on a *production* box — highest confidence |
| `imap-auth-bruteforce` | 10 | IMAP auth failures |
| `imap-auth-success` | 30 | IMAP login on a honeypot |
| `imap-probe` | 2 | IMAP connection without auth |
| `pop3-auth-bruteforce` | 10 | POP3 auth failures |

- [ ] **Step 1: Write the failing test**

Add to `internal/reputation/engine_test.go`:

```go
// TestSMTPWeightsHigherThanDefault verifies SMTP/IMAP events score above the
// 2-point default so a mailcow node reacts faster than it would to generic reasons.
func TestSMTPWeightsHigherThanDefault(t *testing.T) {
	cases := []struct {
		reason  string
		wantMin float64
	}{
		{"smtp-auth-bruteforce", 9},
		{"smtp-spamtrap", 45},
		{"imap-auth-bruteforce", 9},
		{"pop3-auth-bruteforce", 9},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			e := openEngineCap(t, 15) // helper already defined in this file
			score, err := e.Record("192.0.2.10", tc.reason, "self", 1.0, "self", true)
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			if score < tc.wantMin {
				t.Errorf("reason=%q: score=%.2f, want >= %.2f", tc.reason, score, tc.wantMin)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
cd /root/federloom && go test ./internal/reputation/ -run TestSMTPWeights -v
```
Expected: FAIL — `smtp-auth-bruteforce` scores only ~2 (default weight).

- [ ] **Step 3: Add entries to `reportWeight`**

In `internal/reputation/engine.go`, extend the `reportWeight` map:

```go
var reportWeight = map[string]float64{
	"ssh-auth-success":      40,
	"ssh-auth-bruteforce":   10,
	"ssh-post-auth-command": 10,
	"ssh-probe":             2,
	"ssh-unknown":           2,
	// SMTP/IMAP — mirrors SSH weights; spamtrap is highest (zero-FP on production)
	"smtp-auth-bruteforce": 10,
	"smtp-auth-success":    40,
	"smtp-probe":           2,
	"smtp-spamtrap":        50,
	"imap-auth-bruteforce": 10,
	"imap-auth-success":    30,
	"imap-probe":           2,
	"pop3-auth-bruteforce": 10,
}
```

- [ ] **Step 4: Run test to confirm it passes**

```bash
go test ./internal/reputation/ -run TestSMTPWeights -v
```
Expected: PASS.

- [ ] **Step 5: Run the full reputation suite**

```bash
go test ./internal/reputation/ -v
```
Expected: all existing tests still PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/reputation/engine.go internal/reputation/engine_test.go
git commit -m "feat(reputation): add SMTP/IMAP scoring weights for mailcow sensor"
```

---

## Task 2: Config additions

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/config/config_test.go`:

```go
func TestLoadYAMLMailcowConfig(t *testing.T) {
	cfg, err := config.LoadYAML([]byte(`
ingest:
  mailcow_logs:
    enabled: true
    postfix_container: mailcowdockerized-postfix-1
    dovecot_container: mailcowdockerized-dovecot-1
    poll_interval: 30s
  spamtrap:
    enabled: true
    log_file: /var/log/spamtrap.log
    poll_interval: 5s
`))
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if !cfg.Ingest.MailcowLogs.Enabled {
		t.Error("expected mailcow_logs.enabled = true")
	}
	if cfg.Ingest.MailcowLogs.PostfixContainer != "mailcowdockerized-postfix-1" {
		t.Errorf("postfix_container: got %q", cfg.Ingest.MailcowLogs.PostfixContainer)
	}
	if cfg.Ingest.MailcowLogs.DovecotContainer != "mailcowdockerized-dovecot-1" {
		t.Errorf("dovecot_container: got %q", cfg.Ingest.MailcowLogs.DovecotContainer)
	}
	if cfg.Ingest.MailcowLogs.PollInterval.Duration != 30*time.Second {
		t.Errorf("poll_interval: got %v", cfg.Ingest.MailcowLogs.PollInterval.Duration)
	}
	if !cfg.Ingest.Spamtrap.Enabled {
		t.Error("expected spamtrap.enabled = true")
	}
	if cfg.Ingest.Spamtrap.LogFile != "/var/log/spamtrap.log" {
		t.Errorf("log_file: got %q", cfg.Ingest.Spamtrap.LogFile)
	}
}

func TestDefaultsMailcowPollInterval(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Ingest.MailcowLogs.PollInterval.Duration <= 0 {
		t.Errorf("MailcowLogs default PollInterval must be > 0, got %v", cfg.Ingest.MailcowLogs.PollInterval.Duration)
	}
	if cfg.Ingest.Spamtrap.PollInterval.Duration <= 0 {
		t.Errorf("Spamtrap default PollInterval must be > 0, got %v", cfg.Ingest.Spamtrap.PollInterval.Duration)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/config/ -run TestLoadYAMLMailcow -v
```
Expected: FAIL — `cfg.Ingest.MailcowLogs` doesn't exist yet.

- [ ] **Step 3: Add config types and extend `IngestConfig`**

In `internal/config/config.go`, add these two new struct types (place them after `CrowdSecConfig`):

```go
// MailcowConfig configures the Mailcow native log ingest adapter.
// Reads Postfix and Dovecot container logs via "docker logs --since=<timestamp>".
type MailcowConfig struct {
	Enabled          bool     `yaml:"enabled"`
	PostfixContainer string   `yaml:"postfix_container"` // default: mailcowdockerized-postfix-1
	DovecotContainer string   `yaml:"dovecot_container"` // default: mailcowdockerized-dovecot-1
	PollInterval     Duration `yaml:"poll_interval"`
}

// SpamtrapConfig configures the spamtrap ingest adapter.
// Tails a log file where operators write one attacker IPv4 per line.
type SpamtrapConfig struct {
	Enabled      bool     `yaml:"enabled"`
	LogFile      string   `yaml:"log_file"`
	PollInterval Duration `yaml:"poll_interval"`
}
```

Extend `IngestConfig` to include the two new fields:

```go
type IngestConfig struct {
	Honeypot    HoneypotConfig   `yaml:"honeypot"`
	OpenCanary  OpenCanaryConfig `yaml:"opencanary"`
	CrowdSec    CrowdSecConfig   `yaml:"crowdsec"`
	MailcowLogs MailcowConfig    `yaml:"mailcow_logs"`
	Spamtrap    SpamtrapConfig   `yaml:"spamtrap"`
}
```

Add defaults inside the `Defaults()` function, inside the `Ingest:` block:

```go
MailcowLogs: MailcowConfig{
    PollInterval: Duration{30 * time.Second},
},
Spamtrap: SpamtrapConfig{
    PollInterval: Duration{time.Second},
},
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
go test ./internal/config/ -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add MailcowConfig and SpamtrapConfig ingest types"
```

---

## Task 3: Mailcow log ingest adapter

**Files:**
- Replace stub: `internal/ingest/mailcow_logs.go`
- Create: `internal/ingest/mailcow_logs_test.go`

### Design notes

The adapter polls two Docker containers by running `docker logs --since=<RFC3339> <container>` on each tick. The `--since` timestamp advances after every successful poll so no line is re-processed. An injectable `logFetcher` function decouples the exec call from tests.

Postfix log line format:
```
Jun 17 10:12:34 mx mailcow postfix/smtpd[pid]: warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: authentication failure
Jun 17 10:12:34 mx mailcow postfix/smtpd[pid]: warning: mail.evil.com[1.2.3.4]: SASL PLAIN authentication failed: authentication failure
```

Dovecot log line format:
```
Jun 17 10:12:34 mx dovecot: imap-login: Disconnected (auth failed, 3 attempts in 10 secs): user=<test@domain.com>, method=PLAIN, rip=1.2.3.4, lip=172.22.1.3, TLS
Jun 17 10:12:34 mx dovecot: pop3-login: Disconnected (auth failed): user=<user>, method=PLAIN, rip=1.2.3.4, lip=172.22.1.3
```

- [ ] **Step 1: Write the tests first**

Create `internal/ingest/mailcow_logs_test.go`:

```go
package ingest_test

import (
	"context"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/ingest"
)

// makeMailcow returns a MailcowLogs adapter with a stub log fetcher.
// stubLines is called on each (container, since) pair and returns fake log output.
func makeMailcow(t *testing.T, stubLines func(container string) []byte) *ingest.MailcowLogs {
	t.Helper()
	cfg := config.MailcowConfig{
		Enabled:          true,
		PostfixContainer: "test-postfix",
		DovecotContainer: "test-dovecot",
		PollInterval:     config.Duration{Duration: 50 * time.Millisecond},
	}
	return ingest.NewMailcowWithFetcher(cfg, "selfpeer", func(_ context.Context, container, _ string) ([]byte, error) {
		return stubLines(container), nil
	})
}

func TestMailcowPostfixSASLLoginFailure(t *testing.T) {
	m := makeMailcow(t, func(container string) []byte {
		if container == "test-postfix" {
			return []byte("Jun 17 10:12:34 mx postfix/smtpd[123]: warning: unknown[198.51.100.1]: SASL LOGIN authentication failed: authentication failure\n")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case e := <-ch:
		if e.IP != "198.51.100.1" {
			t.Errorf("IP: got %q, want 198.51.100.1", e.IP)
		}
		if e.Reason != "smtp-auth-bruteforce" {
			t.Errorf("Reason: got %q, want smtp-auth-bruteforce", e.Reason)
		}
		if e.ReporterID != "selfpeer" {
			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestMailcowPostfixSASLPlainWithHostname(t *testing.T) {
	// Postfix sometimes resolves the attacker hostname: "mail.evil.com[1.2.3.4]"
	m := makeMailcow(t, func(container string) []byte {
		if container == "test-postfix" {
			return []byte("Jun 17 10:12:34 mx postfix/smtpd[123]: warning: mail.evil.com[203.0.113.5]: SASL PLAIN authentication failed: authentication failure\n")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := m.Start(ctx)

	select {
	case e := <-ch:
		if e.IP != "203.0.113.5" {
			t.Errorf("IP: got %q, want 203.0.113.5", e.IP)
		}
		if e.Reason != "smtp-auth-bruteforce" {
			t.Errorf("Reason: got %q, want smtp-auth-bruteforce", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestMailcowDovecotIMAPAuthFailed(t *testing.T) {
	m := makeMailcow(t, func(container string) []byte {
		if container == "test-dovecot" {
			return []byte("Jun 17 10:12:34 mx dovecot: imap-login: Disconnected (auth failed, 3 attempts in 10 secs): user=<test@mail.com>, method=PLAIN, rip=198.51.100.2, lip=172.22.1.3\n")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := m.Start(ctx)

	select {
	case e := <-ch:
		if e.IP != "198.51.100.2" {
			t.Errorf("IP: got %q, want 198.51.100.2", e.IP)
		}
		if e.Reason != "imap-auth-bruteforce" {
			t.Errorf("Reason: got %q, want imap-auth-bruteforce", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestMailcowDovecotPOP3AuthFailed(t *testing.T) {
	m := makeMailcow(t, func(container string) []byte {
		if container == "test-dovecot" {
			return []byte("Jun 17 10:12:34 mx dovecot: pop3-login: Disconnected (auth failed): user=<test>, method=PLAIN, rip=203.0.113.7, lip=172.22.1.3\n")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := m.Start(ctx)

	select {
	case e := <-ch:
		if e.IP != "203.0.113.7" {
			t.Errorf("IP: got %q, want 203.0.113.7", e.IP)
		}
		if e.Reason != "pop3-auth-bruteforce" {
			t.Errorf("Reason: got %q, want pop3-auth-bruteforce", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestMailcowSkipsNonAuthLines(t *testing.T) {
	m := makeMailcow(t, func(container string) []byte {
		if container == "test-postfix" {
			return []byte("Jun 17 10:12:34 mx postfix/smtpd[123]: connect from unknown[198.51.100.1]\n")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	ch, _ := m.Start(ctx)

	select {
	case e := <-ch:
		t.Errorf("expected no event for connect line, got %+v", e)
	case <-ctx.Done():
		// correct — no event
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/ingest/ -run TestMailcow -v 2>&1 | head -20
```
Expected: compile error — `ingest.NewMailcowWithFetcher` does not exist.

- [ ] **Step 3: Implement `internal/ingest/mailcow_logs.go`**

Replace the current stub with:

```go
package ingest

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"os/exec"
	"regexp"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/pkg/proto"
)

// logFetcher retrieves container log lines since a given RFC3339 timestamp.
// Injectable so tests can stub without a running Docker daemon.
type logFetcher func(ctx context.Context, container, since string) ([]byte, error)

// dockerFetch is the production logFetcher.
func dockerFetch(ctx context.Context, container, since string) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", "logs", "--since", since, container).CombinedOutput()
}

var (
	// postfixSASLRe matches Postfix SASL auth failures.
	// Handles both "unknown[IP]" and "hostname[IP]" client formats.
	postfixSASLRe = regexp.MustCompile(`\[((?:\d{1,3}\.){3}\d{1,3})\]: SASL \S+ authentication failed`)

	// dovecotAuthRe matches Dovecot IMAP/POP3 auth-failed disconnect lines.
	// Capture group 1 = protocol ("imap" or "pop3"), group 2 = remote IP.
	dovecotAuthRe = regexp.MustCompile(`(imap|pop3)-login: Disconnected \(auth failed[^)]*\).*?rip=((?:\d{1,3}\.){3}\d{1,3}),`)
)

// MailcowLogs reads Postfix and Dovecot container logs via "docker logs --since"
// and emits proto.Events for SMTP-AUTH and IMAP/POP3 brute-force attempts.
type MailcowLogs struct {
	cfg     config.MailcowConfig
	selfID  string
	fetcher logFetcher
}

// Compile-time check.
var _ Source = (*MailcowLogs)(nil)

// NewMailcow creates a MailcowLogs adapter using the real Docker log fetcher.
// PostfixContainer and DovecotContainer default to mailcow's standard container names.
func NewMailcow(cfg config.MailcowConfig, selfID string) *MailcowLogs {
	return NewMailcowWithFetcher(cfg, selfID, dockerFetch)
}

// NewMailcowWithFetcher creates a MailcowLogs adapter with a custom log fetcher.
// Use this in tests to inject a stub without a running Docker daemon.
func NewMailcowWithFetcher(cfg config.MailcowConfig, selfID string, f logFetcher) *MailcowLogs {
	if cfg.PostfixContainer == "" {
		cfg.PostfixContainer = "mailcowdockerized-postfix-1"
	}
	if cfg.DovecotContainer == "" {
		cfg.DovecotContainer = "mailcowdockerized-dovecot-1"
	}
	return &MailcowLogs{cfg: cfg, selfID: selfID, fetcher: f}
}

func (m *MailcowLogs) Name() string { return "mailcow" }

// Start launches the polling goroutine and returns the event channel.
func (m *MailcowLogs) Start(ctx context.Context) (<-chan proto.Event, error) {
	ch := make(chan proto.Event, 64)
	go m.run(ctx, ch)
	return ch, nil
}

func (m *MailcowLogs) run(ctx context.Context, ch chan<- proto.Event) {
	defer close(ch)

	pollInterval := m.cfg.PollInterval.Duration
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}

	// Look back one interval on first poll to catch events just before startup.
	since := time.Now().Add(-pollInterval).UTC().Format(time.RFC3339)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			nextSince := now.UTC().Format(time.RFC3339)
			m.pollPostfix(ctx, since, ch)
			m.pollDovecot(ctx, since, ch)
			since = nextSince
		}
	}
}

func (m *MailcowLogs) pollPostfix(ctx context.Context, since string, ch chan<- proto.Event) {
	data, err := m.fetcher(ctx, m.cfg.PostfixContainer, since)
	if err != nil {
		log.Printf("ingest/mailcow: postfix fetch: %v", err)
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		sub := postfixSASLRe.FindSubmatch(scanner.Bytes())
		if sub == nil {
			continue
		}
		ip := string(sub[1])
		select {
		case ch <- proto.Event{IP: ip, Reason: "smtp-auth-bruteforce", Timestamp: time.Now(), ReporterID: m.selfID}:
		case <-ctx.Done():
			return
		default:
			log.Printf("ingest/mailcow: channel full, dropping %s", ip)
		}
	}
}

func (m *MailcowLogs) pollDovecot(ctx context.Context, since string, ch chan<- proto.Event) {
	data, err := m.fetcher(ctx, m.cfg.DovecotContainer, since)
	if err != nil {
		log.Printf("ingest/mailcow: dovecot fetch: %v", err)
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		sub := dovecotAuthRe.FindSubmatch(scanner.Bytes())
		if sub == nil {
			continue
		}
		proto_ := string(sub[1]) // "imap" or "pop3"
		ip := string(sub[2])
		reason := proto_ + "-auth-bruteforce"
		select {
		case ch <- proto.Event{IP: ip, Reason: reason, Timestamp: time.Now(), ReporterID: m.selfID}:
		case <-ctx.Done():
			return
		default:
			log.Printf("ingest/mailcow: channel full, dropping %s", ip)
		}
	}
}
```

Note: `proto_` (with underscore) avoids shadowing the imported `proto` package.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/ingest/ -run TestMailcow -v
```
Expected: all 5 tests PASS.

- [ ] **Step 5: Run full ingest suite**

```bash
go test ./internal/ingest/ -v
```
Expected: all existing honeypot, opencanary, crowdsec tests still PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/ingest/mailcow_logs.go internal/ingest/mailcow_logs_test.go
git commit -m "feat(ingest): implement Mailcow native log adapter (Postfix + Dovecot)"
```

---

## Task 4: Spamtrap ingest adapter

**Files:**
- Replace stub: `internal/ingest/spamtrap.go`
- Create: `internal/ingest/spamtrap_test.go`

### Log file format

One IPv4 address per line. Lines starting with `#` and blank lines are skipped. The operator writes to this file however they like (Postfix `local_recipient_maps` script, milter, manual). Example:

```
# FederLoom spamtrap hits
198.51.100.99
203.0.113.44
```

The adapter tails the file exactly like the `Honeypot` adapter tails `cowrie.json`.

- [ ] **Step 1: Write the tests first**

Create `internal/ingest/spamtrap_test.go`:

```go
package ingest_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/ingest"
)

func TestSpamtrapEmitsEvent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "spamtrap.log")

	cfg := config.SpamtrapConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	s := ingest.NewSpamtrap(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{"198.51.100.5"})

	select {
	case e := <-ch:
		if e.IP != "198.51.100.5" {
			t.Errorf("IP: got %q, want 198.51.100.5", e.IP)
		}
		if e.Reason != "smtp-spamtrap" {
			t.Errorf("Reason: got %q, want smtp-spamtrap", e.Reason)
		}
		if e.ReporterID != "selfpeer" {
			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestSpamtrapSkipsComments(t *testing.T) {
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

	writeLines(t, logPath, []string{
		"# this is a comment",
		"",
		"   ",
	})

	select {
	case e := <-ch:
		t.Errorf("expected no event for comment/blank lines, got %+v", e)
	case <-ctx.Done():
		// correct
	}
}

func TestSpamtrapSkipsInvalidIP(t *testing.T) {
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

	writeLines(t, logPath, []string{"not-an-ip", "256.1.2.3"})

	select {
	case e := <-ch:
		t.Errorf("expected no event for invalid IPs, got %+v", e)
	case <-ctx.Done():
		// correct
	}
}

func TestSpamtrapMultipleIPs(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "spamtrap.log")

	cfg := config.SpamtrapConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	s := ingest.NewSpamtrap(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		"# attacker 1",
		"198.51.100.10",
		"198.51.100.11",
	})

	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case e := <-ch:
			seen[e.IP] = true
		case <-ctx.Done():
			t.Fatalf("timed out after seeing %d events: %v", i, seen)
		}
	}
	if !seen["198.51.100.10"] || !seen["198.51.100.11"] {
		t.Errorf("missing expected IPs: got %v", seen)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/ingest/ -run TestSpamtrap -v 2>&1 | head -20
```
Expected: compile error — `ingest.NewSpamtrap` does not exist.

- [ ] **Step 3: Implement `internal/ingest/spamtrap.go`**

Replace the current stub with:

```go
package ingest

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/pkg/proto"
)

// Spamtrap tails a log file written by the operator when a never-used mailbox
// receives a delivery attempt. One IPv4 address per line; lines starting with
// "#" and blank lines are ignored. Any event emitted here has zero false-positive
// risk when the configured mailboxes are truly unused (spec §4.1).
type Spamtrap struct {
	cfg    config.SpamtrapConfig
	selfID string
}

// Compile-time check.
var _ Source = (*Spamtrap)(nil)

// NewSpamtrap creates a Spamtrap adapter. selfID is the local node's peer ID.
func NewSpamtrap(cfg config.SpamtrapConfig, selfID string) *Spamtrap {
	return &Spamtrap{cfg: cfg, selfID: selfID}
}

func (s *Spamtrap) Name() string { return "spamtrap" }

// Start begins tailing the spamtrap log file and emitting events until ctx is cancelled.
func (s *Spamtrap) Start(ctx context.Context) (<-chan proto.Event, error) {
	ch := make(chan proto.Event, 64)
	go s.tail(ctx, ch)
	return ch, nil
}

func (s *Spamtrap) tail(ctx context.Context, ch chan<- proto.Event) {
	defer close(ch)

	pollInterval := s.cfg.PollInterval.Duration
	if pollInterval <= 0 {
		pollInterval = time.Second
	}

	var offset int64
	var lastSize int64

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f, err := os.Open(s.cfg.LogFile)
			if err != nil {
				continue // file not yet created — wait
			}

			fi, err := f.Stat()
			if err != nil {
				f.Close()
				continue
			}

			// Log rotation: file shrank — reopen from start.
			if fi.Size() < lastSize {
				offset = 0
			}
			lastSize = fi.Size()

			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				f.Close()
				continue
			}

			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 1<<20), 1<<20)
			for scanner.Scan() {
				raw := scanner.Bytes()
				offset += int64(len(raw)) + 1 // +1 for newline

				line := strings.TrimSpace(string(raw))
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if net.ParseIP(line) == nil || !strings.Contains(line, ".") {
					log.Printf("ingest/spamtrap: invalid IPv4 %q in %s — skipping", line, s.cfg.LogFile)
					continue
				}

				select {
				case ch <- proto.Event{IP: line, Reason: "smtp-spamtrap", Timestamp: time.Now(), ReporterID: s.selfID}:
				case <-ctx.Done():
					f.Close()
					return
				default:
					log.Printf("ingest/spamtrap: channel full, dropping %s", line)
				}
			}
			if err := scanner.Err(); err != nil {
				log.Printf("ingest/spamtrap: scan error on %s: %v", s.cfg.LogFile, err)
			}
			f.Close()
		}
	}
}
```

Note: `strings.Contains(line, ".")` distinguishes IPv4 from IPv6 (both pass `net.ParseIP`, but spamtrap log files only carry IPv4 in practice — IPv6 is accepted by the rule engine anyway).

- [ ] **Step 4: Run tests**

```bash
go test ./internal/ingest/ -run TestSpamtrap -v
```
Expected: all 4 tests PASS.

- [ ] **Step 5: Run full ingest suite**

```bash
go test ./internal/ingest/ -v
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/ingest/spamtrap.go internal/ingest/spamtrap_test.go
git commit -m "feat(ingest): implement Spamtrap file-tail adapter (smtp-spamtrap events)"
```

---

## Task 5: Node wiring

**Files:**
- Modify: `internal/node/node.go` (the `New()` function, around lines 93–105)

- [ ] **Step 1: Write a failing test**

In `internal/node/node_test.go`, add a test that verifies the node accepts MailcowLogs and Spamtrap configs (the simplest check is that `New()` does not error when both are enabled with valid dummy paths):

```go
func TestNodeAcceptsMailcowAndSpamtrapConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.BlockThreshold = 1000

	// Point to non-existent log paths — adapters silently wait for the file.
	cfg.Ingest.MailcowLogs.Enabled = true
	cfg.Ingest.MailcowLogs.PostfixContainer = "test-postfix"
	cfg.Ingest.MailcowLogs.DovecotContainer = "test-dovecot"
	cfg.Ingest.Spamtrap.Enabled = true
	cfg.Ingest.Spamtrap.LogFile = filepath.Join(dir, "spamtrap.log")

	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New with mailcow+spamtrap config: %v", err)
	}
	defer n.CloseStores()

	// Verify the sources slice contains both new adapters.
	found := map[string]bool{}
	for _, src := range n.sources {
		found[src.Name()] = true
	}
	if !found["mailcow"] {
		t.Error("expected mailcow source in node.sources")
	}
	if !found["spamtrap"] {
		t.Error("expected spamtrap source in node.sources")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/node/ -run TestNodeAcceptsMailcow -v
```
Expected: FAIL — `n.sources` has no mailcow or spamtrap entries (field is unexported). 

If `sources` is unexported (it is), the test above won't compile. Use this alternative that just checks `New()` succeeds and the node has the right source count:

```go
func TestNodeAcceptsMailcowAndSpamtrapConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.BlockThreshold = 1000
	cfg.Ingest.MailcowLogs.Enabled = true
	cfg.Ingest.MailcowLogs.PostfixContainer = "test-postfix"
	cfg.Ingest.MailcowLogs.DovecotContainer = "test-dovecot"
	cfg.Ingest.Spamtrap.Enabled = true
	cfg.Ingest.Spamtrap.LogFile = filepath.Join(dir, "spamtrap.log")

	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New with mailcow+spamtrap config: %v", err)
	}
	defer n.CloseStores()
}
```

Expected: FAIL — `New()` doesn't use `cfg.Ingest.MailcowLogs` or `cfg.Ingest.Spamtrap` yet (no error, but it's not wired). Actually this test would PASS already since New() just ignores the new fields. Add an explicit count check using a package-level helper (since `sources` is unexported, expose a `SourceCount()` method for tests in the same package):

Since the test is in `package node` (not `node_test`), it can access `n.sources` directly:

```go
// internal/node/node_test.go (package node — internal test file)
func TestNodeAcceptsMailcowAndSpamtrapConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.BlockThreshold = 1000
	cfg.Ingest.MailcowLogs.Enabled = true
	cfg.Ingest.MailcowLogs.PostfixContainer = "test-postfix"
	cfg.Ingest.MailcowLogs.DovecotContainer = "test-dovecot"
	cfg.Ingest.Spamtrap.Enabled = true
	cfg.Ingest.Spamtrap.LogFile = filepath.Join(dir, "spamtrap.log")

	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New with mailcow+spamtrap config: %v", err)
	}
	defer n.CloseStores()

	names := make([]string, 0, len(n.sources))
	for _, src := range n.sources {
		names = append(names, src.Name())
	}
	hasMail := false
	hasSpam := false
	for _, name := range names {
		if name == "mailcow" {
			hasMail = true
		}
		if name == "spamtrap" {
			hasSpam = true
		}
	}
	if !hasMail {
		t.Errorf("mailcow source not wired; sources = %v", names)
	}
	if !hasSpam {
		t.Errorf("spamtrap source not wired; sources = %v", names)
	}
}
```

- [ ] **Step 3: Wire both sources in `node.go`**

In `internal/node/node.go`, in the `New()` function, add after the existing `if cfg.Ingest.CrowdSec.Enabled` block:

```go
if cfg.Ingest.MailcowLogs.Enabled {
    sources = append(sources, ingest.NewMailcow(cfg.Ingest.MailcowLogs, selfID))
}
if cfg.Ingest.Spamtrap.Enabled {
    sources = append(sources, ingest.NewSpamtrap(cfg.Ingest.Spamtrap, selfID))
}
```

Also add `"path/filepath"` to the import if it isn't already there (check the test file's imports).

- [ ] **Step 4: Run the test**

```bash
go test ./internal/node/ -run TestNodeAcceptsMailcow -v
```
Expected: PASS.

- [ ] **Step 5: Run the full node suite**

```bash
go test ./internal/node/ -v
```
Expected: all PASS.

- [ ] **Step 6: Build everything**

```bash
make build
```
Expected: clean compile, `bin/federloomd` and `bin/federloomctl` produced.

- [ ] **Step 7: Commit**

```bash
git add internal/node/node.go internal/node/node_test.go
git commit -m "feat(node): wire MailcowLogs and Spamtrap ingest sources"
```

---

## Task 6: Deploy config and rules updates

**Files:**
- Modify: `deploy/mailcow/config.yaml`
- Replace: `deploy/mailcow/rules.yaml`
- Modify: `deploy/mailcow/bootstrap-mailcow.sh`

This task has no unit tests (it's deployment config), but all changes are verified by `make test` passing.

- [ ] **Step 1: Update `deploy/mailcow/config.yaml`**

Add the two new ingest sections. The full updated `ingest:` block:

```yaml
ingest:
  mailcow_logs:
    enabled: true
    postfix_container: mailcowdockerized-postfix-1
    dovecot_container: mailcowdockerized-dovecot-1
    poll_interval: 30s
  spamtrap:
    enabled: false          # enable after creating spamtrap mailboxes and writing IPs to log_file
    log_file: /var/log/federloom-spamtrap.log
    poll_interval: 5s
  crowdsec:
    enabled: false          # enable after: cscli bouncers add federloom
    lapi_url: "http://127.0.0.1:8080"
    api_key: ""             # set in config.local.yaml — never commit
    poll_interval: 30s
    enable_decisions: true
    enable_alerts: false    # alerts require machine auth; bouncer key only covers decisions
```

- [ ] **Step 2: Replace `deploy/mailcow/rules.yaml`**

The existing file has `reason: crowdsec-decision` (stale since commit bc13180 changed ingest to emit real scenario names). Replace with:

```yaml
# FederLoom rules for the Mailcow production node.
# Rules are evaluated top-to-bottom; first match wins.
# Reason patterns: exact string OR prefix wildcard ending in "*" (e.g. "smtp-*").

# Delivery to a never-used mailbox on this server — zero-false-positive signal.
- name: spamtrap-hit
  reason: smtp-spamtrap
  min_corroboration: 1
  action: block

# CrowdSec confirmed SMTP/SSH ban from local instance — block immediately.
- name: crowdsec-smtp-ban
  reason: smtp-*
  min_corroboration: 1
  action: block

- name: crowdsec-ssh-ban
  reason: ssh-*
  min_corroboration: 1
  action: block

# SMTP brute force confirmed by 2+ federation reporters.
- name: smtp-brute-consensus
  reason: smtp-auth-bruteforce
  min_corroboration: 2
  action: block

# IMAP brute force confirmed by 2+ federation reporters.
- name: imap-brute-consensus
  reason: imap-auth-bruteforce
  min_corroboration: 2
  action: block

# POP3 brute force confirmed by 2+ reporters.
- name: pop3-brute-consensus
  reason: pop3-auth-bruteforce
  min_corroboration: 2
  action: block

# SSH post-auth command reported by honeypot — attacker ran shell commands.
- name: honeypot-shell-exec
  reason: ssh-post-auth-command
  min_corroboration: 1
  action: block

# SSH auth success on honeypot — attacker authenticated.
- name: honeypot-auth-success
  reason: ssh-auth-success
  min_corroboration: 1
  action: block

# SSH burst — 15 events in 10 min.
- name: ssh-brute-burst
  reason: ssh-auth-bruteforce
  min_burst: 15
  burst_window: 10m
  action: block

# Score-based fallback — catches anything not matched above.
- name: score-fallback
  min_score: 75
  action: block
```

- [ ] **Step 3: Update `deploy/mailcow/bootstrap-mailcow.sh`**

Three fixes:

**Fix 1** — Idempotent bouncer registration (add delete before add). Find the existing bouncer-add line and replace:

```bash
# DELETE OLD VERSION (find this block):
RAW=$(sudo_run docker exec "$CROWDSEC_CTR" cscli bouncers add federloom 2>&1 || true)

# REPLACE WITH:
sudo_run docker exec "$CROWDSEC_CTR" cscli bouncers delete federloom 2>/dev/null || true
RAW=$(sudo_run docker exec "$CROWDSEC_CTR" cscli bouncers add federloom 2>&1 || true)
```

**Fix 2** — In the heredoc that writes `config.local.yaml`, change `enable_alerts: true` → `enable_alerts: false`:

```bash
    enable_alerts: false   # alerts require machine auth; bouncer key only covers decisions
```

Also add `mailcow_logs` section to the heredoc's `ingest:` block:

```bash
ingest:
  mailcow_logs:
    enabled: true
    postfix_container: mailcowdockerized-postfix-1
    dovecot_container: mailcowdockerized-dovecot-1
    poll_interval: 30s
  spamtrap:
    enabled: false
    log_file: /var/log/federloom-spamtrap.log
    poll_interval: 5s
  crowdsec:
    enabled: ${CROWDSEC_ENABLED}
    lapi_url: "http://127.0.0.1:8080"
    api_key: "${API_KEY}"
    poll_interval: 30s
    enable_decisions: true
    enable_alerts: false
```

**Fix 3** — Change `chain: INPUT` → `chains: [DOCKER-USER, INPUT]` in the enforce block of the heredoc (Mailcow runs in Docker so DOCKER-USER is needed for container traffic):

```bash
enforce:
  backend: ipset
  set_name: federloom
  chains:
    - DOCKER-USER
    - INPUT
  extra_whitelist:
    - 135.181.91.151   # this server's public IP
    - 100.120.31.14    # tailscale
    - 172.22.1.0/24    # mailcow Docker network
    - 172.17.0.0/16    # Docker default bridge
```

- [ ] **Step 4: Run full test suite to confirm no regressions**

```bash
make test
```
Expected: all packages PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/mailcow/config.yaml deploy/mailcow/rules.yaml deploy/mailcow/bootstrap-mailcow.sh
git commit -m "fix(deploy): update mailcow config, rules, and bootstrap for native log ingest"
```

---

## Verification

After all 6 tasks are committed:

```bash
# Full build + test
make build && make test

# Confirm new sources appear in the binary help/version
./bin/federloomd --help 2>&1 | head -5

# Confirm the mailcow config parses cleanly
./bin/federloomd --config deploy/mailcow/config.yaml --dry-run 2>/dev/null || true
```

To verify on the actual mailcow server after running `bootstrap-mailcow.sh`:

```bash
# Watch for smtp-auth-bruteforce events in metrics
curl -s http://MAILCOW_SERVER:9101/metrics | grep federloom_events_received

# Confirm both chains have the ipset DROP rule
iptables -L DOCKER-USER -n | grep federloom
iptables -L INPUT -n | grep federloom

# Tail container logs to see parsed events
ssh joe@nixos-mailcow "sudo docker logs federloom-mailcow 2>&1 | grep -E 'block|smtp|imap' | tail -20"
```
