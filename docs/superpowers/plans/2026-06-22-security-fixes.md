# Security Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three confirmed security vulnerabilities: CIDR injection via the nftables sink, unauthenticated API exposure on the public internet, and newline injection in the CrowdSec CTI export.

**Architecture:** A single `net.ParseIP` gate added to `processLocal` and `ProcessRemote` in `internal/node/node.go` stops all invalid IPs before they reach the reputation engine or firewall sink (fixes Vulns 1 & 3). A defense-in-depth check in the CTI handler sanitizes any pre-existing malformed store keys. A bearer token middleware in `internal/api/server.go`, combined with Docker port bindings restricted to the Tailscale interface (`100.71.239.1`), protects the API (fixes Vuln 2).

**Tech Stack:** Go 1.22 standard library (`net`, `os`, `net/http`); Docker Compose port binding syntax; BadgerDB (via existing store abstraction).

---

## Files Modified / Created

| File | Change |
|------|--------|
| `internal/node/node.go` | Add `net.ParseIP` gate in `processLocal` and `ProcessRemote`; add `"net"` import |
| `internal/node/node_test.go` | Add IP validation tests for both functions |
| `internal/api/handler_blocklist.go` | Skip malformed keys in `handleCrowdSecCTI` |
| `internal/api/handler_blocklist_test.go` | Add test for malformed key sanitization |
| `internal/api/server.go` | Add `bearerTokenMiddleware`; apply when `FEDERLOOM_API_TOKEN` is set; add `"os"` import |
| `internal/api/server_test.go` | Add four bearer token tests |
| `test/adversarial/poisoning_test.go` | Add `TestCIDRInjectionNeverRecorded` scenario |
| `deploy/honeypot/docker-compose.yml` | Bind ports 9101/9102 to `100.71.239.1`; add `env_file` |
| `deploy/honeypot/.env.example` | Create with placeholder token |
| `.gitignore` | Add `**/.env` |

---

## Task 1: IP Validation Gate — Tests

**Files:**
- Modify: `internal/node/node_test.go`

- [ ] **Step 1: Add failing tests**

Append to `internal/node/node_test.go`. Add `"context"` to the import block (it is not currently imported):

```go
import (
    "context"           // add this
    "path/filepath"
    "testing"
    "time"

    "github.com/JoeRu/federloom/internal/config"
    "github.com/JoeRu/federloom/internal/enforce"
    "github.com/JoeRu/federloom/internal/identity"
    "github.com/JoeRu/federloom/internal/reputation"
    "github.com/JoeRu/federloom/internal/rules"
    "github.com/JoeRu/federloom/internal/store"
    "github.com/JoeRu/federloom/internal/transport"
    "github.com/JoeRu/federloom/internal/trust"
    "github.com/JoeRu/federloom/pkg/proto"
)
```

Then append these tests at the end of the file:

```go
// TestProcessLocalDropsInvalidIP verifies that processLocal silently drops events
// whose IP field is not a bare IPv4/IPv6 address (CIDR, hostname, newline-embedded).
func TestProcessLocalDropsInvalidIP(t *testing.T) {
    cases := []string{
        "0.0.0.0/0",        // CIDR — block-all nftables attack
        "1.2.3.4\n5.6.7.8", // newline injection
        "example.com",      // hostname
        "",                 // empty
    }
    for _, ip := range cases {
        ip := ip
        t.Run(ip, func(t *testing.T) {
            n, _ := testNode(t)
            n.processLocal(context.Background(), proto.Event{IP: ip, Reason: "ssh-probe"})
            rec, _ := n.rep.GetRecord(ip)
            if !rec.LastSeen.IsZero() {
                t.Errorf("invalid IP %q was recorded in reputation store", ip)
            }
        })
    }
}

// TestProcessRemoteDropsInvalidIP verifies that ProcessRemote silently drops events
// whose IP field is not a bare IPv4/IPv6 address.
func TestProcessRemoteDropsInvalidIP(t *testing.T) {
    cases := []string{
        "0.0.0.0/0",
        "1.2.3.4\n5.6.7.8",
        "example.com",
        "",
    }
    for _, ip := range cases {
        ip := ip
        t.Run(ip, func(t *testing.T) {
            n, _ := testNode(t)
            n.ProcessRemote(transport.ReceivedEvent{
                Event: proto.Event{IP: ip, Reason: "ssh-probe", ReporterID: "12D3KooWpeer"},
                From:  "12D3KooWpeer",
            })
            rec, _ := n.rep.GetRecord(ip)
            if !rec.LastSeen.IsZero() {
                t.Errorf("invalid IP %q was recorded in reputation store", ip)
            }
        })
    }
}

// TestProcessLocalAcceptsValidIP is the control: a valid bare IP must be recorded.
func TestProcessLocalAcceptsValidIP(t *testing.T) {
    n, _ := testNode(t)
    n.processLocal(context.Background(), proto.Event{IP: "203.0.113.1", Reason: "ssh-probe"})
    rec, err := n.rep.GetRecord("203.0.113.1")
    if err != nil {
        t.Fatalf("GetRecord: %v", err)
    }
    if rec.LastSeen.IsZero() {
        t.Error("valid IP was not recorded in reputation store")
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/node/ -run "TestProcessLocalDropsInvalidIP|TestProcessRemoteDropsInvalidIP|TestProcessLocalAcceptsValidIP" -v
```

Expected: `TestProcessLocalDropsInvalidIP` and `TestProcessRemoteDropsInvalidIP` FAIL (invalid IPs currently reach the store). `TestProcessLocalAcceptsValidIP` should PASS already.

---

## Task 2: IP Validation Gate — Implementation

**Files:**
- Modify: `internal/node/node.go`

- [ ] **Step 1: Add `"net"` to the import block**

In `internal/node/node.go`, add `"net"` to the import block (keep alphabetical order):

```go
import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "os"
    "sync"
    "time"

    "github.com/JoeRu/federloom/internal/api"
    // ... rest of imports unchanged
)
```

- [ ] **Step 2: Add gate at the top of `processLocal`**

In `internal/node/node.go`, `processLocal` currently begins:

```go
func (n *Node) processLocal(ctx context.Context, e proto.Event) {
	if n.neverblock.Contains(e.IP) {
		return
	}
```

Change it to:

```go
func (n *Node) processLocal(ctx context.Context, e proto.Event) {
	if net.ParseIP(e.IP) == nil {
		log.Printf("node: drop event with invalid IP %q", e.IP)
		return
	}
	if n.neverblock.Contains(e.IP) {
		return
	}
```

- [ ] **Step 3: Add gate in `ProcessRemote`**

In `internal/node/node.go`, `ProcessRemote` currently has this block (around line 259):

```go
	if e.ReporterID != re.From {
		log.Printf("node: drop spoofed event: reporter %q != verified publisher %q", e.ReporterID, re.From)
		return
	}
	if n.neverblock.Contains(e.IP) {
		return
	}
```

Change it to:

```go
	if e.ReporterID != re.From {
		log.Printf("node: drop spoofed event: reporter %q != verified publisher %q", e.ReporterID, re.From)
		return
	}
	if net.ParseIP(e.IP) == nil {
		log.Printf("node: drop event with invalid IP %q", e.IP)
		return
	}
	if n.neverblock.Contains(e.IP) {
		return
	}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
go test ./internal/node/ -v
```

Expected: all tests PASS including the three new ones.

- [ ] **Step 5: Commit**

```bash
git add internal/node/node.go internal/node/node_test.go
git commit -m "fix(node): reject non-IP strings before reputation recording

Adds net.ParseIP gate in processLocal and ProcessRemote. Prevents CIDR
strings (0.0.0.0/0), newline-embedded values, and hostnames from reaching
the reputation engine or firewall sink (Vulns 1 & 3).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 3: CTI Sanitization — Tests

**Files:**
- Modify: `internal/api/handler_blocklist_test.go`

- [ ] **Step 1: Add malformed-key stub and failing test**

Append to `internal/api/handler_blocklist_test.go`:

```go
// malformedKeyStore returns one valid IP and one CIDR key to test sanitization.
type malformedKeyStore struct{}

func (s *malformedKeyStore) GetScore(ip string) (store.ScoreRecord, error) {
    return store.ScoreRecord{}, nil
}

func (s *malformedKeyStore) ScanScores(fn func(ip string, r store.ScoreRecord) error) error {
    now := time.Now()
    _ = fn("203.0.113.1", store.ScoreRecord{Score: 90.0, LastSeen: now, Reasons: []string{"ssh-probe"}})
    _ = fn("0.0.0.0/0", store.ScoreRecord{Score: 90.0, LastSeen: now, Reasons: []string{"ssh-probe"}})
    return nil
}

// TestHandleCrowdSecCTI_SkipsMalformedKeys verifies that malformed store keys
// (CIDRs, newline-embedded strings) are not emitted in the CTI plaintext feed.
func TestHandleCrowdSecCTI_SkipsMalformedKeys(t *testing.T) {
    srv := New(
        config.APIConfig{Addr: ":0"},
        &malformedKeyStore{},
        config.ReputationConfig{BlockThreshold: 0},
    )
    r := httptest.NewRequest(http.MethodGet, "/crowdsec/v1/decisions?min_score=0", nil)
    w := httptest.NewRecorder()

    srv.handleCrowdSecCTI(w, r)

    body := w.Body.String()
    lines := countNonEmptyLines(body)
    if lines != 1 {
        t.Errorf("got %d lines, want 1 (malformed key must be skipped)\nbody: %q", lines, body)
    }
    if !strings.Contains(body, "203.0.113.1") {
        t.Errorf("valid IP missing from CTI output; body: %q", body)
    }
    if strings.Contains(body, "0.0.0.0/0") {
        t.Errorf("CIDR key leaked into CTI output; body: %q", body)
    }
}
```

- [ ] **Step 3: Run test to confirm it fails**

```bash
go test ./internal/api/ -run TestHandleCrowdSecCTI_SkipsMalformedKeys -v
```

Expected: FAIL — currently `handleCrowdSecCTI` emits both lines (2 lines, not 1).

---

## Task 4: CTI Sanitization — Implementation

**Files:**
- Modify: `internal/api/handler_blocklist.go`

- [ ] **Step 1: Add `"net"` to imports in `handler_blocklist.go`**

`internal/api/handler_blocklist.go` already imports `"net/http"` but not `"net"`. Add it:

```go
import (
    "fmt"
    "net"
    "net/http"
    // ... rest unchanged
)
```

- [ ] **Step 2: Add `net.ParseIP` skip in `handleCrowdSecCTI`**

The current `handleCrowdSecCTI` ScanScores callback in `internal/api/handler_blocklist.go` is:

```go
	_ = s.store.ScanScores(func(ip string, rec store.ScoreRecord) error {
		if s.passRecord(rec, f, purposePatterns) {
			fmt.Fprintln(w, ip)
		}
		return nil
	})
```

Change it to:

```go
	_ = s.store.ScanScores(func(ip string, rec store.ScoreRecord) error {
		if net.ParseIP(ip) == nil {
			return nil
		}
		if s.passRecord(rec, f, purposePatterns) {
			fmt.Fprintln(w, ip)
		}
		return nil
	})
```

Add `"net"` to the import block of `handler_blocklist.go` if not already present. Check the current imports with `grep -n '"net"' internal/api/handler_blocklist.go` — if absent, add it.

- [ ] **Step 2: Run tests**

```bash
go test ./internal/api/ -v
```

Expected: all tests PASS including `TestHandleCrowdSecCTI_SkipsMalformedKeys`.

- [ ] **Step 3: Commit**

```bash
git add internal/api/handler_blocklist.go internal/api/handler_blocklist_test.go
git commit -m "fix(api): skip malformed store keys in CrowdSec CTI export

Defense-in-depth: handleCrowdSecCTI now skips any key that fails
net.ParseIP, preventing newline-injected or CIDR keys from leaking
into the plaintext decisions feed (Vuln 3).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 5: Adversarial Scenario — CIDR Injection

**Files:**
- Modify: `test/adversarial/poisoning_test.go`

- [ ] **Step 1: Add imports and test**

In `test/adversarial/poisoning_test.go`, the existing import block already has `"context"`, `"fmt"`, `"testing"`, `"time"`, `enforce`, `reputation`, and `store`. Add the four missing packages to the import block:

```go
    "github.com/JoeRu/federloom/internal/config"
    "github.com/JoeRu/federloom/internal/node"
    "github.com/JoeRu/federloom/internal/transport"
    "github.com/JoeRu/federloom/pkg/proto"
```

Then append this test at the end of the file:

```go
// TestCIDRInjectionNeverRecorded verifies that a remote peer repeatedly publishing
// a CIDR string as the IP field cannot accumulate score in the reputation store.
// This is the end-to-end guard for the nftables block-all attack (spec §6.2).
func TestCIDRInjectionNeverRecorded(t *testing.T) {
    dir := t.TempDir()
    cfg := config.Defaults()
    cfg.Store.Dir = dir
    cfg.Reputation.BlockThreshold = 75

    n, err := node.New(cfg, nil)
    if err != nil {
        t.Fatalf("node.New: %v", err)
    }
    defer n.CloseStores()

    // Flood 20 events with a CIDR as the IP from a high-weight peer.
    for i := 0; i < 20; i++ {
        n.ProcessRemote(transport.ReceivedEvent{
            Event: proto.Event{
                IP:         "0.0.0.0/0",
                Reason:     "ssh-probe",
                ReporterID: "12D3KooWattacker",
            },
            From: "12D3KooWattacker",
        })
    }

    rec, err := n.GetScore("0.0.0.0/0")
    if err != nil {
        t.Fatalf("GetScore: %v", err)
    }
    if !rec.LastSeen.IsZero() {
        t.Errorf("CIDR IP reached reputation engine: score=%.1f — IP validation gate missing", rec.Score)
    }
}
```

- [ ] **Step 2: Run the adversarial suite**

```bash
make adversarial
```

Expected: all adversarial tests PASS including `TestCIDRInjectionNeverRecorded`.

- [ ] **Step 3: Commit**

```bash
git add test/adversarial/poisoning_test.go
git commit -m "test(adversarial): add CIDR injection end-to-end scenario

Verifies that a remote peer flooding CIDR strings as IP values never
accumulates score in the reputation store (end-to-end guard for the
nftables block-all attack identified in security review).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 6: Bearer Token Middleware — Tests

**Files:**
- Modify: `internal/api/server_test.go`

- [ ] **Step 1: Add `net/http` and `net/http/httptest` to `server_test.go` imports**

`internal/api/server_test.go` currently only imports `"testing"`, `"time"`, `config`, and `store`. Add the HTTP packages:

```go
import (
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/JoeRu/federloom/internal/config"
    "github.com/JoeRu/federloom/internal/store"
)
```

- [ ] **Step 2: Add failing tests**

Append to `internal/api/server_test.go`:

```go
// TestBearerTokenMiddleware_MissingHeader verifies that a request with no
// Authorization header is rejected with 401 when a token is configured.
func TestBearerTokenMiddleware_MissingHeader(t *testing.T) {
    inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })
    h := bearerTokenMiddleware("secret-token", inner)

    r := httptest.NewRequest(http.MethodGet, "/", nil)
    w := httptest.NewRecorder()
    h.ServeHTTP(w, r)

    if w.Code != http.StatusUnauthorized {
        t.Errorf("got %d, want 401", w.Code)
    }
}

// TestBearerTokenMiddleware_WrongToken verifies that an incorrect token is rejected.
func TestBearerTokenMiddleware_WrongToken(t *testing.T) {
    inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })
    h := bearerTokenMiddleware("secret-token", inner)

    r := httptest.NewRequest(http.MethodGet, "/", nil)
    r.Header.Set("Authorization", "Bearer wrong-token")
    w := httptest.NewRecorder()
    h.ServeHTTP(w, r)

    if w.Code != http.StatusUnauthorized {
        t.Errorf("got %d, want 401", w.Code)
    }
}

// TestBearerTokenMiddleware_CorrectToken verifies that the correct token passes through.
func TestBearerTokenMiddleware_CorrectToken(t *testing.T) {
    var reached bool
    inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        reached = true
        w.WriteHeader(http.StatusOK)
    })
    h := bearerTokenMiddleware("secret-token", inner)

    r := httptest.NewRequest(http.MethodGet, "/", nil)
    r.Header.Set("Authorization", "Bearer secret-token")
    w := httptest.NewRecorder()
    h.ServeHTTP(w, r)

    if w.Code != http.StatusOK {
        t.Errorf("got %d, want 200", w.Code)
    }
    if !reached {
        t.Error("inner handler was not called with correct token")
    }
}

// TestBearerTokenMiddleware_EmptyToken verifies that an empty Authorization value
// is rejected even when the token happens to be empty (edge case: don't call
// bearerTokenMiddleware with empty token — server.go guards this).
func TestBearerTokenMiddleware_EmptyAuthHeader(t *testing.T) {
    inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })
    h := bearerTokenMiddleware("secret-token", inner)

    r := httptest.NewRequest(http.MethodGet, "/", nil)
    r.Header.Set("Authorization", "")
    w := httptest.NewRecorder()
    h.ServeHTTP(w, r)

    if w.Code != http.StatusUnauthorized {
        t.Errorf("got %d, want 401", w.Code)
    }
}
```

- [ ] **Step 3: Run tests to confirm they fail**

```bash
go test ./internal/api/ -run "TestBearerTokenMiddleware" -v
```

Expected: FAIL — `bearerTokenMiddleware` does not exist yet.

---

## Task 7: Bearer Token Middleware — Implementation

**Files:**
- Modify: `internal/api/server.go`

- [ ] **Step 1: Add `"os"` to imports**

In `internal/api/server.go`, add `"os"` to the import block:

```go
import (
    "context"
    "log"
    "net/http"
    "os"
    "sync"
    "time"

    "github.com/JoeRu/federloom/internal/config"
    "github.com/JoeRu/federloom/internal/store"
)
```

- [ ] **Step 2: Add `bearerTokenMiddleware` function**

Append to `internal/api/server.go` (before the closing of the file, after `unsubscribe`):

```go
// bearerTokenMiddleware returns an http.Handler that rejects requests not
// carrying the expected Authorization: Bearer <token> header with 401.
func bearerTokenMiddleware(token string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("Authorization") != "Bearer "+token {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

- [ ] **Step 3: Apply middleware in `Start`**

In `internal/api/server.go`, replace the `Start` function body (the part that builds `srv`) to conditionally wrap the mux:

Current code (lines 61–67):

```go
    mux := http.NewServeMux()
    mux.HandleFunc("GET /api/v1/score/{ip}", s.handleScore)
    mux.HandleFunc("GET /api/v1/blocklist", s.handleBlocklist)
    mux.HandleFunc("GET /api/v1/events", s.handleEvents)
    mux.HandleFunc("GET /crowdsec/v1/decisions", s.handleCrowdSecCTI)

    srv := &http.Server{Addr: s.cfg.Addr, Handler: mux}
```

Replace with:

```go
    mux := http.NewServeMux()
    mux.HandleFunc("GET /api/v1/score/{ip}", s.handleScore)
    mux.HandleFunc("GET /api/v1/blocklist", s.handleBlocklist)
    mux.HandleFunc("GET /api/v1/events", s.handleEvents)
    mux.HandleFunc("GET /crowdsec/v1/decisions", s.handleCrowdSecCTI)

    var handler http.Handler = mux
    if token := os.Getenv("FEDERLOOM_API_TOKEN"); token != "" {
        log.Printf("api: bearer token authentication enabled")
        handler = bearerTokenMiddleware(token, mux)
    } else {
        log.Printf("api: FEDERLOOM_API_TOKEN not set — API is unauthenticated")
    }

    srv := &http.Server{Addr: s.cfg.Addr, Handler: handler}
```

- [ ] **Step 4: Run all API tests**

```bash
go test ./internal/api/ -v
```

Expected: all tests PASS including the four `TestBearerTokenMiddleware_*` tests.

- [ ] **Step 5: Run the full test suite**

```bash
make test
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/api/server.go internal/api/server_test.go
git commit -m "fix(api): add bearer token middleware for API authentication

Reads FEDERLOOM_API_TOKEN from environment. When set, wraps all API
routes with a middleware that rejects requests missing the correct
Authorization: Bearer header with 401. When unset, logs a warning and
operates without auth (backward-compatible). Fixes Vuln 2.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 8: Docker Binding + Secret Management

**Files:**
- Modify: `deploy/honeypot/docker-compose.yml`
- Create: `deploy/honeypot/.env.example`
- Modify: `.gitignore`

- [ ] **Step 1: Restrict port bindings in docker-compose.yml**

In `deploy/honeypot/docker-compose.yml`, the `federloom` service `ports` section currently reads:

```yaml
    ports:
      - "7700:7700"
      - "9101:9101"
      - "9102:9102"
      - "5353:5353/udp"
```

Change to (bind API and Prometheus to Tailscale interface only):

```yaml
    ports:
      - "7700:7700"
      - "100.71.239.1:9101:9101"
      - "100.71.239.1:9102:9102"
      - "5353:5353/udp"
```

- [ ] **Step 2: Add `env_file` to the federloom service**

In the same `federloom` service block, add `env_file` directly after `restart`:

```yaml
  federloom:
    image: ghcr.io/joeru/federloom:latest
    container_name: federloom
    restart: unless-stopped
    env_file:
      - .env
    cap_add: [NET_ADMIN, NET_RAW]
```

- [ ] **Step 3: Create `.env.example`**

Create `deploy/honeypot/.env.example` with content:

```
# Copy to .env and set a strong random value before deploying.
# Generate with: openssl rand -hex 32
FEDERLOOM_API_TOKEN=changeme
```

- [ ] **Step 4: Add `.env` to `.gitignore`**

In `.gitignore`, append under the "Secrets" section:

```
**/.env
```

The secrets section currently ends at `cs-firewall-bouncer.yaml`. Add the line after it.

- [ ] **Step 5: Verify `.env` is ignored**

```bash
echo "FEDERLOOM_API_TOKEN=test" > deploy/honeypot/.env
git check-ignore -v deploy/honeypot/.env
rm deploy/honeypot/.env
```

Expected output: `.gitignore:N:**/.env    deploy/honeypot/.env` (confirms it is gitignored).

- [ ] **Step 6: Commit**

```bash
git add deploy/honeypot/docker-compose.yml deploy/honeypot/.env.example .gitignore
git commit -m "fix(deploy): bind API/Prometheus to Tailscale interface; add token secret

- Port 9101 (Prometheus) and 9102 (API) now bound to 100.71.239.1 only,
  making them invisible to the public internet.
- env_file: .env wires FEDERLOOM_API_TOKEN into the container.
- .env.example committed; **/.env added to .gitignore.
Fixes Vuln 2 (network layer).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Final Verification

- [ ] **Run the full test suite**

```bash
make test
```

Expected: all tests pass.

- [ ] **Run the adversarial suite**

```bash
make adversarial
```

Expected: all adversarial scenarios pass including `TestCIDRInjectionNeverRecorded`.

- [ ] **Run the build**

```bash
make build
```

Expected: `bin/federloomd` and `bin/federloomctl` built without errors.
