# HTTP Honeypot (OpenCanary HTTP/HTTPS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable OpenCanary's built-in HTTP (port 80) and HTTPS (port 443) honeypot modules and map their log entries to `http-*` reason codes in the SwarmGuard ingest adapter.

**Architecture:** Two tasks. Task 1 is pure config — update `opencanary.json` and `docker-compose.yml`, deploy to the honeypot server, verify HTTP/HTTPS responds. Task 2 discovers the actual OpenCanary logtype integers from the running container, then adds them to the existing `openCanaryReasons` map in `internal/ingest/opencanary.go` following the TDD pattern already established for SMTP and IMAP.

**Tech Stack:** Go (existing `ingest` package), OpenCanary Docker container, JSON config, bash (rsync + SSH for deploy).

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `deploy/honeypot/opencanary.json` | Modify | Enable `http` and `https` modules |
| `deploy/honeypot/docker-compose.yml` | Modify | Expose ports 80 and 443 on the opencanary service |
| `internal/ingest/opencanary.go` | Modify | Add HTTP/HTTPS logtypes to `openCanaryReasons` |
| `internal/ingest/opencanary_test.go` | Modify | Add tests for `http-probe` and `https-probe` reason codes |

---

## Task 1: Enable HTTP/HTTPS in OpenCanary config and compose

**Files:**
- Modify: `deploy/honeypot/opencanary.json`
- Modify: `deploy/honeypot/docker-compose.yml`

No Go code in this task. Verification is a live `curl` against the honeypot server.

- [ ] **Step 1: Enable HTTP and HTTPS in `deploy/honeypot/opencanary.json`**

  The file currently has `"http.enabled": false`. Add/update these six keys (keep all existing keys intact):

  ```json
  {
      "device.node_id": "swarmguard-honeypot-1",
      "git.enabled": false,
      "ftp.enabled": false,
      "http.enabled": true,
      "http.port": 80,
      "http.banner": "Apache/2.2.22 (Ubuntu)",
      "https.enabled": true,
      "https.port": 443,
      "https.banner": "Apache/2.2.22 (Ubuntu)",
      "imap.enabled": true,
      "imap.port": 143,
      "smtp.enabled": true,
      "smtp.port": 25,
      "smtp.banner": "220 mail.example.com ESMTP",
      "ssh.enabled": false,
      "telnet.enabled": false,
      "logger": {
          "class": "PyLogger",
          "kwargs": {
              "formatters": {
                  "plain": {
                      "format": "%(message)s"
                  }
              },
              "handlers": {
                  "file": {
                      "class": "logging.FileHandler",
                      "filename": "/var/log/opencanary/opencanary.log",
                      "mode": "a"
                  }
              }
          }
      }
  }
  ```

- [ ] **Step 2: Expose ports 80 and 443 in `deploy/honeypot/docker-compose.yml`**

  In the `opencanary` service's `ports:` block, add two lines after `- "143:143"`:

  ```yaml
    ports:
      - "25:25"
      - "143:143"
      - "80:80"
      - "443:443"
  ```

- [ ] **Step 3: Rsync config to honeypot and restart OpenCanary**

  Run from the repo root:

  ```bash
  rsync -az --delete \
    --exclude='.git' --exclude='bin/' --exclude='data/' \
    --exclude='deploy/wordpress/config.local.yaml' \
    --exclude='deploy/mailcow/config.local.yaml' \
    -e "ssh -p 2244" \
    ./ \
    root@167.233.115.41:/opt/swarmguard/

  ssh -p 2244 root@167.233.115.41 \
    "docker compose -f /opt/swarmguard/deploy/honeypot/docker-compose.yml \
     restart opencanary"
  ```

  Expected: `Container opencanary  Restarted`

- [ ] **Step 4: Verify HTTP and HTTPS respond**

  ```bash
  # HTTP — expect a 200 or 302, not "connection refused"
  curl -si http://swarmguard.jru.me/ 2>&1 | head -3

  # HTTPS — -k to skip cert validation (OpenCanary uses self-signed)
  curl -sik https://swarmguard.jru.me/ 2>&1 | head -3
  ```

  Expected output (exact content varies, but must not be `curl: (7) Failed to connect`):
  ```
  HTTP/1.0 200 OK
  Content-Type: text/html
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add deploy/honeypot/opencanary.json deploy/honeypot/docker-compose.yml
  git commit -m "feat(honeypot): enable OpenCanary HTTP (port 80) and HTTPS (port 443)"
  ```

---

## Task 2: Add HTTP/HTTPS logtypes to the ingest adapter

**Files:**
- Modify: `internal/ingest/opencanary_test.go`
- Modify: `internal/ingest/opencanary.go`

Follow the same TDD pattern as the existing SMTP and IMAP entries. The logtype integers OpenCanary assigns to HTTP events must be discovered from the running container before writing tests — they are version-specific and not reliably documented.

- [ ] **Step 1: Discover the HTTP and HTTPS logtype integers**

  Trigger HTTP and HTTPS requests against the honeypot, then read the log:

  ```bash
  ssh -p 2244 root@167.233.115.41 "
    curl -sf http://localhost/ >/dev/null 2>&1
    curl -sfk https://localhost/ >/dev/null 2>&1
    curl -sf -X POST http://localhost/ -d 'user=admin&pass=test' >/dev/null 2>&1
    sleep 2
    docker exec opencanary tail -6 /var/log/opencanary/opencanary.log
  "
  ```

  Each line will be a JSON object. Extract the `logtype` field:

  ```bash
  ssh -p 2244 root@167.233.115.41 "
    docker exec opencanary tail -6 /var/log/opencanary/opencanary.log
  " | grep -o '"logtype":[0-9]*' | sort -u
  ```

  Example output (actual values depend on the installed OpenCanary version):
  ```
  "logtype":3
  "logtype":3
  ```

  Note all distinct logtype integers. If GET and POST produce the same logtype, one map entry covers both. If they differ, you get separate entries. Use whatever integers this command actually produces — they are the ground truth.

  If the log is empty (no events appeared), verify OpenCanary restarted cleanly:
  ```bash
  ssh -p 2244 root@167.233.115.41 "docker logs opencanary 2>&1 | tail -10"
  ```

- [ ] **Step 2: Write failing tests for the discovered logtypes**

  In `internal/ingest/opencanary_test.go`, add two new test functions after `TestOpenCanaryUnknownLogtype`. Replace `<HTTP_LOGTYPE>` and `<HTTPS_LOGTYPE>` with the integers discovered in Step 1. If HTTP and HTTPS share the same logtype integer, only one test is needed (adjust the reason string accordingly).

  ```go
  func TestOpenCanaryParsesHTTPProbe(t *testing.T) {
  	dir := t.TempDir()
  	logPath := filepath.Join(dir, "opencanary.log")

  	cfg := config.OpenCanaryConfig{
  		Enabled:      true,
  		LogFile:      logPath,
  		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
  	}
  	o := ingest.NewOpenCanary(cfg, "selfpeer")

  	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
  	defer cancel()

  	ch, err := o.Start(ctx)
  	if err != nil {
  		t.Fatalf("Start: %v", err)
  	}

  	writeLines(t, logPath, []string{
  		`{"src_host":"198.51.100.3","logtype":<HTTP_LOGTYPE>,"local_time":"2026-06-19 10:00:00.000000"}`,
  	})

  	select {
  	case e := <-ch:
  		if e.IP != "198.51.100.3" {
  			t.Errorf("IP: got %q, want 198.51.100.3", e.IP)
  		}
  		if e.Reason != "http-probe" {
  			t.Errorf("Reason: got %q, want http-probe", e.Reason)
  		}
  		if e.ReporterID != "selfpeer" {
  			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
  		}
  	case <-ctx.Done():
  		t.Fatal("timed out waiting for event")
  	}
  }

  func TestOpenCanaryParsesHTTPSProbe(t *testing.T) {
  	dir := t.TempDir()
  	logPath := filepath.Join(dir, "opencanary.log")

  	cfg := config.OpenCanaryConfig{
  		Enabled:      true,
  		LogFile:      logPath,
  		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
  	}
  	o := ingest.NewOpenCanary(cfg, "selfpeer")

  	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
  	defer cancel()

  	ch, err := o.Start(ctx)
  	if err != nil {
  		t.Fatalf("Start: %v", err)
  	}

  	writeLines(t, logPath, []string{
  		`{"src_host":"198.51.100.4","logtype":<HTTPS_LOGTYPE>,"local_time":"2026-06-19 10:00:01.000000"}`,
  	})

  	select {
  	case e := <-ch:
  		if e.IP != "198.51.100.4" {
  			t.Errorf("IP: got %q, want 198.51.100.4", e.IP)
  		}
  		if e.Reason != "https-probe" {
  			t.Errorf("Reason: got %q, want https-probe", e.Reason)
  		}
  	case <-ctx.Done():
  		t.Fatal("timed out waiting for event")
  	}
  }
  ```

  **Note:** If HTTP and HTTPS produce the same logtype integer (common in some OpenCanary versions), map it to `"http-probe"` (the more general label) and write only one test. Both `http-probe` and `https-probe` match `http-*` in the taxonomy.

- [ ] **Step 3: Run the tests to confirm they fail**

  ```bash
  go test ./internal/ingest/ -run "TestOpenCanaryParsesHTTP" -v
  ```

  Expected: `FAIL` — the logtypes are not yet in the map, so events come through as `"opencanary-unknown"` instead of `"http-probe"` / `"https-probe"`.

- [ ] **Step 4: Add HTTP/HTTPS logtypes to `internal/ingest/opencanary.go`**

  In `openCanaryReasons`, add entries for the discovered logtype integers. The existing map is:

  ```go
  var openCanaryReasons = map[int]string{
      3000: "smtp-probe",
      3001: "smtp-auth-bruteforce",
      2100: "imap-probe",
      2101: "imap-auth-bruteforce",
  }
  ```

  Add the HTTP/HTTPS entries (replace `<HTTP_LOGTYPE>` and `<HTTPS_LOGTYPE>` with the integers from Step 1):

  ```go
  var openCanaryReasons = map[int]string{
      3000: "smtp-probe",
      3001: "smtp-auth-bruteforce",
      2100: "imap-probe",
      2101: "imap-auth-bruteforce",
      <HTTP_LOGTYPE>:  "http-probe",
      <HTTPS_LOGTYPE>: "https-probe",
  }
  ```

  If HTTP and HTTPS share the same logtype integer, add only one entry:

  ```go
  <SHARED_LOGTYPE>: "http-probe",
  ```

- [ ] **Step 5: Run the tests to confirm they pass**

  ```bash
  go test ./internal/ingest/ -run "TestOpenCanaryParsesHTTP" -v
  ```

  Expected:
  ```
  --- PASS: TestOpenCanaryParsesHTTPProbe (0.05s)
  --- PASS: TestOpenCanaryParsesHTTPSProbe (0.05s)
  PASS
  ```

- [ ] **Step 6: Run the full ingest test suite to check for regressions**

  ```bash
  go test ./internal/ingest/ -v
  ```

  Expected: all tests pass. The previously-passing SMTP and IMAP tests must still pass.

- [ ] **Step 7: Commit**

  ```bash
  git add internal/ingest/opencanary.go internal/ingest/opencanary_test.go
  git commit -m "feat(ingest): add OpenCanary HTTP/HTTPS logtypes to openCanaryReasons"
  ```

---

## Verification

After both tasks are committed and the honeypot is running:

```bash
# 1. Confirm HTTP events appear in swarmguard metrics on the honeypot
#    (make a test request first to generate an event)
curl -s http://swarmguard.jru.me/ >/dev/null
sleep 35   # wait for one poll cycle

curl -s http://167.233.115.41:9101/metrics \
  | grep 'swarmguard_events_received_total.*http'
```

Expected output (reporter label will be the honeypot's peer ID):
```
swarmguard_events_received_total{reason="http-probe",reporter_id="12D3KooW..."} 1
```

```bash
# 2. Confirm the event federated to mailcow (web taxonomy check)
curl -s http://100.120.31.14:9101/metrics \
  | grep 'swarmguard_events_received_total.*http'
```
