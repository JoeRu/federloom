# Honeypot Node Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy a first real-life SwarmGuard honeypot node on `167.233.115.41` that ingests SSH (Cowrie), SMTP, and IMAP (OpenCanary) attack signals and federates them to a local peer via gossipsub.

**Architecture:** A new `internal/ingest/opencanary.go` adapter mirrors `honeypot.go` — it tails OpenCanary's JSONL log and emits `proto.Event`s. Two Docker Compose files deploy the honeypot stack (Cowrie + OpenCanary + SwarmGuard) to the server and a client peer locally. A bootstrap script handles the fresh-server setup.

**Tech Stack:** Go 1.22, Docker Compose v2, Cowrie SSH honeypot, OpenCanary SMTP/IMAP honeypot, libp2p gossipsub.

---

## File Map

| Action | File | Responsibility |
|---|---|---|
| Modify | `internal/config/config.go` | Add `OpenCanaryConfig` struct + field in `IngestConfig` |
| Create | `internal/ingest/opencanary.go` | OpenCanary JSONL log adapter (implements `ingest.Source`) |
| Create | `internal/ingest/opencanary_test.go` | Unit tests for the adapter |
| Modify | `internal/node/node.go` | Wire the OpenCanary source into the node's source list |
| Create | `deploy/honeypot/docker-compose.yml` | Cowrie + OpenCanary + SwarmGuard stack |
| Create | `deploy/honeypot/config.yaml` | SwarmGuard config for honeypot node (sensor-only) |
| Create | `deploy/honeypot/opencanary.json` | OpenCanary module config (smtp + imap enabled) |
| Create | `deploy/honeypot/bootstrap.sh` | Install Docker on server, rsync repo, build image, start stack |
| Create | `deploy/client/docker-compose.yml` | Local SwarmGuard peer |
| Create | `deploy/client/config.yaml` | Client SwarmGuard config (federated, no ingest) |

---

## Task 1: Add OpenCanaryConfig to config

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: Write failing test**

Open `internal/config/config_test.go` and append:

```go
func TestDefaultsOpenCanaryPollInterval(t *testing.T) {
    cfg := config.Defaults()
    if cfg.Ingest.OpenCanary.PollInterval.Duration <= 0 {
        t.Errorf("OpenCanary default PollInterval must be > 0, got %v", cfg.Ingest.OpenCanary.PollInterval.Duration)
    }
}

func TestLoadYAMLOpenCanaryEnabled(t *testing.T) {
    raw := []byte(`
ingest:
  opencanary:
    enabled: true
    log_file: /var/log/opencanary/opencanary.log
    poll_interval: 2s
`)
    cfg, err := config.LoadYAML(raw)
    if err != nil {
        t.Fatalf("LoadYAML: %v", err)
    }
    if !cfg.Ingest.OpenCanary.Enabled {
        t.Error("OpenCanary.Enabled should be true")
    }
    if cfg.Ingest.OpenCanary.LogFile != "/var/log/opencanary/opencanary.log" {
        t.Errorf("LogFile: got %q, want /var/log/opencanary/opencanary.log", cfg.Ingest.OpenCanary.LogFile)
    }
    if cfg.Ingest.OpenCanary.PollInterval.Duration != 2*time.Second {
        t.Errorf("PollInterval: got %v, want 2s", cfg.Ingest.OpenCanary.PollInterval.Duration)
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

```
go test ./internal/config/... -run TestDefaultsOpenCanaryPollInterval -v
```

Expected: `FAIL` — `cfg.Ingest.OpenCanary` field does not exist yet.

- [ ] **Step 3: Add OpenCanaryConfig to config.go**

In `internal/config/config.go`, replace the `IngestConfig` struct:

```go
// IngestConfig groups all ingest source configs.
type IngestConfig struct {
	Honeypot   HoneypotConfig   `yaml:"honeypot"`
	OpenCanary OpenCanaryConfig `yaml:"opencanary"`
}

// OpenCanaryConfig configures the OpenCanary ingest adapter.
type OpenCanaryConfig struct {
	Enabled      bool     `yaml:"enabled"`
	LogFile      string   `yaml:"log_file"`
	PollInterval Duration `yaml:"poll_interval"`
}
```

In `Defaults()`, extend the `Ingest` field:

```go
Ingest: IngestConfig{
    Honeypot: HoneypotConfig{
        PollInterval: Duration{time.Second},
    },
    OpenCanary: OpenCanaryConfig{
        PollInterval: Duration{time.Second},
    },
},
```

- [ ] **Step 4: Run test — expect PASS**

```
go test ./internal/config/... -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add OpenCanaryConfig to IngestConfig"
```

---

## Task 2: Write OpenCanary adapter tests (TDD — red phase)

**Files:**
- Create: `internal/ingest/opencanary_test.go`

Note: `writeLines` is already defined in `internal/ingest/honeypot_test.go` in the same `ingest_test` package — reuse it here.

- [ ] **Step 1: Create the test file**

Create `internal/ingest/opencanary_test.go`:

```go
package ingest_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/ingest"
)

func TestOpenCanaryParsesSMTPProbe(t *testing.T) {
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
		`{"src_host":"198.51.100.1","logtype":3000,"local_time":"2026-06-12 10:00:00.000000"}`,
	})

	select {
	case e := <-ch:
		if e.IP != "198.51.100.1" {
			t.Errorf("IP: got %q, want 198.51.100.1", e.IP)
		}
		if e.Reason != "smtp-probe" {
			t.Errorf("Reason: got %q, want smtp-probe", e.Reason)
		}
		if e.ReporterID != "selfpeer" {
			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestOpenCanaryParsesIMAPAuthBruteforce(t *testing.T) {
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
		`{"src_host":"203.0.113.7","logtype":2101,"local_time":"2026-06-12 10:00:01.000000"}`,
	})

	select {
	case e := <-ch:
		if e.IP != "203.0.113.7" {
			t.Errorf("IP: got %q, want 203.0.113.7", e.IP)
		}
		if e.Reason != "imap-auth-bruteforce" {
			t.Errorf("Reason: got %q, want imap-auth-bruteforce", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestOpenCanarySkipsEmptyHost(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "opencanary.log")

	cfg := config.OpenCanaryConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	o := ingest.NewOpenCanary(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch, err := o.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		`{"src_host":"","logtype":3000,"local_time":"2026-06-12 10:00:00.000000"}`,
	})

	select {
	case e := <-ch:
		t.Errorf("expected no event for empty src_host, got %+v", e)
	case <-ctx.Done():
		// correct — no event emitted
	}
}

func TestOpenCanaryUnknownLogtype(t *testing.T) {
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
		`{"src_host":"198.51.100.2","logtype":9999,"local_time":"2026-06-12 10:00:00.000000"}`,
	})

	select {
	case e := <-ch:
		if e.Reason != "opencanary-unknown" {
			t.Errorf("Reason: got %q, want opencanary-unknown", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}
```

- [ ] **Step 2: Run tests — expect FAIL**

```
go test ./internal/ingest/... -run TestOpenCanary -v
```

Expected: `FAIL` — `ingest.NewOpenCanary` undefined.

---

## Task 3: Implement the OpenCanary ingest adapter (TDD — green phase)

**Files:**
- Create: `internal/ingest/opencanary.go`

- [ ] **Step 1: Create the adapter**

Create `internal/ingest/opencanary.go`:

```go
package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// openCanaryEvent is one JSON line from OpenCanary's log.
type openCanaryEvent struct {
	SrcHost   string `json:"src_host"`
	LogType   int    `json:"logtype"`
	LocalTime string `json:"local_time"`
}

// openCanaryReasons maps OpenCanary logtype to SwarmGuard reason strings.
// Verify these values against the running OpenCanary version if logtypes change:
//
//	docker exec opencanary grep -r "logtype" /usr/local/lib/python*/dist-packages/opencanary/modules/
var openCanaryReasons = map[int]string{
	3000: "smtp-probe",
	3001: "smtp-auth-bruteforce",
	2100: "imap-probe",
	2101: "imap-auth-bruteforce",
}

// OpenCanary tails an OpenCanary JSONL log and emits proto.Events.
// All events carry Trust=1.0 (ground-truth anchor, spec §4.1).
type OpenCanary struct {
	cfg    config.OpenCanaryConfig
	selfID string
}

// Compile-time check: OpenCanary must implement Source.
var _ Source = (*OpenCanary)(nil)

// NewOpenCanary creates an OpenCanary adapter. selfID is the local node's peer ID.
func NewOpenCanary(cfg config.OpenCanaryConfig, selfID string) *OpenCanary {
	return &OpenCanary{cfg: cfg, selfID: selfID}
}

func (o *OpenCanary) Name() string { return "opencanary" }

// Start begins tailing the OpenCanary log file and emitting events until ctx is cancelled.
func (o *OpenCanary) Start(ctx context.Context) (<-chan proto.Event, error) {
	ch := make(chan proto.Event, 64)
	go o.tail(ctx, ch)
	return ch, nil
}

func (o *OpenCanary) tail(ctx context.Context, ch chan<- proto.Event) {
	defer close(ch)

	pollInterval := o.cfg.PollInterval.Duration
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
			f, err := os.Open(o.cfg.LogFile)
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
			for scanner.Scan() {
				line := scanner.Bytes()
				offset += int64(len(line)) + 1 // +1 for newline

				var oe openCanaryEvent
				if err := json.Unmarshal(line, &oe); err != nil {
					continue
				}
				if oe.SrcHost == "" {
					continue
				}

				reason, ok := openCanaryReasons[oe.LogType]
				if !ok {
					reason = "opencanary-unknown"
				}

				e := proto.Event{
					IP:         oe.SrcHost,
					Reason:     reason,
					Timestamp:  time.Now(),
					ReporterID: o.selfID,
				}

				select {
				case ch <- e:
				case <-ctx.Done():
					f.Close()
					return
				default:
					// Channel full — drop (high-volume honeypot noise).
					log.Printf("ingest/opencanary: channel full, dropping event for %s", oe.SrcHost)
				}
			}
			f.Close()
		}
	}
}
```

- [ ] **Step 2: Run OpenCanary tests — expect PASS**

```
go test ./internal/ingest/... -run TestOpenCanary -v
```

Expected: all 4 tests PASS.

- [ ] **Step 3: Run full test suite**

```
go test ./...
```

Expected: all tests PASS. No regressions.

- [ ] **Step 4: Commit**

```bash
git add internal/ingest/opencanary.go internal/ingest/opencanary_test.go
git commit -m "feat(ingest): OpenCanary SMTP/IMAP adapter — tails JSONL, maps logtypes to proto.Event"
```

---

## Task 4: Wire OpenCanary into the node

**Files:**
- Modify: `internal/node/node.go:59-62`

- [ ] **Step 1: Add OpenCanary source to the sources list**

In `internal/node/node.go`, find the block that starts sources (currently around line 59):

```go
	var sources []ingest.Source
	if cfg.Ingest.Honeypot.Enabled {
		sources = append(sources, ingest.NewHoneypot(cfg.Ingest.Honeypot, selfID))
	}
```

Replace with:

```go
	var sources []ingest.Source
	if cfg.Ingest.Honeypot.Enabled {
		sources = append(sources, ingest.NewHoneypot(cfg.Ingest.Honeypot, selfID))
	}
	if cfg.Ingest.OpenCanary.Enabled {
		sources = append(sources, ingest.NewOpenCanary(cfg.Ingest.OpenCanary, selfID))
	}
```

- [ ] **Step 2: Build and test**

```
go build ./...
go test ./...
```

Expected: compiles cleanly, all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/node/node.go
git commit -m "feat(node): wire OpenCanary ingest source when enabled in config"
```

---

## Task 5: Honeypot deploy files

**Files:**
- Create: `deploy/honeypot/docker-compose.yml`
- Create: `deploy/honeypot/config.yaml`
- Create: `deploy/honeypot/opencanary.json`

- [ ] **Step 1: Create deploy/honeypot/docker-compose.yml**

```yaml
# Honeypot stack: Cowrie (SSH) + OpenCanary (SMTP/IMAP) + SwarmGuard node.
# Deploy via deploy/honeypot/bootstrap.sh — do not run directly without reading that script.
services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: cowrie
    restart: unless-stopped
    ports:
      - "22:2222"
    volumes:
      - cowrie-logs:/cowrie/var/log/cowrie

  opencanary:
    image: thinkst/opencanary:latest
    container_name: opencanary
    restart: unless-stopped
    ports:
      - "25:25"
      - "143:143"
    volumes:
      - opencanary-logs:/var/log/opencanary
      - ./opencanary.json:/etc/opencanaryd/opencanary.conf:ro

  swarmguard:
    image: swarmguard:latest
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile
    container_name: swarmguard
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW]
    ports:
      - "7700:7700"
    volumes:
      - ./config.yaml:/etc/swarmguard/config.yaml:ro
      - cowrie-logs:/var/log/cowrie:ro
      - opencanary-logs:/var/log/opencanary:ro
      - swarmguard-data:/var/lib/swarmguard
    command: >
      --config /etc/swarmguard/config.yaml
      --listen /ip4/0.0.0.0/tcp/7700
      --advertise /ip4/167.233.115.41/tcp/7700
    depends_on:
      - cowrie
      - opencanary

volumes:
  cowrie-logs:
  opencanary-logs:
  swarmguard-data:
```

- [ ] **Step 2: Create deploy/honeypot/config.yaml**

```yaml
# SwarmGuard config for the honeypot node.
# block_threshold is set high: this is a sensor node, not a firewall.
federation_mode: federated
store:
  dir: /var/lib/swarmguard
enforce:
  backend: ipset
  set_name: swarmguard
reputation:
  block_threshold: 1000
  unblock_threshold: 900
  half_life: 168h
  decay_interval: 1h
ingest:
  honeypot:
    enabled: true
    log_file: /var/log/cowrie/cowrie.json
    poll_interval: 1s
  opencanary:
    enabled: true
    log_file: /var/log/opencanary/opencanary.log
    poll_interval: 1s
```

- [ ] **Step 3: Create deploy/honeypot/opencanary.json**

```json
{
    "device.node_id": "swarmguard-honeypot-1",
    "git.enabled": false,
    "ftp.enabled": false,
    "http.enabled": false,
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

- [ ] **Step 4: Commit**

```bash
git add deploy/honeypot/
git commit -m "feat(deploy): honeypot stack compose + swarmguard config + opencanary config"
```

---

## Task 6: Bootstrap script

**Files:**
- Create: `deploy/honeypot/bootstrap.sh`

- [ ] **Step 1: Create deploy/honeypot/bootstrap.sh**

```bash
#!/usr/bin/env bash
# Bootstraps the honeypot stack on a fresh Ubuntu server.
# Usage: ./deploy/honeypot/bootstrap.sh
# Requires: ssh access to 167.233.115.41 on port 2244 as root, rsync installed locally.
set -euo pipefail

SERVER="167.233.115.41"
SSH_PORT="2244"
SSH_USER="root"
REMOTE_DIR="/opt/swarmguard"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ssh_run() { ssh -p "$SSH_PORT" "$SSH_USER@$SERVER" "$@"; }

echo "==> [1/5] Installing Docker on $SERVER"
ssh_run '
  set -e
  if command -v docker &>/dev/null; then
    echo "Docker already installed: $(docker --version)"
    exit 0
  fi
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2
  systemctl enable --now docker
  echo "Installed: $(docker --version)"
'

echo "==> [2/5] Syncing repo to $SERVER:$REMOTE_DIR"
rsync -az --delete \
  --exclude='.git' --exclude='bin/' --exclude='data/' \
  -e "ssh -p $SSH_PORT" \
  "$REPO_ROOT/" \
  "$SSH_USER@$SERVER:$REMOTE_DIR/"

echo "==> [3/5] Building swarmguard image on server (first run takes ~2 min)"
ssh_run "cd $REMOTE_DIR && docker build -t swarmguard:latest -f deploy/docker/Dockerfile . -q"

echo "==> [4/5] Starting honeypot stack"
ssh_run "
  docker compose -f $REMOTE_DIR/deploy/honeypot/docker-compose.yml pull --ignore-pull-failures 2>/dev/null || true
  docker compose -f $REMOTE_DIR/deploy/honeypot/docker-compose.yml up -d
"

echo "==> [5/5] Waiting 15s for swarmd to print peer ID..."
sleep 15

PEER_ID=$(ssh_run "docker logs swarmguard 2>/dev/null | grep 'peer ID:' | tail -1 | awk '{print \$NF}'" || true)

echo ""
if [[ -z "$PEER_ID" ]]; then
  echo "WARNING: could not read peer ID from logs yet."
  echo "  Check: ssh -p $SSH_PORT $SSH_USER@$SERVER 'docker logs swarmguard 2>&1 | head -30'"
else
  echo "Honeypot stack running on $SERVER"
  echo "  Peer ID : $PEER_ID"
  echo "  Bootstrap multiaddr: /ip4/$SERVER/tcp/7700/p2p/$PEER_ID"
  echo ""
  echo "Next: start the client peer:"
  echo "  HONEYPOT_PEER_ADDR=/ip4/$SERVER/tcp/7700/p2p/$PEER_ID \\"
  echo "    docker compose -f deploy/client/docker-compose.yml up"
fi
```

- [ ] **Step 2: Make executable**

```bash
chmod +x deploy/honeypot/bootstrap.sh
```

- [ ] **Step 3: Commit**

```bash
git add deploy/honeypot/bootstrap.sh
git commit -m "feat(deploy): bootstrap script — installs Docker, syncs repo, starts honeypot stack"
```

---

## Task 7: Client deploy files

**Files:**
- Create: `deploy/client/docker-compose.yml`
- Create: `deploy/client/config.yaml`

The bootstrap peer address is passed as the `HONEYPOT_PEER_ADDR` environment variable rather than the config file, because `--bootstrap` is a CLI flag in `cmd/swarmd/main.go`, not a YAML config key.

- [ ] **Step 1: Create deploy/client/docker-compose.yml**

```yaml
# Local SwarmGuard peer for smoke-testing federation with the honeypot node.
# Usage:
#   HONEYPOT_PEER_ADDR=/ip4/167.233.115.41/tcp/7700/p2p/<PEER_ID> \
#     docker compose -f deploy/client/docker-compose.yml up
services:
  swarmguard:
    image: swarmguard:latest
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile
    container_name: swarmguard-client
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW]
    ports:
      - "7701:7700"
    volumes:
      - ./config.yaml:/etc/swarmguard/config.yaml:ro
      - swarmguard-client-data:/var/lib/swarmguard
    command: >
      --config /etc/swarmguard/config.yaml
      --listen /ip4/0.0.0.0/tcp/7700
      --bootstrap ${HONEYPOT_PEER_ADDR}

volumes:
  swarmguard-client-data:
```

- [ ] **Step 2: Create deploy/client/config.yaml**

```yaml
# SwarmGuard config for the local federated peer (smoke test client).
# No ingest sources — this node only receives events via gossipsub.
federation_mode: federated
store:
  dir: /var/lib/swarmguard
enforce:
  backend: ipset
  set_name: swarmguard-client
reputation:
  block_threshold: 1000
  unblock_threshold: 900
  half_life: 168h
  decay_interval: 1h
```

- [ ] **Step 3: Build the local client image**

```bash
docker build -t swarmguard:latest -f deploy/docker/Dockerfile .
```

Expected: build succeeds. Both `bin/swarmd` and `bin/swarmctl` produced inside container.

- [ ] **Step 4: Commit**

```bash
git add deploy/client/
git commit -m "feat(deploy): client peer compose + config for federation smoke test"
```

---

## Task 8: Smoke test — run it end-to-end

**Prerequisites:** Docker is installed locally. The server is reachable at `167.233.115.41:2244`.

- [ ] **Step 1: Run bootstrap.sh**

```bash
./deploy/honeypot/bootstrap.sh
```

Expected output ends with something like:
```
Honeypot stack running on 167.233.115.41
  Peer ID : 12D3KooW...
  Bootstrap multiaddr: /ip4/167.233.115.41/tcp/7700/p2p/12D3KooW...
```

If the peer ID is missing, check logs manually:
```bash
ssh -p 2244 root@167.233.115.41 'docker logs swarmguard 2>&1 | head -30'
```

- [ ] **Step 2: Start the local client**

Copy the printed bootstrap multiaddr from Step 1 and run:

```bash
HONEYPOT_PEER_ADDR=/ip4/167.233.115.41/tcp/7700/p2p/12D3KooW... \
  docker compose -f deploy/client/docker-compose.yml up
```

Expected: client logs show:
```
peer ID: 12D3KooW...
listening on: /ip4/0.0.0.0/tcp/7700/p2p/12D3KooW...
```

- [ ] **Step 3: Watch for federated events**

Keep the client running. Within 5 minutes, real internet traffic will hit the honeypot's ports 22/25/143. Watch for the client log line that indicates a remote event was received and scored:

```
node: record remote <IP>: ...
```

or alternatively, watch the honeypot node's own logs for ingest events:
```bash
ssh -p 2244 root@167.233.115.41 'docker logs -f swarmguard 2>&1'
```

You should see lines like:
```
swarmd running (enforce=ipset, honeypot=true)
node: record local <attacker-IP>: ...
```

- [ ] **Step 4: Verify OpenCanary logtypes (if no SMTP/IMAP events appear)**

If SMTP/IMAP events don't flow through after several minutes, verify the actual logtypes OpenCanary emits:

```bash
ssh -p 2244 root@167.233.115.41 '
  # Send a test SMTP connection to trigger a log entry:
  echo "QUIT" | nc -w3 localhost 25 || true
  sleep 2
  docker exec opencanary cat /var/log/opencanary/opencanary.log | tail -5
'
```

Check the `logtype` field in the output. If it differs from 3000/2100, update `openCanaryReasons` in `internal/ingest/opencanary.go`, rebuild, and redeploy:

```bash
./deploy/honeypot/bootstrap.sh
```

- [ ] **Step 5: Pass/fail judgement**

**PASS:** At least one `node: record remote` log line appears in the local client within 5 minutes of connecting.

**FAIL:** If no remote events appear, check:
1. `docker logs swarmguard` on the server — are local events being recorded?
2. `docker logs cowrie` / `docker logs opencanary` — are honeypot logs being written?
3. Network: is port 7700 reachable? `nc -zv 167.233.115.41 7700`
4. Gossipsub: is the peer connected? (libp2p connection log in swarmd output)
