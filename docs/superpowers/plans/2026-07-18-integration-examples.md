# Integration Examples (`examples/`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the public `examples/` folder (9 integrations), the B1 fail2ban bare-metal mode, and the CI validate + smoke harness, per spec `docs/superpowers/specs/2026-07-18-integration-examples-design.md`.

**Architecture:** One new Go config knob (`ingest.fail2ban.mode`), one strict-decode validator tool wired into CI, one shell smoke harness that builds the current image and attacks each docker example, and nine self-contained example folders following the proven deploy pattern (federloomd on `network_mode: host` enforcing ipset; detectors on a bridge network with LAPI published on `127.0.0.1`).

**Tech Stack:** Go 1.22, yaml.v3 strict decoding, Docker Compose v2, CrowdSec (`crowdsecurity/crowdsec` image, `BOUNCER_KEY_*` auto-registration), fail2ban, GitHub Actions.

## Global Constraints

- Go 1.22; conventional commits; docs ship in the same PR as the feature.
- `examples/` folders are fully self-contained (approach C): a user copies ONE folder and follows its README. No cross-folder includes.
- Invariant 1 (lists are aids, not law): every example config/rules file carries a comment that thresholds/rules are locally overridable.
- Observability is default OFF in every example (never enable `observability:` keys; commented-out at most).
- Image reference in examples: `ghcr.io/joeru/federloom:latest` (built from `deploy/docker/Dockerfile`).
- federloomd flags: `--config <path>` (also `--listen <multiaddr>`; examples rely on defaults unless stated).
- Existing config schema is authoritative (`internal/config/config.go`): valid top-level keys include `federation_mode`, `store`, `reputation`, `ingest`, `enforce`, `trust`, `api`, `bootstrap_peers`. `make validate-examples` (Task 2) must pass after every example task.
- Smoke assertions poll `GET /api/v1/score/{ip}` (returns 404 until the IP has a record, then 200) — never parse logs.
- CrowdSec ingest emits reason `crowdsec-decision` for decisions. fail2ban ingest maps jails via `builtinJailReasons` (`sshd`→`ssh-auth-bruteforce`, `nginx-*`→`http-auth-bruteforce`, `apache-*`→`http-auth-bruteforce`, `recidive`→`recidive`).
- `deploy/` is NOT touched (personal lab). `examples/mailcow` and `examples/wordpress` are generalisations, not moves.
- Commit after every task with the exact message given in the task's final step.

---

### Task 1: B1 — fail2ban `mode: local | docker`

**Files:**
- Modify: `internal/config/config.go:155-162` (Fail2BanConfig)
- Modify: `internal/ingest/fail2ban.go`
- Test: `internal/ingest/fail2ban_test.go` (append)
- Modify: `docs/config.md` (fail2ban section — add `mode` key)
- Modify: `docs/backlog.md` (mark B1 done)

**Interfaces:**
- Consumes: existing `config.Fail2BanConfig`, `ingest.NewFail2Ban(cfg, selfID)`, injectable `fail2banFetcher`.
- Produces: new YAML key `ingest.fail2ban.mode` with values `"docker"` (default, empty = docker) and `"local"`. `Start` returns `error` for any other value. All example configs in later tasks rely on `mode: local` existing.

- [ ] **Step 1: Write the failing tests** — append to `internal/ingest/fail2ban_test.go`:

```go
// TestFail2Ban_InvalidMode: unknown mode → Start returns an error.
func TestFail2Ban_InvalidMode(t *testing.T) {
	cfg := makeFail2BanCfg(50 * time.Millisecond)
	cfg.Mode = "bogus"
	f := ingest.NewFail2Ban(cfg, "selfpeer")
	if _, err := f.Start(context.Background()); err == nil {
		t.Fatal("Start: want error for mode \"bogus\", got nil")
	}
}

// TestFail2Ban_LocalModeStarts: mode "local" is accepted (fetcher wired).
func TestFail2Ban_LocalModeStarts(t *testing.T) {
	cfg := makeFail2BanCfg(time.Hour) // long poll: fetcher never actually runs
	cfg.Mode = "local"
	f := ingest.NewFail2Ban(cfg, "selfpeer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := f.Start(ctx); err != nil {
		t.Fatalf("Start: unexpected error for mode \"local\": %v", err)
	}
}

// TestFail2Ban_DockerModeDefault: empty mode behaves as docker mode (no error).
func TestFail2Ban_DockerModeDefault(t *testing.T) {
	cfg := makeFail2BanCfg(time.Hour)
	cfg.Mode = ""
	f := ingest.NewFail2Ban(cfg, "selfpeer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := f.Start(ctx); err != nil {
		t.Fatalf("Start: unexpected error for empty mode: %v", err)
	}
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `go test ./internal/ingest/ -run TestFail2Ban_InvalidMode -v`
Expected: FAIL to compile — `cfg.Mode undefined`.

- [ ] **Step 3: Add the config field** — in `internal/config/config.go`, replace the `Fail2BanConfig` block with:

```go
// Fail2BanConfig configures the fail2ban ingest adapter.
// mode "docker" (default) polls `docker exec <container> fail2ban-client banned`;
// mode "local" polls `fail2ban-client banned` directly on the host (bare-metal
// fail2ban; federloomd needs access to the fail2ban socket, i.e. root).
type Fail2BanConfig struct {
	Enabled      bool              `yaml:"enabled"`
	Mode         string            `yaml:"mode"`          // "docker" (default) | "local"
	Container    string            `yaml:"container"`     // docker mode only; default: "fail2ban"
	PollInterval Duration          `yaml:"poll_interval"` // default: 30s
	JailReasons  map[string]string `yaml:"jail_reasons"`  // operator overrides (exact match only)
}
```

- [ ] **Step 4: Implement mode selection** — in `internal/ingest/fail2ban.go`:

Add `"fmt"` to imports. After `dockerBanned`, add:

```go
// localBanned is the bare-metal fetcher: runs `fail2ban-client banned` directly
// on the host (fail2ban installed as an OS package, no Docker).
func localBanned(ctx context.Context, _ string) ([]byte, error) {
	return exec.CommandContext(ctx, "fail2ban-client", "banned").Output()
}
```

Replace `NewFail2Ban` with:

```go
// NewFail2Ban creates a Fail2Ban adapter, selecting the fetcher by cfg.Mode:
// "docker" (or empty) polls via `docker exec`, "local" polls the host's
// fail2ban-client directly. An unknown mode leaves the fetcher nil; Start
// reports the error.
func NewFail2Ban(cfg config.Fail2BanConfig, selfID string) *Fail2Ban {
	var f fail2banFetcher
	switch cfg.Mode {
	case "", "docker":
		f = dockerBanned
	case "local":
		f = localBanned
	}
	return NewFail2BanWithFetcher(cfg, selfID, f)
}
```

In `Start`, before `ch := make(...)`, add:

```go
	if f.fetcher == nil {
		return nil, fmt.Errorf("fail2ban: unknown mode %q (valid: \"docker\", \"local\")", f.cfg.Mode)
	}
```

- [ ] **Step 5: Run tests, verify pass**

Run: `go test ./internal/ingest/ -run TestFail2Ban -v`
Expected: all `TestFail2Ban_*` PASS (including the four pre-existing ones).

- [ ] **Step 6: Full gate**

Run: `make test && make lint && make adversarial`
Expected: all pass. Adversarial note: this change adds no scoring/trust path (fetcher selection only), so no new scenario is required — state this in the commit body.

- [ ] **Step 7: Update docs** — in `docs/config.md`, find the `ingest.fail2ban` section and add directly under the `enabled` key documentation:

```markdown
| `ingest.fail2ban.mode` | `docker` | `docker` polls `docker exec <container> fail2ban-client banned`; `local` runs `fail2ban-client banned` directly on the host (bare-metal fail2ban — federloomd must run as root or have access to the fail2ban socket). |
```

(Match the table/format style used by the surrounding fail2ban keys in that file; if the section is prose rather than a table, add an equivalent sentence.)

In `docs/backlog.md`, change the B1 heading to `### B1 — fail2ban ingest: bare-metal (non-Docker) mode — DONE` and append the line: `Done: implemented as \`ingest.fail2ban.mode: local | docker\` (default docker).` Remove the "Blocks:" paragraph.

- [ ] **Step 8: Commit**

```bash
git add internal/config/config.go internal/ingest/fail2ban.go internal/ingest/fail2ban_test.go docs/config.md docs/backlog.md
git commit -m "feat(ingest): fail2ban mode local|docker for bare-metal hosts (backlog B1)"
```

---

### Task 2: `validate-examples` tool + Makefile target + CI job

**Files:**
- Create: `tools/validate-examples/main.go`
- Test: `tools/validate-examples/main_test.go`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `config.Config` (`internal/config`), `rules.Rule` (`internal/rules`), yaml.v3 `KnownFields(true)`.
- Produces: `make validate-examples` — strict-decodes every `config*.yaml|yml` and `rules*.yaml|yml` under the given dirs and `docker compose config -q`-validates every `docker-compose*.yml` under `examples/`. Exit 0 = all OK. Every later task runs this as its gate. Exported for tests: `validateFile(path string) error` (returns nil for non-config/rules files).

- [ ] **Step 1: Write the failing test** — `tools/validate-examples/main_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidateFile_GoodConfig(t *testing.T) {
	p := write(t, t.TempDir(), "config.yaml", "federation_mode: solo\nstore:\n  dir: /tmp/x\n")
	if err := validateFile(p); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestValidateFile_UnknownKeyConfig(t *testing.T) {
	p := write(t, t.TempDir(), "config.yaml", "no_such_key: true\n")
	if err := validateFile(p); err == nil {
		t.Error("config with unknown key accepted; want error")
	}
}

func TestValidateFile_GoodRules(t *testing.T) {
	p := write(t, t.TempDir(), "rules.yaml", "- name: r1\n  reason: ssh-auth-bruteforce\n  min_corroboration: 1\n  action: block\n")
	if err := validateFile(p); err != nil {
		t.Errorf("valid rules rejected: %v", err)
	}
}

func TestValidateFile_UnknownKeyRules(t *testing.T) {
	p := write(t, t.TempDir(), "rules.yaml", "- name: r1\n  bogus_field: 1\n  action: block\n")
	if err := validateFile(p); err == nil {
		t.Error("rules with unknown key accepted; want error")
	}
}

func TestValidateFile_OtherFilesSkipped(t *testing.T) {
	p := write(t, t.TempDir(), "docker-compose.yml", "services: {}\n")
	if err := validateFile(p); err != nil {
		t.Errorf("non-config file should be skipped, got: %v", err)
	}
}
```

- [ ] **Step 2: Run test, verify it fails**

Run: `go test ./tools/validate-examples/ -v`
Expected: FAIL — package does not exist / `validateFile` undefined.

- [ ] **Step 3: Implement** — `tools/validate-examples/main.go`:

```go
// Command validate-examples strict-decodes every example config and rules file
// against the current schemas. Unknown keys are errors — this is the CI gate
// that keeps published examples from rotting as the config schema evolves.
//
// Usage: go run ./tools/validate-examples <dir> [<dir>...]
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/rules"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-examples <dir> [<dir>...]")
		os.Exit(2)
	}
	failures := 0
	checked := 0
	for _, root := range os.Args[1:] {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			if !isCandidate(path) {
				return nil
			}
			checked++
			if verr := validateFile(path); verr != nil {
				fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", path, verr)
				failures++
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL walking %s: %v\n", root, err)
			failures++
		}
	}
	if failures > 0 {
		os.Exit(1)
	}
	fmt.Printf("validate-examples: %d files OK\n", checked)
}

func isCandidate(path string) bool {
	base := filepath.Base(path)
	if !strings.HasSuffix(base, ".yaml") && !strings.HasSuffix(base, ".yml") {
		return false
	}
	return strings.HasPrefix(base, "config") || strings.HasPrefix(base, "rules")
}

// validateFile strict-decodes config*.yaml against config.Config and
// rules*.yaml against []rules.Rule. Files matching neither prefix are skipped.
func validateFile(path string) error {
	base := filepath.Base(path)
	switch {
	case !isCandidate(path):
		return nil
	case strings.HasPrefix(base, "config"):
		return strictDecode(path, &config.Config{})
	default: // rules*
		return strictDecode(path, &[]rules.Rule{})
	}
}

func strictDecode(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(target); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `go test ./tools/validate-examples/ -v`
Expected: 5 PASS.

- [ ] **Step 5: Sanity-run against the existing repo files**

Run: `go run ./tools/validate-examples deploy/examples`
Expected: `validate-examples: 4 files OK` (three configs + rules.yaml; they were truth-upped in v0.1.0 and must still pass). If any FAIL, the example file is at fault — fix the example file, not the tool, and note it in the commit.

- [ ] **Step 6: Makefile target** — add to `Makefile` (and add `validate-examples` to the `.PHONY` line):

```make
validate-examples:  ## strict-validate example configs/rules + compose files (CI gate)
	go run ./tools/validate-examples deploy/examples $(wildcard examples)
	@set -e; for f in $$(find examples -name 'docker-compose*.yml' 2>/dev/null); do \
		echo "compose config $$f"; \
		docker compose -f $$f config -q; \
	done
```

Run: `make validate-examples`
Expected: `validate-examples: 4 files OK` (examples/ does not exist yet; `$(wildcard)` drops it and find finds nothing).

- [ ] **Step 7: CI job** — in `.github/workflows/ci.yml`, add under `jobs:`:

```yaml
  examples:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: make validate-examples
```

- [ ] **Step 8: Commit**

```bash
git add tools/validate-examples/ Makefile .github/workflows/ci.yml
git commit -m "feat(ci): validate-examples strict-decode gate for example configs"
```

---

### Task 3: Smoke harness + smoke CI workflow

**Files:**
- Create: `test/examples/run-smoke.sh` (mode 0755)
- Create: `test/examples/lib.sh`
- Create: `.github/workflows/examples-smoke.yml`

**Interfaces:**
- Consumes: `deploy/docker/Dockerfile` (image build), Docker Compose v2.
- Produces: the per-example smoke contract used by Tasks 5–12: each docker example dir may contain an executable `smoke.sh`; the harness `cd`s into the dir, runs `docker compose up -d`, executes `./smoke.sh`, and always runs `docker compose down -v`. `smoke.sh` sources `lib.sh` (path: repo-root-relative `test/examples/lib.sh`) and uses `wait_for_score <base-url> <ip> [timeout-seconds]`.

- [ ] **Step 1: Write `test/examples/lib.sh`**

```bash
# Shared helpers for example smoke tests. Source from an example's smoke.sh:
#   . "$(git rev-parse --show-toplevel)/test/examples/lib.sh"

# wait_for_score <base-url> <ip> [timeout-seconds]
# Polls GET <base-url>/api/v1/score/<ip> until HTTP 200 (the IP has a
# reputation record — proves detector → ingest → reputation → store → API).
wait_for_score() {
    local base="$1" ip="$2" timeout="${3:-120}"
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local code
        code=$(curl -s -o /dev/null -w '%{http_code}' "$base/api/v1/score/$ip" || true)
        if [ "$code" = "200" ]; then
            echo "PASS: score record present for $ip"
            return 0
        fi
        sleep 3
    done
    echo "FAIL: no score record for $ip after ${timeout}s"
    return 1
}

# retry <attempts> <sleep-seconds> <command...>
# Retries a command (e.g. cscli inside a container that is still booting).
retry() {
    local attempts="$1" pause="$2"; shift 2
    local i
    for i in $(seq 1 "$attempts"); do
        if "$@"; then return 0; fi
        sleep "$pause"
    done
    echo "FAIL: command did not succeed after $attempts attempts: $*"
    return 1
}
```

- [ ] **Step 2: Write `test/examples/run-smoke.sh`**

```bash
#!/usr/bin/env bash
# Smoke-runner for docker examples.
# Usage: test/examples/run-smoke.sh [example-dir ...]
# With no args, runs every dir under examples/ that contains a smoke.sh.
# Contract per example dir: docker compose up -d && ./smoke.sh; down -v always.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "--- building federloom image from current source ---"
docker build -t ghcr.io/joeru/federloom:latest \
    -f "$REPO_ROOT/deploy/docker/Dockerfile" "$REPO_ROOT"

dirs=("$@")
if [ ${#dirs[@]} -eq 0 ]; then
    while IFS= read -r s; do dirs+=("$(dirname "$s")"); done \
        < <(find "$REPO_ROOT/examples" -name smoke.sh 2>/dev/null | sort)
fi
if [ ${#dirs[@]} -eq 0 ]; then
    echo "no smoke-testable examples found — nothing to do"
    exit 0
fi

fail=0
for dir in "${dirs[@]}"; do
    echo "=== smoke: $dir ==="
    if (
        cd "$dir"
        trap 'docker compose down -v >/dev/null 2>&1 || true' EXIT
        docker compose up -d
        ./smoke.sh
    ); then
        echo "=== PASS: $dir ==="
    else
        echo "=== FAIL: $dir ==="
        fail=1
    fi
done
exit $fail
```

Run: `chmod +x test/examples/run-smoke.sh`

- [ ] **Step 3: Verify the empty-set path**

Run: `./test/examples/run-smoke.sh`
Expected: image builds, then `no smoke-testable examples found — nothing to do`, exit 0.

- [ ] **Step 4: CI workflow** — `.github/workflows/examples-smoke.yml`:

```yaml
name: examples-smoke
on:
  pull_request:
    paths:
      - 'examples/**'
      - 'test/examples/**'
      - 'deploy/docker/**'
  schedule:
    - cron: '17 3 * * *'   # nightly — catches rot from upstream image changes
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./test/examples/run-smoke.sh
```

- [ ] **Step 5: Commit**

```bash
git add test/examples/ .github/workflows/examples-smoke.yml
git commit -m "feat(ci): docker-example smoke harness (build image, attack, assert via score API)"
```

---

### Task 4: `examples/vps-fail2ban/` — bare-metal hello-world

**Files:**
- Create: `examples/vps-fail2ban/README.md`
- Create: `examples/vps-fail2ban/config.yaml`
- Create: `examples/vps-fail2ban/rules.yaml`
- Create: `examples/vps-fail2ban/federloomd.service`

**Interfaces:**
- Consumes: `ingest.fail2ban.mode: local` (Task 1).
- Produces: the README structure template every later example README follows: **What you get → Prerequisites → Setup → Verify it works → Solo vs. join a federation → Teardown**.

- [ ] **Step 1: Write `config.yaml`**

```yaml
# FederLoom on a plain VPS: federate what your fail2ban already detects.
# Every value here is a local default — lists are aids, not law; override freely.
federation_mode: solo          # switch to "federated" to share/receive (see README)
store:
  dir: /var/lib/federloom
ingest:
  fail2ban:
    enabled: true
    mode: local                # host-installed fail2ban (no Docker)
    poll_interval: 30s
enforce:
  backend: ipset
  set_name: federloom
  chains: [INPUT]              # host services (sshd) arrive via INPUT
reputation:
  rules_file: /etc/federloom/rules.yaml
api:
  addr: "127.0.0.1:9102"       # local status API — keep it off public interfaces
# Join a federation: set federation_mode: federated and add peers, e.g.
# bootstrap_peers:
#   - /dns4/peer.example.org/tcp/7700/p2p/12D3KooW...
```

- [ ] **Step 2: Write `rules.yaml`**

```yaml
# Blocking rules — yours to change: lists are aids, not law.
# Local fail2ban detections are high-confidence: one report is enough to block.
- name: local-ssh-bruteforce
  reason: ssh-auth-bruteforce
  min_corroboration: 1
  action: block
- name: local-recidive
  reason: recidive
  min_corroboration: 1
  action: block
# Federation dividend: block what 3+ independent reporters agree on
# (only fires once you are federated).
- name: multi-reporter
  min_corroboration: 3
  action: block
```

- [ ] **Step 3: Write `federloomd.service`**

```ini
[Unit]
Description=FederLoom federated blocklist daemon
Documentation=https://github.com/JoeRu/federloom
After=network-online.target fail2ban.service
Wants=network-online.target

[Service]
# Root is required: ipset enforcement + fail2ban-client socket access.
ExecStart=/usr/local/bin/federloomd --config /etc/federloom/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 4: Write `README.md`**

```markdown
# FederLoom on a plain VPS (fail2ban, 5 minutes)

Already running fail2ban? This example federates it: every IP your jails ban
feeds your local FederLoom reputation store, gets blocked in O(1) via ipset,
and — once you federate — is shared with peers you trust (and you benefit from
theirs).

## What you get

- `config.yaml` — FederLoom reading your host fail2ban (`mode: local`).
- `rules.yaml` — block rules (your own detections block immediately).
- `federloomd.service` — systemd unit.

## Prerequisites

- Linux host with `fail2ban` installed and running (e.g. the stock `sshd` jail).
- `ipset` + `iptables` installed.
- Go 1.22+ to build the binary (prebuilt binaries: see project releases).

## Setup

1. Build and install the daemon:

       git clone https://github.com/JoeRu/federloom && cd federloom
       make build
       sudo install -m 0755 bin/federloomd /usr/local/bin/

2. Install the config (review it first — every threshold is yours to override):

       sudo mkdir -p /etc/federloom /var/lib/federloom
       sudo cp examples/vps-fail2ban/config.yaml examples/vps-fail2ban/rules.yaml /etc/federloom/

3. Install and start the service:

       sudo cp examples/vps-fail2ban/federloomd.service /etc/systemd/system/
       sudo systemctl daemon-reload
       sudo systemctl enable --now federloomd

## Verify it works

Ban a documentation IP through fail2ban, watch it appear in FederLoom:

    sudo fail2ban-client set sshd banip 203.0.113.99
    sleep 35   # one poll interval
    curl -s http://127.0.0.1:9102/api/v1/score/203.0.113.99   # → JSON with score
    sudo ipset list federloom | grep 203.0.113.99             # → blocked in the set

Clean up the test entry:

    sudo fail2ban-client set sshd unbanip 203.0.113.99
    sudo ipset del federloom 203.0.113.99 2>/dev/null || true

## Solo vs. join a federation

The config ships `federation_mode: solo`: everything stays on this host. To
federate, set `federation_mode: federated`, uncomment `bootstrap_peers` with a
peer you trust, and restart. See `docs/federation-guide.md` for anchors and
invites. Your local whitelist (own IPs, gateway, DNS) is never shared.

## Teardown

    sudo systemctl disable --now federloomd
    sudo rm /etc/systemd/system/federloomd.service /usr/local/bin/federloomd
    sudo rm -r /etc/federloom /var/lib/federloom
    sudo ipset destroy federloom 2>/dev/null || true
```

- [ ] **Step 5: Validate**

Run: `make validate-examples`
Expected: `validate-examples: 6 files OK` (4 in deploy/examples + this config + rules), no compose failures.

- [ ] **Step 6: Commit**

```bash
git add examples/vps-fail2ban/
git commit -m "docs(examples): vps-fail2ban — bare-metal hello-world integration"
```

---

### Task 5: `examples/crowdsec/` — bidirectional CrowdSec bridge (docker, smoke-tested)

**Files:**
- Create: `examples/crowdsec/README.md`
- Create: `examples/crowdsec/docker-compose.yml`
- Create: `examples/crowdsec/config.yaml`
- Create: `examples/crowdsec/rules.yaml`
- Create: `examples/crowdsec/smoke.sh` (mode 0755)

**Interfaces:**
- Consumes: smoke contract from Task 3 (`lib.sh`: `wait_for_score`, `retry`); CrowdSec image `BOUNCER_KEY_<name>` env auto-registration.
- Produces: the docker example pattern reused by Tasks 6–10: CrowdSec sidecar publishing LAPI on `127.0.0.1:8080`, federloomd on `network_mode: host`, API on `127.0.0.1:9102`, bouncer key pair `BOUNCER_KEY_federloom` env ↔ `api_key` in config.

- [ ] **Step 1: Write `docker-compose.yml`**

```yaml
# CrowdSec ⇄ FederLoom bridge. Both directions:
#   ingest: FederLoom polls CrowdSec LAPI decisions
#   serve:  FederLoom exposes GET /crowdsec/v1/decisions (plain-text IP list)
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: federloom-crowdsec
    restart: unless-stopped
    environment:
      # Auto-registers a bouncer named "federloom" with this key.
      # CHANGE THE KEY if this host is shared; it must match api_key in config.yaml.
      BOUNCER_KEY_federloom: "federloom-example-key"
    ports:
      - "127.0.0.1:8080:8080"   # LAPI, localhost only — never expose publicly
    volumes:
      - crowdsec-config:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data

  federloom:
    image: ghcr.io/joeru/federloom:latest
    container_name: federloom
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW]
    network_mode: host          # enforce on the host firewall; reach LAPI via 127.0.0.1
    volumes:
      - ./config.yaml:/etc/federloom/config.yaml:ro
      - ./rules.yaml:/etc/federloom/rules.yaml:ro
      - federloom-data:/var/lib/federloom
    depends_on: [crowdsec]

volumes:
  crowdsec-config:
  crowdsec-data:
  federloom-data:
```

- [ ] **Step 2: Write `config.yaml`**

```yaml
# FederLoom fed by a local CrowdSec. Every value is locally overridable —
# lists are aids, not law.
federation_mode: solo          # switch to "federated" to share/receive (see README)
store:
  dir: /var/lib/federloom
ingest:
  crowdsec:
    enabled: true
    lapi_url: "http://127.0.0.1:8080"
    api_key: "federloom-example-key"   # must match BOUNCER_KEY_federloom in docker-compose.yml
    poll_interval: 10s
    enable_decisions: true
    enable_alerts: false       # alerts need machine auth; decisions are enough here
enforce:
  backend: ipset
  set_name: federloom
  chains: [INPUT, DOCKER-USER]   # protect host services and containers
reputation:
  rules_file: /etc/federloom/rules.yaml
api:
  addr: "127.0.0.1:9102"       # score API + /crowdsec/v1/decisions plain-text feed
```

- [ ] **Step 3: Write `rules.yaml`**

```yaml
# Blocking rules — yours to change: lists are aids, not law.
# A decision your own CrowdSec already made is high-confidence.
- name: local-crowdsec-decision
  reason: crowdsec-decision
  min_corroboration: 1
  action: block
# Federation dividend (fires once federated).
- name: multi-reporter
  min_corroboration: 3
  action: block
```

- [ ] **Step 4: Write `smoke.sh`**

```bash
#!/usr/bin/env bash
# Smoke: inject a CrowdSec decision, expect it in the FederLoom score API and
# in the plain-text serve endpoint. Run via test/examples/run-smoke.sh.
set -euo pipefail
. "$(git rev-parse --show-toplevel)/test/examples/lib.sh"

IP=203.0.113.99

# LAPI may still be booting; retry the injection.
retry 20 3 docker compose exec -T crowdsec \
    cscli decisions add -i "$IP" -d 5m -R smoke-test

wait_for_score "http://127.0.0.1:9102" "$IP" 120

# Serve direction: the plain-text feed must include the IP.
retry 10 3 sh -c "curl -fsS http://127.0.0.1:9102/crowdsec/v1/decisions | grep -q '^$IP\$'"
echo "PASS: serve endpoint lists $IP"
```

Run: `chmod +x examples/crowdsec/smoke.sh`

- [ ] **Step 5: Write `README.md`** — same section structure as Task 4's README. Content requirements (write full prose, no placeholders):
  - *What you get*: both directions explained — FederLoom as a CrowdSec "bouncer" consuming decisions; FederLoom serving `GET /crowdsec/v1/decisions` (one IP per line) that any remote bouncer/firewall can pull.
  - *Prerequisites*: Docker + Compose v2. Nothing else — CrowdSec is part of the compose file.
  - *Setup*: `docker compose up -d`; note to change `federloom-example-key` in BOTH files; where CrowdSec acquis would be added for real log sources (`docker compose exec crowdsec cscli collections install ...`).
  - *Verify it works*: the exact three commands from `smoke.sh` (cscli decisions add → curl score → curl decisions feed), plus `sudo ipset list federloom`.
  - *Solo vs. join a federation*: same text pattern as Task 4.
  - *Teardown*: `docker compose down -v`, `sudo ipset destroy federloom`.

- [ ] **Step 6: Validate + smoke**

Run: `make validate-examples`
Expected: 8 files OK + `compose config examples/crowdsec/docker-compose.yml` passes.

Run: `./test/examples/run-smoke.sh examples/crowdsec`
Expected: image build, compose up, `PASS: score record present for 203.0.113.99`, `PASS: serve endpoint lists 203.0.113.99`, `=== PASS`. If ipset creation fails inside the runner, that is logged by federloomd but must not fail the smoke (assertions are API-only). Debug with `docker compose logs federloom` before changing anything.

- [ ] **Step 7: Commit**

```bash
git add examples/crowdsec/
git commit -m "docs(examples): crowdsec bridge — bidirectional, smoke-tested"
```

---

### Task 6: `examples/nginx/` — os + docker variants

**Files:**
- Create: `examples/nginx/os/README.md`
- Create: `examples/nginx/os/jail.d/federloom-nginx.local`
- Create: `examples/nginx/os/config.yaml`
- Create: `examples/nginx/os/rules.yaml`
- Create: `examples/nginx/docker/README.md`
- Create: `examples/nginx/docker/docker-compose.yml`
- Create: `examples/nginx/docker/acquis.yaml`
- Create: `examples/nginx/docker/config.yaml`
- Create: `examples/nginx/docker/rules.yaml`
- Create: `examples/nginx/docker/smoke.sh` (0755)

**Interfaces:**
- Consumes: Task 1 (`mode: local`), Task 5 pattern (CrowdSec sidecar + host-net federloomd), Task 3 smoke contract.
- Produces: the os-variant pattern (jail.d snippet + local-mode config) reused by Task 9.

- [ ] **Step 1: os variant — `jail.d/federloom-nginx.local`**

```ini
# Drop into /etc/fail2ban/jail.d/ — enables the stock nginx jails.
# FederLoom picks the bans up via `fail2ban-client banned` (mode: local).
[nginx-http-auth]
enabled = true

[nginx-botsearch]
enabled = true
```

- [ ] **Step 2: os variant — `config.yaml`**: identical to Task 4 Step 1 content with one change — the comment on line 1 reads `# FederLoom on a bare-metal nginx host: federate what fail2ban detects in your nginx logs.` (fail2ban `mode: local` picks up ALL enabled jails including sshd — that is desired; say so in the README).

- [ ] **Step 3: os variant — `rules.yaml`**

```yaml
# Blocking rules — yours to change: lists are aids, not law.
- name: local-http-bruteforce
  reason: http-auth-bruteforce
  min_corroboration: 1
  action: block
- name: local-ssh-bruteforce
  reason: ssh-auth-bruteforce
  min_corroboration: 1
  action: block
- name: multi-reporter
  min_corroboration: 3
  action: block
```

- [ ] **Step 4: os variant — `README.md`**: Task 4 README structure. Setup = Task 4 setup steps plus `sudo cp jail.d/federloom-nginx.local /etc/fail2ban/jail.d/ && sudo systemctl reload fail2ban`. Verify = `sudo fail2ban-client set nginx-http-auth banip 203.0.113.99` then the same curl/ipset checks as Task 4.

- [ ] **Step 5: docker variant — `docker-compose.yml`**

```yaml
# nginx protected by CrowdSec (log parsing) + FederLoom (federated reputation
# + host-firewall enforcement). Attackers blocked in DOCKER-USER never reach nginx.
services:
  nginx:
    image: nginx:alpine
    container_name: federloom-nginx
    restart: unless-stopped
    ports:
      - "8081:80"
    volumes:
      - nginx-logs:/var/log/nginx   # real files (replaces the stdout symlinks)

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: federloom-nginx-crowdsec
    restart: unless-stopped
    environment:
      COLLECTIONS: "crowdsecurity/nginx"
      BOUNCER_KEY_federloom: "federloom-example-key"   # change me; must match config.yaml
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - nginx-logs:/var/log/nginx:ro
      - ./acquis.yaml:/etc/crowdsec/acquis.d/nginx.yaml:ro
      - crowdsec-config:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
    depends_on: [nginx]

  federloom:
    image: ghcr.io/joeru/federloom:latest
    container_name: federloom
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW]
    network_mode: host
    volumes:
      - ./config.yaml:/etc/federloom/config.yaml:ro
      - ./rules.yaml:/etc/federloom/rules.yaml:ro
      - federloom-data:/var/lib/federloom
    depends_on: [crowdsec]

volumes:
  nginx-logs:
  crowdsec-config:
  crowdsec-data:
  federloom-data:
```

- [ ] **Step 6: docker variant — `acquis.yaml`**

```yaml
filenames:
  - /var/log/nginx/*.log
labels:
  type: nginx
```

- [ ] **Step 7: docker variant — `config.yaml` and `rules.yaml`**: identical content to Task 5 Steps 2–3 (CrowdSec ingest, `crowdsec-decision` rule), with the `config.yaml` line-1 comment `# FederLoom for a dockerized nginx, fed by the CrowdSec sidecar.`.

- [ ] **Step 8: docker variant — `smoke.sh`**: identical to Task 5 Step 4 minus the serve-endpoint block (that direction is covered once, in the crowdsec example):

```bash
#!/usr/bin/env bash
set -euo pipefail
. "$(git rev-parse --show-toplevel)/test/examples/lib.sh"
IP=203.0.113.99
retry 20 3 docker compose exec -T crowdsec \
    cscli decisions add -i "$IP" -d 5m -R smoke-test
wait_for_score "http://127.0.0.1:9102" "$IP" 120
```

Run: `chmod +x examples/nginx/docker/smoke.sh`

- [ ] **Step 9: docker variant — `README.md`**: Task 4 structure. Verify section: real-traffic path (`for i in $(seq 1 20); do curl -s -o /dev/null http://<public-ip>:8081/wp-login.php; done` from an external host triggers `crowdsecurity/http-probing`; note that requests from private/RFC1918 addresses are whitelisted by CrowdSec's default parsers, so test from outside or use the cscli injection shown in the smoke script).

- [ ] **Step 10: Validate + smoke + commit**

Run: `make validate-examples` → all OK. Run: `./test/examples/run-smoke.sh examples/nginx/docker` → PASS.

```bash
git add examples/nginx/
git commit -m "docs(examples): nginx — os (fail2ban) and docker (crowdsec sidecar) variants"
```

---

### Task 7: `examples/wordpress/docker/` — override for the canonical WordPress compose

**Files:**
- Create: `examples/wordpress/docker/README.md`
- Create: `examples/wordpress/docker/docker-compose.yml`
- Create: `examples/wordpress/docker/acquis.yaml`
- Create: `examples/wordpress/docker/config.yaml`
- Create: `examples/wordpress/docker/rules.yaml`
- Create: `examples/wordpress/docker/smoke.sh` (0755)

**Interfaces:**
- Consumes: Task 5 pattern; Task 3 smoke contract; CrowdSec docker-acquisition (needs `/var/run/docker.sock:ro`).
- Produces: the docker-log-acquisition pattern (for services that log to stdout) reused by Tasks 9–10.

- [ ] **Step 1: `docker-compose.yml`** — full standalone stack (wordpress + db + crowdsec + federloom). WordPress logs to stdout, so CrowdSec reads it via the Docker socket:

```yaml
# WordPress + MariaDB + CrowdSec (wordpress collection) + FederLoom.
# wp-login/xmlrpc brute force → CrowdSec decision → FederLoom reputation →
# host-firewall block (DOCKER-USER) → attacker never reaches WordPress again.
services:
  db:
    image: mariadb:11
    container_name: federloom-wp-db
    restart: unless-stopped
    environment:
      MARIADB_DATABASE: wordpress
      MARIADB_USER: wordpress
      MARIADB_PASSWORD: "change-me-db-pass"
      MARIADB_RANDOM_ROOT_PASSWORD: "1"
    volumes:
      - db-data:/var/lib/mysql

  wordpress:
    image: wordpress:latest
    container_name: federloom-wordpress
    restart: unless-stopped
    ports:
      - "8081:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_NAME: wordpress
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: "change-me-db-pass"
    depends_on: [db]

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: federloom-wp-crowdsec
    restart: unless-stopped
    environment:
      COLLECTIONS: "crowdsecurity/wordpress"
      BOUNCER_KEY_federloom: "federloom-example-key"   # change me; must match config.yaml
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro   # read wordpress stdout logs
      - ./acquis.yaml:/etc/crowdsec/acquis.d/wordpress.yaml:ro
      - crowdsec-config:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
    depends_on: [wordpress]

  federloom:
    image: ghcr.io/joeru/federloom:latest
    container_name: federloom
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW]
    network_mode: host
    volumes:
      - ./config.yaml:/etc/federloom/config.yaml:ro
      - ./rules.yaml:/etc/federloom/rules.yaml:ro
      - federloom-data:/var/lib/federloom
    depends_on: [crowdsec]

volumes:
  db-data:
  crowdsec-config:
  crowdsec-data:
  federloom-data:
```

- [ ] **Step 2: `acquis.yaml`**

```yaml
source: docker
container_name:
  - federloom-wordpress
labels:
  type: apache2
```

- [ ] **Step 3: `config.yaml` / `rules.yaml`**: identical to Task 5 Steps 2–3; `config.yaml` line-1 comment `# FederLoom for a dockerized WordPress, fed by the CrowdSec sidecar.`

- [ ] **Step 4: `smoke.sh`**: identical content to Task 6 Step 8. `chmod +x`.

- [ ] **Step 5: `README.md`**: Task 4 structure. Extra content: (a) "Already have a WordPress compose stack?" subsection — copy only the `crowdsec` + `federloom` services and the `acquis.yaml`/`config.yaml`/`rules.yaml` files into the existing project and set `container_name` in `acquis.yaml` to the real WordPress container; (b) change-me notes for the DB password and bouncer key; (c) verify via `cscli decisions add` as in the smoke script.

- [ ] **Step 6: Validate + smoke + commit**

Run: `make validate-examples` → OK. Run: `./test/examples/run-smoke.sh examples/wordpress/docker` → PASS.

```bash
git add examples/wordpress/
git commit -m "docs(examples): wordpress — crowdsec sidecar stack, smoke-tested"
```

---

### Task 8: `examples/traefik/docker/`

**Files:**
- Create: `examples/traefik/docker/README.md`
- Create: `examples/traefik/docker/docker-compose.yml`
- Create: `examples/traefik/docker/acquis.yaml`
- Create: `examples/traefik/docker/config.yaml`
- Create: `examples/traefik/docker/rules.yaml`
- Create: `examples/traefik/docker/smoke.sh` (0755)

**Interfaces:**
- Consumes: Task 5 pattern (file-based acquis like Task 6, since traefik writes an access-log file), Task 3 smoke contract.

- [ ] **Step 1: `docker-compose.yml`**

```yaml
# Traefik + demo backend + CrowdSec (traefik collection) + FederLoom.
# One FederLoom protects EVERY service behind Traefik: blocked attackers are
# dropped in DOCKER-USER before they reach the proxy.
services:
  traefik:
    image: traefik:v3.1
    container_name: federloom-traefik
    restart: unless-stopped
    command:
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
      - --accesslog=true
      - --accesslog.filepath=/var/log/traefik/access.log
    ports:
      - "8081:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - traefik-logs:/var/log/traefik

  whoami:
    image: traefik/whoami
    container_name: federloom-whoami
    restart: unless-stopped
    labels:
      - traefik.enable=true
      - traefik.http.routers.whoami.rule=PathPrefix(`/`)
      - traefik.http.routers.whoami.entrypoints=web

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: federloom-traefik-crowdsec
    restart: unless-stopped
    environment:
      COLLECTIONS: "crowdsecurity/traefik"
      BOUNCER_KEY_federloom: "federloom-example-key"   # change me; must match config.yaml
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - traefik-logs:/var/log/traefik:ro
      - ./acquis.yaml:/etc/crowdsec/acquis.d/traefik.yaml:ro
      - crowdsec-config:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
    depends_on: [traefik]

  federloom:
    image: ghcr.io/joeru/federloom:latest
    container_name: federloom
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW]
    network_mode: host
    volumes:
      - ./config.yaml:/etc/federloom/config.yaml:ro
      - ./rules.yaml:/etc/federloom/rules.yaml:ro
      - federloom-data:/var/lib/federloom
    depends_on: [crowdsec]

volumes:
  traefik-logs:
  crowdsec-config:
  crowdsec-data:
  federloom-data:
```

- [ ] **Step 2: `acquis.yaml`**

```yaml
filenames:
  - /var/log/traefik/access.log
labels:
  type: traefik
```

- [ ] **Step 3: `config.yaml` / `rules.yaml`**: identical to Task 5 Steps 2–3; line-1 comment `# FederLoom behind Traefik: one node protects every routed service.`

- [ ] **Step 4: `smoke.sh`**: identical content to Task 6 Step 8. `chmod +x`.

- [ ] **Step 5: `README.md`**: Task 4 structure + "Add to your existing Traefik stack" subsection (copy crowdsec + federloom services; point the shared log volume at your traefik's `--accesslog.filepath`).

- [ ] **Step 6: Validate + smoke + commit**

Run: `make validate-examples` → OK. Run: `./test/examples/run-smoke.sh examples/traefik/docker` → PASS.

```bash
git add examples/traefik/
git commit -m "docs(examples): traefik — protect every routed service, smoke-tested"
```

---

### Task 9: `examples/apache/` — os + docker variants

**Files:**
- Create: `examples/apache/os/README.md`
- Create: `examples/apache/os/jail.d/federloom-apache.local`
- Create: `examples/apache/os/config.yaml`
- Create: `examples/apache/os/rules.yaml`
- Create: `examples/apache/docker/README.md`
- Create: `examples/apache/docker/docker-compose.yml`
- Create: `examples/apache/docker/acquis.yaml`
- Create: `examples/apache/docker/config.yaml`
- Create: `examples/apache/docker/rules.yaml`
- Create: `examples/apache/docker/smoke.sh` (0755)

**Interfaces:**
- Consumes: Task 6 os pattern; Task 7 docker-acquisition pattern; Task 3 smoke contract.

- [ ] **Step 1: os variant** — mirror Task 6 Steps 1–4 with apache substitutions:

`jail.d/federloom-apache.local`:

```ini
# Drop into /etc/fail2ban/jail.d/ — enables the stock apache jails.
# FederLoom picks the bans up via `fail2ban-client banned` (mode: local).
[apache-auth]
enabled = true

[apache-badbots]
enabled = true
```

`config.yaml`: Task 4 Step 1 content, line-1 comment `# FederLoom on a bare-metal Apache host: federate what fail2ban detects in your Apache logs.`
`rules.yaml`: identical to Task 6 Step 3.
`README.md`: Task 6 Step 4 content with apache jail names (`apache-auth` in the verify command).

- [ ] **Step 2: docker variant** — mirror Task 6 docker with httpd + docker-acquisition:

`docker-compose.yml`: same shape as Task 7 Step 1 minus the `db`/`wordpress` services, with instead:

```yaml
  apache:
    image: httpd:2.4
    container_name: federloom-apache
    restart: unless-stopped
    ports:
      - "8081:80"
```

crowdsec service: `COLLECTIONS: "crowdsecurity/apache2"`, Docker socket + `./acquis.yaml:/etc/crowdsec/acquis.d/apache.yaml:ro` mounts, `depends_on: [apache]`. federloom service and volumes identical to Task 7 (without `db-data`).

`acquis.yaml`:

```yaml
source: docker
container_name:
  - federloom-apache
labels:
  type: apache2
```

`config.yaml` / `rules.yaml`: Task 5 Steps 2–3 content, comment `# FederLoom for a dockerized Apache httpd, fed by the CrowdSec sidecar.`
`smoke.sh`: Task 6 Step 8 content, `chmod +x`.
`README.md`: Task 4 structure.

- [ ] **Step 3: Validate + smoke + commit**

Run: `make validate-examples` → OK. Run: `./test/examples/run-smoke.sh examples/apache/docker` → PASS.

```bash
git add examples/apache/
git commit -m "docs(examples): apache — os (fail2ban) and docker (crowdsec sidecar) variants"
```

---

### Task 10: `examples/haproxy/docker/` — detect AND consume at the edge

**Files:**
- Create: `examples/haproxy/docker/README.md`
- Create: `examples/haproxy/docker/docker-compose.yml`
- Create: `examples/haproxy/docker/haproxy.cfg`
- Create: `examples/haproxy/docker/blocklist.acl` (empty file, committed)
- Create: `examples/haproxy/docker/fetch-blocklist.sh` (0755)
- Create: `examples/haproxy/docker/acquis.yaml`
- Create: `examples/haproxy/docker/config.yaml`
- Create: `examples/haproxy/docker/rules.yaml`
- Create: `examples/haproxy/docker/smoke.sh` (0755)

**Interfaces:**
- Consumes: Task 7 docker-acquisition pattern; Task 3 smoke contract; `GET /crowdsec/v1/decisions` plain-text feed.
- Produces: the consume-side fetch pattern referenced by Task 12's README.

- [ ] **Step 1: `haproxy.cfg`**

```
global
    log stdout format raw local0

defaults
    mode http
    log global
    option httplog
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend web
    bind :80
    # FederLoom deny list, refreshed by fetch-blocklist.sh (see README).
    acl blocked src -f /usr/local/etc/haproxy/blocklist.acl
    http-request deny deny_status 403 if blocked
    default_backend app

backend app
    server whoami whoami:80
```

- [ ] **Step 2: `docker-compose.yml`**

```yaml
# HAProxy + CrowdSec (detect) + FederLoom (federate + enforce), plus the
# reverse direction: HAProxy denies IPs from FederLoom's blocklist feed at the
# proxy layer (defence in depth on top of the host-firewall block).
services:
  haproxy:
    image: haproxy:2.9-alpine
    container_name: federloom-haproxy
    restart: unless-stopped
    ports:
      - "8081:80"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
      - ./blocklist.acl:/usr/local/etc/haproxy/blocklist.acl:ro
    depends_on: [whoami]

  whoami:
    image: traefik/whoami
    container_name: federloom-haproxy-whoami
    restart: unless-stopped

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: federloom-haproxy-crowdsec
    restart: unless-stopped
    environment:
      COLLECTIONS: "crowdsecurity/haproxy"
      BOUNCER_KEY_federloom: "federloom-example-key"   # change me; must match config.yaml
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./acquis.yaml:/etc/crowdsec/acquis.d/haproxy.yaml:ro
      - crowdsec-config:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
    depends_on: [haproxy]

  federloom:
    image: ghcr.io/joeru/federloom:latest
    container_name: federloom
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW]
    network_mode: host
    volumes:
      - ./config.yaml:/etc/federloom/config.yaml:ro
      - ./rules.yaml:/etc/federloom/rules.yaml:ro
      - federloom-data:/var/lib/federloom
    depends_on: [crowdsec]

volumes:
  crowdsec-config:
  crowdsec-data:
  federloom-data:
```

- [ ] **Step 3: `acquis.yaml`**

```yaml
source: docker
container_name:
  - federloom-haproxy
labels:
  type: haproxy
```

- [ ] **Step 4: `fetch-blocklist.sh`**

```bash
#!/usr/bin/env bash
# Refresh HAProxy's deny list from FederLoom and hot-reload HAProxy.
# Run periodically, e.g. */5 cron:  cd <this dir> && ./fetch-blocklist.sh
set -euo pipefail
cd "$(dirname "$0")"
curl -fsS http://127.0.0.1:9102/crowdsec/v1/decisions > blocklist.acl.tmp
mv blocklist.acl.tmp blocklist.acl
docker compose kill -s HUP haproxy
```

- [ ] **Step 5: `blocklist.acl`** — create empty (`touch examples/haproxy/docker/blocklist.acl`); add the comment line `# populated by fetch-blocklist.sh — one IP per line` as its only content.

- [ ] **Step 6: `config.yaml` / `rules.yaml`**: Task 5 Steps 2–3 content; comment `# FederLoom at the HAProxy edge: detect via CrowdSec, deny at proxy + firewall.`

- [ ] **Step 7: `smoke.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
. "$(git rev-parse --show-toplevel)/test/examples/lib.sh"
IP=203.0.113.99
retry 20 3 docker compose exec -T crowdsec \
    cscli decisions add -i "$IP" -d 5m -R smoke-test
wait_for_score "http://127.0.0.1:9102" "$IP" 120
# Consume direction: fetch script must land the IP in the ACL file.
./fetch-blocklist.sh
grep -q "^$IP\$" blocklist.acl
echo "PASS: blocklist.acl contains $IP"
git checkout -- blocklist.acl   # restore the committed placeholder
```

Run: `chmod +x examples/haproxy/docker/smoke.sh examples/haproxy/docker/fetch-blocklist.sh`

- [ ] **Step 8: `README.md`**: Task 4 structure + a "Both directions" section explaining detect (CrowdSec parses HAProxy logs) vs. consume (cron `fetch-blocklist.sh`; note the deny also exists at the host firewall — the ACL adds proxy-layer defence and works even where federloom runs on a different host).

- [ ] **Step 9: Validate + smoke + commit**

Run: `make validate-examples` → OK. Run: `./test/examples/run-smoke.sh examples/haproxy/docker` → PASS.

```bash
git add examples/haproxy/
git commit -m "docs(examples): haproxy — detect via crowdsec, consume blocklist as edge ACL"
```

---

### Task 11: `examples/mailcow/` — generalised non-invasive override

**Files:**
- Create: `examples/mailcow/README.md`
- Create: `examples/mailcow/docker-compose.override.yml`
- Create: `examples/mailcow/federloom/config.yaml`
- Create: `examples/mailcow/federloom/rules.yaml`

**Interfaces:**
- Consumes: `deploy/mailcow/*` as source material (generalise; do NOT modify deploy/). MailcowConfig defaults (`mailcowdockerized-postfix-mailcow-1`, `mailcowdockerized-dovecot-mailcow-1`).
- Produces: nothing consumed later. No smoke.sh — this override requires a live Mailcow install; it is gate-checked by `make validate-examples` only. State this in the README.

- [ ] **Step 1: `docker-compose.override.yml`** — copy `deploy/mailcow/docker-compose.override.yml` (it is already generic: image, docker.sock ro, `./federloom/config.yaml` mount, host network, NET_ADMIN) and add one line to the federloom service's volume list: `- ./federloom/rules.yaml:/etc/federloom/rules.yaml:ro`.

- [ ] **Step 2: `federloom/config.yaml`** — generalised from `deploy/mailcow/config.yaml`: remove the personal bootstrap peer and the `config.local.yaml` merge comment; `federation_mode: solo` with the commented federated block (Task 4 Step 1 pattern); keep `ingest.mailcow_logs` (enabled, default container names, 30s poll), commented-out `spamtrap` and `crowdsec` blocks with their existing explanatory comments, `enforce` (ipset, `chains: [INPUT, DOCKER-USER]`), `reputation.rules_file: /etc/federloom/rules.yaml`, `api` (addr `127.0.0.1:9102`, purpose `mail`, the mail taxonomy block from the deploy config). Omit `observability` and `dnsbl` entirely (README mentions both as opt-in, pointing at docs/config.md).

- [ ] **Step 3: `federloom/rules.yaml`**

```yaml
# Blocking rules — yours to change: lists are aids, not law.
- name: local-smtp-bruteforce
  reason: smtp-auth-bruteforce
  min_corroboration: 1
  action: block
- name: local-imap-bruteforce
  reason: imap-auth-bruteforce
  min_corroboration: 1
  action: block
- name: multi-reporter
  min_corroboration: 3
  action: block
```

- [ ] **Step 4: `README.md`**: Task 4 structure, based on `deploy/mailcow/README.md` content but generic. Key points: copy the folder into `/opt/mailcow-dockerized/`, `docker compose up -d federloom` — non-invasive/upgrade-safe (compose merges the override; zero changes to mailcow's files, pattern of JoeRu/Mailcow-Crowdsec-Override); verify via `docker logs federloom` + score API after a real failed IMAP/SMTP login; note "cannot be smoke-tested standalone — validated against the config schema in CI"; adjust container names if the mailcow project dir differs (`docker ps | grep postfix`).

- [ ] **Step 5: Validate + commit**

Run: `make validate-examples` → OK (config + rules strict-decode; `docker compose -f examples/mailcow/docker-compose.override.yml config -q` passes standalone).

```bash
git add examples/mailcow/
git commit -m "docs(examples): mailcow — generalised non-invasive override"
```

---

### Task 12: `examples/firewall-export/` — agentless consumption by firewalls

**Files:**
- Create: `examples/firewall-export/README.md`
- Create: `examples/firewall-export/docker-compose.yml`
- Create: `examples/firewall-export/config.yaml`
- Create: `examples/firewall-export/smoke.sh` (0755)

**Interfaces:**
- Consumes: `GET /crowdsec/v1/decisions` (plain text, one IP/line), Task 3 smoke contract.

- [ ] **Step 1: `docker-compose.yml`**

```yaml
# FederLoom as a blocklist SOURCE for firewalls (OPNsense, pfSense, MikroTik,
# FortiGate): no agent on the firewall — it just fetches a plain-text URL.
# SECURITY: bind the published port to a management/VPN interface, never to a
# WAN address. The API has no auth; network reachability IS the trust boundary.
services:
  federloom:
    image: ghcr.io/joeru/federloom:latest
    container_name: federloom-export
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW]
    ports:
      # Change 127.0.0.1 to your management/VPN interface IP so your firewall
      # can reach it, e.g. "10.0.0.5:9102:9102".
      - "127.0.0.1:9102:9102"
    volumes:
      - ./config.yaml:/etc/federloom/config.yaml:ro
      - federloom-data:/var/lib/federloom

volumes:
  federloom-data:
```

- [ ] **Step 2: `config.yaml`**

```yaml
# Export-only FederLoom node. On its own it serves an EMPTY list — join a
# federation (or enable an ingest source) so there is something to export.
# Every threshold is locally overridable — lists are aids, not law.
federation_mode: solo          # set to "federated" + bootstrap_peers for real use
store:
  dir: /var/lib/federloom
enforce:
  backend: ipset
  set_name: federloom
api:
  addr: ":9102"                # container-internal; host binding set in docker-compose.yml
# bootstrap_peers:
#   - /dns4/peer.example.org/tcp/7700/p2p/12D3KooW...
```

- [ ] **Step 3: `smoke.sh`**

```bash
#!/usr/bin/env bash
# Smoke: the export endpoint answers 200 text/plain (empty list is fine —
# this example has no ingest; it proves the serving path only).
set -euo pipefail
. "$(git rev-parse --show-toplevel)/test/examples/lib.sh"
retry 20 3 curl -fsS -o /dev/null http://127.0.0.1:9102/crowdsec/v1/decisions
ct=$(curl -fsS -o /dev/null -w '%{content_type}' http://127.0.0.1:9102/crowdsec/v1/decisions)
case "$ct" in text/plain*) echo "PASS: export endpoint serves text/plain" ;;
              *) echo "FAIL: content-type $ct"; exit 1 ;; esac
```

Run: `chmod +x examples/firewall-export/smoke.sh`

- [ ] **Step 4: `README.md`** — Task 4 structure, with one subsection per consumer (exact steps):
  - **OPNsense**: Firewall → Aliases → add alias, Type *URL Table (IPs)*, Content `http://<federloom-host>:9102/crowdsec/v1/decisions`, refresh interval 0.25 days (≈ every 6 h; pick shorter for faster reaction) → use the alias in a WAN block rule.
  - **pfSense**: Firewall → Aliases → URLs → *URL Table (IPs)* with the same URL; update frequency 1 day minimum granularity — note pfSense refresh is coarser.
  - **MikroTik RouterOS**: `/tool fetch url="http://<host>:9102/crowdsec/v1/decisions" dst-path=federloom.txt` + `/import` script converting lines to `/ip firewall address-list add list=federloom address=$ip timeout=6h`, run from `/system scheduler` — include the complete RouterOS script in the README.
  - **FortiGate**: Security Fabric → External Connectors → Threat Feeds → *IP Address*, URL as above, refresh rate 60 min → use as source in a deny policy.
  - **Security section** (mandatory, spec): the endpoint is unauthenticated by design; expose only on management/VPN networks; the list contains IPs treated as personal data under GDPR — do not republish publicly (spec §9).

- [ ] **Step 5: Validate + smoke + commit**

Run: `make validate-examples` → OK. Run: `./test/examples/run-smoke.sh examples/firewall-export` → PASS.

```bash
git add examples/firewall-export/
git commit -m "docs(examples): firewall-export — agentless OPNsense/pfSense/MikroTik/FortiGate feeds"
```

---

### Task 13: `examples/README.md` chooser + docs integration + CHANGELOG

**Files:**
- Create: `examples/README.md`
- Modify: `README.md` (root — add Integrations section)
- Modify: `docs/getting-started.md` (pointer to vps-fail2ban)
- Modify: `CHANGELOG.md` (Unreleased section)

**Interfaces:**
- Consumes: all nine example folders (verify each link resolves).

- [ ] **Step 1: `examples/README.md`**

```markdown
# FederLoom integration examples

Copy-paste-ready integrations. Every folder is self-contained: copy it, follow
its README, done. Configs are CI-validated against the current schema; docker
examples are smoke-tested (simulated attack → IP appears in the blocklist API).

## I run … → go here

| You run | Example | Style | Detector |
|---|---|---|---|
| A plain VPS with fail2ban | [`vps-fail2ban/`](vps-fail2ban/) | OS install | fail2ban (`mode: local`) |
| nginx on the host | [`nginx/os/`](nginx/os/) | OS install | fail2ban web jails |
| nginx in Docker | [`nginx/docker/`](nginx/docker/) | Compose | CrowdSec sidecar |
| Apache on the host | [`apache/os/`](apache/os/) | OS install | fail2ban web jails |
| Apache in Docker | [`apache/docker/`](apache/docker/) | Compose | CrowdSec sidecar |
| WordPress | [`wordpress/docker/`](wordpress/docker/) | Compose | CrowdSec (wordpress collection) |
| Traefik | [`traefik/docker/`](traefik/docker/) | Compose | CrowdSec (traefik collection) |
| HAProxy | [`haproxy/docker/`](haproxy/docker/) | Compose | CrowdSec + edge ACL consume |
| CrowdSec already | [`crowdsec/`](crowdsec/) | Compose | bidirectional bridge |
| Mailcow | [`mailcow/`](mailcow/) | Compose override | native mailcow log ingest |
| OPNsense / pfSense / MikroTik / FortiGate | [`firewall-export/`](firewall-export/) | agentless | consumes the plain-text feed |

## How the docker examples are built

The pattern everywhere: your service + a CrowdSec sidecar (parses the logs,
publishes LAPI on `127.0.0.1:8080`) + `federloomd` on the host network
(ingests decisions, maintains reputation, enforces via ipset in `DOCKER-USER`
/`INPUT`). Every threshold and rule is locally overridable — lists are aids,
not law.

Web-server examples route detection through fail2ban/CrowdSec today; a direct
access-log ingest is planned (see `docs/backlog.md`, B2).
```

- [ ] **Step 2: Root `README.md`** — add a section `## Integrations` after the existing quick-start/core-ideas content:

```markdown
## Integrations

Ready-made, CI-validated examples under [`examples/`](examples/): plain VPS
with fail2ban, nginx, Apache, WordPress, Traefik, HAProxy, a bidirectional
CrowdSec bridge, a non-invasive Mailcow override, and agentless blocklist
feeds for OPNsense/pfSense/MikroTik/FortiGate. Start with
[`examples/vps-fail2ban/`](examples/vps-fail2ban/) — fail2ban to federated
blocklist in five minutes.
```

(Adjust placement to fit the README's existing section flow; keep its tone.)

- [ ] **Step 3: `docs/getting-started.md`** — add near the top, after the intro paragraph:

```markdown
> **Fastest path:** if you already run fail2ban, CrowdSec, Mailcow, or a
> dockerized web stack, use a ready-made integration from
> [`examples/`](../examples/README.md) instead of a manual setup.
```

- [ ] **Step 4: `CHANGELOG.md`** — add at the top, above the `[0.1.0]` entry:

```markdown
## [Unreleased]

### Added
- `examples/` — self-contained, CI-validated integration examples: vps-fail2ban,
  nginx (os+docker), apache (os+docker), wordpress, traefik, haproxy,
  crowdsec bridge, mailcow override, firewall-export
  (OPNsense/pfSense/MikroTik/FortiGate).
- fail2ban ingest `mode: local | docker` — bare-metal (non-Docker) fail2ban
  support (backlog B1).
- `make validate-examples` CI gate (strict schema decode of all example
  configs + compose validation) and a docker-example smoke harness
  (`test/examples/run-smoke.sh`).
```

(Match the heading style already used in CHANGELOG.md.)

- [ ] **Step 5: Link check + final gate**

Run: `for d in vps-fail2ban nginx/os nginx/docker apache/os apache/docker wordpress/docker traefik/docker haproxy/docker crowdsec mailcow firewall-export; do test -f "examples/$d/README.md" || echo "MISSING examples/$d/README.md"; done`
Expected: no output.

Run: `make validate-examples && make test && make lint`
Expected: all pass.

Run: `./test/examples/run-smoke.sh`
Expected: all seven smoke-testable examples PASS (crowdsec, nginx/docker, wordpress/docker, traefik/docker, apache/docker, haproxy/docker, firewall-export).

- [ ] **Step 6: Commit**

```bash
git add examples/README.md README.md docs/getting-started.md CHANGELOG.md
git commit -m "docs(examples): chooser matrix, README/getting-started integration, changelog"
```

---

## Verification checklist (whole plan)

- `make test && make lint && make adversarial` — green.
- `make validate-examples` — every example config/rules file strict-decodes; every compose file validates.
- `./test/examples/run-smoke.sh` — all docker examples pass end-to-end on a clean host.
- OS-variant READMEs (vps-fail2ban, nginx/os, apache/os): hand-verification on a real VPS remains a **user follow-up** — flag it when reporting completion; do not claim it was done.
- Invariant sweep: every config/rules file carries the "lists are aids, not law" note; no `observability:` enabled anywhere; no personal data (IPs, keys) from `deploy/` leaked into `examples/`.
```
