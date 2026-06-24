# Bootstrap Peer Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move bootstrap peer multiaddrs from hardcoded `--bootstrap` CLI flags in docker-compose files into a `bootstrap_peers:` YAML field, with the CLI flag becoming additive.

**Architecture:** Three changes in sequence: (1) add `BootstrapPeers []string` to `Config`; (2) modify `cmd/federloomd/main.go` to parse the config field and append any CLI `--bootstrap` args to it before dialing; (3) update all four deploy config.yaml files to carry the peers, and strip `--bootstrap` from all docker-compose `command:` blocks.

**Tech Stack:** Go stdlib `flag`, `github.com/libp2p/go-libp2p/core/peer`, `github.com/multiformats/go-multiaddr`, YAML config.

---

## File Map

| File | Action | What changes |
|---|---|---|
| `internal/config/config.go` | Modify | Add `BootstrapPeers []string` to `Config` struct |
| `internal/config/config_test.go` | Modify | Two new tests: default empty, YAML round-trip |
| `cmd/federloomd/main.go` | Modify | Parse config peers + append CLI peers, warn when empty, call `Bootstrap` with merged list |
| `deploy/mailcow/config.yaml` | Modify | Add `bootstrap_peers:` section |
| `deploy/mailcow/docker-compose.yml` | Modify | Remove `--bootstrap` line from `command:` |
| `deploy/wordpress/config.yaml` | Modify | Add `bootstrap_peers:` section |
| `deploy/wordpress/docker-compose.yml` | Modify | Remove `--bootstrap` line from `command:` |
| `deploy/honeypot/config.yaml` | Modify | Add `bootstrap_peers:` section |
| `deploy/honeypot/docker-compose.yml` | Modify | Remove `--bootstrap` line from `command:` |
| `deploy/examples/config.federated.yaml` | Modify | Add `bootstrap_peers: []` with comment |

---

## Task 1: Add `BootstrapPeers` to Config struct

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing tests**

Add to the bottom of `internal/config/config_test.go`:

```go
func TestBootstrapPeersDefaultEmpty(t *testing.T) {
	cfg := config.Defaults()
	if len(cfg.BootstrapPeers) != 0 {
		t.Errorf("Defaults().BootstrapPeers must be empty, got %v", cfg.BootstrapPeers)
	}
}

func TestBootstrapPeersFromYAML(t *testing.T) {
	raw := []byte(`
bootstrap_peers:
  - /ip4/1.2.3.4/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD
  - /ip4/5.6.7.8/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD
`)
	cfg, err := config.LoadYAML(raw)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if len(cfg.BootstrapPeers) != 2 {
		t.Fatalf("expected 2 bootstrap peers, got %d", len(cfg.BootstrapPeers))
	}
	if cfg.BootstrapPeers[0] != "/ip4/1.2.3.4/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD" {
		t.Errorf("unexpected peer[0]: %s", cfg.BootstrapPeers[0])
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/config/ -run TestBootstrapPeers -v
```

Expected: `FAIL — cfg.BootstrapPeers undefined`

- [ ] **Step 3: Add the field to Config**

In `internal/config/config.go`, add `BootstrapPeers` as the last field of the `Config` struct (before the closing brace):

```go
// Config is the top-level runtime configuration.
type Config struct {
	FederationMode string              `yaml:"federation_mode"`
	Store          StoreConfig         `yaml:"store"`
	Reputation     ReputationConfig    `yaml:"reputation"`
	Ingest         IngestConfig        `yaml:"ingest"`
	Enforce        EnforceConfig       `yaml:"enforce"`
	Trust          TrustConfig         `yaml:"trust"`
	Observability  ObservabilityConfig `yaml:"observability"`
	API            APIConfig           `yaml:"api"`
	BootstrapPeers []string            `yaml:"bootstrap_peers"`
}
```

No change to `Defaults()` — the zero value of `[]string` is already nil/empty, which is correct.

- [ ] **Step 4: Run tests to confirm they pass**

```bash
go test ./internal/config/ -run TestBootstrapPeers -v
```

Expected: both tests PASS.

- [ ] **Step 5: Run full test suite to verify no regressions**

```bash
go test ./...
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add bootstrap_peers field to Config

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 2: Merge CLI `--bootstrap` into config and call Bootstrap with combined list

**Files:**
- Modify: `cmd/federloomd/main.go`

The current code in `main.go` (lines 76–93) only calls `t.Bootstrap()` when `*bootstrap != ""`. The new code must:
1. Parse `cfg.BootstrapPeers` into `[]peer.AddrInfo`
2. Append any CLI `--bootstrap` multiaddrs to that same slice
3. Log a warning if the slice is still empty after both sources
4. Call `t.Bootstrap()` with the combined slice

- [ ] **Step 1: Replace the bootstrap block in `cmd/federloomd/main.go`**

Replace lines 76–93 (the existing `if *bootstrap != ""` block):

```go
// OLD — delete this:
if *bootstrap != "" {
	var peers []peer.AddrInfo
	for _, raw := range strings.Split(*bootstrap, ",") {
		raw = strings.TrimSpace(raw)
		ma, err := multiaddr.NewMultiaddr(raw)
		if err != nil {
			log.Fatalf("invalid bootstrap addr %q: %v", raw, err)
		}
		ai, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			log.Fatalf("parse bootstrap peer %q: %v", raw, err)
		}
		peers = append(peers, *ai)
	}
	if err := t.Bootstrap(ctx, peers); err != nil {
		log.Printf("bootstrap warning: %v", err)
	}
}
```

Replace with:

```go
// Merge bootstrap peers from config file and --bootstrap CLI flag (additive).
var bootstrapPeers []peer.AddrInfo
for _, raw := range cfg.BootstrapPeers {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		continue
	}
	ma, err := multiaddr.NewMultiaddr(raw)
	if err != nil {
		log.Fatalf("invalid bootstrap_peers entry %q: %v", raw, err)
	}
	ai, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		log.Fatalf("parse bootstrap_peers entry %q: %v", raw, err)
	}
	bootstrapPeers = append(bootstrapPeers, *ai)
}
if *bootstrap != "" {
	for _, raw := range strings.Split(*bootstrap, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ma, err := multiaddr.NewMultiaddr(raw)
		if err != nil {
			log.Fatalf("invalid --bootstrap addr %q: %v", raw, err)
		}
		ai, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			log.Fatalf("parse --bootstrap peer %q: %v", raw, err)
		}
		bootstrapPeers = append(bootstrapPeers, *ai)
	}
}
if len(bootstrapPeers) == 0 {
	log.Println("no bootstrap peers configured, starting as isolated node")
} else {
	if err := t.Bootstrap(ctx, bootstrapPeers); err != nil {
		log.Printf("bootstrap warning: %v", err)
	}
}
```

- [ ] **Step 2: Build to confirm it compiles**

```bash
go build ./cmd/federloomd/
```

Expected: exits 0, produces `federloomd` binary.

- [ ] **Step 3: Vet the binary**

```bash
go vet ./cmd/federloomd/
```

Expected: exits 0, no output.

- [ ] **Step 4: Run full test suite**

```bash
go test ./...
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add cmd/federloomd/main.go
git commit -m "feat(federloomd): merge bootstrap_peers config with --bootstrap CLI flag (additive)

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 3: Update deploy config files and strip `--bootstrap` from docker-compose files

**Files:**
- Modify: `deploy/mailcow/config.yaml`
- Modify: `deploy/mailcow/docker-compose.yml`
- Modify: `deploy/wordpress/config.yaml`
- Modify: `deploy/wordpress/docker-compose.yml`
- Modify: `deploy/honeypot/config.yaml`
- Modify: `deploy/honeypot/docker-compose.yml`
- Modify: `deploy/examples/config.federated.yaml`

- [ ] **Step 1: Add `bootstrap_peers` to `deploy/mailcow/config.yaml`**

Add this block after the closing `api:` section:

```yaml
bootstrap_peers:
  - /ip4/167.233.115.41/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD  # honeypot relay
```

- [ ] **Step 2: Remove `--bootstrap` from `deploy/mailcow/docker-compose.yml`**

The `command:` block currently reads:

```yaml
    command: >
      --config /etc/federloom/config.yaml
      --listen /ip4/0.0.0.0/tcp/7700
      --advertise /ip4/135.181.91.151/tcp/7700
      --bootstrap /ip4/167.233.115.41/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD
```

Replace with (removing only the `--bootstrap` line):

```yaml
    command: >
      --config /etc/federloom/config.yaml
      --listen /ip4/0.0.0.0/tcp/7700
      --advertise /ip4/135.181.91.151/tcp/7700
```

- [ ] **Step 3: Add `bootstrap_peers` to `deploy/wordpress/config.yaml`**

Add this block after the closing `api:` section:

```yaml
bootstrap_peers:
  - /ip4/167.233.115.41/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD  # honeypot relay
```

- [ ] **Step 4: Remove `--bootstrap` from `deploy/wordpress/docker-compose.yml`**

The `command:` block currently reads:

```yaml
    command: >
      --config /etc/federloom/config.yaml
      --listen /ip4/0.0.0.0/tcp/7700
      --advertise /ip4/65.108.62.108/tcp/7700
      --bootstrap /ip4/167.233.115.41/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD
```

Replace with:

```yaml
    command: >
      --config /etc/federloom/config.yaml
      --listen /ip4/0.0.0.0/tcp/7700
      --advertise /ip4/65.108.62.108/tcp/7700
```

- [ ] **Step 5: Add `bootstrap_peers` to `deploy/honeypot/config.yaml`**

Add this block after the closing `api:` section:

```yaml
bootstrap_peers:
  - /ip4/167.233.115.41/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD  # relay peer
```

- [ ] **Step 6: Remove `--bootstrap` from `deploy/honeypot/docker-compose.yml`**

The `command:` block currently reads:

```yaml
    command: >
      --config /etc/federloom/config.yaml
      --listen /ip4/0.0.0.0/tcp/7700
      --advertise /ip4/213.199.36.212/tcp/7700
      --bootstrap /ip4/167.233.115.41/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD
```

Replace with:

```yaml
    command: >
      --config /etc/federloom/config.yaml
      --listen /ip4/0.0.0.0/tcp/7700
      --advertise /ip4/213.199.36.212/tcp/7700
```

- [ ] **Step 7: Add `bootstrap_peers` comment to `deploy/examples/config.federated.yaml`**

Add this block after the existing content:

```yaml
# List well-known relay peers to connect to at startup.
# Peers are tried once on boot; the DHT routing table takes over after that.
# Update this list when a peer's node key rotates (key rotation = new peer ID).
bootstrap_peers: []
# Example:
#   - /ip4/1.2.3.4/tcp/7700/p2p/12D3KooW...
```

- [ ] **Step 8: Build to confirm everything still compiles**

```bash
go build ./...
```

Expected: exits 0.

- [ ] **Step 9: Run full test suite**

```bash
go test ./...
```

Expected: all tests pass.

- [ ] **Step 10: Commit**

```bash
git add deploy/mailcow/config.yaml deploy/mailcow/docker-compose.yml \
        deploy/wordpress/config.yaml deploy/wordpress/docker-compose.yml \
        deploy/honeypot/config.yaml deploy/honeypot/docker-compose.yml \
        deploy/examples/config.federated.yaml
git commit -m "feat(deploy): move bootstrap peers from --bootstrap CLI flag to config.yaml

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```
