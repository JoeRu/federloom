# Bootstrap Peer Config Design

**Feature:** Auto-discovery / well-known bootstrap peers (Feature 4)
**Date:** 2026-06-17
**Status:** Approved

## Problem

All SwarmGuard nodes currently require `--bootstrap <multiaddr>` passed as a CLI flag, hardcoded in each `deploy/*/docker-compose.yml`. When the bootstrap peer's node key rotates, every docker-compose file must be updated manually. Private-swarm operators have no standard place to declare their own bootstrap peers without editing project-managed files.

## Goal

Move bootstrap peer declarations from CLI flags in docker-compose files to a `bootstrap_peers:` field in `config.yaml`. The CLI flag becomes additive so local overrides remain possible. No new infrastructure required; peer IDs are updated manually when they change (DHT peer caching deferred to Feature 5).

## Design

### Config struct (`internal/config/config.go`)

```go
type Config struct {
    // ... existing fields ...
    BootstrapPeers []string `yaml:"bootstrap_peers"`
    // Multiaddrs of libp2p peers to dial at startup, e.g.:
    // "/ip4/167.233.115.41/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD"
}
```

`Defaults()` returns an empty slice. No project-provided peer IDs are baked into code — they live in deploy-specific config files so private-swarm operators start with a clean slate.

### CLI flag (`cmd/swarmd/main.go`)

The existing `--bootstrap` flag remains. After config is loaded, CLI-provided multiaddrs are **appended** to `cfg.BootstrapPeers` (not replaced). This means:

```
# config.yaml has peer A
# --bootstrap peer-B
# → dials [A, B]
```

If both config and CLI are empty, swarmd logs `"no bootstrap peers configured, starting as isolated node"` and continues.

### Transport wiring (`internal/node/node.go`)

After building the libp2p host, pass the merged peer list to the existing `transport.Bootstrap(ctx, peers)` call. No new transport logic is needed; `dht.go` already implements this function.

### Deploy configs

**`deploy/mailcow/config.yaml`** and **`deploy/wordpress/config.yaml`** — add:

```yaml
bootstrap_peers:
  - /ip4/167.233.115.41/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD
```

**`deploy/mailcow/docker-compose.yml`** and **`deploy/wordpress/docker-compose.yml`** — remove the `--bootstrap ...` argument from `command:`. The honeypot's `docker-compose.yml` keeps the listen/advertise flags but no longer hardcodes `--bootstrap`.

**`deploy/mailcow/bootstrap-mailcow.sh`** — no changes needed; bootstrap peers are now in config.yaml which is rsync'd to the server.

### Startup sequence

1. Load and merge `config.yaml` + `config.local.yaml`
2. Parse `--bootstrap` CLI flags; append to `cfg.BootstrapPeers`
3. If slice is empty → log isolation warning, continue
4. Call `transport.Bootstrap(ctx, cfg.BootstrapPeers)` — dials each peer, populates DHT routing table
5. Startup complete; no reconnect timer (deferred to Feature 5 DHT work)

### Peer ID rotation

Peer IDs are libp2p cryptographic identities tied to the node's private key. When a key is rotated (server rebuild, explicit rotation), the new multiaddr must be updated in `deploy/*/config.yaml` and committed. This is the accepted manual procedure until Feature 5 introduces a DHT peer cache or DNS-TXT resolution.

## Out of Scope

- Periodic re-dial on routing table shrink (Feature 5)
- DNS TXT record resolution (Feature 5)
- DHT peer caching to data dir (Feature 5)
- Removing the `--bootstrap` flag (no current reason to deprecate it; additive model keeps it useful for one-off overrides)

## Files Changed

| File | Action |
|---|---|
| `internal/config/config.go` | Add `BootstrapPeers []string` to `Config`; empty default |
| `cmd/swarmd/main.go` | Change `--bootstrap` handler to append to `cfg.BootstrapPeers` instead of passing directly to transport |
| `internal/node/node.go` | Pass `cfg.BootstrapPeers` to `transport.Bootstrap()` instead of CLI-derived value |
| `deploy/mailcow/config.yaml` | Add `bootstrap_peers:` section |
| `deploy/mailcow/docker-compose.yml` | Remove `--bootstrap` from `command:` |
| `deploy/wordpress/config.yaml` | Add `bootstrap_peers:` section (if exists) |
| `deploy/wordpress/docker-compose.yml` | Remove `--bootstrap` from `command:` (if present) |
| `deploy/examples/*.yaml` | Add `bootstrap_peers: []` with comment |
