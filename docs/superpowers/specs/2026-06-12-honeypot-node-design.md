# Honeypot Node Design

**Date:** 2026-06-12
**Status:** Approved

## Goal

Deploy a first real-life FederLoom honeypot node to `167.233.115.41` that captures
SSH, SMTP, and IMAP attack signals and federates them to a peer. Provides a
production smoke test of the full ingest → reputation → p2p pipeline.

## Architecture

### Honeypot stack (runs on `167.233.115.41`)

Three containers, deployed via `deploy/honeypot/docker-compose.yml`:

| Container | Image | Role | Ports |
|---|---|---|---|
| `cowrie` | `cowrie/cowrie` | SSH honeypot; logs sessions to JSONL | 22 |
| `opencanary` | `thinkst/opencanary` | SMTP + IMAP honeypot; logs to JSONL | 25, 143 |
| `federloom` | built from this repo | Tails both logs, scores IPs, runs p2p | 7700 |

Two named Docker volumes share log files between honeypots and FederLoom:

- `cowrie-logs` — mounted at `/var/log/cowrie` in `cowrie` and `federloom`
- `opencanary-logs` — mounted at `/var/log/opencanary` in `opencanary` and `federloom`

### Client stack (runs locally on the dev machine)

One container in `deploy/client/docker-compose.yml`:

| Container | Image | Role |
|---|---|---|
| `federloom` | built from this repo | Federated peer; connects to honeypot node via gossipsub |

### Bootstrap script

`deploy/honeypot/bootstrap.sh`:
1. SSHes into the server on port 2244
2. Installs Docker via `apt`
3. Copies compose files and configs to `/opt/federloom-honeypot/`
4. Runs `docker compose up -d`
5. Prints the FederLoom peer ID (from `docker logs federloom | grep peer_id`)

## Go Code Changes

### `internal/config/config.go`

Add `OpenCanaryConfig` to `IngestConfig`:

```go
type IngestConfig struct {
    Honeypot   HoneypotConfig   `yaml:"honeypot"`
    OpenCanary OpenCanaryConfig `yaml:"opencanary"`
}

type OpenCanaryConfig struct {
    Enabled      bool     `yaml:"enabled"`
    LogFile      string   `yaml:"log_file"`
    PollInterval Duration `yaml:"poll_interval"`
}
```

### `internal/ingest/opencanary.go`

New ingest adapter (~80 lines), mirroring `honeypot.go`:

- Tails a JSONL file with the same poll-and-rotation-detect loop
- Parses OpenCanary's event format: `{"src_host": "1.2.3.4", "logtype": 3000, "local_time": "..."}`
- Maps logtypes to `proto.Event` reasons:

| logtype | Reason |
|---|---|
| 3000 | `smtp-probe` |
| 3001 | `smtp-auth-bruteforce` |
| 2100 | `imap-probe` |
| 2101 | `imap-auth-bruteforce` |

- All events: `Trust=1.0` (ground-truth anchor, spec §4.1)
- `Name()` returns `"opencanary"`
- Implements `ingest.Source` — no changes to any other package

## Deploy Layout

```
deploy/
  honeypot/
    docker-compose.yml     # cowrie + opencanary + federloom
    config.yaml            # federloom: federated, both ingest adapters enabled
    opencanary.json        # opencanary: smtp + imap modules enabled
    bootstrap.sh           # ssh → install docker → copy files → docker compose up
  client/
    docker-compose.yml     # single federloom peer
    config.yaml            # federation_mode: federated, bootstrap_peers: [honeypot addr]
```

### `deploy/honeypot/config.yaml`

```yaml
federation_mode: federated
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

### `deploy/client/config.yaml`

```yaml
federation_mode: federated
transport:
  bootstrap_peers:
    - /ip4/167.233.115.41/tcp/7700/p2p/<HONEYPOT_PEER_ID>
```

`<HONEYPOT_PEER_ID>` is filled in by the operator after running `bootstrap.sh`.

## Smoke Test Procedure

1. Run `deploy/honeypot/bootstrap.sh` — installs Docker, deploys honeypot stack, prints peer ID
2. Paste peer ID into `deploy/client/config.yaml`
3. Run `docker compose -f deploy/client/docker-compose.yml up` locally
4. Within seconds, internet traffic hits ports 22/25/143 on the server
5. Verify: local client logs show gossipsub events arriving from the honeypot node

**Pass criteria:** At least one `proto.Event` appears in the client node's log within 5 minutes
of the client connecting, corroborating that the full pipeline (hit → honeypot log → ingest →
reputation → gossipsub → peer) works end-to-end.

## What is NOT in scope

- Enforcement (`ipset`/`nftables`) on the honeypot node — it's a sensor, not a firewall
- TLS on SMTP/IMAP honeypot ports (port 993/465) — can be added later
- Adversarial test coverage for OpenCanary adapter — follow-up after smoke test passes
- Peer ID key management / persistent identity — uses ephemeral key for the smoke test
