# Fresh Redeploy + Smoke Test Design

**Goal:** A single script (`deploy/redeploy.sh`) that wipes all three FederLoom nodes, pulls the latest GHCR image, rotates peer IDs, generates a federation invite file from the honeypot, patches every `bootstrap_peers` entry with the new multiaddr, and runs a full smoke test — all without manual SSH sessions.

---

## Scope

Three production nodes:

| Node | Host | SSH | Container |
|---|---|---|---|
| honeypot | `167.233.115.41` | port 2244, root | `federloom` |
| mailcow | `mail.jru.me` | port 2222, joe | `federloom-mailcow` |
| wordpress | `d.jru.me` | port 2222, root | `federloom-wordpress` |

---

## Pre-flight changes (committed before running the script)

Three files need updating before the script works:

### `deploy/honeypot/bootstrap.sh`
Replace `docker build` with `docker pull ghcr.io/joeru/federloom:latest`. Drop `--build` from `docker compose up`. Add `config.local.yaml` rsync exclusions (same fix already applied to mailcow and wordpress scripts).

### `deploy/honeypot/config.yaml`
Add DNSBL block:
```yaml
dnsbl:
  addr: ":5353"
  zone: "dnsbl.federloom.jru.me."
```

### `deploy/honeypot/docker-compose.yml`
- Add `"5353:5353/udp"` to ports
- Change `--advertise /ip4/213.199.36.212/tcp/7700` → `--advertise /dns4/federloom.jru.me/tcp/7700`

DNS record `federloom.jru.me` resolves to the honeypot's public IP (both A and AAAA). Using the DNS name in `--advertise` makes the multiaddr stable across IP changes.

---

## `deploy/redeploy.sh` — 8 phases

### Phase 0: Pre-flight checks
Verify before touching any running node:
1. `gh run list --workflow=docker.yml --limit=1 --json conclusion` — abort if `!= "success"`
2. `docker manifest inspect ghcr.io/joeru/federloom:latest` — abort if unreachable

### Phase 1: Honeypot teardown + restart
```
ssh honeypot → docker compose down -v
               docker pull ghcr.io/joeru/federloom:latest
               docker compose up -d
sleep 20s
verify container status == "running"
```

### Phase 2: Identity setup + invite generation
```
docker exec federloom federloomctl setup --config /etc/federloom/config.yaml --label honeypot
docker exec federloom federloomctl federation invite \
  --config /etc/federloom/config.yaml \
  --addr /dns4/federloom.jru.me/tcp/7700 \
  --out /tmp/invite.json
ssh honeypot → docker exec federloom cat /tmp/invite.json → honeypot-invite.json (local)
```

`honeypot-invite.json` is gitignored. The invite JSON contains `.federation.bootstrap_peer` — the full multiaddr including the new peer ID.

### Phase 3: Patch config files
Replace any previous honeypot multiaddr in all three config files:
- `deploy/honeypot/config.yaml`
- `deploy/mailcow/config.yaml`
- `deploy/wordpress/config.yaml`

Two `sed` passes per file: one for the old IP-based pattern (`/ip4/167.233.115.41/tcp/7700/p2p/<id>`), one for the DNS-based pattern (`/dns4/federloom.jru.me/tcp/7700/p2p/<id>`). Both are replaced with the new multiaddr extracted from the invite JSON.

### Phase 4: Mailcow teardown + restart
```
rsync repo → nixos-mailcow (excludes .git, bin/, data/, both config.local.yaml files)
ssh mailcow → docker compose down -v
              docker pull ghcr.io/joeru/federloom:latest
              docker compose up -d
```

### Phase 5: WordPress teardown + restart
Same as Phase 4 for the wordpress host.

### Phase 6: Wait for all metrics endpoints
Poll each `http://<host>:9101/metrics` (via curl) every 5 seconds, up to 120 seconds. Exit 1 if any node times out.

Metrics URLs:
- Honeypot: `http://167.233.115.41:9101/metrics`
- Mailcow: `http://100.120.31.14:9101/metrics` (Tailscale)
- WordPress: `http://100.92.58.24:9101/metrics` (Tailscale)

### Phase 7: Smoke test (pass/fail table)

| Check | Method |
|---|---|
| Honeypot DNSBL responds | `dig @federloom.jru.me -p 5353 2.0.0.127.dnsbl.federloom.jru.me. A` — expect NXDOMAIN (empty reply) for `127.0.0.2` |
| Mailcow federation events | `federloom_events_received_total > 0` from mailcow metrics |
| WordPress federation events | `federloom_events_received_total > 0` from wordpress metrics |
| Honeypot peer count | `federloom_federation_peers > 0` |
| Mailcow peer count | `federloom_federation_peers > 0` |
| WordPress peer count | `federloom_federation_peers > 0` |

Exit 0 only when all checks pass. Print a summary table regardless.

---

## Security constraints (must be preserved verbatim)

- rsync MUST always exclude `deploy/wordpress/config.local.yaml` and `deploy/mailcow/config.local.yaml`
- `honeypot-invite.json` MUST be gitignored (contains trust bundle with private key material)
- No API keys or passwords in any committed file

---

## Outputs

After a successful run:
- `honeypot-invite.json` written locally (gitignored)
- All three `config.yaml` files updated with the new honeypot multiaddr
- A pass/fail table printed to stdout
- Exit 0 on full pass, exit 1 on any failure
