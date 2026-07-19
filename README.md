![FederLoom](federbloom-logo.png)

# FederLoom

A **decentralised, federated, reputation-based IP blocklist** — threat
intelligence shared peer-to-peer between self-hosted servers, with **local
sovereignty** at its core.

FederLoom runs as a Docker sidecar alongside your existing stack (Mailcow,
WordPress, CrowdSec, fail2ban). It ingests attack signals from your tools,
scores IPs locally using a configurable rules engine, and shares reputation
with peers you trust — peer-to-peer, no central authority, no mandatory cloud
calls.

Where CrowdSec shares intel through a *central* community network, FederLoom is
the *decentralised* counterpart: trust is **federated** (Mastodon-style trust
domains), block/allow lists are only **aids** the operator can always override,
and IP reputation **decays** over time — which doubles as the GDPR
storage-limitation mechanism.

## Quick start (Docker)

See **[docs/getting-started.md](docs/getting-started.md)** — pick your stack
(Mailcow, WordPress, CrowdSec standalone, fail2ban, or standalone sensor) and
follow the one-section guide. One bootstrap script, one `curl` to verify.

```bash
cp deploy/mailcow/.env.example deploy/mailcow/.env
# edit .env
bash deploy/mailcow/bootstrap-mailcow.sh
curl -s http://YOUR_SERVER:9101/metrics | grep federloom_blocked_ips
```

## Join this federation

A trust invite from the `federloom.jru.me` honeypot node is included in this
repository. To join:

```bash
# 1. Set up your own node first (see getting-started.md)
# 2. Verify the fingerprint out-of-band: 79bb d13a 114b 88fe

# From the deploy directory on your server (the bootstrap rsync placed
# federation.invite at the repo root, one level up from deploy/<stack>/):
docker compose cp ../../federation.invite federloom:/tmp/federation.invite
docker compose exec federloom federloomctl federation join /tmp/federation.invite \
    --config /etc/federloom/config.yaml
```

Your node will connect to `/dns4/federloom.jru.me/tcp/7700` and start
receiving federated reputation events. You can revoke or adjust the trust
weight at any time:

```bash
docker compose exec federloom federloomctl trust set --weight 0.8 PERSON \
    --config /etc/federloom/config.yaml
```

## Core ideas

- **Reputation score per IP**, not a hard global list. Your local threshold turns
  it into a blocklist. Three output levels: score / drop-in blocklist / raw events.
- **Anti-poisoning by structure** (spec §4): ground-truth anchors (honeypots,
  spamtraps), diversity-weighted corroboration (N *independent* ASNs/countries,
  not N nodes), asymmetric reputation decay (trust rises slowly, falls fast).
- **Federated trust** (spec §5): a curatable list of signed trust anchors plus
  your own subnets. Defederation is the answer to a bad subnet.
- **Scales by querying, not replicating** (spec §11): DNSBL-style on-demand
  lookup + compact local bloom filter; `ipset`/`nftables` (O(1)), never one rule
  per IP.
- **Good-neighbour load shedding** (spec §11.5): an optional processing-rate budget
  (`resources.max_events_per_sec`, off by default) sheds network-contribution work
  under load — remote scoring, bridge re-emit, federated queries — while local
  protection always runs.
- **Disputes** (spec §4.4): federated anti-trust votes can retract a *federated*
  block; a single stranger can't (diversity is anchored-gated).
- **Materialise-on-verdict** (E3 §8): a strong federated verdict about an IP that
  contacted you enforces locally via ipset (O(1)); opt-in, TTL-bounded.
- **Observability** (spec §11.2, default OFF): optional Prometheus `/metrics` and a
  local SQLite event history.
- **GDPR by design** (spec §9): IPs are personal data; lawful basis is legitimate
  interest (Art. 6(1)(f), Recital 49); decay is automatic deletion.

## Operating a federation

If you run (not just join) a trust domain, read
[`docs/onboarding/`](docs/onboarding/) first:

1. **[Ground-truth anchors](docs/onboarding/01-ground-truth.md)** — register your honeypots / spamtrap systems.
2. **[Mass whitelist + local truth](docs/onboarding/02-whitelist.md)** — own IPs, gateway, Docker ranges.
3. **[Key management](docs/onboarding/03-key-management.md)** — issuance, rotation, revocation.
4. **[Lists are aids, not law](docs/onboarding/04-override.md)** — the invariant that ties it together.

Federation invite exchange — all via `docker compose exec`:

```bash
# Existing operator: generate an invite
docker compose exec federloom federloomctl federation invite \
    --addr /dns4/your.host/tcp/7700 --config /etc/federloom/config.yaml

# New operator: join using an invite file (path relative to wherever you saved it,
# e.g. the deploy directory if the sender rsynced it there):
docker compose cp ./some.invite federloom:/tmp/some.invite
docker compose exec federloom federloomctl federation join /tmp/some.invite \
    --config /etc/federloom/config.yaml
```

## Extending it: plugins

Two small interfaces cover the full integration surface
(see [`docs/plugins.md`](docs/plugins.md)):

- **`ingest.Source`** — attack-signal producers: Mailcow logs, spamtraps,
  honeypots (Cowrie/OpenCanary), CrowdSec, fail2ban.
- **`enforce.Sink`** — enforcement backends: `ipset`, `nftables`, or emit a
  CrowdSec-compatible blocklist so an existing bouncer does the blocking.

## Integrations

Ready-made, CI-validated examples under [`examples/`](examples/): plain VPS
with fail2ban, nginx, Apache, WordPress, Traefik, HAProxy, a bidirectional
CrowdSec bridge, a non-invasive Mailcow override, and agentless blocklist
feeds for OPNsense/pfSense/MikroTik/FortiGate. Start with
[`examples/vps-fail2ban/`](examples/vps-fail2ban/) — fail2ban to federated
blocklist in five minutes.

## Repository layout

See [`docs/project-structure.md`](docs/project-structure.md) for the full tree.
In brief: `cmd/` binaries, `internal/` logic (data plane = `enforce`, control
plane = `reputation`/`transport`/`store`/`trust`, observability plane =
`observability`), `pkg/proto` the public wire contract, `deploy/` Docker stacks,
`docs/` the design.

Key docs:

| Document | What it covers |
|---|---|
| [`docs/spec.md`](docs/spec.md) | Full design — trust stack, federation, GDPR, scaling |
| [`docs/getting-started.md`](docs/getting-started.md) | Docker quick start for all stacks |
| [`docs/config.md`](docs/config.md) | Complete config.yaml / config.local.yaml reference |
| [`docs/rules.md`](docs/rules.md) | Rules engine + reason code catalogue |
| [`docs/threat-model.md`](docs/threat-model.md) | What we defend against and how |
| [`docs/federation-guide.md`](docs/federation-guide.md) | Trust exchange and peer management |
| [`docs/dnsbl-integration.md`](docs/dnsbl-integration.md) | Wiring Postfix, nginx, fail2ban to the DNSBL |

## Build & test

```bash
make build        # bin/federloomd, bin/federloomctl
make test         # go test ./...
make adversarial  # poisoning/sybil suite — the security CI gate
make fmt lint     # gofmt + go vet
```

## License

MIT — see [`LICENSE`](LICENSE).

## Related

- [JoeRu/Mailcow-Crowdsec-Override](https://github.com/JoeRu/Mailcow-Crowdsec-Override)
  — the complementary CrowdSec integration this project federates alongside.
