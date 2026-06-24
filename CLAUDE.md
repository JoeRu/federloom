# CLAUDE.md

Guidance for Claude when working in the **FederLoom** repository.

## What this project is

A decentralised, federated, reputation-based IP blocklist shared peer-to-peer,
built first as a non-invasive Mailcow add-on. It is currently in **design /
scaffold phase**: the specification and architecture are written, the Go packages
are mostly stubs. The authoritative design is in `docs/spec.md`; the layout and
rationale in `docs/project-structure.md`. Read those before making structural
changes.

## Read the design before coding

- `docs/spec.md` — full design across all sections (trust stack, federation,
  GDPR, scaling). Section numbers (§4, §5, …) are referenced throughout the code.
- `docs/project-structure.md` — directory tree, tech choices, phase plan.
- `docs/threat-model.md` — what we defend against and how.
- `docs/plugins.md` — how to add ingest sources and enforce sinks.

When code comments cite a spec section (e.g. "spec §4.2"), keep that reference
accurate if you change behaviour.

## Tech stack

- **Go 1.22**, single static binary per command (`cmd/federloomd`, `cmd/federloomctl`).
- **libp2p** for transport (gossipsub + kademlia DHT), **BadgerDB** for the
  reputation store (TTL = decay GC), **bloom filter** as the negative pre-filter.
- Config: YAML + ENV override (`internal/config`, examples in `deploy/examples/`).
- Deployment: Docker; Mailcow integration via `docker-compose.override.yml`
  (non-invasive, upgrade-safe — mirrors JoeRu/Mailcow-Crowdsec-Override).

## Architecture in three planes (keep them separate)

- **Data plane** — `internal/enforce` (writes the firewall; small + isolated
  because it is security-critical).
- **Control plane** — `internal/reputation`, `internal/transport`,
  `internal/store`, `internal/trust`.
- **Observability plane** — `internal/observability` (opt-in, **default OFF**;
  never make the firehose mandatory).

`pkg/proto` is the **public wire contract**. Treat changes there as breaking —
follow `.claude/skills/wire-protocol`.

## Non-negotiable invariants (these encode the design's safety)

1. **Lists are aids, not law.** Any reputation/blocking parameter must remain
   locally overridable (spec Leitprinzip 7). Never add a code path the operator
   cannot override.
2. **IPs are cleartext on the wire, treated as personal data.** Do not introduce
   hashing as a pretend-anonymisation (spec §9). Lawful basis = legitimate
   interest + decay as deletion.
3. **Local-only whitelist is never federated.** Install-script-detected
   infrastructure (own IP, gateway, DNS, Docker ranges) is `scope: local-only`
   and must never be shared (privacy, spec §6.2 / problem E).
4. **Enforcement is O(1).** Use `ipset`/`nftables` sets. Never generate one
   firewall rule per IP (spec §11.3 / problem Q).
5. **Trust rises slowly, falls fast.** Preserve the asymmetry in any decay/trust
   change (spec §4.3).
6. **Anchors are locally removable.** Project-provided trust anchors are a default,
   never mandatory — otherwise we re-centralise (spec §5.1 / problem I).
7. **`internal/enforce` and `scripts/install/` are security-critical.** Extra
   review, conservative defaults, explicit operator confirmation before writing.

## Plugins

Two interfaces; prefer adding a plugin over modifying the core:

- `ingest.Source` (`internal/ingest/plugin.go`) — emits `proto.Event`s. Adapters:
  `mailcow_logs.go`, `spamtrap.go`, `honeypot.go`, `crowdsec.go`.
- `enforce.Sink` (`internal/enforce/plugin.go`) — applies the blocklist. Backends:
  `ipset.go`, `nftables.go`, `crowdsec.go`.

See `.claude/skills/add-ingest-plugin` and `.claude/skills/enforce-backend`.

## Build & test

```bash
make build        # bin/federloomd, bin/federloomctl
make test         # go test ./...
make adversarial  # poisoning/sybil scenarios — runs in CI on every PR
make fmt lint     # gofmt + go vet
```

The **adversarial suite is a CI gate**: when you touch reputation, trust, or
ingest, add or update a scenario in `test/adversarial/`. Security is a feature
here, not an afterthought.

## Conventions

- Conventional Commits + SemVer.
- Keep `internal/` private; only `pkg/` is a public contract.
- Documentation ships in the same PR as the feature (esp. the `docs/onboarding/`
  duties — they decay otherwise). It's part of "done".
- Never commit secrets: keys, filled-in `cs-firewall-bouncer.yaml`, or
  `config.local.yaml` (see `.gitignore`).
