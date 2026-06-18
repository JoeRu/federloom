# SwarmGuard

> **Status: early scaffold / design phase.** This repository contains the
> specification, architecture, plugin interfaces and skeleton — not yet a working
> daemon. See [`docs/spec.md`](docs/spec.md) for the full design.

A **decentralised, federated, reputation-based IP blocklist** — threat
intelligence shared peer-to-peer between self-hosted servers, with **local
sovereignty** at its core. Built first as a non-invasive **Mailcow** add-on, and
designed to complement existing tools like Fail2Ban and CrowdSec rather than
replace them.

Where CrowdSec shares intel through a *central* community network, SwarmGuard is
the *decentralised* counterpart: trust is **federated** (Mastodon-style trust
domains), block/allow lists are only **aids** the operator can always override,
and IP reputation **decays** over time — which doubles as the GDPR
storage-limitation mechanism.

## Core ideas (one screen)

- **Reputation score per IP**, not a hard global list. Your local threshold turns
  it into a blocklist. Three output levels: score / drop-in blocklist / raw events.
- **Anti-poisoning by structure, not blind trust** (spec §4): ground-truth anchors
  (honeypots or spamtrap-semantics on real systems), diversity-weighted
  corroboration (N *independent* ASNs/countries, not N nodes), and asymmetric
  reputation decay (trust rises slowly, falls fast).
- **Federated trust** (spec §5): a curatable list of signed trust anchors plus
  your own subnets that federate (with a trust discount) or stay isolated.
  Defederation is the answer to a bad subnet.
- **Scales by querying, not replicating** (spec §11): DNSBL-style on-demand lookup
  + a compact local bloom filter; `ipset`/`nftables` (O(1)), never a rule per IP.
  The daemon is a good neighbour — resource-budgeted, sheds load under attack.
- **GDPR by design** (spec §9): IPs *are* personal data; lawful basis is legitimate
  interest in network security (Art. 6(1)(f), Recital 49), with decay as automatic
  deletion and the local admin as controller.

## Operating a federation? Read this first.

See `docs/getting-started.md` for step-by-step instructions. Use `swarmctl setup` to initialise identity, then `swarmctl federation invite` (existing operators) or `swarmctl federation join` (joining operators) to exchange trust bundles.

If you run (not just join) a trust domain, you must establish three things up
front. **This is mandatory reading**, documented in
[`docs/onboarding/`](docs/onboarding/):

1. **[Ground-truth anchors](docs/onboarding/01-ground-truth.md)** — register the
   signatures of your honeypots / spamtrap systems.
2. **[Mass whitelist + local truth](docs/onboarding/02-whitelist.md)** — maintain
   the federation whitelist; each install adds its own local truth via the script.
3. **[Key management](docs/onboarding/03-key-management.md)** — issuance, rotation,
   revocation of anchor keys.

…and the principle that ties it together:
**[lists are aids, not law](docs/onboarding/04-override.md)** — the user can
override any parameter.

## Repository layout

See [`docs/project-structure.md`](docs/project-structure.md) for the full tree and
rationale. In short: `cmd/` binaries, `internal/` logic (three planes: data =
`enforce`, control = `reputation`/`transport`/`store`, observability =
`observability`), `pkg/proto` the wire contract, `deploy/` Docker + Mailcow,
`docs/` the design, `.claude/skills/` developer skills.

## Extending it: plugins

SwarmGuard is built around two small plugin interfaces so it can wrap existing
tools (see [`docs/plugins.md`](docs/plugins.md)):

- **`ingest.Source`** — attack-signal producers: Mailcow logs, spamtraps,
  honeypots (Cowrie/Dionaea/OpenCanary/T-Pot), CrowdSec, Fail2Ban.
- **`enforce.Sink`** — enforcement backends: `ipset`, `nftables`, or emit a
  CrowdSec-compatible blocklist so an existing bouncer does the blocking.

## Install & first run

```bash
make build
./bin/swarmd -config config.yaml   # first run generates the node key
./bin/swarmctl setup               # initialise identity and self-certify
```

See **[docs/getting-started.md](docs/getting-started.md)** for the full guide (solo node, starting a federation, or joining one).

```bash
make test            # runs tests
make adversarial     # poisoning/sybil suite — the security CI gate
```

Mailcow add-on install: see [`deploy/mailcow/README.md`](deploy/mailcow/README.md).

## Roadmap (phased, see project-structure §6)

1. **MVP single-node**: ingest (Mailcow + spamtrap) → reputation → ipset.
2. **P2P core**: gossip + bloom + diversity corroboration (~80 % of the value).
3. **Trust anchors** + key lifecycle.
4. **Federation**: import-with-discount, defederation, DHT on-demand lookup.
5. **Scaling/hardening**: relay role, resource budget, opt-in observability.

## Status of open problems

Tracked in the spec's risk table (spec §12): poisoning is *mitigated, never
"solved"*; reporter privacy and decay half-life tuning are the notable open items.

## License

MIT — see [`LICENSE`](LICENSE).

## Related

- [JoeRu/Mailcow-Crowdsec-Override](https://github.com/JoeRu/Mailcow-Crowdsec-Override)
  — the complementary central-intel CrowdSec integration this project federates with.
