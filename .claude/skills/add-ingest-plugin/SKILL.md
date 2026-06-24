---
name: add-ingest-plugin
description: >
  Use this skill whenever adding, wiring, or debugging a FederLoom ingest source
  — i.e. any integration that turns an external attack signal into reports. Trigger
  it for requests like "add support for Cowrie / Dionaea / OpenCanary / T-Pot",
  "ingest CrowdSec or Fail2Ban", "read Mailcow/Postfix/Dovecot logs", "wire up a
  honeypot/spamtrap as a source", or "create a new ingest.Source / attack-signal
  producer". Use it even when the user just names a honeypot tool without saying
  "plugin".
---

# Add an ingest source plugin

A Source observes some system and emits `proto.Event`s into the control plane.

## Steps

1. Read `internal/ingest/plugin.go` (the `Source` interface) and `docs/plugins.md`.
2. Create `internal/ingest/<tool>.go` in `package ingest`.
3. Implement `Source`:
   - `Name()` returns a stable lowercase identifier.
   - `Start(ctx)` returns a channel of `proto.Event` and stops on `ctx.Done()`.
4. Map the tool's output to `proto.Event`: set `IP`, `Reason` (reuse existing
   reason vocabulary where possible), `Timestamp`, `PortClass`. Leave `ReporterID`,
   `Signature`, `SubnetID`, `OriginTrace` to the node layer.
5. Register from `init()`: `ingest.Register("<tool>", func() Source { ... })`.
6. **Ground-truth sources** (honeypots, spamtraps): any connection is malicious by
   definition — wire them as high-weight trust anchors via `internal/trust`, not as
   ordinary low-trust reporters (spec §4.1, §6.1).
7. If the source influences scoring, add an adversarial test in
   `test/adversarial/` (poisoning/sybil). The CI gate runs it.

## Invariants to respect

- Don't leak operator topology: a source must not emit local infrastructure as
  shareable events (that's the local-only whitelist's job).
- Cleartext IPs are fine on the wire; never hash as pretend-anonymisation (spec §9).
