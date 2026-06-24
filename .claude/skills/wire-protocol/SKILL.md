---
name: wire-protocol
description: >
  Use this skill whenever changing the FederLoom wire format — anything in
  pkg/proto (Event, ScoreEntry, AnchorEntry, WhitelistEntry) or the messages nodes
  exchange over gossip/DHT. Trigger for "add a field to Event", "change the report
  schema", "version the protocol", "what does a node send on the wire", or any edit
  under pkg/proto. Changes here are breaking and ripple across every node and every
  federation, so consult this before touching the contract.
---

# Change the wire protocol (pkg/proto)

`pkg/proto` is the **stable public contract** between nodes (spec §7). A change
here affects every node and every federation — treat as breaking.

## Rules

1. **Bump `SchemaVersion`** on any field add/remove/semantic change. Document it in
   `CHANGELOG.md`.
2. **Backward compatibility:** prefer additive, optional fields. Nodes must tolerate
   unknown fields and missing optional ones (mixed-version networks are normal).
3. **No pretend-anonymisation:** `IP` stays cleartext; do not add hashing as
   "privacy" (spec §9). Real privacy work belongs in transport/lookup, not the schema.
4. **Preserve provenance:** keep `OriginTrace`/`SubnetID` accurate — they prevent
   federation feedback loops (spec §5.2, problem K). Don't drop them in transforms.
5. **Signatures cover the right bytes:** if you add a field that should be
   authenticated, include it in the signed payload and update verification.

## Checklist before merging

- `SchemaVersion` bumped + CHANGELOG entry.
- Encode/decode round-trips for old and new shapes.
- Federation import still discounts and traces origin correctly.
- Adversarial tests updated if the change affects scoring inputs.
