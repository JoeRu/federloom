---
name: adversarial-test
description: >
  Use this skill whenever writing, updating, or reasoning about SwarmGuard's
  security tests — poisoning, Sybil, patient-Sybil, compromised-high-trust-node,
  mass-whitelist, or federation feedback-loop scenarios. Trigger for "add a
  poisoning test", "test Sybil resistance", "how do we prove the anti-poisoning
  works", "adversarial suite", or any change to reputation/trust/ingest that needs
  a security scenario. The adversarial suite is the CI gate, so reach for this
  whenever scoring or trust logic changes.
---

# Write an adversarial test

The `test/adversarial/` suite is a **CI gate** (every PR). It encodes the design
claim that poisoning is *mitigated by structure*. When you change reputation,
trust, or an ingest source that feeds scoring, add or update a scenario.

## Scenario catalogue (from docs/threat-model.md)

- **Single-source poisoning** — one (even high-trust) node reports a benign IP;
  assert the score stays below block threshold without independent corroboration.
- **Sybil cluster** — many reporters from one ASN/subnet; assert diversity
  weighting collapses them toward ~1 effective vote.
- **Patient Sybil** — aged-but-inactive nodes activate together; assert age alone
  doesn't buy trust without activity + consensus agreement.
- **Compromised high-trust node** — sudden anomalous reports (e.g. 8.8.8.8); assert
  fast trust decay / anomaly response kicks in.
- **Mass-whitelist shield** — Sybils whitelist a real attacker; assert weighted
  whitelist votes don't override broad block consensus.
- **Federation feedback loop** — A↔B mutual import of the same event; assert origin
  tracing prevents double-counting.

## Shape of a test

Construct a controlled set of `proto.Event`s + anchors + trust state, run the
reputation engine, assert on the resulting `ScoreEntry` (or trust values). Keep
each scenario independent and named after the adversary goal it defends.
