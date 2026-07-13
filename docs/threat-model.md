# Threat model

Maps to the spec risk table (§12). The guiding stance: **poisoning is mitigated,
never "solved"** — we make it expensive and conspicuous by exploiting the
structural properties of real attacks (broad, independent, against unused targets).

## Adversaries & defences

| Adversary goal | Defence |
| --- | --- |
| Poison the list (block a victim/competitor) | Diversity-weighted corroboration (N independent ASNs/countries), ground-truth anchors that can refute, dispute feedback (spec §4.2/§4.4) |
| Sybil cluster fabricates consensus | Independence weighting (same ASN ≈ 1 vote); reputation-stake with slow-rise/fast-fall trust (spec §4.3) |
| "Patient Sybil" (age accounts, then activate) | Age counts only coupled with activity + consensus agreement (spec §4.3) |
| High-trust node gets compromised, reports 8.8.8.8 | Fast trust decay on anomaly; corroboration requirement; key revocation (spec §4.3, §6.3) |
| Mass-whitelist to shield a real attacker | Whitelist votes are diversity/trust-weighted like block votes (spec §4.4 / problem H) |
| Re-centralise via project anchors | Anchors locally removable; project anchors are default, not mandatory (problem I) |
| Malicious/compromised subnet | Defederation (problem L) |
| Bridge nodes intercept/poison traffic | Anchored-corroboration block backstop, per-hop discount, defederation by not bridging |
| Federation feedback loop inflates scores | Origin tracing + per-hop discount (problem K) |
| Forged remote verdict forces a block (materialise path) | Remote-sourced enforcement is opt-in, provisional (TTL self-expiry), diversity-gated (≥N subnets) + high-threshold, never-block/whitelist-respecting; a forged low-diversity aggregate cannot materialise; defederation is containment |
| Learn who-sees-whom via on-demand lookups | **Open** — DNSBL-style lookups leak query patterns; consider prefix-block caching / oblivious lookup (related to problem E) |
| Reputation-oracle abuse (repquery) | the on-demand query responder authorizes per peer — anchored ∧ not blocked, fail closed — so strangers and defederated peers cannot read reputation data (closes the E3 review finding). Streams carry a deadline (slowloris-bounded); a Sybil stranger wave gains nothing (adversarial: `repquery_sybil_test.go`). |
| Reporter deanonymisation / topology leak | Local-only whitelist never shared; Tor-style submission vs. Sybil-accountability is an **open** tension (problem E) |

## Known open items

- Reporter privacy (E) and decay half-life tuning (D) are the notable unresolved
  design decisions.
- The on-demand-lookup privacy leak is a *new* consequence of the scaling design —
  decide it deliberately, don't let the performance optimum dictate it.
