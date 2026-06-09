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
| Federation feedback loop inflates scores | Origin tracing + per-hop discount (problem K) |
| Learn who-sees-whom via on-demand lookups | **Open** — DNSBL-style lookups leak query patterns; consider prefix-block caching / oblivious lookup (related to problem E) |
| Reporter deanonymisation / topology leak | Local-only whitelist never shared; Tor-style submission vs. Sybil-accountability is an **open** tension (problem E) |

## Known open items

- Reporter privacy (E) and decay half-life tuning (D) are the notable unresolved
  design decisions.
- The on-demand-lookup privacy leak is a *new* consequence of the scaling design —
  decide it deliberately, don't let the performance optimum dictate it.
