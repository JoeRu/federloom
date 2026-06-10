---
name: spec-nav
description: >
  Consult when a code comment cites a spec section (e.g. "spec §4.2"), when
  implementing any reputation/trust/federation logic, or when a change might affect
  a non-negotiable invariant. Ensures implementation matches the authoritative
  design in docs/spec.md before writing code.
user-invocable: false
---

Before implementing any reputation, trust, ingest, or enforcement logic:

1. Read `docs/spec.md` — locate all cited sections (§N.N) relevant to the change.
2. Read `docs/threat-model.md` if the change touches trust or federation.
3. Verify the 7 non-negotiable invariants from CLAUDE.md are preserved:
   - Local overridability of all block parameters (spec Leitprinzip 7)
   - IPs as personal data — no pseudonymisation hashing (spec §9)
   - Local-only whitelist never federated (spec §6.2 / problem E)
   - Enforcement is O(1) via ipset/nftables sets (spec §11.3 / problem Q)
   - Trust rises slowly, falls fast — asymmetric decay (spec §4.3)
   - Trust anchors locally removable (spec §5.1 / problem I)
   - internal/enforce and scripts/install/ require extra review
4. Keep spec section references accurate in code comments when changing behaviour.
