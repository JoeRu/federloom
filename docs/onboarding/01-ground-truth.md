# Onboarding 1/4 — Ground-truth anchors

*Founding duty of every federation (spec §6.1).*

Ground-truth anchors are the unbribable source of truth that bootstraps trust and
calibrates everyone else. Register their signatures as high-weight trust anchors.

## Two ways to provide ground truth

- **Dedicated honeypots** — IPs/mailboxes never used legitimately. Every
  connection is malicious by definition → **zero false positives**. Costs extra
  infrastructure.
- **Real systems under load** — see real attack patterns, no extra box. **Caveat:**
  a production system also receives legitimate traffic, so it is *not* zero-FP by
  itself. Carve out **honeypot semantics inside the real system** instead:
  - spamtrap addresses (never-used mailboxes),
  - auth attempts against non-existent accounts,
  - connections to unused/closed ports.

  These signals keep the zero-false-positive property on a live box.

## What to do

1. Stand up at least one ground-truth source (honeypot and/or spamtrap signals).
2. Generate its key and register it as an anchor (`swarmctl anchor add ...`).
3. Decide the operating model: **central** (project runs anchors) or **decentralised**
   (volunteers run anchors, status attested in-network). Both are valid (spec §4.1).
