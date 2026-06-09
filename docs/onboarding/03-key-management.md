# Onboarding 3/4 — Key management

*Founding duty of every federation (spec §6.3).*

Define, up front:

- **Issuance & vouching** — who issues anchor/node keys, and who may vouch for new
  nodes (if web-of-trust is enabled).
- **Rotation** — validity periods and the rotation procedure for anchor keys.
- **Revocation** — how the revocation list is distributed; short validities reduce
  blast radius.
- **Compromise** — fast-revoke + trust-reset procedure for a leaked key (recall the
  "high-trust node gets hacked and reports 8.8.8.8" scenario — asymmetric decay and
  revocation are the defence).

Keys and filled-in secrets are never committed (see `.gitignore`).
