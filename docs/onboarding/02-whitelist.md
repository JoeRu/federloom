# Onboarding 2/4 — Mass whitelist + local truth

*Founding duty of every federation (spec §6.2).*

## Federation mass whitelist (shared)

Maintain the federation-wide never-block set: RFC1918, root DNS / public resolvers
(8.8.8.8, 1.1.1.1), big mail provider ranges (Google, Microsoft/Outlook), CDNs
(Cloudflare). Modelled as a project trust anchor (spec §5.1, §10).

## Local truth (never shared) — via the install script

Each installation augments the whitelist with its **own** infrastructure, detected
by `scripts/install/detect_local_truth.sh`: own public IP(s), gateways, configured
DNS, local Docker ranges, RFC1918/loopback.

**Two scopes — do not mix them:**

- `local-only` — local infrastructure. **Never shared** (irrelevant to others and
  would leak your topology). Suppresses only local blocks.
- `shared-vote` — deliberate "this public IP is legitimate" signals, trust-weighted
  (spec §4.4).

**Security caveat:** the install script writes the whitelist. A too-broad entry
(e.g. a whole public provider range marked local) is a real hole. Be conservative,
confirm every entry, default to *not* whitelisting when unsure.
