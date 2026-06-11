---
name: enforce-backend
description: >
  Use this skill whenever working on SwarmGuard enforcement — adding or changing an
  enforce.Sink, touching ipset/nftables/iptables logic, emitting a CrowdSec or
  Fail2Ban-compatible blocklist, or anything that writes block decisions to the
  firewall. Trigger for "add an nftables backend", "block via ipset", "produce a
  CrowdSec bouncer feed", "how do we enforce bans", or any change under
  internal/enforce. Treat this as security-critical work.
---

# Add or change an enforcement backend (Sink)

`internal/enforce` is the **only** place that writes to the firewall. It is
security-critical: extra care, conservative defaults.

## Steps

1. Read `internal/enforce/plugin.go` (`Sink`) and the existing `ipset.go`.
2. Implement `Sink`:
   - `Name()` stable identifier.
   - `Apply(blocked)` **idempotently reconciles** the backend to exactly the given
     set — add missing, remove stale. No drift.
3. Use **O(1) set membership** (`ipset`/`nftables` sets). **Never** generate one
   firewall rule per IP — that is O(n) per packet and melts (spec §11.3, problem Q).
4. Always subtract the **never-block set** before applying (`neverblock.go`); the
   hard whitelist is non-overridable.
5. Honour the **local override** principle: the operator's manual unblocks win.

## CrowdSec interop

To run alongside JoeRu/Mailcow-Crowdsec-Override, emit a CrowdSec-compatible
decisions/blocklist feed (`crowdsec.go`) and let the existing `cs-firewall-bouncer`
do the kernel-level blocking, rather than fighting over iptables chains.

## Test

Add an integration test that asserts reconcile is idempotent and that never-block
entries are never written.
