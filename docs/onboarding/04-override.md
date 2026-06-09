# Onboarding 4/4 — Lists are aids, not law

*Core principle (spec Leitprinzip 7 / §6.4).*

The federation's defaults — thresholds, anchors, whitelists, block/allow lists —
are **aids**. The operator can override **any** parameter, locally and at any time.
The final decision always rests with the local admin, never with the network.

Make this explicit in your federation's own docs so nobody mistakes the defaults
for binding rules. In code, this means: never add a path the operator cannot
override (enforced as an invariant in `CLAUDE.md`).
