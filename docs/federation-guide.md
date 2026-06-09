# Federation guide

How to set up, join, federate, and defederate trust domains (subnets). Background:
`spec.md` §5.

## Choose a mode (config `federation_mode`)

- **solo** — single node, no network. Local detection + enforcement (MVP).
- **federated** — contribute to and import from a trust domain, foreign scores
  discounted (`federation.import_discount`).
- **isolated** — own subnet, own trust roots, import nothing
  (`import_discount: 0.0`). For closed org/consortium networks.

## Joining a federation

1. Obtain the federation's trust anchor(s) and add them
   (`swarmctl anchor add --source subnet ...`). Anchors stay locally removable.
2. Pick the federation mode: `allowlist` (default-deny) or `blocklist`
   (default-allow). Allowlist is the safer default.
3. Set `import_discount` — start conservative; foreign consensus should weigh less
   than your own.

## Federating with another subnet

Federation imports another domain's scores at a discount, with **origin tracing**
so a mutual A↔B link does not double-count the same information (spec §5.2,
problem K). Prefer federation-as-default with discount over isolation, so coverage
doesn't fragment before network effects appear.

## Defederation (the security lever)

A malicious or compromised subnet is cut off like a bad Mastodon instance:
`swarmctl defederate <subnet_id>`. This is the Sybil answer at the subnet level
(problem L).
