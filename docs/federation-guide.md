> For the quickest path, see [`docs/getting-started.md`](getting-started.md).
> This file covers the underlying concepts and advanced federation options.

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
   (`federloomctl anchor add --source subnet ...`). Anchors stay locally removable.
2. Pick the federation mode: `allowlist` (default-deny) or `blocklist`
   (default-allow). Allowlist is the safer default.
3. Set `import_discount` — start conservative; foreign consensus should weigh less
   than your own.

## Federating with another subnet

Federation imports another domain's scores at a discount, with **origin tracing**
so a mutual A↔B link does not double-count the same information (spec §5.2,
problem K). Prefer federation-as-default with discount over isolation, so coverage
doesn't fragment before network effects appear.

## Person-to-person trust pairing

Before federating at the subnet level, you can extend trust to specific
operators whose machines you want to count as vouched (spec §5.1). This is
lighter-weight than a full subnet federation and works peer-to-peer.

### Exchange identity bundles

Both operators run `federloomctl trust export` and share the resulting JSON bundle
over a channel they already trust (Signal, signed email, in person):

```bash
# Alice exports her bundle and sends it to Bob out-of-band.
federloomctl trust export > alice.bundle

# Bob verifies Alice's fingerprint, then imports.
federloomctl trust import alice.bundle --as alice --weight 0.8
# → "identity:    ed25519:AAAA..."
# → "fingerprint: ab12 cd34 ef56 78gh"
# → "→ verify this fingerprint with alice over a channel you already trust"
```

Bob reads the fingerprint aloud (or pastes it into a secure channel) and Alice
confirms it matches `federloomctl identity show` on her end. Only then does Bob
press Enter to confirm.

### What pairing does

Once Bob anchors Alice (weight 0.8), every machine Alice has certified inherits
that weight and contributes to the **"alice" corroboration group**. Alice's
machines collectively count as **one distinct voice** in corroboration — spinning
up ten Alice machines does not multiply her vote (spec §4.2).

Un-vouched ("stranger") reporters are capped at a total score contribution of
`trust.stranger_score_cap` (default 15 pts) regardless of how many Sybil
peers participate.

### Remove a pairing

```bash
federloomctl trust remove alice
```

Takes effect within the trust reload interval (≤10 s by default). Alice's
machines immediately resolve as strangers on the next event.

---

## Defederation (the security lever)

A malicious or compromised subnet is cut off like a bad Mastodon instance:
`federloomctl defederate <subnet_id>`. This is the Sybil answer at the subnet level
(problem L).
