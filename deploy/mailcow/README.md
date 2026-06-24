# FederLoom — Mailcow add-on

Non-invasive integration, in the spirit of
[JoeRu/Mailcow-Crowdsec-Override](https://github.com/JoeRu/Mailcow-Crowdsec-Override):
everything lives in `docker-compose.override.yml`, so Mailcow's own files are
untouched and updates stay safe.

## Relationship to CrowdSec

CrowdSec already detects attacks and shares intel with its **central** community
network. FederLoom is the **decentralised / federated** counterpart and can:

- **consume** CrowdSec LAPI decisions as ingest (`internal/ingest/crowdsec.go`), and
- **emit** a CrowdSec-compatible blocklist (`internal/enforce/crowdsec.go`) so an
  existing `cs-firewall-bouncer` enforces FederLoom's federated reputation.

So you can run it *alongside* the CrowdSec override: CrowdSec for local detection
+ enforcement, FederLoom for federated, trust-weighted intel sharing.

## Install (scaffold)

1. `cp -r federloom/ /opt/mailcow-dockerized/` and copy
   `docker-compose.override.yml` into `/opt/mailcow-dockerized/`
   (merge the `services:`/`volumes:` blocks if you already have an override).
2. Run the install script to seed the **local-only** whitelist (own IP, gateway,
   DNS, Docker ranges): `scripts/install/install.sh`.
3. Set your federation/anchors in `config.yaml` (see `deploy/examples/`).
4. `cd /opt/mailcow-dockerized && docker compose up -d federloom`.

> Read `docs/onboarding/` first if you operate (not just join) a federation.
