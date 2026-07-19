# FederLoom as a firewall blocklist feed (agentless, Docker)

No agent, no bouncer, no plugin to install on your perimeter firewall. This
example runs a FederLoom node whose only job is to serve
`GET /crowdsec/v1/decisions` — a plain-text list of blocked IPs, one per line.
Point OPNsense, pfSense, MikroTik RouterOS, or a FortiGate at the URL and let
each device's own native URL-fetch/Threat-Feed mechanism do the rest.

## What you get

- `docker-compose.yml` — a single FederLoom container, published on host port
  `9102` (bound to `127.0.0.1` by default — change this to your management/VPN
  interface, see *Setup*).
- `config.yaml` — export-only node: `federation_mode: solo`, no ingest source
  enabled. **On its own this node has nothing to report and serves an EMPTY
  list.** To make the feed useful, either join a federation (see *Solo vs.
  join a federation* below) or add an ingest source (e.g. `crowdsec`,
  `fail2ban`, `honeypot` — see `examples/crowdsec/`, `examples/vps-fail2ban/`)
  on this same node so it has local detections to export.
- Four consumer subsections below (OPNsense, pfSense, MikroTik RouterOS,
  FortiGate) with exact steps for pulling the feed into each device natively.

## Prerequisites

- Docker + Compose v2 on the host that will run the FederLoom export node.
- Network reachability from your firewall's management/VPN interface to that
  host's published port (see the SECURITY note in *Setup*).

## Setup

1. Change into the example directory:

       cd examples/firewall-export

2. Review `docker-compose.yml`. By default the port is published on
   `127.0.0.1:9102` — this is deliberately unreachable from your firewall
   until you change it. Edit the `ports:` line to your host's
   management/VPN interface IP, e.g.:

       ports:
         - "10.0.0.5:9102:9102"

   **SECURITY:** the `/crowdsec/v1/decisions` endpoint is unauthenticated by
   design — network reachability IS the trust boundary. Never bind it to a
   WAN-facing address. See the *Security* section below.

3. Start the stack:

       docker compose up -d

## Verify it works

From the same host (or anywhere that can reach the published port):

    curl -s http://127.0.0.1:9102/crowdsec/v1/decisions

An empty response with HTTP 200 is expected and correct for a fresh solo node
with no ingest — it proves the serving path works. Once this node has
detections (local ingest or federation), the same command lists them, one IP
per line.

## Solo vs. join a federation

The config ships `federation_mode: solo`: this node only ever serves whatever
it locally knows about, which — with no ingest source configured — is
nothing. To federate, set `federation_mode: federated`, uncomment
`bootstrap_peers` in `config.yaml` with a peer you trust, and restart. See
`docs/federation-guide.md` for anchors and invites. Your local whitelist (own
IPs, gateway, DNS) is never shared or federated — it stays `scope: local-only`
on this node regardless of federation mode.

### OPNsense

1. **Firewall → Aliases →** click **+** to add a new alias.
2. Set **Type** to **URL Table (IPs)**.
3. Set **Content** to `http://<federloom-host>:9102/crowdsec/v1/decisions`
   (use the management/VPN interface IP you published in *Setup*).
4. Set **Refresh Frequency** to `0.25` days (≈ every 6 hours; pick a shorter
   interval for faster reaction to new detections).
5. Save, then use the new alias as the source in a **WAN** block rule
   (**Firewall → Rules → WAN**, action **Block**, source = your alias).

### pfSense

1. **Firewall → Aliases → URLs** tab, click **+** to add.
2. Set **Type** to **URL Table (IPs)**.
3. Set **URL** to the same
   `http://<federloom-host>:9102/crowdsec/v1/decisions`.
4. Set **Update Frequency** — pfSense's URL Table refresh granularity is
   coarser than OPNsense's; the minimum is **1 day**. Plan for a slower
   reaction time than OPNsense/MikroTik when relying on this mechanism alone.
5. Save, then reference the alias as the source in a block rule on your WAN
   interface.

### MikroTik RouterOS

RouterOS has no native URL Table alias, so this uses `/tool fetch` plus a
scheduled script that imports the fetched list into an address-list.

1. Fetch the list manually once, to confirm reachability:

       /tool fetch url="http://<federloom-host>:9102/crowdsec/v1/decisions" dst-path=federloom.txt

2. Create the import script (**System → Scripts**, or via CLI) that fetches
   the feed, clears stale entries, and re-adds each IP with a timeout so it
   self-expires if the feed later drops it (defence in depth against a
   frozen/stale copy):

       :local url "http://<federloom-host>:9102/crowdsec/v1/decisions"
       :local file "federloom.txt"
       /tool fetch url=$url dst-path=$file
       :local data [/file get $file contents]
       /ip firewall address-list remove [/ip firewall address-list find list=federloom]
       :foreach ip in=[:toarray $data] do={
         :if ([:len $ip] > 0) do={
           /ip firewall address-list add list=federloom address=$ip timeout=6h
         }
       }
       /file remove $file

   Save this as `federloom-import` under **System → Scripts**.

3. Schedule it to run periodically (every 15 minutes here; adjust to taste):

       /system scheduler add name=federloom-fetch interval=15m on-event=federloom-import

4. Reference the `federloom` address-list as the source in a `drop` rule in
   `/ip firewall filter`, e.g.:

       /ip firewall filter add chain=input src-address-list=federloom action=drop

### FortiGate

1. **Security Fabric → External Connectors → Threat Feeds →** create new,
   type **IP Address**.
2. Set **URI of external resource** to
   `http://<federloom-host>:9102/crowdsec/v1/decisions`.
3. Set **Refresh Rate** to `60` minutes.
4. Save, then reference the new external-resource object as a source (or
   destination, for outbound protection) in a **deny** firewall policy.

## Security

- `GET /crowdsec/v1/decisions` is **unauthenticated by design** — it is meant
  to be pulled by devices that cannot hold a credential (firewall URL-table
  fetchers). Network reachability IS the trust boundary: expose the published
  port only on a management or VPN interface, never on a WAN address.
- The list contains IP addresses, which are treated as personal data under
  GDPR (spec §9). Do not republish this feed publicly or forward it to a
  third party without your own lawful basis for doing so.

## Teardown

    docker compose down -v
