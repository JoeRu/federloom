# FederLoom on a plain VPS (fail2ban, 5 minutes)

Already running fail2ban? This example federates it: every IP your jails ban
feeds your local FederLoom reputation store, gets blocked in O(1) via ipset,
and — once you federate — is shared with peers you trust (and you benefit from
theirs).

## What you get

- `config.yaml` — FederLoom reading your host fail2ban (`mode: local`).
- `rules.yaml` — block rules (your own detections block immediately).
- `federloomd.service` — systemd unit.

## Prerequisites

- Linux host with `fail2ban` installed and running (e.g. the stock `sshd` jail).
- `ipset` + `iptables` installed.
- Go 1.22+ to build the binary (prebuilt binaries: see project releases).

## Setup

1. Build and install the daemon:

       git clone https://github.com/JoeRu/federloom && cd federloom
       make build
       sudo install -m 0755 bin/federloomd /usr/local/bin/

2. Install the config (review it first — every threshold is yours to override):

       sudo mkdir -p /etc/federloom /var/lib/federloom
       sudo cp examples/vps-fail2ban/config.yaml examples/vps-fail2ban/rules.yaml /etc/federloom/

3. Install and start the service:

       sudo cp examples/vps-fail2ban/federloomd.service /etc/systemd/system/
       sudo systemctl daemon-reload
       sudo systemctl enable --now federloomd

## Verify it works

Ban a documentation IP through fail2ban, watch it appear in FederLoom:

    sudo fail2ban-client set sshd banip 203.0.113.99
    sleep 35   # one poll interval
    curl -s http://127.0.0.1:9102/api/v1/score/203.0.113.99   # → JSON with score
    sudo ipset list federloom | grep 203.0.113.99             # → blocked in the set

Clean up the test entry:

    sudo fail2ban-client set sshd unbanip 203.0.113.99
    sudo ipset del federloom 203.0.113.99 2>/dev/null || true

## Solo vs. join a federation

The config ships `federation_mode: solo`: everything stays on this host. To
federate, set `federation_mode: federated`, uncomment `bootstrap_peers` with a
peer you trust, and restart. See `docs/federation-guide.md` for anchors and
invites. Your local whitelist (own IPs, gateway, DNS) is never shared.

## Teardown

    sudo systemctl disable --now federloomd
    sudo rm /etc/systemd/system/federloomd.service /usr/local/bin/federloomd
    sudo rm -r /etc/federloom /var/lib/federloom
    sudo ipset destroy federloom 2>/dev/null || true
