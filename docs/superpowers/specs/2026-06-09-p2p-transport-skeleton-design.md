# Design: P2P Transport Walking Skeleton

**Date:** 2026-06-09
**Status:** Approved
**Goal:** Prove the libp2p transport architecture (gossipsub + Kademlia DHT + relay topology) before building reputation logic on top of it.

---

## 1. Motivation

The SwarmGuard codebase is fully scaffolded but contains zero implementation. The highest-risk unknown is the networking layer: will libp2p gossipsub + DHT + relay/aggregator topology actually behave as the spec describes? This skeleton answers that question first, before any reputation, enforcement, or trust logic is written.

Approach: build the thinnest end-to-end path that runs — a binary that hosts a libp2p node, gossips `proto.Event`s, and logs what it receives. Prove the topology with both an in-process CI test and a real-process smoke test.

---

## 2. Scope

### In scope

- `internal/transport/`: libp2p host, gossipsub, Kademlia DHT, relay mode
- `cmd/swarmd/main.go`: walking skeleton binary (~80 lines)
- `test/integration/cluster_test.go`: in-process 5-node star-topology test (CI gate)
- `scripts/dev/docker-compose.dev.yml` + `scripts/dev/smoke-test.sh`: real-process smoke test (manual gate)

### Explicitly out of scope

- Reputation scoring, decay, corroboration
- Enforcement (ipset, nftables)
- Ingest (mailcow logs, spamtrap, honeypot)
- Trust anchors, federation, signatures
- Config file loading (CLI flags only)
- Event authentication/signatures (events are unsigned in the skeleton)

---

## 3. `internal/transport`

Three files replace the current stubs.

### `gossip.go`

Owns the libp2p host and gossipsub. A `Node` struct wraps:

```go
type Node struct {
    host  host.Host
    ps    *pubsub.PubSub
    topic *pubsub.Topic
    sub   *pubsub.Subscription
    dht   *dht.IpfsDHT
}
```

Public API:

```go
func New(ctx context.Context, opts Options) (*Node, error)
func (n *Node) Publish(ctx context.Context, e proto.Event) error
func (n *Node) Subscribe() <-chan proto.Event
func (n *Node) Close() error
```

Wire encoding: JSON (proto types already carry JSON tags). Topic constant: `swarmguard/events/v0`.

### `dht.go`

Bootstraps a Kademlia DHT (`go-libp2p-kad-dht`) on the same host. For the skeleton: build routing table from bootstrap peers and stay connectable. On-demand score-lookup (spec §11.4 DNSBL model) is a later concern.

```go
func (n *Node) Bootstrap(ctx context.Context, peers []peer.AddrInfo) error
```

### `relay.go`

Controls relay vs. leaf mode. Exposed via `Options.Mode`:

| Mode | Behaviour |
|---|---|
| `ModeRelay` | Well-connected hub; always in gossipsub mesh; runs libp2p circuit relay v2 service; DHT server mode |
| `ModeLeaf` | Client; connects through relay for NAT traversal; DHT client mode |

### `Options`

```go
type Options struct {
    ListenAddrs    []multiaddr.Multiaddr
    BootstrapPeers []peer.AddrInfo
    Mode           NodeMode  // ModeRelay | ModeLeaf
    PrivKey        crypto.PrivKey // nil = generate ephemeral (tests use fixed keys)
    Topic          string         // default: "swarmguard/events/v0"
}
```

### Dependencies (to add to `go.mod`)

- `github.com/libp2p/go-libp2p`
- `github.com/libp2p/go-libp2p-kad-dht`
- `github.com/libp2p/go-libp2p-pubsub`

---

## 4. `cmd/swarmd/main.go`

CLI flags:

```
--listen      multiaddr to bind on (default /ip4/0.0.0.0/tcp/7700)
--bootstrap   comma-separated multiaddrs of bootstrap peers (empty = bootstrap node)
--relay       run as relay/aggregator node (default false)
```

Startup sequence:
1. Parse flags, build `transport.Options`
2. `transport.New(ctx, opts)` — starts host, joins topic, bootstraps DHT
3. Print own peer ID and listen addresses to stdout
4. If `--relay`: log "running as relay", block (relays don't publish)
5. If leaf: ticker every 5s publishes a synthetic `proto.Event{IP: "198.51.100.1", Reason: "smtp-auth-bruteforce", ReporterID: <own peer ID>}`
6. Goroutine reads `Node.Subscribe()` and logs each received event as JSON

Shutdown: graceful on SIGINT/SIGTERM via context cancel.

---

## 5. `test/integration/cluster_test.go`

Uses libp2p's `swarm/testing` in-memory transport — real gossipsub and DHT logic, no sockets, no root required.

### Topology

```
L1 ─┐
L2 ─┤─ R (relay)
L3 ─┤
L4 ─┘
```

Leaf nodes connect only to R. No direct leaf-to-leaf connections. Directly tests spec §11.4 "Relay-Hierarchie statt Full-Mesh."

### Test sequence

1. Spin up 5 `transport.Node`s with in-memory transport and fixed ephemeral keys
2. Connect each leaf to R only
3. Wait 500ms for gossipsub mesh to stabilise (graft handshakes)
4. L1 publishes one `proto.Event`
5. Assert L2, L3, L4 each receive the event within 3s
6. Assert R also received it
7. Repeat with L3 as publisher (proves relay is symmetric)

### Additional assertions

- DHT routing table on R contains all 4 leaf peer IDs after bootstrap
- A leaf can resolve another leaf's addresses via R's DHT (proves on-demand lookup path exists)

### CI integration

This test runs under `make test` (`go test ./test/integration/...`) and is a gate on every PR alongside the adversarial suite.

---

## 6. `scripts/dev/docker-compose.dev.yml`

Five containers on a shared bridge network:

| Container | Role | Key flags |
|---|---|---|
| `bootstrap` | first node, no peers | `--listen /ip4/0.0.0.0/tcp/7700` |
| `relay` | relay/aggregator | `--bootstrap /dns4/bootstrap/tcp/7700 --relay` |
| `leaf1` | leaf | `--bootstrap /dns4/bootstrap/tcp/7700` |
| `leaf2` | leaf | `--bootstrap /dns4/bootstrap/tcp/7700` |
| `leaf3` | leaf | `--bootstrap /dns4/bootstrap/tcp/7700` |

Startup order: `bootstrap` first (healthcheck on stdout peer ID), then `relay` and leaves in parallel.

### `scripts/dev/smoke-test.sh`

```
docker-compose -f docker-compose.dev.yml up -d
sleep 10
check docker logs leaf2 for at least one received event
check docker logs leaf3 for at least one received event
docker-compose down
exit 0/1
```

Invoked via `make smoke`. Not a CI gate — manual pre-push check requiring Docker and ~30s.

---

## 7. What success looks like

- `make test` passes: in-process 5-node star topology propagates events through the relay in both directions; DHT routing table is populated
- `make smoke` passes: `docker logs leaf2` and `docker logs leaf3` contain JSON event lines published by other leaves
- No reputation, enforcement, or trust logic written yet — this sprint is purely the transport foundation

---

## 8. Next steps (after this sprint)

Per spec §13 / project-structure §6 phase plan:
1. Ingest layer: `internal/ingest/mailcow_logs.go` + `spamtrap.go` — real attack signals
2. Reputation engine: `internal/reputation/decay.go` + `corroboration.go` — scoring logic
3. Enforcement: `internal/enforce/ipset.go` — write the blocklist to the firewall
4. Trust anchors: `internal/trust/anchors.go` — key management, local override
5. Federation: `internal/trust/federation.go` — trust discount, origin tracking
