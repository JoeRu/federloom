# P2P Transport Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the libp2p gossipsub + Kademlia DHT + relay/aggregator topology works before building reputation logic on top of it.

**Architecture:** A `transport.Node` wraps a libp2p host, gossipsub topic, and Kademlia DHT. The relay mode runs a well-connected DHT server and circuit relay service; leaf mode is a standard client. An in-process star-topology test gates CI; a docker-compose smoke test provides real-process confidence.

**Tech Stack:** Go 1.22, `github.com/libp2p/go-libp2p`, `github.com/libp2p/go-libp2p-kad-dht`, `github.com/libp2p/go-libp2p-pubsub`, stdlib `encoding/json`.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `go.mod` / `go.sum` | Modify | Add three libp2p dependencies |
| `internal/transport/options.go` | Create | `Options` struct, `NodeMode`, `DefaultTopic` |
| `internal/transport/gossip.go` | Create | `Node` struct, `New()`, `Publish()`, `Subscribe()`, `Close()`, `Host()`, `readLoop()` |
| `internal/transport/relay.go` | Create | `buildLibp2pOptions()` — relay vs leaf libp2p option sets |
| `internal/transport/dht.go` | Create | `Bootstrap()`, `FindPeer()`, `buildDHT()` |
| `internal/transport/doc.go` | Modify | Remove "scaffold stub" language |
| `internal/transport/options_test.go` | Create | Options constants smoke test |
| `internal/transport/gossip_test.go` | Create | Two-node Publish/Subscribe test |
| `internal/transport/dht_test.go` | Create | DHT FindPeer-via-relay test |
| `test/integration/cluster_test.go` | Create | Five-node star topology test (CI gate) |
| `cmd/federloomd/main.go` | Modify | Replace stub with walking skeleton binary |
| `scripts/dev/docker-compose.dev.yml` | Create | Five-container smoke topology |
| `scripts/dev/smoke-test.sh` | Create | Smoke test runner script |
| `Makefile` | Modify | Add `smoke` target |

---

## Task 1: Add libp2p dependencies

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add the three libp2p packages**

```bash
cd /path/to/federloom
go get github.com/libp2p/go-libp2p@latest
go get github.com/libp2p/go-libp2p-kad-dht@latest
go get github.com/libp2p/go-libp2p-pubsub@latest
go mod tidy
```

Expected: `go.mod` now lists all three packages plus their transitive deps in `go.sum`.

- [ ] **Step 2: Verify the existing stubs still compile**

```bash
go build ./...
```

Expected: builds without errors (all existing files are stubs with no imports that conflict).

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add libp2p transport dependencies"
```

---

## Task 2: Define transport.Options type

**Files:**
- Create: `internal/transport/options.go`
- Create: `internal/transport/options_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/transport/options_test.go`:

```go
package transport

import "testing"

func TestNodeModeConstants(t *testing.T) {
	if ModeLeaf != 0 {
		t.Fatalf("ModeLeaf should be 0, got %d", ModeLeaf)
	}
	if ModeRelay != 1 {
		t.Fatalf("ModeRelay should be 1, got %d", ModeRelay)
	}
	if DefaultTopic != "federloom/events/v0" {
		t.Fatalf("unexpected DefaultTopic: %q", DefaultTopic)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/transport/...
```

Expected: compile error — `ModeLeaf`, `ModeRelay`, `DefaultTopic` undefined.

- [ ] **Step 3: Create options.go**

Create `internal/transport/options.go`:

```go
package transport

import (
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// NodeMode controls how this node participates in the swarm.
type NodeMode int

const (
	// ModeLeaf is a standard node: DHT client, connects to peers normally.
	ModeLeaf NodeMode = iota
	// ModeRelay is a well-connected hub: DHT server, runs circuit relay v2 service.
	ModeRelay
)

// DefaultTopic is the gossipsub topic for FederLoom events.
const DefaultTopic = "federloom/events/v0"

// Options configures a transport Node.
type Options struct {
	// ListenAddrs are the multiaddrs to listen on.
	ListenAddrs []multiaddr.Multiaddr
	// BootstrapPeers are known peers to connect to on startup (via Bootstrap).
	BootstrapPeers []peer.AddrInfo
	// Mode controls relay vs leaf behaviour.
	Mode NodeMode
	// PrivKey is the node's identity key. nil = generate ephemeral Ed25519.
	PrivKey crypto.PrivKey
	// Topic is the gossipsub topic to join. Default: DefaultTopic.
	Topic string
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/transport/...
```

Expected: `PASS` (the options_test.go passes).

- [ ] **Step 5: Commit**

```bash
git add internal/transport/options.go internal/transport/options_test.go
git commit -m "feat(transport): add Options type and NodeMode constants"
```

---

## Task 3: Implement Node gossipsub core

**Files:**
- Create: `internal/transport/gossip.go`
- Create: `internal/transport/relay.go`
- Create: `internal/transport/gossip_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/transport/gossip_test.go`:

```go
package transport_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

// testOpts returns options for a test node listening on a random localhost port.
func testOpts(t *testing.T, mode transport.NodeMode) transport.Options {
	t.Helper()
	ma, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("build listen addr: %v", err)
	}
	return transport.Options{
		ListenAddrs: []multiaddr.Multiaddr{ma},
		Mode:        mode,
	}
}

// connect wires two nodes together (caller → target).
func connect(t *testing.T, caller, target *transport.Node) {
	t.Helper()
	ai := peer.AddrInfo{ID: target.Host().ID(), Addrs: target.Host().Addrs()}
	if err := caller.Host().Connect(context.Background(), ai); err != nil {
		t.Fatalf("connect: %v", err)
	}
}

func TestTwoNodeGossip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeA, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create nodeA: %v", err)
	}
	defer nodeA.Close()

	nodeB, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create nodeB: %v", err)
	}
	defer nodeB.Close()

	connect(t, nodeA, nodeB)
	time.Sleep(500 * time.Millisecond) // allow gossipsub to graft

	want := proto.Event{IP: "192.0.2.1", Reason: "test-bruteforce", ReporterID: "tester"}
	if err := nodeA.Publish(ctx, want); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case got := <-nodeB.Subscribe():
		if got.IP != want.IP || got.Reason != want.Reason {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nodeB did not receive event within 3s")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/transport/...
```

Expected: compile error — `transport.New`, `transport.Node`, `.Host()` undefined.

- [ ] **Step 3: Create relay.go**

Create `internal/transport/relay.go`:

```go
package transport

import "github.com/libp2p/go-libp2p"

// buildLibp2pOptions translates Options into libp2p functional options.
func buildLibp2pOptions(opts Options) []libp2p.Option {
	var lo []libp2p.Option

	if len(opts.ListenAddrs) > 0 {
		lo = append(lo, libp2p.ListenAddrs(opts.ListenAddrs...))
	}

	if opts.PrivKey != nil {
		lo = append(lo, libp2p.Identity(opts.PrivKey))
	}

	if opts.Mode == ModeRelay {
		lo = append(lo, libp2p.EnableRelayService())
	}

	return lo
}
```

- [ ] **Step 4: Create gossip.go**

Create `internal/transport/gossip.go`:

```go
package transport

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"

	"github.com/JoeRu/federloom/pkg/proto"
)

// Node is a FederLoom P2P peer: libp2p host + gossipsub topic + Kademlia DHT.
type Node struct {
	host   host.Host
	ps     *pubsub.PubSub
	topic  *pubsub.Topic
	sub    *pubsub.Subscription
	dht    *dht.IpfsDHT
	events chan proto.Event
}

// New creates and starts a Node. Call Close() to release all resources.
func New(ctx context.Context, opts Options) (*Node, error) {
	if opts.Topic == "" {
		opts.Topic = DefaultTopic
	}

	h, err := libp2p.New(buildLibp2pOptions(opts)...)
	if err != nil {
		return nil, fmt.Errorf("transport: create host: %w", err)
	}

	d, err := buildDHT(ctx, h, opts.Mode)
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("transport: create dht: %w", err)
	}

	ps, err := pubsub.NewGossipSub(ctx, h, pubsub.WithFloodPublish(true))
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("transport: create gossipsub: %w", err)
	}

	t, err := ps.Join(opts.Topic)
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("transport: join topic %q: %w", opts.Topic, err)
	}

	sub, err := t.Subscribe()
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("transport: subscribe: %w", err)
	}

	n := &Node{
		host:   h,
		ps:     ps,
		topic:  t,
		sub:    sub,
		dht:    d,
		events: make(chan proto.Event, 64),
	}
	go n.readLoop(ctx)
	return n, nil
}

// Host returns the underlying libp2p host (for direct peer wiring in tests and Bootstrap).
func (n *Node) Host() host.Host { return n.host }

// Publish JSON-encodes e and publishes it to the gossipsub topic.
func (n *Node) Publish(ctx context.Context, e proto.Event) error {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("transport: marshal event: %w", err)
	}
	return n.topic.Publish(ctx, data)
}

// Subscribe returns a channel that delivers decoded events from the network.
// The channel is closed when the Node is closed.
func (n *Node) Subscribe() <-chan proto.Event { return n.events }

// Close shuts down the subscription, topic, DHT, and host.
func (n *Node) Close() error {
	n.sub.Cancel()
	_ = n.topic.Close()
	_ = n.dht.Close()
	return n.host.Close()
}

func (n *Node) readLoop(ctx context.Context) {
	defer close(n.events)
	for {
		msg, err := n.sub.Next(ctx)
		if err != nil {
			return
		}
		// skip messages we published ourselves
		if msg.ReceivedFrom == n.host.ID() {
			continue
		}
		var e proto.Event
		if err := json.Unmarshal(msg.Data, &e); err != nil {
			continue
		}
		select {
		case n.events <- e:
		case <-ctx.Done():
			return
		}
	}
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
go test ./internal/transport/... -run TestTwoNodeGossip -v
```

Expected:
```
=== RUN   TestTwoNodeGossip
--- PASS: TestTwoNodeGossip (0.5xs)
PASS
```

- [ ] **Step 6: Commit**

```bash
git add internal/transport/gossip.go internal/transport/relay.go internal/transport/gossip_test.go
git commit -m "feat(transport): implement Node gossipsub core with two-node test"
```

---

## Task 4: Implement DHT Bootstrap and FindPeer

**Files:**
- Create: `internal/transport/dht.go`
- Create: `internal/transport/dht_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/transport/dht_test.go`:

```go
package transport_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/transport"
)

// TestDHTFindPeerViaRelay proves a leaf can resolve another leaf's address
// through the relay's DHT routing table — no direct leaf-to-leaf connection needed.
func TestDHTFindPeerViaRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	relay, err := transport.New(ctx, testOpts(t, transport.ModeRelay))
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	defer relay.Close()

	leaf1, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create leaf1: %v", err)
	}
	defer leaf1.Close()

	leaf2, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create leaf2: %v", err)
	}
	defer leaf2.Close()

	// Both leaves bootstrap from relay; no direct leaf↔leaf connection.
	relayInfo := peer.AddrInfo{ID: relay.Host().ID(), Addrs: relay.Host().Addrs()}
	if err := leaf1.Bootstrap(ctx, []peer.AddrInfo{relayInfo}); err != nil {
		t.Fatalf("leaf1 bootstrap: %v", err)
	}
	if err := leaf2.Bootstrap(ctx, []peer.AddrInfo{relayInfo}); err != nil {
		t.Fatalf("leaf2 bootstrap: %v", err)
	}

	// Allow routing tables to populate.
	time.Sleep(500 * time.Millisecond)

	found, err := leaf1.FindPeer(ctx, leaf2.Host().ID())
	if err != nil {
		t.Fatalf("FindPeer: %v", err)
	}
	if found.ID != leaf2.Host().ID() {
		t.Fatalf("found wrong peer: got %s, want %s", found.ID, leaf2.Host().ID())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/transport/... -run TestDHTFindPeerViaRelay -v
```

Expected: compile error — `Bootstrap`, `FindPeer` undefined on `*transport.Node`.

- [ ] **Step 3: Create dht.go**

Create `internal/transport/dht.go`:

```go
package transport

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	dht "github.com/libp2p/go-libp2p-kad-dht"
)

// Bootstrap connects to the given peers and refreshes the DHT routing table.
func (n *Node) Bootstrap(ctx context.Context, peers []peer.AddrInfo) error {
	for _, p := range peers {
		if err := n.host.Connect(ctx, p); err != nil {
			return fmt.Errorf("transport: connect bootstrap peer %s: %w", p.ID, err)
		}
	}
	return n.dht.Bootstrap(ctx)
}

// FindPeer resolves a peer's addresses via the DHT routing table.
func (n *Node) FindPeer(ctx context.Context, id peer.ID) (peer.AddrInfo, error) {
	return n.dht.FindPeer(ctx, id)
}

// buildDHT creates the Kademlia DHT in server mode (relay) or client mode (leaf).
func buildDHT(ctx context.Context, h host.Host, mode NodeMode) (*dht.IpfsDHT, error) {
	if mode == ModeRelay {
		return dht.New(ctx, h, dht.Mode(dht.ModeServer))
	}
	return dht.New(ctx, h, dht.Mode(dht.ModeClient))
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/transport/... -v
```

Expected: both `TestTwoNodeGossip` and `TestDHTFindPeerViaRelay` pass.

- [ ] **Step 5: Commit**

```bash
git add internal/transport/dht.go internal/transport/dht_test.go
git commit -m "feat(transport): add DHT Bootstrap and FindPeer"
```

---

## Task 5: Five-node in-process cluster integration test

**Files:**
- Create: `test/integration/cluster_test.go`

This is the CI gate test proving spec §11.4 "Relay-Hierarchie statt Full-Mesh."

- [ ] **Step 1: Create the test**

Create `test/integration/cluster_test.go`:

```go
package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

func localOpts(t *testing.T, mode transport.NodeMode) transport.Options {
	t.Helper()
	ma, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("build listen addr: %v", err)
	}
	return transport.Options{ListenAddrs: []multiaddr.Multiaddr{ma}, Mode: mode}
}

// startCluster creates a relay node R and n leaf nodes. Leaves connect only to R.
// Returns relay first, then leaves. Caller must call Close() on each.
func startCluster(t *testing.T, ctx context.Context, nLeaves int) (*transport.Node, []*transport.Node) {
	t.Helper()

	relay, err := transport.New(ctx, localOpts(t, transport.ModeRelay))
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}

	relayInfo := peer.AddrInfo{ID: relay.Host().ID(), Addrs: relay.Host().Addrs()}
	leaves := make([]*transport.Node, nLeaves)
	for i := range leaves {
		leaf, err := transport.New(ctx, localOpts(t, transport.ModeLeaf))
		if err != nil {
			t.Fatalf("create leaf%d: %v", i, err)
		}
		// Leaf connects to relay only — no direct leaf↔leaf connections.
		if err := leaf.Host().Connect(ctx, relayInfo); err != nil {
			t.Fatalf("leaf%d connect to relay: %v", i, err)
		}
		leaves[i] = leaf
	}

	time.Sleep(500 * time.Millisecond) // gossipsub mesh stabilisation
	return relay, leaves
}

// TestStarTopologyGossipForward proves events from L0 reach all other nodes via relay.
func TestStarTopologyGossipForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	relay, leaves := startCluster(t, ctx, 4)
	defer relay.Close()
	for _, l := range leaves { defer l.Close() }

	want := proto.Event{IP: "198.51.100.42", Reason: "smtp-auth-bruteforce", ReporterID: "forward-test"}
	if err := leaves[0].Publish(ctx, want); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// L1, L2, L3, and relay must all receive the event.
	receivers := append([]*transport.Node{relay}, leaves[1:]...)
	for i, r := range receivers {
		select {
		case got := <-r.Subscribe():
			if got.IP != want.IP {
				t.Errorf("receiver %d: got IP %q, want %q", i, got.IP, want.IP)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("receiver %d did not receive event within 3s", i)
		}
	}
}

// TestStarTopologyGossipSymmetric proves the relay is symmetric: L2 publishing reaches L0, L1, L3.
func TestStarTopologyGossipSymmetric(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	relay, leaves := startCluster(t, ctx, 4)
	defer relay.Close()
	for _, l := range leaves { defer l.Close() }

	want := proto.Event{IP: "203.0.113.99", Reason: "dict-attack", ReporterID: "symmetric-test"}
	if err := leaves[2].Publish(ctx, want); err != nil {
		t.Fatalf("publish: %v", err)
	}

	receivers := []*transport.Node{relay, leaves[0], leaves[1], leaves[3]}
	for i, r := range receivers {
		select {
		case got := <-r.Subscribe():
			if got.IP != want.IP {
				t.Errorf("receiver %d: got IP %q, want %q", i, got.IP, want.IP)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("receiver %d did not receive event within 3s", i)
		}
	}
}

// TestDHTDiscoveryViaRelay proves a leaf can find another leaf through relay's DHT.
func TestDHTDiscoveryViaRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	relay, err := transport.New(ctx, localOpts(t, transport.ModeRelay))
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	defer relay.Close()

	relayInfo := peer.AddrInfo{ID: relay.Host().ID(), Addrs: relay.Host().Addrs()}

	leaf1, err := transport.New(ctx, localOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("leaf1: %v", err)
	}
	defer leaf1.Close()

	leaf2, err := transport.New(ctx, localOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("leaf2: %v", err)
	}
	defer leaf2.Close()

	if err := leaf1.Bootstrap(ctx, []peer.AddrInfo{relayInfo}); err != nil {
		t.Fatalf("leaf1 bootstrap: %v", err)
	}
	if err := leaf2.Bootstrap(ctx, []peer.AddrInfo{relayInfo}); err != nil {
		t.Fatalf("leaf2 bootstrap: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	found, err := leaf1.FindPeer(ctx, leaf2.Host().ID())
	if err != nil {
		t.Fatalf("FindPeer: %v", err)
	}
	if found.ID != leaf2.Host().ID() {
		t.Fatalf("found wrong peer %s, want %s", found.ID, leaf2.Host().ID())
	}
}
```

- [ ] **Step 2: Run the integration tests**

```bash
go test ./test/integration/... -v -timeout 60s
```

Expected: all three tests pass. If `TestDHTDiscoveryViaRelay` is flaky (DHT routing tables need more time), increase the `time.Sleep` before `FindPeer` from 500ms to 1s.

- [ ] **Step 3: Run the full test suite**

```bash
make test
```

Expected: `ok github.com/JoeRu/federloom/internal/transport`, `ok github.com/JoeRu/federloom/test/integration`, all other packages pass (stubs have no test failures).

- [ ] **Step 4: Commit**

```bash
git add test/integration/cluster_test.go
git commit -m "test(integration): add 5-node star topology cluster test (CI gate)"
```

---

## Task 6: Walking skeleton federloomd binary

**Files:**
- Modify: `cmd/federloomd/main.go`

- [ ] **Step 1: Replace the stub with the skeleton binary**

Replace `cmd/federloomd/main.go` with:

```go
// Command federloomd is the long-running FederLoom P2P node daemon.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/pkg/proto"
)

func main() {
	listen    := flag.String("listen", "/ip4/0.0.0.0/tcp/7700", "multiaddr to listen on")
	advertise := flag.String("advertise", "", "multiaddr to print as the public address (for Docker/NAT)")
	bootstrap := flag.String("bootstrap", "", "comma-separated bootstrap peer multiaddrs (must include /p2p/<peerID>)")
	relay     := flag.Bool("relay", false, "run as relay/aggregator node (does not publish events)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	listenMA, err := multiaddr.NewMultiaddr(*listen)
	if err != nil {
		log.Fatalf("--listen %q: %v", *listen, err)
	}

	mode := transport.ModeLeaf
	if *relay {
		mode = transport.ModeRelay
	}

	node, err := transport.New(ctx, transport.Options{
		ListenAddrs: []multiaddr.Multiaddr{listenMA},
		Mode:        mode,
	})
	if err != nil {
		log.Fatalf("start node: %v", err)
	}
	defer node.Close()

	fmt.Printf("peer ID: %s\n", node.Host().ID())
	if *advertise != "" {
		fmt.Printf("listening on: %s/p2p/%s\n", *advertise, node.Host().ID())
	} else {
		for _, addr := range node.Host().Addrs() {
			fmt.Printf("listening on: %s/p2p/%s\n", addr, node.Host().ID())
		}
	}

	if *bootstrap != "" {
		var peers []peer.AddrInfo
		for _, raw := range strings.Split(*bootstrap, ",") {
			raw = strings.TrimSpace(raw)
			ma, err := multiaddr.NewMultiaddr(raw)
			if err != nil {
				log.Fatalf("invalid bootstrap addr %q: %v", raw, err)
			}
			ai, err := peer.AddrInfoFromP2pAddr(ma)
			if err != nil {
				log.Fatalf("parse bootstrap peer %q: %v", raw, err)
			}
			peers = append(peers, *ai)
		}
		if err := node.Bootstrap(ctx, peers); err != nil {
			log.Printf("bootstrap warning: %v", err)
		}
	}

	if *relay {
		log.Println("running as relay/aggregator — not publishing")
		<-ctx.Done()
		return
	}

	go func() {
		for e := range node.Subscribe() {
			data, _ := json.Marshal(e)
			fmt.Printf("received: %s\n", data)
		}
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e := proto.Event{
				IP:         "198.51.100.1",
				Reason:     "smtp-auth-bruteforce",
				Timestamp:  time.Now(),
				ReporterID: node.Host().ID().String(),
			}
			if err := node.Publish(ctx, e); err != nil {
				log.Printf("publish: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}
```

- [ ] **Step 2: Build and verify**

```bash
make build
```

Expected: `bin/federloomd` and `bin/federloomctl` produced without errors.

- [ ] **Step 3: Manual two-terminal smoke test**

Terminal 1 — start bootstrap/relay node:
```bash
./bin/federloomd --relay
```
Expected output (peer ID and address will differ):
```
peer ID: 12D3KooWAbc...
listening on: /ip4/192.168.x.x/tcp/7700/p2p/12D3KooWAbc...
running as relay/aggregator — not publishing
```
Copy the full `listening on:` address (the `/ip4/.../p2p/...` part).

Terminal 2 — start a leaf node pointing at the relay:
```bash
./bin/federloomd --listen /ip4/0.0.0.0/tcp/7701 --bootstrap <paste-the-address-from-terminal-1>
```
Expected: after ~5s, terminal 2 publishes an event; both terminals log activity. `Ctrl-C` to stop.

- [ ] **Step 4: Commit**

```bash
git add cmd/federloomd/main.go
git commit -m "feat(federloomd): replace stub with P2P walking skeleton binary"
```

---

## Task 7: Docker smoke test

**Files:**
- Create: `scripts/dev/docker-compose.dev.yml`
- Create: `scripts/dev/smoke-test.sh`
- Modify: `Makefile`
- Modify: `internal/transport/doc.go`

- [ ] **Step 1: Create docker-compose.dev.yml**

Create `scripts/dev/docker-compose.dev.yml`:

```yaml
# Development smoke test topology: bootstrap + relay + 3 leaf nodes.
# Used by scripts/dev/smoke-test.sh — do not run directly (needs BOOTSTRAP_PEER_ID env var).
services:
  bootstrap:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile
    command: >
      --listen /ip4/0.0.0.0/tcp/7700
      --advertise /dns4/bootstrap/tcp/7700

  relay:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile
    command: >
      --listen /ip4/0.0.0.0/tcp/7700
      --bootstrap /dns4/bootstrap/tcp/7700/p2p/${BOOTSTRAP_PEER_ID}
      --relay
    depends_on:
      - bootstrap

  leaf1:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile
    command: >
      --listen /ip4/0.0.0.0/tcp/7700
      --bootstrap /dns4/bootstrap/tcp/7700/p2p/${BOOTSTRAP_PEER_ID}
    depends_on:
      - bootstrap

  leaf2:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile
    command: >
      --listen /ip4/0.0.0.0/tcp/7700
      --bootstrap /dns4/bootstrap/tcp/7700/p2p/${BOOTSTRAP_PEER_ID}
    depends_on:
      - bootstrap

  leaf3:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile
    command: >
      --listen /ip4/0.0.0.0/tcp/7700
      --bootstrap /dns4/bootstrap/tcp/7700/p2p/${BOOTSTRAP_PEER_ID}
    depends_on:
      - bootstrap
```

- [ ] **Step 2: Create smoke-test.sh**

Create `scripts/dev/smoke-test.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="docker compose -f $SCRIPT_DIR/docker-compose.dev.yml"

cleanup() {
    echo "--- cleaning up containers ---"
    $COMPOSE down -v 2>/dev/null || true
}
trap cleanup EXIT

echo "=== FederLoom smoke test ==="

# Build image from current source
echo "--- building image ---"
$COMPOSE build

# Start bootstrap only and extract its peer ID
echo "--- starting bootstrap node ---"
$COMPOSE up -d bootstrap

BOOTSTRAP_PEER_ID=""
for i in $(seq 1 20); do
    LINE=$($COMPOSE logs bootstrap 2>&1 | grep "^peer ID:" | head -1 || true)
    if [ -n "$LINE" ]; then
        BOOTSTRAP_PEER_ID=$(echo "$LINE" | awk '{print $NF}')
        break
    fi
    sleep 1
done

if [ -z "$BOOTSTRAP_PEER_ID" ]; then
    echo "FAIL: bootstrap did not start (no peer ID in logs after 20s)"
    exit 1
fi
echo "--- bootstrap peer ID: $BOOTSTRAP_PEER_ID ---"

# Start relay and leaves now that we know the bootstrap peer ID
echo "--- starting relay and leaf nodes ---"
BOOTSTRAP_PEER_ID="$BOOTSTRAP_PEER_ID" $COMPOSE up -d relay leaf1 leaf2 leaf3

# Wait for mesh to form and events to flow
echo "--- waiting 15s for mesh formation ---"
sleep 15

# Assert leaf2 and leaf3 received events from leaf1 (or leaf2/leaf3 from each other)
FAIL=0
for container in leaf2 leaf3; do
    if $COMPOSE logs "$container" 2>&1 | grep -q '"ip":"198.51.100.1"'; then
        echo "PASS: $container received events"
    else
        echo "FAIL: $container did not receive events"
        echo "--- $container logs ---"
        $COMPOSE logs "$container" 2>&1 | tail -20
        FAIL=1
    fi
done

if [ "$FAIL" -eq 0 ]; then
    echo "=== SMOKE TEST PASSED ==="
else
    echo "=== SMOKE TEST FAILED ==="
    exit 1
fi
```

- [ ] **Step 3: Make the script executable**

```bash
chmod +x scripts/dev/smoke-test.sh
```

- [ ] **Step 4: Add smoke target to Makefile**

Edit `Makefile` and add after the `clean` target:

```makefile
smoke:        ## manual smoke test — real docker containers (~30s, requires Docker)
	./scripts/dev/smoke-test.sh
```

- [ ] **Step 5: Update transport/doc.go**

Replace `internal/transport/doc.go` with:

```go
// Package transport is the libp2p layer: gossipsub (control plane) +
// Kademlia DHT (on-demand peer/score lookup) + relay role (spec §5, §11).
//
// Node is the main type. Relay nodes run DHT server mode and circuit relay v2;
// leaf nodes are standard clients. See docs/spec.md §11.4 and
// docs/superpowers/specs/2026-06-09-p2p-transport-skeleton-design.md.
package transport
```

- [ ] **Step 6: Run the full test suite one last time**

```bash
make test
```

Expected: all packages pass.

- [ ] **Step 7: Commit**

```bash
git add scripts/dev/docker-compose.dev.yml scripts/dev/smoke-test.sh Makefile internal/transport/doc.go
git commit -m "feat(dev): add docker smoke test for 5-node P2P topology"
```

---

## Self-review notes

**Spec coverage check:**

| Spec requirement | Covered by |
|---|---|
| gossipsub mesh propagation (§11.4) | Tasks 3, 5 |
| Kademlia DHT bootstrap (§11.4) | Task 4, 5 |
| Relay/aggregator topology (§11.4 "Relay-Hierarchie") | Task 5 `startCluster` star topology |
| DHT on-demand peer lookup | Task 4 `TestDHTFindPeerViaRelay`, Task 5 `TestDHTDiscoveryViaRelay` |
| `proto.Event` on the wire (§7.1) | Task 3 `TestTwoNodeGossip` publishes real `proto.Event` |
| In-process CI gate | Task 5 runs under `make test` |
| Real-process smoke test | Task 7 `make smoke` |
| Relay mode = DHT server + circuit relay v2 | Task 3 `relay.go` `buildLibp2pOptions` |

**Things to verify at implementation time:**

1. After `go get github.com/libp2p/go-libp2p@latest`, run `go doc github.com/libp2p/go-libp2p EnableRelayService` to confirm the option name is correct (it may be `libp2p.EnableRelayService()` or similar in the version pulled).
2. After `go get github.com/libp2p/go-libp2p-kad-dht@latest`, run `go doc github.com/libp2p/go-libp2p-kad-dht ModeServer` to confirm `dht.ModeServer`, `dht.ModeClient`, and `dht.Mode()` match the pulled version.
3. `pubsub.WithFloodPublish(true)` — confirm this option exists in the pulled `go-libp2p-pubsub` version.
4. If `TestDHTDiscoveryViaRelay` is flaky with 500ms sleep, increase to 1000ms.
5. The `--bootstrap` flag requires a full `/p2p/<peerID>` suffix in the multiaddr. The manual smoke test in Task 6 Step 3 documents this expectation.
