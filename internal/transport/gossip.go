package transport

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"

	"github.com/JoeRu/federloom/pkg/proto"
)

// ReceivedEvent pairs a decoded Event with the gossipsub-verified original
// publisher. From is authenticated by libp2p message signing — the node layer
// rejects events whose ReporterID does not match it (spec §5.1 spoof guard).
type ReceivedEvent struct {
	Event  proto.Event
	From   string
	Subnet string // subnet whose topic delivered this copy
}

// Node is a FederLoom P2P peer: libp2p host + gossipsub topic + Kademlia DHT.
type Node struct {
	host     host.Host
	ps       *pubsub.PubSub
	dht      *dht.IpfsDHT
	topics   map[string]*topicHandle // keyed by subnet name (canonical config string)
	events   chan ReceivedEvent
	stopLoop context.CancelFunc
}

// topicHandle bundles a joined topic + its subscription for one subnet.
type topicHandle struct {
	subnet string
	topic  *pubsub.Topic
	sub    *pubsub.Subscription
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

	// cleanup closes both d and h if we return early below
	var ok bool
	defer func() {
		if !ok {
			_ = d.Close()
			_ = h.Close()
		}
	}()

	ps, err := pubsub.NewGossipSub(ctx, h, pubsub.WithFloodPublish(true))
	if err != nil {
		return nil, fmt.Errorf("transport: create gossipsub: %w", err)
	}

	base := opts.Topic
	if base == "" {
		base = DefaultTopic
	}

	// Join the home subnet + each bridge subnet (deduplicated by subnet name).
	subnets := []string{opts.Subnet}
	seen := map[string]bool{opts.Subnet: true}
	for _, s := range opts.BridgeSubnets {
		if !seen[s] {
			seen[s] = true
			subnets = append(subnets, s)
		}
	}

	loopCtx, stopLoop := context.WithCancel(ctx)
	n := &Node{
		host:     h,
		ps:       ps,
		dht:      d,
		topics:   make(map[string]*topicHandle, len(subnets)),
		events:   make(chan ReceivedEvent, 64),
		stopLoop: stopLoop,
	}
	for _, s := range subnets {
		t, err := ps.Join(SubnetTopic(base, s))
		if err != nil {
			return nil, fmt.Errorf("transport: join subnet %q: %w", s, err)
		}
		sub, err := t.Subscribe()
		if err != nil {
			return nil, fmt.Errorf("transport: subscribe subnet %q: %w", s, err)
		}
		h := &topicHandle{subnet: s, topic: t, sub: sub}
		n.topics[s] = h
		go n.readLoop(loopCtx, h)
	}
	ok = true
	return n, nil
}

// Host returns the underlying libp2p host (for direct peer wiring in tests and Bootstrap).
func (n *Node) Host() host.Host { return n.host }

// DHT returns the underlying Kademlia DHT (needed by the discovery manager).
func (n *Node) DHT() *dht.IpfsDHT { return n.dht }

// Publish JSON-encodes e and publishes it to the given subnet's topic. The node
// must be joined to that subnet (home or a bridge subnet), else an error.
func (n *Node) Publish(ctx context.Context, e proto.Event, subnet string) error {
	h, ok := n.topics[subnet]
	if !ok {
		return fmt.Errorf("transport: not joined to subnet %q", subnet)
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("transport: marshal event: %w", err)
	}
	return h.topic.Publish(ctx, data)
}

// Subscribe returns a channel that delivers decoded events from the network
// together with their verified publisher. Closed when the Node is closed.
func (n *Node) Subscribe() <-chan ReceivedEvent { return n.events }

// Close shuts down the subscriptions, topics, DHT, and host.
func (n *Node) Close() error {
	n.stopLoop()
	for _, h := range n.topics {
		h.sub.Cancel()
		_ = h.topic.Close()
	}
	_ = n.dht.Close()
	return n.host.Close()
}

func (n *Node) readLoop(ctx context.Context, h *topicHandle) {
	for {
		msg, err := h.sub.Next(ctx)
		if err != nil {
			return
		}
		// skip messages we published ourselves (GetFrom = verified original publisher)
		if msg.GetFrom() == n.host.ID() {
			continue
		}
		var e proto.Event
		if err := json.Unmarshal(msg.Data, &e); err != nil {
			continue
		}
		select {
		case n.events <- ReceivedEvent{Event: e, From: msg.GetFrom().String(), Subnet: h.subnet}:
		case <-ctx.Done():
			return
		}
	}
}
