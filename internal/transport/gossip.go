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
	Event proto.Event
	From  string
}

// Node is a FederLoom P2P peer: libp2p host + gossipsub topic + Kademlia DHT.
type Node struct {
	host     host.Host
	ps       *pubsub.PubSub
	topic    *pubsub.Topic
	sub      *pubsub.Subscription
	dht      *dht.IpfsDHT
	events   chan ReceivedEvent
	stopLoop context.CancelFunc
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

	t, err := ps.Join(opts.Topic)
	if err != nil {
		return nil, fmt.Errorf("transport: join topic %q: %w", opts.Topic, err)
	}

	sub, err := t.Subscribe()
	if err != nil {
		return nil, fmt.Errorf("transport: subscribe: %w", err)
	}

	loopCtx, stopLoop := context.WithCancel(ctx)
	n := &Node{
		host:     h,
		ps:       ps,
		topic:    t,
		sub:      sub,
		dht:      d,
		events:   make(chan ReceivedEvent, 64),
		stopLoop: stopLoop,
	}
	go n.readLoop(loopCtx)
	ok = true
	return n, nil
}

// Host returns the underlying libp2p host (for direct peer wiring in tests and Bootstrap).
func (n *Node) Host() host.Host { return n.host }

// DHT returns the underlying Kademlia DHT (needed by the discovery manager).
func (n *Node) DHT() *dht.IpfsDHT { return n.dht }

// Publish JSON-encodes e and publishes it to the gossipsub topic.
func (n *Node) Publish(ctx context.Context, e proto.Event) error {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("transport: marshal event: %w", err)
	}
	return n.topic.Publish(ctx, data)
}

// Subscribe returns a channel that delivers decoded events from the network
// together with their verified publisher. Closed when the Node is closed.
func (n *Node) Subscribe() <-chan ReceivedEvent { return n.events }

// Close shuts down the subscription, topic, DHT, and host.
func (n *Node) Close() error {
	n.stopLoop()
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
		// skip messages we published ourselves (GetFrom = verified original publisher)
		if msg.GetFrom() == n.host.ID() {
			continue
		}
		var e proto.Event
		if err := json.Unmarshal(msg.Data, &e); err != nil {
			continue
		}
		select {
		case n.events <- ReceivedEvent{Event: e, From: msg.GetFrom().String()}:
		case <-ctx.Done():
			return
		}
	}
}
