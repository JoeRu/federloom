package transport

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"

	"github.com/JoeRu/swarmguard/pkg/proto"
)

// Node is a SwarmGuard P2P peer: libp2p host + gossipsub topic + Kademlia DHT.
type Node struct {
	host     host.Host
	ps       *pubsub.PubSub
	topic    *pubsub.Topic
	sub      *pubsub.Subscription
	dht      *dht.IpfsDHT
	events   chan proto.Event
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
		events:   make(chan proto.Event, 64),
		stopLoop: stopLoop,
	}
	go n.readLoop(loopCtx)
	ok = true
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
