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
