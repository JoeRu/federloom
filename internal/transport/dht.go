package transport

import (
	"context"
	"errors"
	"fmt"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// Bootstrap connects to the given peers and refreshes the DHT routing table.
// It tries every peer: one unreachable peer must not stop the node from
// joining through the others. Connected bootstrap peers are protected from
// connection trimming. The returned error joins every failed connect (and a
// failed DHT refresh); it is non-nil even when other peers connected, so the
// caller can log it, but it is not fatal.
func (n *Node) Bootstrap(ctx context.Context, peers []peer.AddrInfo) error {
	var errs []error
	self := n.host.ID()
	for _, p := range peers {
		if p.ID == self {
			continue
		}
		if err := n.host.Connect(ctx, p); err != nil {
			errs = append(errs, fmt.Errorf("transport: connect bootstrap peer %s: %w", p.ID, err))
			continue
		}
		n.host.ConnManager().Protect(p.ID, bootstrapProtectTag)
	}
	if err := n.dht.Bootstrap(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
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
