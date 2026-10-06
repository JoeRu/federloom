package transport

import (
	"context"
	"log"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
)

// DefaultBootstrapReconnectInterval is how often KeepBootstrapPeers checks the
// configured bootstrap peers when the caller passes no interval.
const DefaultBootstrapReconnectInterval = time.Minute

// bootstrapProtectTag marks bootstrap connections so the connection manager
// never trims them: they are the node's way back into the swarm.
const bootstrapProtectTag = "federloom-bootstrap"

// KeepBootstrapPeers re-dials every configured bootstrap peer that is not
// connected, every interval, until ctx is done. Bootstrap alone connects only
// once at start-up; a leaf whose only peer was its hub lost its DHT routing
// table together with that connection, so after a hub restart it could not
// find any peer again and stayed isolated until it was restarted itself.
//
// After a successful reconnect the DHT is re-bootstrapped so discovery can
// find the rest of the swarm again. Failures are logged once per outage, not
// on every attempt.
func (n *Node) KeepBootstrapPeers(ctx context.Context, peers []peer.AddrInfo, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultBootstrapReconnectInterval
	}
	self := n.host.ID()
	down := make(map[peer.ID]bool)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		reconnected := false
		for _, p := range peers {
			if p.ID == self {
				continue
			}
			if n.host.Network().Connectedness(p.ID) == network.Connected {
				if down[p.ID] {
					log.Printf("transport: bootstrap peer %s connected again", p.ID)
					delete(down, p.ID)
				}
				continue
			}
			// The swarm backs off from addresses that failed recently (the hub
			// while it was down) for up to several minutes; this loop is the
			// rate limit, so clear that backoff before each attempt.
			if sw, ok := n.host.Network().(interface{ Backoff() *swarm.DialBackoff }); ok {
				sw.Backoff().Clear(p.ID)
			}
			dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := n.host.Connect(dctx, p)
			cancel()
			if err != nil {
				if !down[p.ID] {
					log.Printf("transport: bootstrap peer %s unreachable, will keep retrying every %s: %v", p.ID, interval, err)
					down[p.ID] = true
				}
				continue
			}
			n.host.ConnManager().Protect(p.ID, bootstrapProtectTag)
			log.Printf("transport: reconnected to bootstrap peer %s", p.ID)
			delete(down, p.ID)
			reconnected = true
		}
		if reconnected {
			if err := n.dht.Bootstrap(ctx); err != nil {
				log.Printf("transport: DHT refresh after reconnect: %v", err)
			}
		}
	}
}
