package discovery

import (
	"context"
	"log"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/resources"
)

// rendezvousPoint is the well-known DHT key under which SwarmGuard nodes advertise
// themselves (spec §14.2). All nodes on the same topic find each other here.
const rendezvousPoint = "/swarmguard/v1/peers"

// Manager drives peer discovery: DHT rendezvous advertisement + relay list bootstrap.
type Manager struct {
	host   host.Host
	dht    *dht.IpfsDHT
	cfg    config.DiscoveryConfig
	relays []RelayEntry
}

// New creates a Manager. Call Start to begin advertising and/or discovering.
func New(h host.Host, d *dht.IpfsDHT, cfg config.DiscoveryConfig) *Manager {
	relays, err := LoadRelayList(cfg.RelayListPath, resources.RelayList)
	if err != nil {
		log.Printf("discovery: relay list load error: %v — continuing without relay list", err)
	}
	return &Manager{host: h, dht: d, cfg: cfg, relays: relays}
}

// Start connects to relay peers (fallback bootstrap), then begins advertising
// and/or peer-finding according to the configured opt-out flags.
// Blocks until ctx is cancelled.
func (m *Manager) Start(ctx context.Context) {
	m.connectRelays(ctx)

	rd := drouting.NewRoutingDiscovery(m.dht)

	if m.cfg.Advertise {
		dutil.Advertise(ctx, rd, rendezvousPoint)
		log.Printf("discovery: advertising as %s at %q", m.host.ID(), rendezvousPoint)
	}

	if m.cfg.Discover {
		go m.findPeers(ctx, rd)
	}
}

// connectRelays dials the relay list peers to bootstrap DHT routing.
// Errors are logged and skipped — relay list items may be stale.
func (m *Manager) connectRelays(ctx context.Context) {
	for _, relay := range m.relays {
		pid, err := peer.Decode(relay.PeerID)
		if err != nil {
			log.Printf("discovery: relay list: bad peer ID %q: %v", relay.PeerID, err)
			continue
		}
		var maddrs []multiaddr.Multiaddr
		for _, a := range relay.Addrs {
			ma, err := multiaddr.NewMultiaddr(a)
			if err != nil {
				log.Printf("discovery: relay list: bad addr %q: %v", a, err)
				continue
			}
			maddrs = append(maddrs, ma)
		}
		if len(maddrs) == 0 {
			continue
		}
		info := peer.AddrInfo{ID: pid, Addrs: maddrs}
		if err := m.host.Connect(ctx, info); err != nil {
			log.Printf("discovery: relay %s (%s): connect failed: %v", relay.Label, relay.PeerID, err)
		} else {
			log.Printf("discovery: connected to relay %s (%s)", relay.Label, relay.PeerID)
		}
	}
}

// findPeers loops, finding new peers via DHT rendezvous and connecting to them.
func (m *Manager) findPeers(ctx context.Context, rd *drouting.RoutingDiscovery) {
	for {
		peers, err := rd.FindPeers(ctx, rendezvousPoint)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("discovery: FindPeers error: %v — retrying in 60s", err)
			select {
			case <-time.After(60 * time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}
		for p := range peers {
			if p.ID == m.host.ID() {
				continue // skip self
			}
			if m.host.Network().Connectedness(p.ID) == 0 {
				if err := m.host.Connect(ctx, p); err != nil {
					log.Printf("discovery: connect %s: %v", p.ID, err)
				} else {
					log.Printf("discovery: connected to discovered peer %s", p.ID)
				}
			}
		}
		select {
		case <-time.After(30 * time.Second):
		case <-ctx.Done():
			return
		}
	}
}
