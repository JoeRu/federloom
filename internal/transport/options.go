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
const DefaultTopic = "federloom/events/v2"

// Options configures a transport Node.
type Options struct {
	// ListenAddrs are the multiaddrs to listen on.
	ListenAddrs []multiaddr.Multiaddr
	// BootstrapPeers are known peers for DHT routing. Pass them to Bootstrap() after New().
	BootstrapPeers []peer.AddrInfo
	// Mode controls relay vs leaf behaviour.
	Mode NodeMode
	// PrivKey is the node's identity key. nil = generate ephemeral Ed25519.
	PrivKey crypto.PrivKey
	// Topic is the gossipsub topic to join. Default: DefaultTopic.
	Topic string
	// Subnet is this node's home trust domain. "" or "default" = the base topic.
	Subnet string
	// BridgeSubnets are additional subnets this node joins and relays between.
	BridgeSubnets []string
}

// SubnetTopic returns the gossipsub topic for a subnet. "" or "default" maps to
// the base topic (backward compatible); a named subnet s maps to base+"/"+s.
func SubnetTopic(base, subnet string) string {
	if subnet == "" || subnet == "default" {
		return base
	}
	return base + "/" + subnet
}
