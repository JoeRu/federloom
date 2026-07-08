// Command federloomd is the long-running FederLoom P2P node daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"strings"
	"syscall"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/transport"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file (optional; flags override)")
	listen := flag.String("listen", "/ip4/0.0.0.0/tcp/7700", "multiaddr to listen on")
	advertise := flag.String("advertise", "", "multiaddr to print as the public address (for Docker/NAT)")
	bootstrap := flag.String("bootstrap", "", "comma-separated bootstrap peer multiaddrs (must include /p2p/<peerID>)")
	relay := flag.Bool("relay", false, "run as relay/aggregator node (does not process local events)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := config.Defaults()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("load config %q: %v", *configPath, err)
		}
		cfg = loaded
	}

	listenMA, err := multiaddr.NewMultiaddr(*listen)
	if err != nil {
		log.Fatalf("--listen %q: %v", *listen, err)
	}

	mode := transport.ModeLeaf
	if *relay {
		mode = transport.ModeRelay
	}

	priv, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if err != nil {
		log.Fatalf("node identity: %v", err)
	}

	t, err := transport.New(ctx, transport.Options{
		ListenAddrs:   []multiaddr.Multiaddr{listenMA},
		Mode:          mode,
		PrivKey:       priv,
		Subnet:        cfg.FederationSubnet,
		BridgeSubnets: cfg.EffectiveBridgeSubnets(),
	})
	if err != nil {
		log.Fatalf("start transport: %v", err)
	}
	defer t.Close()

	fmt.Printf("peer ID: %s\n", t.Host().ID())
	if *advertise != "" {
		fmt.Printf("listening on: %s/p2p/%s\n", *advertise, t.Host().ID())
	} else {
		for _, addr := range t.Host().Addrs() {
			fmt.Printf("listening on: %s/p2p/%s\n", addr, t.Host().ID())
		}
	}

	// Merge bootstrap peers from config file and --bootstrap CLI flag (additive).
	var bootstrapPeers []peer.AddrInfo
	for _, raw := range cfg.BootstrapPeers {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ma, err := multiaddr.NewMultiaddr(raw)
		if err != nil {
			log.Fatalf("invalid bootstrap_peers entry %q: %v", raw, err)
		}
		ai, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			log.Fatalf("parse bootstrap_peers entry %q: %v", raw, err)
		}
		bootstrapPeers = append(bootstrapPeers, *ai)
	}
	if *bootstrap != "" {
		for _, raw := range strings.Split(*bootstrap, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			ma, err := multiaddr.NewMultiaddr(raw)
			if err != nil {
				log.Fatalf("invalid --bootstrap addr %q: %v", raw, err)
			}
			ai, err := peer.AddrInfoFromP2pAddr(ma)
			if err != nil {
				log.Fatalf("parse --bootstrap peer %q: %v", raw, err)
			}
			bootstrapPeers = append(bootstrapPeers, *ai)
		}
	}
	if len(bootstrapPeers) == 0 {
		log.Println("no bootstrap peers configured, starting as isolated node")
	} else {
		if err := t.Bootstrap(ctx, bootstrapPeers); err != nil {
			log.Printf("bootstrap warning: %v", err)
		}
	}

	if *relay {
		log.Println("running as relay/aggregator — waiting for connections")
		<-ctx.Done()
		return
	}

	n, err := node.New(cfg, t)
	if err != nil {
		log.Fatalf("create node: %v", err)
	}

	log.Printf("federloomd running (enforce=%s, honeypot=%v)",
		cfg.Enforce.Backend, cfg.Ingest.Honeypot.Enabled)

	if err := n.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("node exited: %v", err)
	}
}
