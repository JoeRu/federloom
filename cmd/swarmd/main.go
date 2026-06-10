// Command swarmd is the long-running SwarmGuard P2P node daemon.
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

	"github.com/JoeRu/swarmguard/internal/transport"
	"github.com/JoeRu/swarmguard/pkg/proto"
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
