package node

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/enforce"
	"github.com/JoeRu/swarmguard/internal/ingest"
	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/internal/transport"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// Node is the composition root that connects ingest, reputation, enforce, and transport.
type Node struct {
	cfg        *config.Config
	transport  *transport.Node // may be nil (solo mode without bootstrap)
	store      *store.BadgerStore
	rep        *reputation.Engine
	sources    []ingest.Source
	sink       enforce.Sink
	neverblock *enforce.NeverBlockList
	selfID     string
}

// New wires all subsystems from cfg. t may be nil for local-only operation.
func New(cfg *config.Config, t *transport.Node) (*Node, error) {
	s, err := store.Open(cfg.Store.Dir)
	if err != nil {
		return nil, fmt.Errorf("node: open store: %w", err)
	}

	halfLife := cfg.Reputation.HalfLife.Duration
	if halfLife <= 0 {
		halfLife = 7 * 24 * time.Hour
	}
	eng := reputation.New(s, halfLife)

	var sink enforce.Sink
	switch cfg.Enforce.Backend {
	case "nftables":
		sink = enforce.NewNftables(cfg.Enforce.SetName, cfg.Enforce.NftHook)
	default:
		sink = enforce.NewIpset(cfg.Enforce.SetName, cfg.Enforce.Chain)
	}

	nbl := enforce.NewNeverBlockList(cfg.Enforce.ExtraWhitelist)

	selfID := ""
	if t != nil {
		selfID = t.Host().ID().String()
	}

	var sources []ingest.Source
	if cfg.Ingest.Honeypot.Enabled {
		sources = append(sources, ingest.NewHoneypot(cfg.Ingest.Honeypot, selfID))
	}
	if cfg.Ingest.OpenCanary.Enabled {
		sources = append(sources, ingest.NewOpenCanary(cfg.Ingest.OpenCanary, selfID))
	}

	return &Node{
		cfg:        cfg,
		transport:  t,
		store:      s,
		rep:        eng,
		sources:    sources,
		sink:       sink,
		neverblock: nbl,
		selfID:     selfID,
	}, nil
}

// Run starts all subsystems and blocks until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	if err := n.sink.Start(ctx); err != nil {
		return fmt.Errorf("node: start enforce sink: %w", err)
	}
	defer n.sink.Close()
	defer n.store.Close()

	var ingestChans []<-chan proto.Event
	for _, src := range n.sources {
		ch, err := src.Start(ctx)
		if err != nil {
			return fmt.Errorf("node: start source %s: %w", src.Name(), err)
		}
		ingestChans = append(ingestChans, ch)
	}
	localEvents := fanIn(ctx, ingestChans...)

	decayInterval := n.cfg.Reputation.DecayInterval.Duration
	if decayInterval <= 0 {
		decayInterval = time.Hour
	}
	ticker := time.NewTicker(decayInterval)
	defer ticker.Stop()

	var remoteCh <-chan proto.Event
	if n.transport != nil {
		remoteCh = n.transport.Subscribe()
	}

	for {
		select {
		case e, ok := <-localEvents:
			if !ok {
				localEvents = nil
				continue
			}
			n.processLocal(ctx, e)
		case e, ok := <-remoteCh:
			if !ok {
				remoteCh = nil
				continue
			}
			n.processRemote(e)
		case <-ticker.C:
			n.runDecay()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (n *Node) processLocal(ctx context.Context, e proto.Event) {
	if n.neverblock.Contains(e.IP) {
		return
	}
	e.ReporterID = n.selfID
	score, err := n.rep.Record(e.IP, e.Reason, n.selfID, 1.0)
	if err != nil {
		log.Printf("node: record local %s: %v", e.IP, err)
		return
	}
	if score >= n.cfg.Reputation.BlockThreshold {
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		}
	}
	if n.transport != nil {
		if err := n.transport.Publish(ctx, e); err != nil {
			log.Printf("node: publish %s: %v", e.IP, err)
		}
	}
}

func (n *Node) processRemote(e proto.Event) {
	if n.neverblock.Contains(e.IP) {
		return
	}
	score, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, 0.3)
	if err != nil {
		log.Printf("node: record remote %s: %v", e.IP, err)
		return
	}
	if score >= n.cfg.Reputation.BlockThreshold {
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		}
	}
}

func (n *Node) runDecay() {
	err := n.store.ScanScores(func(ip string, _ store.ScoreRecord) error {
		score, err := n.rep.Decay(ip)
		if err != nil {
			log.Printf("node: decay %s: %v", ip, err)
			return nil
		}
		if score < n.cfg.Reputation.UnblockThreshold {
			if err := n.sink.Unblock(ip); err != nil {
				log.Printf("node: unblock %s: %v", ip, err)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("node: decay scan: %v", err)
	}
}

// fanIn merges multiple event channels into one.
func fanIn(ctx context.Context, chans ...<-chan proto.Event) <-chan proto.Event {
	out := make(chan proto.Event, 64)
	var wg sync.WaitGroup
	for _, ch := range chans {
		wg.Add(1)
		go func(c <-chan proto.Event) {
			defer wg.Done()
			for {
				select {
				case e, ok := <-c:
					if !ok {
						return
					}
					select {
					case out <- e:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}(ch)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
