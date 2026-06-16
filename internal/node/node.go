package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/JoeRu/swarmguard/internal/api"
	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/enforce"
	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/ingest"
	"github.com/JoeRu/swarmguard/internal/observability"
	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/rules"
	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/internal/transport"
	"github.com/JoeRu/swarmguard/internal/trust"
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
	trust      *trust.Store
	vouch      *proto.PeerCert   // this node's own peer-cert, attached to published events
	rules      *rules.RuleSet    // NEW
	burst      *rules.BurstStore // NEW
	obs        *observability.Observer
	api        *api.Server // nil-safe: all methods no-op when cfg.API.Addr == ""
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
	eng := reputation.New(s, halfLife, cfg.Trust.StrangerScoreCap)

	var sink enforce.Sink
	switch cfg.Enforce.Backend {
	case "nftables":
		sink = enforce.NewNftables(cfg.Enforce.SetName, cfg.Enforce.NftHook)
	case "crowdsec":
		sink = enforce.NewCrowdSec(cfg.Enforce, halfLife)
	default:
		sink = enforce.NewIpset(cfg.Enforce.SetName, cfg.Enforce.Chain)
	}

	nbl := enforce.NewNeverBlockList(cfg.Enforce.ExtraWhitelist)

	selfID := ""
	if t != nil {
		selfID = t.Host().ID().String()
	}

	ts := trust.NewStore(cfg.TrustAnchorsFile(), cfg.TrustCertsFile(), cfg.Trust.StrangerWeight)

	var vouch *proto.PeerCert
	if data, err := os.ReadFile(cfg.TrustPeerCertFile()); err == nil {
		var cert proto.PeerCert
		if jerr := json.Unmarshal(data, &cert); jerr != nil {
			log.Printf("node: ignoring malformed peer cert %s: %v", cfg.TrustPeerCertFile(), jerr)
		} else if verr := identity.VerifyCert(cert, time.Now()); verr != nil {
			log.Printf("node: ignoring invalid peer cert %s: %v", cfg.TrustPeerCertFile(), verr)
		} else if selfID != "" && cert.PeerID == selfID {
			vouch = &cert
		} else {
			// No transport identity (selfID == "") or the cert names a different
			// peer: a node must only vouch for its own verified peer ID.
			log.Printf("node: peer cert %s is for %s, not this node (%q) — ignoring", cfg.TrustPeerCertFile(), cert.PeerID, selfID)
		}
	}

	var sources []ingest.Source
	if cfg.Ingest.Honeypot.Enabled {
		sources = append(sources, ingest.NewHoneypot(cfg.Ingest.Honeypot, selfID))
	}
	if cfg.Ingest.OpenCanary.Enabled {
		sources = append(sources, ingest.NewOpenCanary(cfg.Ingest.OpenCanary, selfID))
	}
	if cfg.Ingest.CrowdSec.Enabled {
		sources = append(sources, ingest.NewCrowdSec(cfg.Ingest.CrowdSec, selfID))
	}

	obs, err := observability.New(cfg.Observability, cfg.Reputation, cfg.Store.Dir)
	if err != nil {
		return nil, fmt.Errorf("node: observability: %w", err)
	}

	apiSrv := api.New(cfg.API, s, cfg.Reputation)

	return &Node{
		cfg:        cfg,
		transport:  t,
		store:      s,
		rep:        eng,
		sources:    sources,
		sink:       sink,
		neverblock: nbl,
		selfID:     selfID,
		trust:      ts,
		vouch:      vouch,
		rules:      rules.Load(cfg.RulesFilePath(), cfg.Reputation.BlockThreshold),
		burst:      rules.NewBurstStore(),
		obs:        obs,
		api:        apiSrv,
	}, nil
}

// Run starts all subsystems and blocks until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	n.obs.Start(ctx)
	n.api.Start(ctx)
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

	var remoteCh <-chan transport.ReceivedEvent
	if n.transport != nil {
		remoteCh = n.transport.Subscribe()
	}

	if n.transport != nil {
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					n.obs.UpdatePeers(len(n.transport.Host().Network().Peers()))
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	for {
		select {
		case e, ok := <-localEvents:
			if !ok {
				localEvents = nil
				continue
			}
			n.processLocal(ctx, e)
		case re, ok := <-remoteCh:
			if !ok {
				remoteCh = nil
				continue
			}
			n.ProcessRemote(re)
			n.obs.RecordFederated("in")
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
	e.Vouch = n.vouch
	if _, err := n.rep.Record(e.IP, e.Reason, n.selfID, 1.0, n.selfID, true); err != nil {
		log.Printf("node: record local %s: %v", e.IP, err)
		return
	}
	n.burst.Record(e.IP, e.Reason, time.Now())
	rec, _ := n.rep.GetRecord(e.IP)
	action, ruleName := n.rules.Evaluate(e, rec, n.burst)
	switch action {
	case rules.ActionBlock:
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		} else {
			n.obs.RecordBlock(e.IP, rec.Score)
		}
	case rules.ActionWatch:
		log.Printf("node: watch %s reason=%s score=%.1f", e.IP, e.Reason, rec.Score)
	}
	n.obs.RecordEvent(e, rec.Score, ruleName, string(action))
	n.api.Broadcast(e.IP, rec.Score, e.Reason, e.ReporterID)
	if n.transport != nil {
		if err := n.transport.Publish(ctx, e); err != nil {
			log.Printf("node: publish %s: %v", e.IP, err)
		} else {
			n.obs.RecordFederated("out")
		}
	}
}

// ProcessRemote scores one event received from the swarm: it drops spoofed
// reporters, verifies any attached vouch, resolves the reporter's trust, and
// records the observation. Exported so the adversarial suite can drive the
// remote path directly.
func (n *Node) ProcessRemote(re transport.ReceivedEvent) {
	e := re.Event
	// An empty publisher means the message carried no verified origin — never
	// trust it (real libp2p peer IDs are non-empty; this also stops the spoof
	// guard below from passing trivially on "" == "").
	if re.From == "" {
		log.Printf("node: drop event with empty verified publisher")
		return
	}
	if e.ReporterID != re.From {
		log.Printf("node: drop spoofed event: reporter %q != verified publisher %q", e.ReporterID, re.From)
		return
	}
	if n.neverblock.Contains(e.IP) {
		return
	}

	if e.Vouch != nil {
		if e.Vouch.PeerID != e.ReporterID {
			// A cert for a different peer (replayed by this reporter) proves
			// nothing about the reporter — ignore it; they stay a stranger.
			log.Printf("node: vouch for %q attached by %q — ignoring cert", e.Vouch.PeerID, e.ReporterID)
		} else if err := n.trust.AddCert(*e.Vouch, time.Now()); err != nil {
			log.Printf("node: invalid vouch from %q: %v", e.ReporterID, err)
		}
	}

	weight, group, anchored := n.trust.Resolve(e.ReporterID)
	if _, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, weight, group, anchored); err != nil {
		log.Printf("node: record remote %s: %v", e.IP, err)
		return
	}
	n.burst.Record(e.IP, e.Reason, time.Now())
	rec, _ := n.rep.GetRecord(e.IP)
	action, ruleName := n.rules.Evaluate(e, rec, n.burst)
	switch action {
	case rules.ActionBlock:
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		} else {
			n.obs.RecordBlock(e.IP, rec.Score)
		}
	case rules.ActionWatch:
		log.Printf("node: watch %s reason=%s score=%.1f", e.IP, e.Reason, rec.Score)
	}
	n.obs.RecordEvent(e, rec.Score, ruleName, string(action))
	n.api.Broadcast(e.IP, rec.Score, e.Reason, e.ReporterID)
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
			} else {
				n.obs.RecordUnblock(ip)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("node: decay scan: %v", err)
	}
}

// GetScore returns the raw ScoreRecord for ip (zero value if not found).
// Exported so the adversarial suite can inspect reputation state without
// calling Run.
func (n *Node) GetScore(ip string) (store.ScoreRecord, error) {
	return n.rep.GetRecord(ip)
}

// SetTrustReloadInterval overrides the trust-store file re-check interval.
// Pass 0 in tests to force a reload on every Resolve call.
func (n *Node) SetTrustReloadInterval(d time.Duration) {
	n.trust.SetReloadInterval(d)
}

// CloseStores releases BadgerDB resources. Call in tests that build a Node
// outside of Run (which closes the store via defer on return).
func (n *Node) CloseStores() {
	_ = n.store.Close()
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
