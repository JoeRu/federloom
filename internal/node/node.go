package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/JoeRu/federloom/internal/api"
	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/discovery"
	"github.com/JoeRu/federloom/internal/dnsbl"
	"github.com/JoeRu/federloom/internal/enforce"
	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/ingest"
	"github.com/JoeRu/federloom/internal/observability"
	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/rules"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/internal/trust"
	"github.com/JoeRu/federloom/pkg/proto"
)

// maxOriginTraceLen is the maximum number of hops we accept in OriginTrace.
// Events with longer traces are dropped to prevent unbounded trace growth.
const maxOriginTraceLen = 8

// Node is the composition root that connects ingest, reputation, enforce, and transport.
type Node struct {
	cfg         *config.Config
	transport   *transport.Node // may be nil (solo mode without bootstrap)
	store       *store.BadgerStore
	rep         *reputation.Engine
	sources     []ingest.Source
	sink        enforce.Sink
	neverblock  *enforce.NeverBlockList
	whitelist   *store.WhitelistStore // local-only allowlist; never nil (may be empty)
	selfID      string
	trust       *trust.Store
	vouch       *proto.PeerCert      // this node's own peer-cert, attached to published events
	identityKey libp2pcrypto.PrivKey // nil in solo mode (no transport); set for signing events
	rules       *rules.RuleSet       // NEW
	burst       *rules.BurstStore    // NEW
	obs         *observability.Observer
	api         *api.Server        // nil-safe: all methods no-op when cfg.API.Addr == ""
	dnsbl       *dnsbl.Server      // nil-safe: Start is no-op when addr/zone are empty
	discovery   *discovery.Manager // nil in solo mode (no transport)
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
		sink = enforce.NewIpset(cfg.Enforce.SetName, cfg.Enforce.EffectiveChains())
	}

	nbl := enforce.NewNeverBlockList(cfg.Enforce.ExtraWhitelist)

	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("node: load whitelist: %w", err)
	}

	selfID := ""
	if t != nil {
		selfID = t.Host().ID().String()
	}

	ts := trust.NewStore(cfg.TrustAnchorsFile(), cfg.TrustCertsFile(), cfg.TrustBlockedPeersFile(), cfg.Trust.StrangerWeight)

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

	var identityKey libp2pcrypto.PrivKey
	if t != nil {
		identityKey, err = identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("node: load identity key for signing: %w", err)
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
	if cfg.Ingest.MailcowLogs.Enabled {
		sources = append(sources, ingest.NewMailcow(cfg.Ingest.MailcowLogs, selfID))
	}
	if cfg.Ingest.Spamtrap.Enabled {
		sources = append(sources, ingest.NewSpamtrap(cfg.Ingest.Spamtrap, selfID))
	}
	if cfg.Ingest.Fail2Ban.Enabled {
		sources = append(sources, ingest.NewFail2Ban(cfg.Ingest.Fail2Ban, selfID))
	}

	obs, err := observability.New(cfg.Observability, cfg.Reputation, cfg.Store.Dir)
	if err != nil {
		return nil, fmt.Errorf("node: observability: %w", err)
	}

	apiSrv := api.New(cfg.API, s, cfg.Reputation)
	dnsblSrv := dnsbl.New(cfg.DNSBL, s, cfg.Reputation)

	var disc *discovery.Manager
	if t != nil {
		disc = discovery.New(t.Host(), t.DHT(), cfg.Discovery)
	}

	return &Node{
		cfg:         cfg,
		transport:   t,
		store:       s,
		rep:         eng,
		sources:     sources,
		sink:        sink,
		neverblock:  nbl,
		whitelist:   wl,
		selfID:      selfID,
		trust:       ts,
		vouch:       vouch,
		identityKey: identityKey,
		rules:       rules.Load(cfg.RulesFilePath(), cfg.Reputation.BlockThreshold, cfg.Trust.StrangerScoreCap),
		burst:       rules.NewBurstStore(),
		obs:         obs,
		api:         apiSrv,
		dnsbl:       dnsblSrv,
		discovery:   disc,
	}, nil
}

// Run starts all subsystems and blocks until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	n.obs.Start(ctx)
	n.api.Start(ctx)
	n.dnsbl.Start(ctx)
	if n.discovery != nil {
		go n.discovery.Start(ctx)
	}
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
	addr, err := netip.ParseAddr(e.IP)
	if err != nil {
		log.Printf("node: drop event with invalid IP %q", e.IP)
		return
	}
	e.IP = addr.Unmap().String()
	if n.neverblock.Contains(e.IP) {
		return
	}
	if n.whitelist.Contains(e.IP) {
		return
	}
	e.ReporterID = n.selfID
	e.Vouch = n.vouch
	if n.selfID != "" {
		e.OriginTrace = []string{n.selfID}
	}
	if n.identityKey != nil {
		if err := identity.SignEvent(&e, n.identityKey); err != nil {
			log.Printf("node: sign event for %s: %v", e.IP, err)
			// non-fatal: publish unsigned rather than drop local observation
		}
	}
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
			n.obs.RecordBlock(e.IP, ruleName, rec.Score, rec.FirstSeen, rec.Corroboration)
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
	if n.trust.IsBlocked(re.From) {
		log.Printf("node: drop event from blocked peer %s", re.From)
		return
	}
	if len(e.Signature) > 0 {
		if err := identity.VerifyEventSig(e); err != nil {
			log.Printf("node: drop event with bad signature from %s: %v", re.From, err)
			return
		}
	}
	addr, err := netip.ParseAddr(e.IP)
	if err != nil {
		log.Printf("node: drop event with invalid IP %q", e.IP)
		return
	}
	e.IP = addr.Unmap().String()
	// Feedback loop guard: drop events that have already passed through this node.
	if n.selfID != "" {
		for _, hop := range e.OriginTrace {
			if hop == n.selfID {
				log.Printf("node: drop feedback-loop event from %s (selfID in OriginTrace)", re.From)
				return
			}
		}
	}
	// Trace length cap: prevent unbounded growth on misbehaving relays.
	if len(e.OriginTrace) > maxOriginTraceLen {
		log.Printf("node: drop event from %s: OriginTrace length %d exceeds limit %d", re.From, len(e.OriginTrace), maxOriginTraceLen)
		return
	}
	if n.neverblock.Contains(e.IP) {
		return
	}
	if n.whitelist.Contains(e.IP) {
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
	// Federation discount: non-anchored reporters lose weight per hop (spec §5.2).
	// Anchored reporters are exempt — their trust is explicitly established.
	// NOTE: gossipsub forwards raw bytes without appending relay hops to OriginTrace,
	// so len(OriginTrace) is always 1 (set by the originator in processLocal) and the
	// cross-node A→B→A feedback-loop guard above is not yet active at runtime. Both
	// become effective when the forwarding path appends selfID before re-broadcast.
	if !anchored && len(e.OriginTrace) > 0 {
		discount := n.cfg.Trust.FederationDiscount
		if discount <= 0 || discount > 1 {
			discount = 0.5 // safe fallback for misconfigured values
		}
		for i := 0; i < len(e.OriginTrace); i++ {
			weight *= discount
		}
	}
	if _, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, weight, group, anchored); err != nil {
		log.Printf("node: record remote %s: %v", e.IP, err)
		return
	}
	// Only anchored reporters feed the burst window: an un-anchored remote peer
	// must not be able to trip a min_burst block rule (spec Leitprinzip 8; P0-2).
	if anchored {
		n.burst.Record(e.IP, e.Reason, time.Now())
	}
	rec, _ := n.rep.GetRecord(e.IP)
	action, ruleName := n.rules.Evaluate(e, rec, n.burst)
	// Structural guarantee (spec Leitprinzip 8): a remote signal may never FORCE a
	// block on stranger-only evidence. rec.Groups holds only anchored Person names
	// (P0-1), so len==0 means no anchored voucher backs this IP; downgrade any block
	// to watch regardless of rule configuration (bare-reason block, min_score below
	// the stranger cap, or legacy fallback).
	if action == rules.ActionBlock && len(rec.Groups) == 0 {
		log.Printf("node: downgrading stranger-only block to watch for %s (rule %q, no anchored corroboration)", e.IP, ruleName)
		action = rules.ActionWatch
	}
	switch action {
	case rules.ActionBlock:
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		} else {
			n.obs.RecordBlock(e.IP, ruleName, rec.Score, rec.FirstSeen, rec.Corroboration)
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

// SetSinkForTest replaces the enforce sink. Test-only: lets adversarial tests
// observe Block/Unblock decisions through a mock sink without touching a real
// firewall. Not called in production paths.
func (n *Node) SetSinkForTest(s enforce.Sink) { n.sink = s }

// CloseStores releases BadgerDB resources. Call in tests that build a Node
// outside of Run (which closes the store via defer on return).
func (n *Node) CloseStores() {
	_ = n.store.Close()
}

// SelfID returns this node's libp2p peer ID string (empty in solo mode).
func (n *Node) SelfID() string { return n.selfID }

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
