package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/api"
	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/discovery"
	"github.com/JoeRu/federloom/internal/dnsbl"
	"github.com/JoeRu/federloom/internal/enforce"
	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/ingest"
	"github.com/JoeRu/federloom/internal/netutil"
	"github.com/JoeRu/federloom/internal/observability"
	"github.com/JoeRu/federloom/internal/repquery"
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
	dedup       *dedupCache

	matMu        sync.Mutex          // guards materialised/disputed
	materialised map[string]struct{} // IPs with a live materialised federated block
	disputed     map[string]struct{} // IPs suppressed from re-materialise by a diverse dispute
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
	if p := cfg.Reputation.IPv6Prefix; p != 0 && (p < 1 || p > 128) {
		log.Printf("node: reputation.ipv6_prefix %d out of range [1,128]; using default 64", p)
	}
	eng := reputation.New(s, halfLife, cfg.Trust.StrangerScoreCap, cfg.EffectiveDiversityRepeatFactor(), cfg.EffectiveDisputeWeight())

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

	if t != nil {
		// Serve role (design 2026-07-10 §4): always answer anchored,
		// non-blocked peers when federated. Defederation (blocked_peers)
		// is the per-peer off switch.
		repquery.RegisterResponder(t.Host(), s, ts)
	}

	var resolver *repquery.Resolver
	if t != nil && len(cfg.FederationAggregators) > 0 {
		aggs := parseAggregators(cfg.FederationAggregators)
		if len(aggs) == 0 {
			log.Printf("node: federation_aggregators set but none parsed to a valid peer; federated query disabled")
		} else {
			q := repquery.NewQuerier(t.Host(), aggs, cfg.EffectiveQueryTimeout(), cfg.EffectiveQueryCacheTTL(),
				halfLife, cfg.Trust.StrangerScoreCap, cfg.Trust.FederationDiscount, cfg.EffectiveDiversityRepeatFactor(), cfg.EffectiveDisputeWeight())
			resolver = repquery.NewResolver(s, q, nil)
		}
	}

	var dnsblReader dnsbl.StoreReader = s
	if resolver != nil {
		dnsblReader = resolver
	}

	apiSrv := api.New(cfg.API, s, cfg.Reputation)
	if resolver != nil {
		apiSrv.SetPointReader(resolver)
	}
	dnsblSrv := dnsbl.New(cfg.DNSBL, dnsblReader, cfg.Reputation)

	var disc *discovery.Manager
	if t != nil {
		disc = discovery.New(t.Host(), t.DHT(), cfg.Discovery)
	}

	dedup := newDedupCache(100_000, 10*time.Minute)

	n := &Node{
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
		dedup:       dedup,

		materialised: make(map[string]struct{}),
		disputed:     make(map[string]struct{}),
	}

	if resolver != nil && cfg.FederationMaterialize {
		resolver.SetMaterialiser(n.materialiseFederated)
	}

	return n, nil
}

// Run starts all subsystems and blocks until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	if n.transport != nil {
		n.publishSharedVotes(ctx)
	}
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
	key, err := netutil.NormalizeIP(e.IP, n.cfg.Reputation.EffectiveIPv6Prefix())
	if err != nil {
		log.Printf("node: drop event with invalid IP %q: %v", e.IP, err)
		return
	}
	e.IP = key
	if n.neverblock.Contains(e.IP) {
		return
	}
	if n.whitelist.Contains(e.IP) {
		return
	}
	e.ReporterID = n.selfID
	e.Vouch = n.vouch
	e.SubnetID = n.cfg.FederationSubnet
	if n.selfID != "" {
		e.OriginTrace = []string{n.selfID}
	}
	if n.identityKey != nil {
		if err := identity.SignEvent(&e, n.identityKey); err != nil {
			log.Printf("node: sign event for %s: %v", e.IP, err)
			// non-fatal: publish unsigned rather than drop local observation
		}
	}
	_ = n.dedup.Seen(dedupKey(e.ReporterID, e.IP, e.Reason, e.Timestamp), time.Now())
	// Local observations are this node's own direct evidence — they must
	// escalate on repetition (self-defense), so they bypass subnet-diversity
	// damping (empty subnet). Diversity weighting applies only to federated
	// (remote) reports in ProcessRemote, where source independence is the point.
	if _, err := n.rep.Record(e.IP, e.Reason, n.selfID, 1.0, n.selfID, "", true); err != nil {
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
		if err := n.transport.Publish(ctx, e, n.cfg.FederationSubnet); err != nil {
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
		// A relayed (bridged) event is re-published under the relaying node's peer
		// ID, not the originator's. Authenticate it by the originator's signature
		// (verified below against e.ReporterID) and require the verified publisher
		// to be the last hop in OriginTrace — the bridge that re-emitted it. This
		// keeps the anti-spoofing guarantee: a relay cannot forge an event from
		// someone else (it cannot produce that peer's signature).
		if len(e.Signature) == 0 {
			log.Printf("node: drop relayed event from %s: reporter %q != publisher and no signature", re.From, e.ReporterID)
			return
		}
		if len(e.OriginTrace) == 0 || e.OriginTrace[len(e.OriginTrace)-1] != re.From {
			log.Printf("node: drop relayed event: publisher %q is not the last OriginTrace hop", re.From)
			return
		}
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
	key, err := netutil.NormalizeIP(e.IP, n.cfg.Reputation.EffectiveIPv6Prefix())
	if err != nil {
		log.Printf("node: drop event with invalid IP %q: %v", e.IP, err)
		return
	}
	e.IP = key
	if e.Kind == "vote" {
		n.processDispute(e, re)
		return
	}
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

	if n.dedup.Seen(dedupKey(e.ReporterID, e.IP, e.Reason, e.Timestamp), time.Now()) {
		return // already processed this exact event via another path
	}

	weight, group, anchored := n.trust.Resolve(e.ReporterID)
	// Federation discount: a non-anchored reporter loses weight per BRIDGE hop —
	// bridgeHops = len(OriginTrace)-1 (the originator itself is not a hop), so a
	// same-subnet direct event (len 1) is NOT discounted, and each subnet crossing
	// multiplies by FederationDiscount (spec §5.2). Anchored reporters are exempt.
	if bridgeHops := len(e.OriginTrace) - 1; !anchored && bridgeHops > 0 {
		discount := n.cfg.Trust.FederationDiscount
		if discount <= 0 || discount > 1 {
			discount = 0.5 // safe fallback for misconfigured values
		}
		for i := 0; i < bridgeHops; i++ {
			weight *= discount
		}
	}
	if _, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, weight, group, e.SubnetID, anchored); err != nil {
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
	n.reemitIfBridge(re)
}

// processDispute applies a federated dispute vote (Event.Kind == "vote") to the
// IP's score as a diversity-weighted negative vote, and (Task 5) unblocks a
// materialised federated block once distinct disputing subnets cross the floor.
func (n *Node) processDispute(e proto.Event, re transport.ReceivedEvent) {
	// Dedup (reason is "" for a vote → key distinct from any report).
	if n.dedup.Seen(dedupKey(e.ReporterID, e.IP, e.Reason, e.Timestamp), time.Now()) {
		return
	}
	if e.Vouch != nil && e.Vouch.PeerID == e.ReporterID {
		if err := n.trust.AddCert(*e.Vouch, time.Now()); err != nil {
			log.Printf("node: invalid vouch on dispute from %q: %v", e.ReporterID, err)
		}
	}
	weight, _, anchored := n.trust.Resolve(e.ReporterID)
	score, disputeSubnets, err := n.rep.RecordDispute(e.IP, e.ReporterID, weight, e.SubnetID, anchored)
	if err != nil {
		log.Printf("node: record dispute %s: %v", e.IP, err)
		return
	}
	log.Printf("node: dispute %s from %s (subnet=%s anchored=%t) → score=%.1f dispute_subnets=%d", e.IP, e.ReporterID, e.SubnetID, anchored, score, disputeSubnets)
	n.maybeUnblockDisputed(e.IP, disputeSubnets) // implemented in Task 5 (add a no-op stub here)
}

// maybeUnblockDisputed unblocks a materialised FEDERATED block for ip once
// distinct disputing subnets reach the floor, and suppresses re-materialisation.
// It NEVER touches a block that was not materialised by this node (local
// anchored blocks are absent from n.materialised) — local sovereignty.
func (n *Node) maybeUnblockDisputed(ip string, disputeSubnets int) {
	if disputeSubnets < n.cfg.DisputeUnblockMinSubnets {
		return
	}
	n.matMu.Lock()
	_, wasMaterialised := n.materialised[ip]
	n.disputed[ip] = struct{}{} // suppress future re-materialise regardless
	delete(n.materialised, ip)
	n.matMu.Unlock()
	if !wasMaterialised {
		return // never Unblock something we didn't materialise (local block, etc.)
	}
	if err := n.sink.Unblock(ip); err != nil {
		log.Printf("node: dispute-unblock %s: %v", ip, err)
		return
	}
	log.Printf("node: dispute-unblocked federated block %s (dispute_subnets=%d)", ip, disputeSubnets)
	n.obs.RecordUnblock(ip)
}

// publishSharedVotes emits a signed dispute vote for each shared-vote
// whitelist entry (re-announced disputes; late joiners hear them via the
// responder/gossip). local-only entries are never emitted (privacy).
func (n *Node) publishSharedVotes(ctx context.Context) {
	if n.transport == nil || n.identityKey == nil {
		return
	}
	for _, entry := range n.whitelist.List() {
		if entry.Scope != "shared-vote" {
			continue // local-only never federates (privacy)
		}
		v := proto.Event{IP: entry.IPOrRange, Kind: "vote", ReporterID: n.selfID, SubnetID: n.cfg.FederationSubnet, Timestamp: time.Now().UTC()}
		if err := identity.SignEvent(&v, n.identityKey); err != nil {
			log.Printf("node: sign shared-vote for %s: %v", entry.IPOrRange, err)
			continue
		}
		if err := n.transport.Publish(ctx, v, n.cfg.FederationSubnet); err != nil {
			log.Printf("node: publish shared-vote for %s: %v", entry.IPOrRange, err)
		}
		// Apply to our own record too (we count toward the aggregate we serve).
		w, _, anchored := n.trust.Resolve(n.selfID)
		_, _, _ = n.rep.RecordDispute(entry.IPOrRange, n.selfID, w, n.cfg.FederationSubnet, anchored)
	}
}

// reemitIfBridge re-publishes an accepted remote event onto every subnet this
// node is joined to (home + bridges) except the one it arrived on, appending
// selfID to OriginTrace. Leaves (no bridge subnets configured) and loop/cap
// conditions are no-ops. The originator's signature is preserved (OriginTrace
// is not signed).
func (n *Node) reemitIfBridge(re transport.ReceivedEvent) {
	if n.transport == nil || n.selfID == "" {
		return
	}
	bridges := n.cfg.EffectiveBridgeSubnets()
	if len(bridges) == 0 {
		return // leaf
	}
	e := re.Event
	// Loop guard: never re-emit an event that already passed through us.
	for _, hop := range e.OriginTrace {
		if hop == n.selfID {
			return
		}
	}
	if len(e.OriginTrace) >= maxOriginTraceLen {
		return
	}
	out := e
	out.OriginTrace = append(append([]string{}, e.OriginTrace...), n.selfID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, sn := range n.transport.Subnets() {
		if sn == re.Subnet {
			continue // don't echo back onto the subnet it arrived from
		}
		if err := n.transport.Publish(ctx, out, sn); err != nil {
			log.Printf("node: bridge re-emit to subnet %q failed: %v", sn, err)
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

// SinkForTest returns the current enforce sink. Test-only.
func (n *Node) SinkForTest() enforce.Sink { return n.sink }

// DisputeForTest applies a dispute for ip from subnet, driving the same path as
// a received vote (anchored, full trust). Test-only.
func (n *Node) DisputeForTest(ip, subnet string) {
	_, ds, _ := n.rep.RecordDispute(ip, "test-disputer-"+subnet, 1.0, subnet, true)
	n.maybeUnblockDisputed(ip, ds)
}

// DisputeAsStrangerForTest applies a dispute for ip from subnet as an
// UNANCHORED (stranger) vote, at the stranger trust weight, driving the same
// path as a received vote from a non-vouched peer. Lets adversarial tests
// exercise the Sybil-fabricated-subnet path: a stranger can claim any
// SubnetID it likes (unsigned, attacker-controlled) but must never be able to
// grow dispute-subnet diversity — see reputation.ApplyDispute. Test-only.
func (n *Node) DisputeAsStrangerForTest(ip, subnet string) {
	_, ds, _ := n.rep.RecordDispute(ip, "stranger-"+subnet, n.cfg.Trust.StrangerWeight, subnet, false)
	n.maybeUnblockDisputed(ip, ds)
}

// materialiseFederated is the callback the resolver invokes on a federated hit.
// It applies the federated block gate (design 2026-07-13 §4) and, on pass,
// pushes a TTL-bounded block. Read of n.sink is deferred so SetSinkForTest works.
func (n *Node) materialiseFederated(ip string, rec store.ScoreRecord, subnets int) {
	if !n.cfg.FederationMaterialize {
		return
	}
	if n.neverblock.Contains(ip) || n.whitelist.Contains(ip) {
		return // never-block / whitelist always win
	}
	if rec.Score < n.cfg.FederationBlockThreshold || subnets < n.cfg.FederationBlockMinSubnets {
		return // not block-worthy or insufficient diversity
	}
	n.matMu.Lock()
	_, suppressed := n.disputed[ip]
	n.matMu.Unlock()
	if suppressed {
		return // an active diverse dispute suppresses (re-)materialisation
	}
	ttl := n.cfg.EffectiveFederationBlockTTL()
	if err := n.sink.BlockFor(ip, ttl); err != nil {
		log.Printf("node: materialise block %s: %v", ip, err)
		return
	}
	n.matMu.Lock()
	n.materialised[ip] = struct{}{}
	n.matMu.Unlock()
	log.Printf("node: materialised federated block %s (score=%.1f subnets=%d ttl=%s)", ip, rec.Score, subnets, ttl)
	n.obs.RecordBlock(ip, "federated-materialise", rec.Score, rec.FirstSeen, rec.Corroboration)
}

// ScoreViaPointReaderForTest routes an IP through the API point reader (the same
// resolver the DNSBL/API use), so tests can drive the federated read+materialise
// path. Test-only.
func (n *Node) ScoreViaPointReaderForTest(ip string) (store.ScoreRecord, error) {
	return n.api.PointLookupForTest(ip)
}

// MaterialiseForTest drives the federated materialise gate directly with a
// crafted verdict, bypassing the resolver wiring. Test-only.
func (n *Node) MaterialiseForTest(ip string, rec store.ScoreRecord, subnets int) {
	n.materialiseFederated(ip, rec, subnets)
}

// CloseStores releases BadgerDB resources. Call in tests that build a Node
// outside of Run (which closes the store via defer on return).
func (n *Node) CloseStores() {
	_ = n.store.Close()
}

// SelfID returns this node's libp2p peer ID string (empty in solo mode).
func (n *Node) SelfID() string { return n.selfID }

// parseAggregators turns configured multiaddrs into libp2p AddrInfos, skipping bad ones.
func parseAggregators(addrs []string) []peer.AddrInfo {
	var out []peer.AddrInfo
	for _, a := range addrs {
		info, err := peer.AddrInfoFromString(a)
		if err != nil {
			log.Printf("node: bad federation aggregator %q: %v", a, err)
			continue
		}
		out = append(out, *info)
	}
	return out
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
