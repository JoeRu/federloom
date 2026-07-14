package node

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/enforce"
	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/rules"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/internal/trust"
	"github.com/JoeRu/federloom/pkg/proto"
)

// testNode builds a Node with a temp store, no transport, and a permissive
// block threshold so the enforce sink is never invoked.
func testNode(t *testing.T) (*Node, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.BlockThreshold = 1000

	s, err := store.Open(dir + "/db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ts := trust.NewStore(cfg.TrustAnchorsFile(), cfg.TrustCertsFile(), cfg.TrustBlockedPeersFile(), cfg.Trust.StrangerWeight)
	ts.SetReloadInterval(0)

	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}

	return &Node{
		cfg:        cfg,
		store:      s,
		rep:        reputation.New(s, 7*24*time.Hour, cfg.Trust.StrangerScoreCap, cfg.EffectiveDiversityRepeatFactor(), cfg.EffectiveDisputeWeight()),
		neverblock: enforce.NewNeverBlockList(nil),
		whitelist:  wl,
		trust:      ts,
		selfID:     "12D3KooWself",
		rules:      rules.Load("", cfg.Reputation.BlockThreshold, cfg.Trust.StrangerScoreCap),
		burst:      rules.NewBurstStore(),
		dedup:      newDedupCache(100_000, 10*time.Minute),
	}, dir
}

// TestNodeAcceptsMailcowAndSpamtrapConfig verifies that New() wires MailcowLogs
// and Spamtrap sources when their configs have Enabled: true.
func TestNodeAcceptsMailcowAndSpamtrapConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.BlockThreshold = 1000
	cfg.Ingest.MailcowLogs.Enabled = true
	cfg.Ingest.MailcowLogs.PostfixContainer = "test-postfix"
	cfg.Ingest.MailcowLogs.DovecotContainer = "test-dovecot"
	cfg.Ingest.Spamtrap.Enabled = true
	cfg.Ingest.Spamtrap.LogFile = filepath.Join(dir, "spamtrap.log")

	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New with mailcow+spamtrap config: %v", err)
	}
	defer n.CloseStores()

	names := make([]string, 0, len(n.sources))
	for _, src := range n.sources {
		names = append(names, src.Name())
	}
	hasMail := false
	hasSpam := false
	for _, name := range names {
		if name == "mailcow" {
			hasMail = true
		}
		if name == "spamtrap" {
			hasSpam = true
		}
	}
	if !hasMail {
		t.Errorf("mailcow source not wired; sources = %v", names)
	}
	if !hasSpam {
		t.Errorf("spamtrap source not wired; sources = %v", names)
	}
}

// TestSpoofedReporterDropped: ReporterID != verified publisher → event ignored.
func TestSpoofedReporterDropped(t *testing.T) {
	n, _ := testNode(t)
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "192.0.2.10", Reason: "ssh-probe", ReporterID: "12D3KooWvictim"},
		From:  "12D3KooWattacker",
	})
	rec, err := n.rep.GetRecord("192.0.2.10")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if !rec.LastSeen.IsZero() {
		t.Error("spoofed event reached the reputation engine")
	}
}

// TestVouchedReporterScoresAsAnchored: a valid on-wire vouch from an anchored
// Person resolves to the anchor weight and group.
func TestVouchedReporterScoresAsAnchored(t *testing.T) {
	n, dir := testNode(t)

	priv, err := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	if err := trust.SaveAnchors(n.cfg.TrustAnchorsFile(), []trust.Anchor{{
		Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "self-added",
	}}); err != nil {
		t.Fatalf("save anchors: %v", err)
	}

	cert := identity.IssueCert(priv, "12D3KooWjoA", time.Now().Add(time.Hour))
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "192.0.2.11", Reason: "ssh-probe", ReporterID: "12D3KooWjoA", Vouch: &cert},
		From:  "12D3KooWjoA",
	})

	rec, _ := n.rep.GetRecord("192.0.2.11")
	if len(rec.Groups) != 1 || rec.Groups[0] != "jo" {
		t.Errorf("Groups = %v, want [jo]", rec.Groups)
	}
	if rec.StrangerSeen {
		t.Error("vouched reporter recorded as stranger")
	}
}

// TestVouchReplayedCertIsStranger: a cert for peer A attached by peer B is
// rejected — B stays a stranger.
func TestVouchReplayedCertIsStranger(t *testing.T) {
	n, dir := testNode(t)

	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	_ = trust.SaveAnchors(n.cfg.TrustAnchorsFile(), []trust.Anchor{{
		Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "self-added",
	}})

	certForA := identity.IssueCert(priv, "12D3KooWjoA", time.Now().Add(time.Hour))
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "192.0.2.12", Reason: "ssh-probe", ReporterID: "12D3KooWeve", Vouch: &certForA},
		From:  "12D3KooWeve",
	})

	rec, _ := n.rep.GetRecord("192.0.2.12")
	if len(rec.Groups) != 0 {
		t.Errorf("replayed cert produced anchored groups: %v", rec.Groups)
	}
	if !rec.StrangerSeen {
		t.Error("event was dropped entirely; replayed-cert events should score as stranger")
	}
}

// TestProcessLocalDropsInvalidIP verifies that processLocal silently drops events
// whose IP field is not a bare IPv4/IPv6 address (CIDR, hostname, newline-embedded).
func TestProcessLocalDropsInvalidIP(t *testing.T) {
	cases := []string{
		"0.0.0.0/0",        // CIDR — block-all nftables attack
		"1.2.3.4\n5.6.7.8", // newline injection
		"example.com",      // hostname
		"",                 // empty
	}
	for _, ip := range cases {
		ip := ip
		t.Run(ip, func(t *testing.T) {
			n, _ := testNode(t)
			n.processLocal(context.Background(), proto.Event{IP: ip, Reason: "ssh-probe"})
			rec, _ := n.rep.GetRecord(ip)
			if !rec.LastSeen.IsZero() {
				t.Errorf("invalid IP %q was recorded in reputation store", ip)
			}
		})
	}
}

// TestProcessRemoteDropsInvalidIP verifies that ProcessRemote silently drops events
// whose IP field is not a bare IPv4/IPv6 address.
func TestProcessRemoteDropsInvalidIP(t *testing.T) {
	cases := []string{
		"0.0.0.0/0",
		"1.2.3.4\n5.6.7.8",
		"example.com",
		"",
	}
	for _, ip := range cases {
		ip := ip
		t.Run(ip, func(t *testing.T) {
			n, _ := testNode(t)
			n.ProcessRemote(transport.ReceivedEvent{
				Event: proto.Event{IP: ip, Reason: "ssh-probe", ReporterID: "12D3KooWpeer"},
				From:  "12D3KooWpeer",
			})
			rec, _ := n.rep.GetRecord(ip)
			if !rec.LastSeen.IsZero() {
				t.Errorf("invalid IP %q was recorded in reputation store", ip)
			}
		})
	}
}

// TestProcessLocalAcceptsValidIP is the control: a valid bare IP must be recorded.
func TestProcessLocalAcceptsValidIP(t *testing.T) {
	n, _ := testNode(t)
	n.processLocal(context.Background(), proto.Event{IP: "203.0.113.1", Reason: "ssh-probe"})
	rec, err := n.rep.GetRecord("203.0.113.1")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.LastSeen.IsZero() {
		t.Error("valid IP was not recorded in reputation store")
	}
}

func TestProcessRemoteScoresValidEventWithOriginTrace(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	// We can't easily inspect the event after processLocal without a transport.
	// Instead verify via published-event capture — use the exported BroadcastCh helper.
	// Since we have no transport, just confirm the node starts without error.
	// The OriginTrace content is validated in integration tests.
	// Here we at least confirm processLocal does not panic with selfID="".
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:          "203.0.113.1",
			Reason:      "ssh-probe",
			ReporterID:  "12D3KooWtestpeer",
			OriginTrace: []string{"12D3KooWtestpeer"},
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ := n.GetScore("203.0.113.1")
	if rec.LastSeen.IsZero() {
		t.Error("expected score recorded for valid remote event")
	}
}

func TestProcessRemoteDropsFeedbackLoop(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	// When selfID is "" (solo mode), no loop guard fires. Test the logic
	// by injecting an event where the OriginTrace contains the node's own ID
	// via SelfID accessor.
	selfID := n.SelfID()
	if selfID == "" {
		t.Skip("no selfID in solo mode — feedback loop guard requires transport")
	}
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:          "203.0.113.2",
			Reason:      "ssh-probe",
			ReporterID:  "12D3KooWtestpeer",
			OriginTrace: []string{"12D3KooWtestpeer", selfID}, // selfID in trace = loop
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ := n.GetScore("203.0.113.2")
	if !rec.LastSeen.IsZero() {
		t.Error("event with selfID in OriginTrace should have been dropped")
	}
}

func TestProcessRemoteDropsOverlongOriginTrace(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	longTrace := make([]string, 9) // 9 > maxOriginTraceLen(8)
	for i := range longTrace {
		longTrace[i] = fmt.Sprintf("12D3KooWhop%d", i)
	}
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:          "203.0.113.3",
			Reason:      "ssh-probe",
			ReporterID:  "12D3KooWtestpeer",
			OriginTrace: longTrace,
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ := n.GetScore("203.0.113.3")
	if !rec.LastSeen.IsZero() {
		t.Error("event with overlong OriginTrace should have been dropped")
	}
}

func TestProcessRemoteRespectsWhitelist(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir

	// Pre-populate whitelist before node creation (no hot-reload in this phase).
	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	if err := wl.Add(proto.WhitelistEntry{
		IPOrRange: "203.0.113.1",
		Scope:     "local-only",
		Source:    "manual",
	}); err != nil {
		t.Fatalf("whitelist Add: %v", err)
	}

	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	// Whitelisted IP: ProcessRemote must not score it.
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:         "203.0.113.1",
			Reason:     "ssh-probe",
			ReporterID: "12D3KooWtestpeer",
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ := n.GetScore("203.0.113.1")
	if !rec.LastSeen.IsZero() {
		t.Error("whitelisted IP should not be scored")
	}

	// Non-whitelisted IP in same /24: must be scored normally.
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:         "203.0.113.2",
			Reason:     "ssh-probe",
			ReporterID: "12D3KooWtestpeer",
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ = n.GetScore("203.0.113.2")
	if rec.LastSeen.IsZero() {
		t.Error("non-whitelisted IP should be scored normally")
	}
}

func TestProcessLocalNormalizesIPv6(t *testing.T) {
	n, _ := testNode(t)
	ctx := context.Background()

	n.processLocal(ctx, proto.Event{IP: "2001:0db8::0001", Reason: "test"})

	// With the configured (default /64) IPv6 prefix, the event is keyed under
	// the masked CIDR, not the bare /128 address.
	rec, err := n.rep.GetRecord("2001:db8::/64")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Score == 0 {
		t.Error("expected non-zero score stored under canonical key 2001:db8::/64")
	}
	recBare, _ := n.rep.GetRecord("2001:db8::1")
	if recBare.Score != 0 {
		t.Error("bare /128 key must not be recorded — event should aggregate under the /64 key")
	}
}

func TestProcessLocalCollapsesIPv4Mapped(t *testing.T) {
	n, _ := testNode(t)
	ctx := context.Background()

	n.processLocal(ctx, proto.Event{IP: "::ffff:1.2.3.4", Reason: "test"})

	rec, err := n.rep.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Score == 0 {
		t.Error("expected non-zero score under key 1.2.3.4 after IPv4-mapped event")
	}
	recMapped, _ := n.rep.GetRecord("::ffff:1.2.3.4")
	if recMapped.Score != 0 {
		t.Error("key ::ffff:1.2.3.4 must be empty — event should be stored as 1.2.3.4")
	}
}

func TestProcessLocalSplitReputationPrevention(t *testing.T) {
	n, _ := testNode(t)
	ctx := context.Background()

	n.processLocal(ctx, proto.Event{IP: "::ffff:1.2.3.4", Reason: "test"})
	n.processLocal(ctx, proto.Event{IP: "1.2.3.4", Reason: "test"})

	rec, err := n.rep.GetRecord("1.2.3.4")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Score < 2 {
		t.Errorf("expected combined score ≥ 2 (both events merged), got %.1f", rec.Score)
	}
}

func TestProcessRemoteRespectsWhitelistCIDR(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir

	wl, err := store.LoadWhitelist(cfg.WhitelistFile())
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	if err := wl.Add(proto.WhitelistEntry{
		IPOrRange: "198.51.100.0/24",
		Scope:     "local-only",
		Source:    "install-script",
	}); err != nil {
		t.Fatalf("whitelist Add: %v", err)
	}

	n, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.CloseStores()

	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:         "198.51.100.42",
			Reason:     "smtp-auth",
			ReporterID: "12D3KooWtestpeer",
		},
		From: "12D3KooWtestpeer",
	})
	rec, _ := n.GetScore("198.51.100.42")
	if !rec.LastSeen.IsZero() {
		t.Error("IP in whitelisted CIDR must not be scored")
	}
}

// TestDiversityKeysOnOriginSubnet: two remote reports for the same IP that
// originated in the SAME subnet (e.SubnetID) but arrived via DIFFERENT arrival
// subnets (re.Subnet) must count as ONE subnet for diversity — a bridge cannot
// launder a same-origin report into a fresh diversity vote.
func TestDiversityKeysOnOriginSubnet(t *testing.T) {
	n, _ := testNode(t)
	mk := func(arrival string) transport.ReceivedEvent {
		return transport.ReceivedEvent{
			Event: proto.Event{
				IP: "198.51.100.5", Reason: "ssh-probe", ReporterID: "origX",
				Timestamp: time.Now().UTC(), SubnetID: "home", OriginTrace: []string{"origX"},
			},
			From: "origX", Subnet: arrival,
		}
	}
	n.ProcessRemote(mk("bridgepath1"))
	rec1, _ := n.GetScore("198.51.100.5")
	n.ProcessRemote(transport.ReceivedEvent{ // second copy, same origin subnet "home", different arrival
		Event: proto.Event{
			IP: "198.51.100.5", Reason: "ssh-probe", ReporterID: "origX",
			Timestamp: time.Now().UTC(), SubnetID: "home", OriginTrace: []string{"origX"},
		},
		From: "origX", Subnet: "bridgepath2",
	})
	rec2, _ := n.GetScore("198.51.100.5")

	if len(rec2.SubnetsSeen) != 1 || rec2.SubnetsSeen[0] != "home" {
		t.Errorf("diversity must key on origin SubnetID; SubnetsSeen = %v, want [home]", rec2.SubnetsSeen)
	}
	// The second (same-origin-subnet) report is damped, so the score gain is small.
	gain := rec2.Score - rec1.Score
	if gain >= (rec1.Score - 0) { // second gain must be strictly less than the first full contribution
		t.Errorf("same-subnet repeat not damped: first=%v secondGain=%v", rec1.Score, gain)
	}
}

// TestLocalObservationsBypassDiversity locks in the self-defense fix: a node's
// own repeated local observations of the same attacker must escalate normally
// (undamped), even though processLocal's home subnet is populated on the event
// (e.SubnetID = n.cfg.FederationSubnet). If subnet diversity damping ever leaks
// into the local path again, a single-subnet node would be stuck at a low,
// damped score and could never cross a realistic block threshold on its own
// repeated evidence — this test fails loudly in that regression.
func TestLocalObservationsBypassDiversity(t *testing.T) {
	n, _ := testNode(t)
	n.cfg.FederationSubnet = "home" // non-empty, so a damping leak would be visible
	ctx := context.Background()
	ip := "203.0.113.99"

	var scores []float64
	for i := 0; i < 5; i++ {
		n.processLocal(ctx, proto.Event{IP: ip, Reason: "ssh-auth-success", Timestamp: time.Now().UTC()})
		rec, err := n.rep.GetRecord(ip)
		if err != nil {
			t.Fatalf("GetRecord: %v", err)
		}
		scores = append(scores, rec.Score)
	}

	for i := 1; i < len(scores); i++ {
		if scores[i] <= scores[i-1] {
			t.Fatalf("score did not strictly increase on repeat %d: scores=%v", i, scores)
		}
	}
	// A damped single-subnet series (diversity_repeat_factor=0.15) would sit
	// around ~53 after 5 ssh-auth-success (weight 40) reports; undamped local
	// escalation must clear a realistic block threshold well above that.
	if scores[len(scores)-1] <= 75 {
		t.Errorf("local score after 5 repeats = %v, want > 75 (self-defense must escalate undamped)", scores[len(scores)-1])
	}

	rec, err := n.rep.GetRecord(ip)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if len(rec.SubnetsSeen) != 0 {
		t.Errorf("local observation must bypass diversity tracking; SubnetsSeen = %v, want empty", rec.SubnetsSeen)
	}
}

// TestProcessRemoteRoutesVoteToDispute: a Kind:"vote" event lowers the score
// (dispute), it does NOT go through the report path (no Groups added), and an
// anchored disputer's vote registers a distinct dispute-subnet.
func TestProcessRemoteRoutesVoteToDispute(t *testing.T) {
	n, dir := testNode(t)
	// Seed a bad score for the IP via a normal anchored report first.
	priv, err := identity.GeneratePersonKey(filepath.Join(dir, "p.key"))
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	_ = trust.SaveAnchors(n.cfg.TrustAnchorsFile(), []trust.Anchor{{Person: "p", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)), Weight: 0.9, Source: "test"}})
	cert := identity.IssueCert(priv, "12D3KooWrep", time.Now().Add(time.Hour))
	for i := 0; i < 5; i++ {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: "203.0.113.60", Reason: "ssh-auth-success", ReporterID: "12D3KooWrep", SubnetID: "s" + string(rune('a'+i)), Vouch: &cert, Timestamp: time.Now()},
			From:  "12D3KooWrep", Subnet: "home",
		})
	}
	before, _ := n.GetScore("203.0.113.60")
	if before.Score <= 0 {
		t.Fatalf("precondition: IP should be scored, got %v", before.Score)
	}
	// A dispute vote from the anchored disputer. Unsigned + From == ReporterID:
	// the spoof guard passes for a direct event and ProcessRemote skips the
	// signature-verify branch (it only runs when len(Signature) > 0), so it
	// routes purely on Kind. (The end-to-end SIGNED path is covered by Task 5's
	// integration-style tests via the emit/receive round-trip.)
	vote := proto.Event{IP: "203.0.113.60", Kind: "vote", ReporterID: "12D3KooWrep", SubnetID: "sa", Vouch: &cert, Timestamp: time.Now()}
	n.ProcessRemote(transport.ReceivedEvent{Event: vote, From: "12D3KooWrep", Subnet: "home"})
	after, _ := n.GetScore("203.0.113.60")
	if !(after.Score < before.Score) {
		t.Errorf("dispute vote must lower score: before=%v after=%v", before.Score, after.Score)
	}
	if len(after.DisputeSubnetsSeen) < 1 {
		t.Errorf("dispute should register a disputing subnet, got %v", after.DisputeSubnetsSeen)
	}
}
