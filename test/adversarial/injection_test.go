//go:build adversarial

package adversarial

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/internal/trust"
	"github.com/JoeRu/federloom/pkg/proto"
)

// injectionRules is a minimal rule file exercising the two block paths a remote
// stranger could previously abuse: a corroboration:1 block and a burst block.
const injectionRules = `
- name: honeypot-shell-exec
  reason: ssh-post-auth-command
  min_corroboration: 1
  action: block
- name: ssh-brute-burst
  reason: ssh-auth-bruteforce
  min_burst: 15
  burst_window: 10m
  action: block
`

const bareReasonRules = `
- name: bare-probe-block
  reason: ssh-probe
  action: block
`

const lowScoreRules = `
- name: low-score-block
  min_score: 10
  action: block
`

// newNodeWithRules builds a solo Node with the given rules.yaml content and a
// mock sink installed so Block calls are observable.
func newNodeWithRules(t *testing.T, rulesYAML string) (*node.Node, string, *mockSink) {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.RulesFile = rulesPath

	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	n.SetTrustReloadInterval(0)
	sink := &mockSink{}
	n.SetSinkForTest(sink)
	t.Cleanup(func() { n.CloseStores() })
	return n, dir, sink
}

// newInjectionNode builds a solo Node with injectionRules loaded and a mock
// sink installed so Block calls are observable. Returns the node, its data dir,
// and the mock sink.
func newInjectionNode(t *testing.T) (*node.Node, string, *mockSink) {
	t.Helper()
	return newNodeWithRules(t, injectionRules)
}

// TestStrangerCannotInjectCorroborationBlock: a single un-anchored remote event
// matching a min_corroboration:1 block rule must NOT cause a block (P0-1).
func TestStrangerCannotInjectCorroborationBlock(t *testing.T) {
	n, _, sink := newInjectionNode(t)
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "203.0.113.10", Reason: "ssh-post-auth-command", ReporterID: "stranger-peer"},
		From:  "stranger-peer",
	})
	if len(sink.blocked) != 0 {
		t.Errorf("stranger triggered %d block(s) via min_corroboration:1; want 0", len(sink.blocked))
	}
}

// TestStrangerCannotInjectBurstBlock: 15 un-anchored remote events must NOT trip
// the burst block rule, because strangers no longer feed the burst window (P0-2).
func TestStrangerCannotInjectBurstBlock(t *testing.T) {
	n, _, sink := newInjectionNode(t)
	for i := 0; i < 15; i++ {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: "203.0.113.11", Reason: "ssh-auth-bruteforce", ReporterID: "stranger-peer"},
			From:  "stranger-peer",
		})
	}
	if len(sink.blocked) != 0 {
		t.Errorf("stranger burst triggered %d block(s); want 0", len(sink.blocked))
	}
}

// anchoredEvent builds a remote event whose reporter is vouched by an anchored
// Person, so ProcessRemote resolves it as anchored (weight 0.9, group "jo").
func anchoredEvent(t *testing.T, n *node.Node, dir, ip, reason string) transport.ReceivedEvent {
	t.Helper()
	priv, err := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	anchorsPath := filepath.Join(dir, "anchors.json")
	if err := trust.SaveAnchors(anchorsPath, []trust.Anchor{{
		Person:         "jo",
		IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight:         0.9,
		Source:         "self-added",
	}}); err != nil {
		t.Fatalf("save anchors: %v", err)
	}
	const peerID = "anchored-peer-1"
	cert := identity.IssueCert(priv, peerID, time.Now().Add(24*time.Hour))
	return transport.ReceivedEvent{
		Event: proto.Event{IP: ip, Reason: reason, ReporterID: peerID, Vouch: &cert},
		From:  peerID,
	}
}

// TestAnchoredReporterCanBlock: the legit federation path still works — an
// anchored remote reporter's ssh-post-auth-command IS blocked (regression).
func TestAnchoredReporterCanBlock(t *testing.T) {
	n, dir, sink := newInjectionNode(t)
	// SaveAnchors path must match cfg's TrustAnchorsFile; Defaults resolves it
	// under Store.Dir, and anchoredEvent writes anchors.json there.
	re := anchoredEvent(t, n, dir, "203.0.113.12", "ssh-post-auth-command")
	n.ProcessRemote(re)
	if len(sink.blocked) != 1 || sink.blocked[0] != "203.0.113.12" {
		t.Errorf("anchored reporter should block 203.0.113.12; got blocked=%v", sink.blocked)
	}
}

// TestAnchoredBurstStillBlocks: anchored reporters still feed the burst window,
// so 15 anchored ssh-auth-bruteforce events DO block (regression for A2).
func TestAnchoredBurstStillBlocks(t *testing.T) {
	n, dir, sink := newInjectionNode(t)
	// Build the anchored setup + cert ONCE (anchoredEvent generates the Person
	// key and writes anchors.json; calling it in the loop would regenerate the
	// key each iteration). Reuse the same event 15 times to fill the window,
	// but vary the timestamp per attempt: a real burst is 15 distinct attempts,
	// and the dedup cache (keyed on ReporterID/IP/Reason/Timestamp) would
	// otherwise collapse 15 identical events into one.
	re := anchoredEvent(t, n, dir, "203.0.113.13", "ssh-auth-bruteforce")
	for i := 0; i < 15; i++ {
		re.Event.Timestamp = time.Now()
		n.ProcessRemote(re)
	}
	if len(sink.blocked) == 0 {
		t.Error("anchored burst of 15 must trip ssh-brute-burst; got 0 blocks")
	}
}

// TestBareReasonBlockRuleStrangerDowngraded: a block rule with no min_* gates
// (bare reason) must NOT let an un-anchored remote reporter force a block — the
// node-level backstop downgrades it to watch (no anchored corroboration).
func TestBareReasonBlockRuleStrangerDowngraded(t *testing.T) {
	n, _, sink := newNodeWithRules(t, bareReasonRules)
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "203.0.113.20", Reason: "ssh-probe", ReporterID: "stranger-peer"},
		From:  "stranger-peer",
	})
	if len(sink.blocked) != 0 {
		t.Errorf("bare-reason block rule let a stranger block; want 0, got %d", len(sink.blocked))
	}
}

// TestLowMinScoreBlockRuleStrangerDowngraded: a block rule whose min_score is
// below the stranger cap must still not let a stranger flood force a block.
func TestLowMinScoreBlockRuleStrangerDowngraded(t *testing.T) {
	n, _, sink := newNodeWithRules(t, lowScoreRules)
	// ssh-auth-success (weight 40) × stranger weight 0.3 → ~12 on the first event,
	// capping toward 15 — always >= min_score:10, so the rule matches every time.
	for i := 0; i < 3; i++ {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: "203.0.113.21", Reason: "ssh-auth-success", ReporterID: "stranger-peer"},
			From:  "stranger-peer",
		})
	}
	if len(sink.blocked) != 0 {
		t.Errorf("low min_score block rule let a stranger flood block; want 0, got %d", len(sink.blocked))
	}
}

// TestBareReasonBlockRuleAnchoredStillBlocks: the backstop only stops
// stranger-only blocks — an anchored reporter still blocks via the same
// bare-reason rule (regression).
func TestBareReasonBlockRuleAnchoredStillBlocks(t *testing.T) {
	n, dir, sink := newNodeWithRules(t, bareReasonRules)
	re := anchoredEvent(t, n, dir, "203.0.113.22", "ssh-probe")
	n.ProcessRemote(re)
	if len(sink.blocked) != 1 || sink.blocked[0] != "203.0.113.22" {
		t.Errorf("anchored reporter should block via bare-reason rule; got blocked=%v", sink.blocked)
	}
}

// TestIPv6AddressesAggregatePer64: two different /128s in the same /64 collapse
// to one reputation key; a /128 in a different /64 stays separate.
func TestIPv6AddressesAggregatePer64(t *testing.T) {
	n, _, _ := newNodeWithRules(t, injectionRules)
	send := func(ip string) {
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{IP: ip, Reason: "ssh-probe", ReporterID: "stranger-peer"},
			From:  "stranger-peer",
		})
	}
	send("2001:db8:1:2:aaaa::1")
	send("2001:db8:1:2:ffff::9") // same /64
	send("2001:db8:1:3::1")      // different /64

	rec64, _ := n.GetScore("2001:db8:1:2::/64")
	if rec64.LastSeen.IsZero() {
		t.Fatal("expected an aggregated record under the /64 key")
	}
	if len(rec64.ReporterIDs) == 0 || rec64.Score <= 0 {
		t.Errorf("aggregated /64 record looks empty: %+v", rec64)
	}
	// The raw /128s must NOT be separate keys.
	if r, _ := n.GetScore("2001:db8:1:2:aaaa::1"); !r.LastSeen.IsZero() {
		t.Error("raw /128 must not be recorded as its own key")
	}
	// A different /64 is a distinct key.
	if r, _ := n.GetScore("2001:db8:1:3::/64"); r.LastSeen.IsZero() {
		t.Error("a /128 in another /64 should score under that /64 key")
	}
}

// TestFederationDiscountCrossSubnetBinary verifies the discount (v2, spec §5.2)
// is a BINARY rule keyed on the signed origin SubnetID, not on OriginTrace hop
// count (closes B2): a same-subnet event is NOT discounted regardless of how
// many bridge hops it crossed, and a cross-subnet event is discounted exactly
// ONCE — never squared, no matter how many hops it relayed through. The
// cross-subnet event must be a REAL signed relay (publisher = last OriginTrace
// hop) to pass the C1 spoof guard, so this also exercises the relayed-event
// path end to end.
func TestFederationDiscountCrossSubnetBinary(t *testing.T) {
	// Two IPs, same reason/weight; one arrives direct in the node's home subnet
	// (SubnetID == "", len-1 trace), one via a real signed 2-bridge-hop relay
	// whose SIGNED origin subnet differs from the node's home subnet.
	n, _, _ := newNodeWithRules(t, injectionRules)

	direct := transport.ReceivedEvent{
		Event: proto.Event{IP: "203.0.113.40", Reason: "ssh-probe", ReporterID: "strangerD", OriginTrace: []string{"strangerD"}},
		From:  "strangerD",
	}

	priv, _, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	origID, err := identity.PeerIDFromPrivKey(priv)
	if err != nil {
		t.Fatalf("peerid: %v", err)
	}
	crossSubnetEvent := proto.Event{
		IP:          "203.0.113.41",
		Reason:      "ssh-probe",
		ReporterID:  origID,
		Timestamp:   time.Now().UTC(),
		SubnetID:    "othersubnet", // crosses the federation boundary
		OriginTrace: []string{origID, "bridge1", "bridge2"},
	}
	if err := identity.SignEvent(&crossSubnetEvent, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Relayed: publisher is the last OriginTrace hop ("bridge2"), not the originator.
	crossSubnet := transport.ReceivedEvent{Event: crossSubnetEvent, From: "bridge2"}

	n.ProcessRemote(direct)
	n.ProcessRemote(crossSubnet)

	rd, _ := n.GetScore("203.0.113.40")
	rh, _ := n.GetScore("203.0.113.41")
	// Same-subnet (home) event: no discount. Cross-subnet event: discounted ONCE
	// (0.5 with the default), regardless of its 2-bridge-hop OriginTrace.
	if !(rd.Score > rh.Score) {
		t.Errorf("same-subnet score %.4f must exceed cross-subnet (discounted) score %.4f", rd.Score, rh.Score)
	}
	if rh.Score <= 0 {
		t.Errorf("cross-subnet event should still record a positive score, got %.4f", rh.Score)
	}
	const discount = 0.5
	want := rd.Score * discount
	const epsilon = 0.01
	if diff := rh.Score - want; diff > epsilon || diff < -epsilon {
		t.Errorf("cross-subnet score %.4f not within %.2f of same-subnet*discount = %.4f (hop count must not matter)", rh.Score, epsilon, want)
	}
}

// TestRelayedEventAcceptedWhenSigned proves the C1 fix: a relayed (bridged)
// event — publisher (From) is a bridge peer ID that differs from ReporterID —
// is accepted and scored when it carries a valid originator signature and the
// publisher is the last OriginTrace hop. Uses the real libp2p signing path so
// identity.VerifyEventSig actually runs.
func TestRelayedEventAcceptedWhenSigned(t *testing.T) {
	n, _, _ := newNodeWithRules(t, injectionRules)

	// Build a real originator key + signed event.
	priv, _, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	origID, err := identity.PeerIDFromPrivKey(priv)
	if err != nil {
		t.Fatalf("peerid: %v", err)
	}
	ev := proto.Event{IP: "203.0.113.60", Reason: "ssh-probe", ReporterID: origID, Timestamp: time.Now().UTC(), OriginTrace: []string{origID, "bridgeX"}}
	if err := identity.SignEvent(&ev, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Relayed: publisher is the bridge (last OriginTrace hop), not the originator.
	n.ProcessRemote(transport.ReceivedEvent{Event: ev, From: "bridgeX", Subnet: "b"})

	rec, _ := n.GetScore("203.0.113.60")
	if rec.LastSeen.IsZero() {
		t.Fatal("signed relayed event must be scored, not dropped as spoofed")
	}
}

// TestRelayedEventDroppedWhenUnsigned proves the anti-spoofing guarantee still
// holds: a relayed event (ReporterID != From) with no signature must be
// dropped — the bridge cannot forge an event from a different reporter.
func TestRelayedEventDroppedWhenUnsigned(t *testing.T) {
	n, _, _ := newNodeWithRules(t, injectionRules)
	ev := proto.Event{IP: "203.0.113.61", Reason: "ssh-probe", ReporterID: "origZ", Timestamp: time.Now().UTC(), OriginTrace: []string{"origZ", "bridgeX"}}
	n.ProcessRemote(transport.ReceivedEvent{Event: ev, From: "bridgeX", Subnet: "b"}) // no signature
	if rec, _ := n.GetScore("203.0.113.61"); !rec.LastSeen.IsZero() {
		t.Error("unsigned relayed event (reporter != publisher) must be dropped")
	}
}

// TestRelayedEventDroppedWhenPublisherNotLastHop proves the second half of the
// C1 guard: even a validly signed event must be dropped if the verified
// publisher is not the last OriginTrace hop (it can't prove it's the relay
// that actually forwarded this event).
func TestRelayedEventDroppedWhenPublisherNotLastHop(t *testing.T) {
	n, _, _ := newNodeWithRules(t, injectionRules)
	priv, _, _ := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	origID, _ := identity.PeerIDFromPrivKey(priv)
	ev := proto.Event{IP: "203.0.113.62", Reason: "ssh-probe", ReporterID: origID, Timestamp: time.Now().UTC(), OriginTrace: []string{origID, "someOtherBridge"}}
	_ = identity.SignEvent(&ev, priv)
	// Publisher claims to relay but is NOT the last OriginTrace hop.
	n.ProcessRemote(transport.ReceivedEvent{Event: ev, From: "bridgeX", Subnet: "b"})
	if rec, _ := n.GetScore("203.0.113.62"); !rec.LastSeen.IsZero() {
		t.Error("relayed event whose publisher is not the last OriginTrace hop must be dropped")
	}
}

// TestDuplicateRemoteEventScoredOnce verifies the dedup cache: the same event
// delivered twice (e.g. via two topology paths) is recorded once, not twice.
func TestDuplicateRemoteEventScoredOnce(t *testing.T) {
	n, dir, _ := newNodeWithRules(t, injectionRules)
	_ = dir
	ts := time.Now().UTC()
	ev := transport.ReceivedEvent{
		Event: proto.Event{IP: "203.0.113.50", Reason: "ssh-probe", ReporterID: "strangerX", Timestamp: ts, OriginTrace: []string{"strangerX"}},
		From:  "strangerX",
	}
	n.ProcessRemote(ev)
	first, _ := n.GetScore("203.0.113.50")
	n.ProcessRemote(ev) // identical event (same reporter/ip/reason/timestamp)
	second, _ := n.GetScore("203.0.113.50")

	if second.Score != first.Score {
		t.Errorf("duplicate event changed score: first=%.4f second=%.4f (want equal — deduped)", first.Score, second.Score)
	}
}
