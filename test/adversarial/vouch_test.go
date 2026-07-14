//go:build adversarial

package adversarial

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/reputation"
	"github.com/JoeRu/federloom/internal/store"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/internal/trust"
	"github.com/JoeRu/federloom/pkg/proto"
)

// newTestNode builds a Node backed by a temp BadgerDB, with no transport
// (solo mode), a prohibitively high block threshold (so the un-started ipset
// sink is never invoked), and reload interval 0 so trust files re-read on
// every Resolve call.
func newTestNode(t *testing.T) (*node.Node, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.BlockThreshold = 1000

	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	n.SetTrustReloadInterval(0)
	t.Cleanup(func() { n.CloseStores() })
	return n, dir
}

// TestSybilStrangerFloodCapped verifies that 100 un-anchored Sybil reporters
// cannot push a single IP's score past the strangerScoreCap (15 pts). All
// Sybils share one stranger bucket; spinning up more peer IDs does not buy
// more score or corroboration votes (spec §5.1 / design: capped-stranger).
func TestSybilStrangerFloodCapped(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	const cap = 15.0
	eng := reputation.New(s, 7*24*time.Hour, cap, 0.15, 10)
	const ip = "203.0.113.100"

	for i := 0; i < 100; i++ {
		peerID := fmt.Sprintf("sybil-%d", i)
		if _, err := eng.Record(ip, "ssh-probe", peerID, 0.3, "", "", false); err != nil {
			t.Fatalf("Record[%d]: %v", i, err)
		}
	}

	rec, err := eng.GetRecord(ip)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Score > cap+0.0001 {
		t.Errorf("100-Sybil flood exceeded strangerCap: score=%.4f, cap=%.0f", rec.Score, cap)
	}
	if rec.Corroboration != 0 {
		t.Errorf("corroboration = %d, want 0 (strangers never corroborate)", rec.Corroboration)
	}
}

// TestAnchoredPersonCountsOnce verifies that 3 machines certified by the same
// Person all count as ONE corroboration group while their combined score can
// exceed the stranger cap — anchored reports bypass the cap (spec §5.1).
func TestAnchoredPersonCountsOnce(t *testing.T) {
	n, dir := newTestNode(t)

	priv, err := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	anchorsPath := filepath.Join(dir, "anchors.json")
	if err := trust.SaveAnchors(anchorsPath, []trust.Anchor{{
		Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "self-added",
	}}); err != nil {
		t.Fatalf("save anchors: %v", err)
	}

	const ip = "203.0.113.101"
	for _, peerID := range []string{"12D3KooWjoA", "12D3KooWjoB", "12D3KooWjoC"} {
		cert := identity.IssueCert(priv, peerID, time.Now().Add(time.Hour))
		n.ProcessRemote(transport.ReceivedEvent{
			Event: proto.Event{
				IP: ip, Reason: "ssh-auth-success",
				ReporterID: peerID, Vouch: &cert,
			},
			From: peerID,
		})
	}

	rec, err := n.GetScore(ip)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if len(rec.Groups) != 1 || rec.Groups[0] != "jo" {
		t.Errorf("Groups = %v, want [jo] — 3 machines from the same Person are one group", rec.Groups)
	}
	// Anchored reports bypass the stranger cap; score after 3 ssh-auth-success
	// (weight=40, trust=0.9) should be well above the 15-pt stranger cap.
	if rec.Score <= 15 {
		t.Errorf("anchored Person score %.2f ≤ strangerCap 15; anchor should bypass the cap", rec.Score)
	}
}

// TestVouchForgedSignatureIsStranger verifies that a cert with a flipped
// signature byte is rejected by VerifyCert and the reporter stays a stranger
// — the event itself is still recorded (spoof guard does not fire; the sig
// failure is scoped to the vouch only).
func TestVouchForgedSignatureIsStranger(t *testing.T) {
	n, dir := newTestNode(t)

	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	_ = trust.SaveAnchors(filepath.Join(dir, "anchors.json"), []trust.Anchor{{
		Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "self-added",
	}})

	cert := identity.IssueCert(priv, "12D3KooWjoA", time.Now().Add(time.Hour))
	cert.Sig[0] ^= 0xff // flip first byte — signature is now invalid

	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP: "203.0.113.102", Reason: "ssh-probe",
			ReporterID: "12D3KooWjoA", Vouch: &cert,
		},
		From: "12D3KooWjoA",
	})

	rec, _ := n.GetScore("203.0.113.102")
	if len(rec.Groups) != 0 {
		t.Errorf("forged vouch resolved as anchored: Groups=%v", rec.Groups)
	}
	if !rec.StrangerSeen {
		t.Error("forged-vouch reporter was dropped entirely; it should still score as a stranger")
	}
}

// TestVouchReplayIsStranger verifies the cert-replay attack: Eve steals a cert
// signed for Jo's machine (joA) and attaches it to her own reports. The node
// detects Vouch.PeerID (joA) ≠ ReporterID (eve) and ignores the cert — Eve
// stays a stranger (spec §5.1, replay guard in ProcessRemote).
func TestVouchReplayIsStranger(t *testing.T) {
	n, dir := newTestNode(t)

	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	_ = trust.SaveAnchors(filepath.Join(dir, "anchors.json"), []trust.Anchor{{
		Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "self-added",
	}})

	certForJoA := identity.IssueCert(priv, "12D3KooWjoA", time.Now().Add(time.Hour))
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP: "203.0.113.103", Reason: "ssh-probe",
			ReporterID: "12D3KooWeve", // Eve is the verified publisher…
			Vouch:      &certForJoA,   // …but she attaches joA's cert
		},
		From: "12D3KooWeve",
	})

	rec, _ := n.GetScore("203.0.113.103")
	if len(rec.Groups) != 0 {
		t.Errorf("replayed cert anchored a stranger: Groups=%v", rec.Groups)
	}
	if !rec.StrangerSeen {
		t.Error("replayed-cert event was dropped entirely; Eve should still score as a stranger")
	}
}

// TestExpiredVouchIsStranger verifies that a cert whose ValidUntil is in the
// past is rejected by VerifyCert — the reporter is not anchored even when the
// Person's anchor is present and valid (spec §5.1).
func TestExpiredVouchIsStranger(t *testing.T) {
	n, dir := newTestNode(t)

	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	_ = trust.SaveAnchors(filepath.Join(dir, "anchors.json"), []trust.Anchor{{
		Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "self-added",
	}})

	// Issue a cert that expired 1 minute ago.
	cert := identity.IssueCert(priv, "12D3KooWjoA", time.Now().Add(-time.Minute))
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP: "203.0.113.104", Reason: "ssh-probe",
			ReporterID: "12D3KooWjoA", Vouch: &cert,
		},
		From: "12D3KooWjoA",
	})

	rec, _ := n.GetScore("203.0.113.104")
	if len(rec.Groups) != 0 {
		t.Errorf("expired vouch resolved as anchored: Groups=%v", rec.Groups)
	}
	if !rec.StrangerSeen {
		t.Error("expired-cert reporter was dropped; it should still score as a stranger")
	}
}

// TestPersonRemovalAppliesImmediately verifies Invariant 6: anchors are
// locally removable with immediate effect. After the operator clears
// anchors.json, the next report from a formerly-anchored peer must resolve
// as a stranger — the trust store hot-reloads within the reload interval.
func TestPersonRemovalAppliesImmediately(t *testing.T) {
	n, dir := newTestNode(t)

	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	anchorsPath := filepath.Join(dir, "anchors.json")
	_ = trust.SaveAnchors(anchorsPath, []trust.Anchor{{
		Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "self-added",
	}})

	cert := identity.IssueCert(priv, "12D3KooWjoA", time.Now().Add(time.Hour))

	// First report — Jo is anchored; joA should score as anchored.
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP: "203.0.113.105", Reason: "ssh-probe",
			ReporterID: "12D3KooWjoA", Vouch: &cert,
		},
		From: "12D3KooWjoA",
	})
	pre, _ := n.GetScore("203.0.113.105")
	if len(pre.Groups) == 0 {
		t.Fatalf("precondition failed: first report not anchored (Groups=%v)", pre.Groups)
	}

	// Operator removes Jo's anchor — write an empty list.
	if err := trust.SaveAnchors(anchorsPath, []trust.Anchor{}); err != nil {
		t.Fatalf("clear anchors: %v", err)
	}

	// Second report for a fresh IP: trust store re-reads anchors.json (reload
	// interval is 0), finds no anchors, and resolves joA as a stranger.
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP: "203.0.113.106", Reason: "ssh-probe",
			ReporterID: "12D3KooWjoA", Vouch: &cert,
		},
		From: "12D3KooWjoA",
	})
	post, _ := n.GetScore("203.0.113.106")
	if len(post.Groups) != 0 {
		t.Errorf("anchor removal not honoured: Groups=%v after anchors.json cleared (Invariant 6)", post.Groups)
	}
	if !post.StrangerSeen {
		t.Error("de-anchored peer was neither anchored nor stranger — event may have been dropped")
	}
}
