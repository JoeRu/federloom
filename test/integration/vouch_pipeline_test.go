package integration_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/internal/node"
	"github.com/JoeRu/federloom/internal/transport"
	"github.com/JoeRu/federloom/internal/trust"
	"github.com/JoeRu/federloom/pkg/proto"
)

// newReceiverNode builds a node.Node wired for integration tests: temp BadgerDB,
// no transport (we call ProcessRemote directly), absurdly-high block threshold
// so enforce.Sink.Block is never invoked, and reload interval = 0 so every
// Resolve call re-reads the trust files.
//
// anchorsFile must already exist (or be absent — an absent file is fine; it
// just means no anchors). The caller must have written the trust files BEFORE
// calling this function if they want them loaded on construction.
func newReceiverNode(t *testing.T, storeDir, anchorsFile string) *node.Node {
	t.Helper()
	cfg := config.Defaults()
	cfg.Store.Dir = storeDir
	cfg.Trust.AnchorsFile = anchorsFile
	cfg.Trust.PeerCertFile = filepath.Join(storeDir, "peer.cert") // non-existent → no self-vouch
	cfg.Reputation.BlockThreshold = 1_000_000                     // never block in tests

	n, err := node.New(cfg, nil /* nil transport: drive ProcessRemote directly */)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(n.CloseStores)
	n.SetTrustReloadInterval(0) // reload on every Resolve call
	return n
}

// TestVouchPipeline_AnchoredVsStranger is the end-to-end round trip that proves
// the complete trust-resolve → reputation-record path:
//
//  1. A ReceivedEvent carrying a valid PeerCert signed by an anchored Person
//     resolves to that Person's corroboration group (Groups = ["jo"]).
//
//  2. An un-vouched ReceivedEvent from a different, uncertified peer scores as
//     a stranger (StrangerSeen = true, Groups empty).
//
// We drive node.ProcessRemote directly without a real gossipsub network because
// the invariant under test lives in the trust-resolve → reputation-record path,
// not in message delivery.
func TestVouchPipeline_AnchoredVsStranger(t *testing.T) {
	keyDir := t.TempDir()
	storeDir := t.TempDir()
	anchorsFile := filepath.Join(t.TempDir(), "anchors.json")

	// ── 1. Create a Person identity ("jo") and anchor it ────────────────────
	personPriv, err := identity.GeneratePersonKey(filepath.Join(keyDir, "jo.key"))
	if err != nil {
		t.Fatalf("GeneratePersonKey: %v", err)
	}
	if err := trust.SaveAnchors(anchorsFile, []trust.Anchor{{
		Person:         "jo",
		IdentityPubkey: identity.EncodePub(identity.PersonPub(personPriv)),
		Weight:         0.9,
		Source:         "self-added",
	}}); err != nil {
		t.Fatalf("SaveAnchors: %v", err)
	}

	// ── 2. Build the receiver node ───────────────────────────────────────────
	recv := newReceiverNode(t, storeDir, anchorsFile)

	// ── 3. Issue a PeerCert for the publisher peer ───────────────────────────
	const publisherID = "12D3KooWpublisherFakePeerID000001"
	cert := identity.IssueCert(personPriv, publisherID, time.Now().Add(time.Hour))

	// ── 4. Process a vouched event ───────────────────────────────────────────
	const vouchedIP = "198.51.100.1"
	recv.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:         vouchedIP,
			Reason:     "ssh-auth-bruteforce",
			ReporterID: publisherID,
			Vouch:      &cert,
		},
		From: publisherID,
	})

	// ── 5. Assert: Groups == ["jo"], StrangerSeen == false ──────────────────
	vouchedRec, err := recv.GetScore(vouchedIP)
	if err != nil {
		t.Fatalf("GetScore(vouched IP): %v", err)
	}
	if len(vouchedRec.Groups) != 1 || vouchedRec.Groups[0] != "jo" {
		t.Errorf("vouched event: Groups = %v, want [jo]", vouchedRec.Groups)
	}
	if vouchedRec.StrangerSeen {
		t.Error("vouched event: StrangerSeen = true, want false")
	}

	// ── 6. Process an un-vouched event from a fresh, uncertified peer ────────
	const strangerID = "12D3KooWunknownStrangerPeerID00002"
	const strangerIP = "203.0.113.99"
	recv.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{
			IP:         strangerIP,
			Reason:     "ssh-auth-bruteforce",
			ReporterID: strangerID,
			// Vouch deliberately absent — this peer has no cert.
		},
		From: strangerID,
	})

	// ── 7. Assert: Groups == [], StrangerSeen == true ────────────────────────
	strangerRec, err := recv.GetScore(strangerIP)
	if err != nil {
		t.Fatalf("GetScore(stranger IP): %v", err)
	}
	if len(strangerRec.Groups) != 0 {
		t.Errorf("stranger event: Groups = %v, want []", strangerRec.Groups)
	}
	if !strangerRec.StrangerSeen {
		t.Error("stranger event: StrangerSeen = false, want true")
	}
}

// TestVouchPipeline_CachedCertPersists proves that once a peer's cert has been
// received and cached via a vouched event, subsequent events from that peer
// (with Vouch == nil) continue to resolve as anchored — the cert cache outlives
// the wire field (spec §5.1 vouch caching invariant).
func TestVouchPipeline_CachedCertPersists(t *testing.T) {
	keyDir := t.TempDir()
	storeDir := t.TempDir()
	anchorsFile := filepath.Join(t.TempDir(), "anchors.json")

	personPriv, err := identity.GeneratePersonKey(filepath.Join(keyDir, "jo.key"))
	if err != nil {
		t.Fatalf("GeneratePersonKey: %v", err)
	}
	if err := trust.SaveAnchors(anchorsFile, []trust.Anchor{{
		Person:         "jo",
		IdentityPubkey: identity.EncodePub(identity.PersonPub(personPriv)),
		Weight:         0.9,
		Source:         "self-added",
	}}); err != nil {
		t.Fatalf("SaveAnchors: %v", err)
	}

	recv := newReceiverNode(t, storeDir, anchorsFile)

	const peerID = "12D3KooWpeerWithCachedCert000001"
	cert := identity.IssueCert(personPriv, peerID, time.Now().Add(time.Hour))

	// First event carries the cert — populates the cert cache.
	recv.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "198.51.100.2", Reason: "smtp-auth-fail", ReporterID: peerID, Vouch: &cert},
		From:  peerID,
	})

	// Second event from the same peer, no Vouch field — cert already cached.
	recv.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "198.51.100.3", Reason: "smtp-auth-fail", ReporterID: peerID, Vouch: nil},
		From:  peerID,
	})

	for _, tc := range []struct {
		ip   string
		desc string
	}{
		{"198.51.100.2", "first (vouched) event"},
		{"198.51.100.3", "second (cert-cached, no wire vouch) event"},
	} {
		rec, err := recv.GetScore(tc.ip)
		if err != nil {
			t.Fatalf("GetScore %s: %v", tc.desc, err)
		}
		if len(rec.Groups) != 1 || rec.Groups[0] != "jo" {
			t.Errorf("%s: Groups = %v, want [jo]", tc.desc, rec.Groups)
		}
		if rec.StrangerSeen {
			t.Errorf("%s: StrangerSeen = true, want false", tc.desc)
		}
	}
}
