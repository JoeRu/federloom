package trust_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/trust"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// fixture: a Person key, an anchor for it, and a cached cert for peer "12D3KooWpeerA".
func fixture(t *testing.T) (dir string, st *trust.Store) {
	t.Helper()
	dir = t.TempDir()
	priv, err := identity.GeneratePersonKey(filepath.Join(dir, "person.key"))
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	anchors := []trust.Anchor{{
		Person:         "jo",
		Label:          "Jo",
		IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight:         0.9,
		Source:         "self-added",
	}}
	if err := trust.SaveAnchors(filepath.Join(dir, "anchors.json"), anchors); err != nil {
		t.Fatalf("save anchors: %v", err)
	}
	st = trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "imported-certs.json"), filepath.Join(dir, "blocked.json"), 0.3)
	st.SetReloadInterval(0) // re-stat files on every Resolve in tests
	cert := identity.IssueCert(priv, "12D3KooWpeerA", time.Now().Add(time.Hour))
	if err := st.AddCert(cert, time.Now()); err != nil {
		t.Fatalf("add cert: %v", err)
	}
	return dir, st
}

func TestResolveAnchoredPeer(t *testing.T) {
	_, st := fixture(t)
	w, group, anchored := st.Resolve("12D3KooWpeerA")
	if !anchored || group != "jo" || w != 0.9 {
		t.Errorf("Resolve = (%v, %q, %v), want (0.9, jo, true)", w, group, anchored)
	}
}

func TestResolveUnknownPeerIsStranger(t *testing.T) {
	_, st := fixture(t)
	w, group, anchored := st.Resolve("12D3KooWnobody")
	if anchored || group != "" || w != 0.3 {
		t.Errorf("Resolve = (%v, %q, %v), want (0.3, \"\", false)", w, group, anchored)
	}
}

func TestResolveValidCertUnanchoredIdentityIsStranger(t *testing.T) {
	dir := t.TempDir()
	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "other.key"))
	st := trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "certs.json"), filepath.Join(dir, "blocked.json"), 0.3)
	st.SetReloadInterval(0)
	cert := identity.IssueCert(priv, "12D3KooWpeerX", time.Now().Add(time.Hour))
	if err := st.AddCert(cert, time.Now()); err != nil {
		t.Fatalf("add cert: %v", err)
	}
	if _, _, anchored := st.Resolve("12D3KooWpeerX"); anchored {
		t.Error("valid cert from un-anchored identity must resolve as stranger")
	}
}

func TestAddCertRejectsForgedSig(t *testing.T) {
	_, st := fixture(t)
	dir := t.TempDir()
	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "p.key"))
	cert := identity.IssueCert(priv, "12D3KooWpeerB", time.Now().Add(time.Hour))
	cert.Sig[0] ^= 0xFF
	if err := st.AddCert(cert, time.Now()); err == nil {
		t.Error("forged cert accepted")
	}
}

func TestExpiredCertIsStranger(t *testing.T) {
	dir := t.TempDir()
	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "person.key"))
	anchors := []trust.Anchor{{Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)), Weight: 0.9, Source: "self-added"}}
	if err := trust.SaveAnchors(filepath.Join(dir, "anchors.json"), anchors); err != nil {
		t.Fatalf("save: %v", err)
	}
	st := trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "certs.json"), filepath.Join(dir, "blocked.json"), 0.3)
	st.SetReloadInterval(0)
	cert := identity.IssueCert(priv, "12D3KooWpeerA", time.Now().Add(50*time.Millisecond))
	if err := st.AddCert(cert, time.Now()); err != nil {
		t.Fatalf("add: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, _, anchored := st.Resolve("12D3KooWpeerA"); anchored {
		t.Error("expired cert still resolves as anchored")
	}
}

func TestExpiredAnchorIsStranger(t *testing.T) {
	dir := t.TempDir()
	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "person.key"))
	anchors := []trust.Anchor{{Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)), Weight: 0.9, ValidUntil: time.Now().Add(-time.Minute), Source: "self-added"}}
	if err := trust.SaveAnchors(filepath.Join(dir, "anchors.json"), anchors); err != nil {
		t.Fatalf("save: %v", err)
	}
	st := trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "certs.json"), filepath.Join(dir, "blocked.json"), 0.3)
	st.SetReloadInterval(0)
	cert := identity.IssueCert(priv, "12D3KooWpeerA", time.Now().Add(time.Hour))
	_ = st.AddCert(cert, time.Now())
	if _, _, anchored := st.Resolve("12D3KooWpeerA"); anchored {
		t.Error("expired anchor still resolves as anchored")
	}
}

// TestHotReloadRemoval: removing the person from anchors.json takes effect
// without restart (Invariant 6).
func TestHotReloadRemoval(t *testing.T) {
	dir, st := fixture(t)
	if _, _, anchored := st.Resolve("12D3KooWpeerA"); !anchored {
		t.Fatal("precondition: peerA anchored")
	}
	if err := trust.SaveAnchors(filepath.Join(dir, "anchors.json"), []trust.Anchor{}); err != nil {
		t.Fatalf("save empty: %v", err)
	}
	if _, _, anchored := st.Resolve("12D3KooWpeerA"); anchored {
		t.Error("removed anchor still trusted after reload")
	}
}

// TestCorruptFileKeepsLastGood: a bad write must not drop trust mid-run.
func TestCorruptFileKeepsLastGood(t *testing.T) {
	dir, st := fixture(t)
	if err := os.WriteFile(filepath.Join(dir, "anchors.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, _, anchored := st.Resolve("12D3KooWpeerA"); !anchored {
		t.Error("corrupt file dropped last-good anchors")
	}
}

func TestMissingFileMeansStrangers(t *testing.T) {
	dir := t.TempDir()
	st := trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "certs.json"), filepath.Join(dir, "blocked.json"), 0.3)
	st.SetReloadInterval(0)
	if _, _, anchored := st.Resolve("12D3KooWanyone"); anchored {
		t.Error("missing anchors file must mean no anchors")
	}
}

// TestAnchorWeightClampedToOne: a hand-edited anchors.json must not grant more
// than full trust — an over-weight anchor resolves at weight 1.0, not 50.
func TestAnchorWeightClampedToOne(t *testing.T) {
	dir := t.TempDir()
	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "person.key"))
	anchors := []trust.Anchor{{Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)), Weight: 50, Source: "self-added"}}
	if err := trust.SaveAnchors(filepath.Join(dir, "anchors.json"), anchors); err != nil {
		t.Fatalf("save: %v", err)
	}
	st := trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "certs.json"), filepath.Join(dir, "blocked.json"), 0.3)
	st.SetReloadInterval(0)
	cert := identity.IssueCert(priv, "12D3KooWpeerA", time.Now().Add(time.Hour))
	if err := st.AddCert(cert, time.Now()); err != nil {
		t.Fatalf("add cert: %v", err)
	}
	w, _, anchored := st.Resolve("12D3KooWpeerA")
	if !anchored || w != 1.0 {
		t.Errorf("Resolve weight = %v (anchored=%v), want clamped 1.0", w, anchored)
	}
}

// TestAnchorNonPositiveWeightDropped: a zero/negative weight anchor is useless
// and must be dropped — the peer resolves as a stranger.
func TestAnchorNonPositiveWeightDropped(t *testing.T) {
	dir := t.TempDir()
	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "person.key"))
	anchors := []trust.Anchor{{Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)), Weight: 0, Source: "self-added"}}
	if err := trust.SaveAnchors(filepath.Join(dir, "anchors.json"), anchors); err != nil {
		t.Fatalf("save: %v", err)
	}
	st := trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "certs.json"), filepath.Join(dir, "blocked.json"), 0.3)
	st.SetReloadInterval(0)
	cert := identity.IssueCert(priv, "12D3KooWpeerA", time.Now().Add(time.Hour))
	_ = st.AddCert(cert, time.Now())
	if _, _, anchored := st.Resolve("12D3KooWpeerA"); anchored {
		t.Error("zero-weight anchor still resolves as anchored")
	}
}

// TestReloadKeepsLongerLivedCert: an on-wire cert (long expiry) must not be
// clobbered by a reload of a shorter-lived file cert for the same peer.
func TestReloadKeepsLongerLivedCert(t *testing.T) {
	dir := t.TempDir()
	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "person.key"))
	anchors := []trust.Anchor{{Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)), Weight: 0.9, Source: "self-added"}}
	if err := trust.SaveAnchors(filepath.Join(dir, "anchors.json"), anchors); err != nil {
		t.Fatalf("save anchors: %v", err)
	}
	certsPath := filepath.Join(dir, "certs.json")
	st := trust.NewStore(filepath.Join(dir, "anchors.json"), certsPath, filepath.Join(dir, "blocked.json"), 0.3)
	st.SetReloadInterval(0)

	wire := identity.IssueCert(priv, "12D3KooWpeerA", time.Now().Add(time.Hour))
	if err := st.AddCert(wire, time.Now()); err != nil {
		t.Fatalf("add wire cert: %v", err)
	}
	short := identity.IssueCert(priv, "12D3KooWpeerA", time.Now().Add(2*time.Minute))
	if err := trust.SaveCerts(certsPath, []proto.PeerCert{short}); err != nil {
		t.Fatalf("save file cert: %v", err)
	}
	if _, _, anchored := st.Resolve("12D3KooWpeerA"); !anchored {
		t.Error("reload of shorter file cert dropped the anchored peer")
	}
}
