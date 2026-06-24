package identity_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/identity"
)

func TestCertIssueVerifyRoundTrip(t *testing.T) {
	priv, err := identity.GeneratePersonKey(filepath.Join(t.TempDir(), "person.key"))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cert := identity.IssueCert(priv, "12D3KooWpeerA", time.Now().Add(time.Hour))
	if err := identity.VerifyCert(cert, time.Now()); err != nil {
		t.Errorf("valid cert rejected: %v", err)
	}
}

func TestCertTamperedPeerIDFails(t *testing.T) {
	priv, _ := identity.GeneratePersonKey(filepath.Join(t.TempDir(), "person.key"))
	cert := identity.IssueCert(priv, "12D3KooWpeerA", time.Now().Add(time.Hour))
	cert.PeerID = "12D3KooWattacker"
	if err := identity.VerifyCert(cert, time.Now()); err == nil {
		t.Error("tampered PeerID accepted")
	}
}

func TestCertExpiredFails(t *testing.T) {
	priv, _ := identity.GeneratePersonKey(filepath.Join(t.TempDir(), "person.key"))
	cert := identity.IssueCert(priv, "12D3KooWpeerA", time.Now().Add(-time.Minute))
	if err := identity.VerifyCert(cert, time.Now()); err == nil {
		t.Error("expired cert accepted")
	}
}

func TestCertRejectsEmptyPeerID(t *testing.T) {
	priv, _ := identity.GeneratePersonKey(filepath.Join(t.TempDir(), "person.key"))
	cert := identity.IssueCert(priv, "", time.Now().Add(time.Hour))
	if err := identity.VerifyCert(cert, time.Now()); err == nil {
		t.Error("cert with empty peer ID accepted")
	}
}

func TestCertRejectsDelimiterInPeerID(t *testing.T) {
	priv, _ := identity.GeneratePersonKey(filepath.Join(t.TempDir(), "person.key"))
	cert := identity.IssueCert(priv, "evil|injected", time.Now().Add(time.Hour))
	if err := identity.VerifyCert(cert, time.Now()); err == nil {
		t.Error("cert with reserved delimiter in peer ID accepted")
	}
}

func TestCertWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	privA, _ := identity.GeneratePersonKey(filepath.Join(dir, "a.key"))
	privB, _ := identity.GeneratePersonKey(filepath.Join(dir, "b.key"))
	cert := identity.IssueCert(privA, "12D3KooWpeerA", time.Now().Add(time.Hour))
	// claim the cert came from B's identity
	cert.PersonKey = identity.PersonPub(privB)
	if err := identity.VerifyCert(cert, time.Now()); err == nil {
		t.Error("cert with swapped PersonKey accepted")
	}
}
