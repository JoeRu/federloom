package identity_test

import (
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/JoeRu/federloom/internal/identity"
	"github.com/JoeRu/federloom/pkg/proto"
)

func makeTestKey(t *testing.T) libp2pcrypto.PrivKey {
	t.Helper()
	priv, _, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func makeTestEvent(t *testing.T, priv libp2pcrypto.PrivKey) proto.Event {
	t.Helper()
	// ReporterID must be the libp2p peer ID derived from the key.
	peerID, err := identity.PeerIDFromPrivKey(priv)
	if err != nil {
		t.Fatalf("peer ID: %v", err)
	}
	return proto.Event{
		IP:         "1.2.3.4",
		Reason:     "ssh-probe",
		Timestamp:  time.Now().UTC(),
		ReporterID: peerID,
	}
}

func TestSignAndVerify(t *testing.T) {
	priv := makeTestKey(t)
	e := makeTestEvent(t, priv)

	if err := identity.SignEvent(&e, priv); err != nil {
		t.Fatalf("SignEvent: %v", err)
	}
	if len(e.Signature) == 0 {
		t.Fatal("SignEvent did not set Signature")
	}
	if err := identity.VerifyEventSig(e); err != nil {
		t.Fatalf("VerifyEventSig: %v", err)
	}
}

func TestVerifyEventSig_TamperedIP(t *testing.T) {
	priv := makeTestKey(t)
	e := makeTestEvent(t, priv)
	if err := identity.SignEvent(&e, priv); err != nil {
		t.Fatalf("SignEvent: %v", err)
	}
	e.IP = "9.9.9.9" // tamper
	if err := identity.VerifyEventSig(e); err == nil {
		t.Fatal("expected error for tampered IP, got nil")
	}
}

func TestVerifyEventSig_MissingSig(t *testing.T) {
	priv := makeTestKey(t)
	e := makeTestEvent(t, priv)
	// do not sign
	if err := identity.VerifyEventSig(e); err == nil {
		t.Fatal("expected error for missing signature, got nil")
	}
}

func TestVerifyEventSig_EmptyReporterID(t *testing.T) {
	priv := makeTestKey(t)
	e := makeTestEvent(t, priv)
	if err := identity.SignEvent(&e, priv); err != nil {
		t.Fatalf("SignEvent: %v", err)
	}
	e.ReporterID = ""
	if err := identity.VerifyEventSig(e); err == nil {
		t.Fatal("expected error for empty reporter ID, got nil")
	}
}
