package identity_test

import (
	"bytes"
	"crypto/rand"
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

func TestVoteSignatureDomainSeparated(t *testing.T) {
	priv, _, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	id, err := identity.PeerIDFromPrivKey(priv)
	if err != nil {
		t.Fatalf("peerid: %v", err)
	}
	ts := time.Now().UTC()
	// A vote and a report for the same IP/time/reporter must NOT share a signature.
	vote := proto.Event{IP: "1.2.3.4", Kind: "vote", ReporterID: id, Timestamp: ts}
	report := proto.Event{IP: "1.2.3.4", Reason: "ssh-probe", ReporterID: id, Timestamp: ts}
	if err := identity.SignEvent(&vote, priv); err != nil {
		t.Fatalf("sign vote: %v", err)
	}
	if err := identity.SignEvent(&report, priv); err != nil {
		t.Fatalf("sign report: %v", err)
	}
	if bytes.Equal(vote.Signature, report.Signature) {
		t.Error("vote and report signatures must differ (domain separation)")
	}
	if err := identity.VerifyEventSig(vote); err != nil {
		t.Errorf("vote should verify: %v", err)
	}
	// A vote's signature must not verify if reinterpreted as a report (Kind cleared).
	forged := vote
	forged.Kind = ""
	if err := identity.VerifyEventSig(forged); err == nil {
		t.Error("clearing Kind must invalidate the signature")
	}
}
