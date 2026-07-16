package identity

import (
	"fmt"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/pkg/proto"
)

// eventMessage is the canonical byte string signed to authenticate an event.
// Domain-separated with "federloom-event-v1" so signatures cannot be replayed
// across protocols. Fields joined by "|"; none of them can contain "|".
// NOTE: Vouch is intentionally excluded; PeerCert integrity is enforced independently by identity.VerifyCert.
func eventMessage(e proto.Event) []byte {
	return []byte("federloom-event-v1|" +
		e.IP + "|" +
		e.Reason + "|" +
		e.Timestamp.UTC().Format(time.RFC3339Nano) + "|" +
		e.ReporterID)
}

// voteMessage is the canonical byte string signed for a dispute vote
// (Event.Kind == "vote"), domain-separated from a report so the two are not
// interchangeable. Reason/OriginTrace are not part of a vote.
func voteMessage(e proto.Event) []byte {
	return []byte("federloom-vote-v1|" +
		e.IP + "|" +
		e.Timestamp.UTC().Format(time.RFC3339Nano) + "|" +
		e.ReporterID)
}

// signedMessage returns the canonical bytes for e based on its Kind.
func signedMessage(e proto.Event) []byte {
	if e.Kind == "vote" {
		return voteMessage(e)
	}
	return eventMessage(e)
}

// PeerIDFromPrivKey derives the libp2p peer ID string from priv.
// The peer ID embeds the public key for Ed25519 keys and is used as ReporterID.
func PeerIDFromPrivKey(priv libp2pcrypto.PrivKey) (string, error) {
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("identity: derive peer ID: %w", err)
	}
	return pid.String(), nil
}

// SignEvent signs e's content fields with priv and stores the result in e.Signature.
// Call this in processLocal before publishing, after setting e.ReporterID.
func SignEvent(e *proto.Event, priv libp2pcrypto.PrivKey) error {
	sig, err := priv.Sign(signedMessage(*e))
	if err != nil {
		return fmt.Errorf("identity: sign event: %w", err)
	}
	e.Signature = sig
	return nil
}

// VerifyEventSig verifies e.Signature against the public key embedded in e.ReporterID.
// Returns a non-nil error if the signature is missing, the reporter ID is malformed,
// or the signature does not match the event content.
func VerifyEventSig(e proto.Event) error {
	if e.ReporterID == "" {
		return fmt.Errorf("identity: event has empty reporter ID")
	}
	if len(e.Signature) == 0 {
		return fmt.Errorf("identity: event from %s has no signature", e.ReporterID)
	}
	pid, err := peer.Decode(e.ReporterID)
	if err != nil {
		return fmt.Errorf("identity: decode reporter ID %q: %w", e.ReporterID, err)
	}
	pubKey, err := pid.ExtractPublicKey()
	if err != nil {
		return fmt.Errorf("identity: extract public key from %q: %w", e.ReporterID, err)
	}
	ok, err := pubKey.Verify(signedMessage(e), e.Signature)
	if err != nil {
		return fmt.Errorf("identity: verify event from %s: %w", e.ReporterID, err)
	}
	if !ok {
		return fmt.Errorf("identity: invalid signature on event from %s", e.ReporterID)
	}
	return nil
}
