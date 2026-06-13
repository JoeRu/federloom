package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/JoeRu/swarmguard/pkg/proto"
)

// certMessage is the canonical, domain-separated byte string a Person identity
// signs to vouch for a peer. Any field change invalidates the signature.
func certMessage(peerID string, personKey []byte, validUntil time.Time) []byte {
	return []byte("swarmguard-peer-cert-v1|" + peerID + "|" +
		base64.StdEncoding.EncodeToString(personKey) + "|" +
		validUntil.UTC().Format(time.RFC3339))
}

// IssueCert signs a binding of peerID to the Person identity priv (spec §5.1).
func IssueCert(priv ed25519.PrivateKey, peerID string, validUntil time.Time) proto.PeerCert {
	pub := PersonPub(priv)
	return proto.PeerCert{
		PeerID:     peerID,
		PersonKey:  pub,
		ValidUntil: validUntil,
		Sig:        ed25519.Sign(priv, certMessage(peerID, pub, validUntil)),
	}
}

// VerifyCert checks the cert's signature and expiry. Anchoring of the Person
// key is the caller's concern (internal/trust) — a valid cert from an
// un-anchored identity still resolves as a stranger.
func VerifyCert(cert proto.PeerCert, now time.Time) error {
	if len(cert.PersonKey) != ed25519.PublicKeySize {
		return fmt.Errorf("identity: cert for %s: bad person key length %d", cert.PeerID, len(cert.PersonKey))
	}
	// The "|" delimiter is the only ambiguity vector in certMessage (base64 and
	// RFC3339 cannot contain it). Real libp2p peer IDs never do either; reject
	// any that does rather than trust the canonicalisation by assumption.
	if strings.Contains(cert.PeerID, "|") {
		return fmt.Errorf("identity: cert peer ID %q contains reserved delimiter", cert.PeerID)
	}
	if !now.Before(cert.ValidUntil) {
		return fmt.Errorf("identity: cert for %s expired at %s", cert.PeerID, cert.ValidUntil.Format(time.RFC3339))
	}
	msg := certMessage(cert.PeerID, cert.PersonKey, cert.ValidUntil)
	if !ed25519.Verify(ed25519.PublicKey(cert.PersonKey), msg, cert.Sig) {
		return fmt.Errorf("identity: cert for %s: invalid signature", cert.PeerID)
	}
	return nil
}
