package federation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/trust"
)

// Invitation is the offline bootstrap token produced by `swarmctl federation invite`
// and consumed by a new peer's `swarmctl federation join`. It carries enough
// information to bootstrap trust without any out-of-band coordination.
type Invitation struct {
	Version    int          `json:"version"`      // always 1
	CreatedAt  time.Time    `json:"created_at"`
	InvitedBy  string       `json:"invited_by"`   // fingerprint of inviting Person key
	Federation FedInfo      `json:"federation"`
	Trust      trust.Bundle `json:"trust_bundle"`
}

// FedInfo carries the transport-level bootstrap information embedded in an Invitation.
type FedInfo struct {
	Mode            string  `json:"mode"`
	BootstrapPeer   string  `json:"bootstrap_peer"`   // full /ip4/.../tcp/.../p2p/12D3...
	SuggestedWeight float64 `json:"suggested_weight"` // hint for the recipient's anchor weight
}

// NewInvitation builds a signed Invitation for the local node.
//
// label is the human-readable name for the inviting Person (stored in the Bundle).
// transportAddr must be a multiaddr without a /p2p/ component, e.g. "/ip4/1.2.3.4/tcp/7700".
// The node's peer ID is appended automatically.
func NewInvitation(cfg *config.Config, label string, transportAddr string) (*Invitation, error) {
	// Step 1: parse and validate the transport address.
	ma, err := multiaddr.NewMultiaddr(transportAddr)
	if err != nil {
		return nil, fmt.Errorf("federation: invalid transport addr %q: %w", transportAddr, err)
	}

	// Step 2: reject addresses that already carry a /p2p/ component.
	p2pVal, _ := ma.ValueForProtocol(multiaddr.P_P2P)
	if p2pVal != "" {
		return nil, fmt.Errorf("federation: transportAddr %q already contains a /p2p/ component — pass the bare transport address only", transportAddr)
	}

	// Step 3: load (or create) the node key.
	nodePriv, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if err != nil {
		return nil, fmt.Errorf("federation: load node key: %w", err)
	}

	// Step 4: derive the peer ID from the node key.
	pid, err := peer.IDFromPrivateKey(nodePriv)
	if err != nil {
		return nil, fmt.Errorf("federation: derive peer ID: %w", err)
	}

	// Step 5: build the full multiaddr including the /p2p/<peerID> suffix.
	p2pComp, err := multiaddr.NewMultiaddr("/p2p/" + pid.String())
	if err != nil {
		return nil, fmt.Errorf("federation: build p2p multiaddr: %w", err)
	}
	fullAddr := ma.Encapsulate(p2pComp)

	// Step 6: load the Person key (must already exist — operator runs `swarmctl setup`).
	personPriv, err := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("federation: no person identity — run `swarmctl setup` first")
		}
		return nil, fmt.Errorf("federation: load person key: %w — run `swarmctl setup` first", err)
	}

	// Step 7: load issued certs from "<person_key_file>.issued.json".
	// A missing file is fine — empty cert list is valid.
	issuedPath := cfg.TrustPersonKeyFile() + ".issued.json"
	certs, err := trust.LoadCerts(issuedPath)
	if err != nil {
		return nil, fmt.Errorf("federation: load issued certs: %w", err)
	}

	// Step 8: assemble the Person public key and build the Bundle.
	personPub := identity.PersonPub(personPriv)
	bundle := trust.Bundle{
		Person:         label,
		Label:          label,
		IdentityPubkey: identity.EncodePub(personPub),
		Certs:          certs,
	}

	inv := &Invitation{
		Version:   1,
		CreatedAt: time.Now().UTC(),
		InvitedBy: identity.Fingerprint(personPub),
		Federation: FedInfo{
			Mode:            cfg.FederationMode,
			BootstrapPeer:   fullAddr.String(),
			SuggestedWeight: cfg.Trust.AnchorWeight,
		},
		Trust: bundle,
	}
	return inv, nil
}

// WriteInvitation serialises inv to w as pretty-printed JSON (2-space indent).
func WriteInvitation(w io.Writer, inv *Invitation) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(inv)
}

// ReadInvitation deserialises an Invitation from r and validates its version.
func ReadInvitation(r io.Reader) (*Invitation, error) {
	var inv Invitation
	if err := json.NewDecoder(r).Decode(&inv); err != nil {
		return nil, fmt.Errorf("federation: decode invitation: %w", err)
	}
	if inv.Version != 1 {
		return nil, fmt.Errorf("federation: unsupported invitation version %d (want 1)", inv.Version)
	}
	return &inv, nil
}
