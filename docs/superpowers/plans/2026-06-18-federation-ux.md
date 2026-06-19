# Federation UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `swarmctl setup`, `swarmctl federation invite/join`, `swarmctl status`, and `docs/getting-started.md` so that federation setup becomes a guided, linear flow with no manual key exchange steps.

**Architecture:** New `internal/federation` package holds the invitation data model. Four new files in `cmd/swarmctl/` add the commands. All commands are read-only from files — no config auto-write. `main.go` gets four new dispatch entries. Documentation ships in the same PR.

**Tech Stack:** Go stdlib only (`encoding/json`, `bufio`, `os`), `github.com/multiformats/go-multiaddr` (already in go.mod), `github.com/libp2p/go-libp2p/core/peer` (already in go.mod), existing `internal/identity`, `internal/trust`, `internal/config` packages.

---

## Context for implementers

All commands live in `cmd/swarmctl/` as `package main`. Existing helpers (same package, no import needed):

- `addConfigFlag(fs *flag.FlagSet) func() (*config.Config, error)` — `common.go`
- `labelPath(personKeyFile string) string` — `identity.go:21`
- `issuedCertsPath(personKeyFile string) string` — `identity.go:24`
- `writeCert(path string, cert proto.PeerCert) error` — `identity.go:163`
- `appendIssuedCert(path string, cert proto.PeerCert) error` — `identity.go:181`
- `upsertAnchor(cfg *config.Config, a trust.Anchor) error` — `trust.go:349`
- `anchorStatus(a trust.Anchor, certs []proto.PeerCert, pubRaw []byte, now time.Time) string` — `trust.go:200`

Identity functions (`internal/identity`):

- `identity.LoadOrCreateNodeKey(path string) (crypto.PrivKey, error)` — creates key if missing
- `identity.LoadPersonKey(path string) (ed25519.PrivateKey, error)` — returns `fs.ErrNotExist`-wrapped error if missing
- `identity.GeneratePersonKey(path string) (ed25519.PrivateKey, error)` — overwrites
- `identity.PersonPub(priv ed25519.PrivateKey) ed25519.PublicKey`
- `identity.EncodePub(pub ed25519.PublicKey) string` — `"ed25519:<base64>"`
- `identity.DecodePub(s string) (ed25519.PublicKey, error)`
- `identity.Fingerprint(pub ed25519.PublicKey) string` — `"ab12 cd34 ef56 78gh"`
- `identity.IssueCert(priv ed25519.PrivateKey, peerID string, validUntil time.Time) proto.PeerCert`
- `identity.VerifyCert(cert proto.PeerCert, now time.Time) error`

Trust functions (`internal/trust`):

- `trust.LoadAnchors(path string) ([]Anchor, error)` — missing file = empty list, not error
- `trust.SaveAnchors(path string, anchors []Anchor) error`
- `trust.LoadCerts(path string) ([]proto.PeerCert, error)` — missing file = empty list
- `trust.SaveCerts(path string, certs []proto.PeerCert) error`
- `trust.Bundle{Person, Label, IdentityPubkey string, Certs []proto.PeerCert}`
- `trust.Anchor{Person, Label, IdentityPubkey string, Weight float64, ValidUntil time.Time, Source string}`

Multiaddr (`github.com/multiformats/go-multiaddr`):

- `multiaddr.NewMultiaddr(s string) (multiaddr.Multiaddr, error)` — validates format
- `ma.Encapsulate(other multiaddr.Multiaddr) multiaddr.Multiaddr` — appends `/p2p/<id>`
- `ma.ValueForProtocol(code int) (string, error)` — `multiaddr.P_P2P` constant
- `multiaddr.StringCast("/p2p/" + peerID.String())` — construct /p2p component

Peer ID (`github.com/libp2p/go-libp2p/core/peer`):

- `peer.IDFromPrivateKey(priv crypto.PrivKey) (peer.ID, error)`

Module path: `github.com/JoeRu/swarmguard`

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `internal/federation/invitation.go` | Create | `Invitation` type, `NewInvitation`, `WriteInvitation`, `ReadInvitation` |
| `internal/federation/invitation_test.go` | Create | TDD tests for the invitation package |
| `cmd/swarmctl/setup.go` | Create | `cmdSetup` — doctor wizard for node + person + peer cert |
| `cmd/swarmctl/federation.go` | Create | `cmdFederation` → `federationInvite` + `federationJoin` |
| `cmd/swarmctl/status.go` | Create | `cmdStatus` — local identity/anchor/peer summary |
| `cmd/swarmctl/main.go` | Modify | Add setup/status/federation to usage() + switch |
| `docs/getting-started.md` | Create | Linear operator guide (solo / start / join) |
| `docs/federation-guide.md` | Modify | Add 2-line preamble pointing to getting-started |
| `README.md` | Modify | Update quickstart + federation sections |

---

## Task 1: Invitation package

**Files:**
- Create: `internal/federation/invitation.go`
- Create: `internal/federation/invitation_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/federation/invitation_test.go`:

```go
package federation_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/federation"
	"github.com/JoeRu/swarmguard/internal/identity"
)

func makeTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	return cfg
}

func TestInvitationRoundTrip(t *testing.T) {
	cfg := makeTestConfig(t)

	// Create node key (LoadOrCreateNodeKey creates it)
	if _, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile()); err != nil {
		t.Fatalf("create node key: %v", err)
	}
	// Create person key
	priv, err := identity.GeneratePersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		t.Fatalf("create person key: %v", err)
	}
	pub := identity.PersonPub(priv)
	_ = os.WriteFile(cfg.TrustPersonKeyFile()+".label", []byte("alice\n"), 0o644)

	inv, err := federation.NewInvitation(cfg, "alice", "/ip4/1.2.3.4/tcp/7700")
	if err != nil {
		t.Fatalf("NewInvitation: %v", err)
	}

	if inv.Version != 1 {
		t.Errorf("version = %d, want 1", inv.Version)
	}
	if inv.InvitedBy != "alice" {
		t.Errorf("invited_by = %q, want %q", inv.InvitedBy, "alice")
	}
	if inv.Trust.IdentityPubkey != identity.EncodePub(pub) {
		t.Errorf("identity pubkey mismatch")
	}
	if inv.Federation.BootstrapPeer == "" {
		t.Error("bootstrap_peer is empty")
	}
	if inv.CreatedAt.IsZero() {
		t.Error("created_at is zero")
	}

	// Round-trip through WriteInvitation / ReadInvitation
	var buf bytes.Buffer
	if err := federation.WriteInvitation(&buf, inv); err != nil {
		t.Fatalf("WriteInvitation: %v", err)
	}

	got, err := federation.ReadInvitation(&buf)
	if err != nil {
		t.Fatalf("ReadInvitation: %v", err)
	}
	if got.InvitedBy != inv.InvitedBy {
		t.Errorf("round-trip InvitedBy = %q, want %q", got.InvitedBy, inv.InvitedBy)
	}
	if got.Federation.BootstrapPeer != inv.Federation.BootstrapPeer {
		t.Errorf("round-trip BootstrapPeer = %q, want %q", got.Federation.BootstrapPeer, inv.Federation.BootstrapPeer)
	}
}

func TestNewInvitationMissingPersonKey(t *testing.T) {
	cfg := makeTestConfig(t)
	// Node key exists but NO person key
	if _, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile()); err != nil {
		t.Fatalf("create node key: %v", err)
	}
	_, err := federation.NewInvitation(cfg, "alice", "/ip4/1.2.3.4/tcp/7700")
	if err == nil {
		t.Fatal("expected error for missing person key, got nil")
	}
}

func TestReadInvitationBadVersion(t *testing.T) {
	data := `{"version":2,"invited_by":"alice","federation":{"mode":"federated","bootstrap_peer":"/ip4/1.2.3.4/tcp/7700/p2p/12D3KooWTest"},"trust_bundle":{"person":"alice","label":"alice","identity_pubkey":"ed25519:AAAA","certs":[]}}`
	_, err := federation.ReadInvitation(bytes.NewBufferString(data))
	if err == nil {
		t.Fatal("expected error for version 2, got nil")
	}
}

func TestNewInvitationAddrWithPeerID(t *testing.T) {
	cfg := makeTestConfig(t)
	if _, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile()); err != nil {
		t.Fatalf("create node key: %v", err)
	}
	if _, err := identity.GeneratePersonKey(cfg.TrustPersonKeyFile()); err != nil {
		t.Fatalf("create person key: %v", err)
	}
	// Addr that already has /p2p/... should fail
	_, err := federation.NewInvitation(cfg, "alice", "/ip4/1.2.3.4/tcp/7700/p2p/12D3KooWTest")
	if err == nil {
		t.Fatal("expected error when addr already contains /p2p component, got nil")
	}
}

func TestInvitationBootstrapPeerContainsPeerID(t *testing.T) {
	cfg := makeTestConfig(t)
	if _, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile()); err != nil {
		t.Fatalf("create node key: %v", err)
	}
	if _, err := identity.GeneratePersonKey(cfg.TrustPersonKeyFile()); err != nil {
		t.Fatalf("create person key: %v", err)
	}

	inv, err := federation.NewInvitation(cfg, "bob", "/ip4/10.0.0.1/tcp/7700")
	if err != nil {
		t.Fatalf("NewInvitation: %v", err)
	}
	// bootstrap_peer must contain /p2p/
	if !containsP2P(inv.Federation.BootstrapPeer) {
		t.Errorf("BootstrapPeer %q does not contain /p2p/ component", inv.Federation.BootstrapPeer)
	}
}

func containsP2P(addr string) bool {
	for i := 0; i < len(addr)-4; i++ {
		if addr[i:i+5] == "/p2p/" {
			return true
		}
	}
	return false
}

func TestInvitationCreatedAtIsRecent(t *testing.T) {
	cfg := makeTestConfig(t)
	if _, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile()); err != nil {
		t.Fatalf("create node key: %v", err)
	}
	if _, err := identity.GeneratePersonKey(cfg.TrustPersonKeyFile()); err != nil {
		t.Fatalf("create person key: %v", err)
	}

	before := time.Now().Add(-time.Second)
	inv, err := federation.NewInvitation(cfg, "carol", "/ip4/192.168.1.1/tcp/7700")
	if err != nil {
		t.Fatalf("NewInvitation: %v", err)
	}
	after := time.Now().Add(time.Second)

	if inv.CreatedAt.Before(before) || inv.CreatedAt.After(after) {
		t.Errorf("CreatedAt %v is not recent (expected between %v and %v)", inv.CreatedAt, before, after)
	}
}

// Ensure WriteInvitation/ReadInvitation also round-trips the SuggestedWeight in FedInfo.
func TestInvitationSuggestedWeight(t *testing.T) {
	cfg := makeTestConfig(t)
	cfg.Trust.AnchorWeight = 0.75
	if _, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile()); err != nil {
		t.Fatalf("create node key: %v", err)
	}
	if _, err := identity.GeneratePersonKey(cfg.TrustPersonKeyFile()); err != nil {
		t.Fatalf("create person key: %v", err)
	}

	inv, err := federation.NewInvitation(cfg, "dave", "/ip4/1.2.3.4/tcp/7700")
	if err != nil {
		t.Fatalf("NewInvitation: %v", err)
	}
	if inv.Federation.SuggestedWeight != 0.75 {
		t.Errorf("SuggestedWeight = %.2f, want 0.75", inv.Federation.SuggestedWeight)
	}

	_ = filepath.Join(cfg.Store.Dir, "unused") // silence import
	var buf bytes.Buffer
	if err := federation.WriteInvitation(&buf, inv); err != nil {
		t.Fatalf("WriteInvitation: %v", err)
	}
	got, err := federation.ReadInvitation(&buf)
	if err != nil {
		t.Fatalf("ReadInvitation: %v", err)
	}
	if got.Federation.SuggestedWeight != 0.75 {
		t.Errorf("round-trip SuggestedWeight = %.2f, want 0.75", got.Federation.SuggestedWeight)
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /root/swarmguard
go test ./internal/federation/...
```

Expected: `cannot find package` or `no Go files` — package doesn't exist yet.

- [ ] **Step 3: Implement the invitation package**

Create `internal/federation/invitation.go`:

```go
package federation

import (
	"encoding/json"
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

// Invitation is the shareable bundle an existing federation member generates
// and sends to an operator who wants to join.
type Invitation struct {
	Version    int          `json:"version"`     // always 1
	CreatedAt  time.Time    `json:"created_at"`
	InvitedBy  string       `json:"invited_by"`
	Federation FedInfo      `json:"federation"`
	Trust      trust.Bundle `json:"trust_bundle"`
}

// FedInfo carries the federation topology hints for the joining operator.
type FedInfo struct {
	Mode            string  `json:"mode"`             // "federated" | "isolated"
	BootstrapPeer   string  `json:"bootstrap_peer"`   // full /ip4/.../tcp/.../p2p/12D3...
	SuggestedWeight float64 `json:"suggested_weight"` // default weight for trust import
}

// NewInvitation assembles an invitation bundle for the given label and transport
// address. transportAddr must be a transport-only multiaddr (e.g.
// /ip4/1.2.3.4/tcp/7700) — no /p2p/ component. The peer ID is derived from
// the local node key automatically.
func NewInvitation(cfg *config.Config, label string, transportAddr string) (*Invitation, error) {
	// Validate and parse the transport multiaddr.
	ma, err := multiaddr.NewMultiaddr(transportAddr)
	if err != nil {
		return nil, fmt.Errorf("federation: invalid transport addr %q: %w", transportAddr, err)
	}
	// Reject addrs that already carry a /p2p/ component — the caller must not
	// pass the full multiaddr; we derive the peer ID from the node key.
	if val, _ := ma.ValueForProtocol(multiaddr.P_P2P); val != "" {
		return nil, fmt.Errorf("federation: transportAddr must not include /p2p/ component (got %q)", transportAddr)
	}

	// Load node key to derive peer ID.
	nodePriv, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if err != nil {
		return nil, fmt.Errorf("federation: load node key: %w", err)
	}
	pid, err := peer.IDFromPrivateKey(nodePriv)
	if err != nil {
		return nil, fmt.Errorf("federation: derive peer ID: %w", err)
	}

	// Build the full bootstrap multiaddr: transport + /p2p/<id>.
	p2pComp := multiaddr.StringCast("/p2p/" + pid.String())
	fullAddr := ma.Encapsulate(p2pComp)

	// Load person identity.
	personPriv, err := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		return nil, fmt.Errorf("federation: no person identity — run `swarmctl setup` first: %w", err)
	}
	pub := identity.PersonPub(personPriv)

	// Load issued certs to include in the bundle.
	issuedPath := cfg.TrustPersonKeyFile() + ".issued.json"
	certs, err := trust.LoadCerts(issuedPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("federation: load issued certs: %w", err)
	}

	return &Invitation{
		Version:   1,
		CreatedAt: time.Now().UTC(),
		InvitedBy: label,
		Federation: FedInfo{
			Mode:            cfg.FederationMode,
			BootstrapPeer:   fullAddr.String(),
			SuggestedWeight: cfg.Trust.AnchorWeight,
		},
		Trust: trust.Bundle{
			Person:         label,
			Label:          label,
			IdentityPubkey: identity.EncodePub(pub),
			Certs:          certs,
		},
	}, nil
}

// WriteInvitation encodes inv as indented JSON and writes it to w.
func WriteInvitation(w io.Writer, inv *Invitation) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(inv); err != nil {
		return fmt.Errorf("federation: encode invitation: %w", err)
	}
	return nil
}

// ReadInvitation decodes an invitation from r and validates the version.
func ReadInvitation(r io.Reader) (*Invitation, error) {
	var inv Invitation
	if err := json.NewDecoder(r).Decode(&inv); err != nil {
		return nil, fmt.Errorf("federation: decode invitation: %w", err)
	}
	if inv.Version != 1 {
		return nil, fmt.Errorf("federation: unsupported invitation version %d (expected 1)", inv.Version)
	}
	return &inv, nil
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cd /root/swarmguard
go test ./internal/federation/... -v
```

Expected: all tests pass. If `go-multiaddr` reports `multiaddr.P_P2P` undefined, check with `grep -r "P_P2P\|Protocol(" $(go env GOPATH)/pkg/mod/github.com/multiformats/go-multiaddr*/multiaddr*.go 2>/dev/null | head -5` and use the correct constant or `ma.Protocols()` loop instead.

> **Fallback if P_P2P undefined:** replace `ma.ValueForProtocol(multiaddr.P_P2P)` with:
> ```go
> for _, p := range ma.Protocols() {
>     if p.Name == "p2p" {
>         return nil, fmt.Errorf("federation: transportAddr must not include /p2p/ component")
>     }
> }
> ```

- [ ] **Step 5: Commit**

```bash
git add internal/federation/invitation.go internal/federation/invitation_test.go
git commit -m "feat(federation): add Invitation type, NewInvitation, WriteInvitation, ReadInvitation"
```

---

## Task 2: `swarmctl setup`

**Files:**
- Create: `cmd/swarmctl/setup.go`
- Modify: `cmd/swarmctl/main.go`

- [ ] **Step 1: Write the failing test (smoke test only — setup is interactive)**

The setup command is a wizard with optional interactive prompt; a full unit test would require terminal mocking. Write a minimal compile-check test that also validates idempotency:

Create a small test file that we'll expand later: `cmd/swarmctl/setup_test.go`

```go
package main

import (
	"testing"
)

// TestSetupPackageCompiles is a compile-time guard.
// Integration test: run `swarmctl setup --label Alice` manually.
func TestSetupPackageCompiles(t *testing.T) {
	// Ensures cmdSetup is reachable at the package level.
	_ = cmdSetup
}
```

- [ ] **Step 2: Run to confirm compilation failure**

```bash
cd /root/swarmguard
go build ./cmd/swarmctl/
```

Expected: success (file doesn't exist yet means this is a build check). Actually just verify the test references a function that doesn't exist yet:

```bash
go test -run TestSetupPackageCompiles ./cmd/swarmctl/
```

Expected: `undefined: cmdSetup`

- [ ] **Step 3: Implement `cmd/swarmctl/setup.go`**

```go
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

func cmdSetup(args []string) error {
	fset := flag.NewFlagSet("setup", flag.ExitOnError)
	loadCfg := addConfigFlag(fset)
	label := fset.String("label", "", "your name / label for this identity")
	if err := fset.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}

	fmt.Println("SwarmGuard setup")
	fmt.Println()

	// [1/3] Node key
	fmt.Println("[1/3] Node key")
	nodePriv, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if err != nil {
		// Key file might not exist yet — swarmd must run first.
		fmt.Println("      swarmd must run once first to generate the node key — then re-run setup.")
		return fmt.Errorf("node key not found: %w", err)
	}
	pid, err := peer.IDFromPrivateKey(nodePriv)
	if err != nil {
		return fmt.Errorf("derive peer ID: %w", err)
	}
	fmt.Printf("      peer ID: %s\n\n", pid)

	// [2/3] Person identity
	fmt.Println("[2/3] Person identity")
	personKeyFile := cfg.TrustPersonKeyFile()
	personPriv, personErr := identity.LoadPersonKey(personKeyFile)
	if errors.Is(personErr, fs.ErrNotExist) || os.IsNotExist(personErr) {
		// Person key is missing — create it.
		effectiveLabel := *label
		if effectiveLabel == "" {
			fmt.Print("      Enter your name (label for this identity): ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				effectiveLabel = strings.TrimSpace(scanner.Text())
			}
		}
		if effectiveLabel == "" {
			return fmt.Errorf("label required — pass --label NAME or enter interactively")
		}
		fmt.Print("      creating person.key...")
		personPriv, err = identity.GeneratePersonKey(personKeyFile)
		if err != nil {
			return fmt.Errorf("create person key: %w", err)
		}
		if err := os.WriteFile(labelPath(personKeyFile), []byte(effectiveLabel+"\n"), 0o644); err != nil {
			return fmt.Errorf("write label: %w", err)
		}
		fmt.Println(" done")
	} else if personErr != nil {
		return fmt.Errorf("load person key: %w", personErr)
	}

	pub := identity.PersonPub(personPriv)
	fp := identity.Fingerprint(pub)
	fmt.Printf("      public key:  %s\n", identity.EncodePub(pub))
	fmt.Printf("      fingerprint: %s\n\n", fp)

	// [3/3] Peer certificate
	fmt.Println("[3/3] Peer certificate")
	certFile := cfg.TrustPeerCertFile()
	certData, certErr := os.ReadFile(certFile)
	if certErr == nil {
		// Cert exists — decode and show validity.
		var existing proto.PeerCert
		if err := json.Unmarshal(certData, &existing); err == nil {
			remaining := time.Until(existing.ValidUntil)
			days := int(remaining.Hours() / 24)
			fmt.Printf("      peer.cert valid until %s  (%dd remaining)\n\n",
				existing.ValidUntil.Format("2006-01-02"), days)
		} else {
			fmt.Println("      peer.cert exists (could not decode validity)")
			fmt.Println()
		}
	} else {
		// No cert — self-certify now.
		fmt.Print("      self-certifying this node...")
		validFor := 365 * 24 * time.Hour
		cert := identity.IssueCert(ed25519.PrivateKey(personPriv), pid.String(), time.Now().Add(validFor))
		if err := writeCert(certFile, cert); err != nil {
			return fmt.Errorf("write peer cert: %w", err)
		}
		if err := appendIssuedCert(issuedCertsPath(personKeyFile), cert); err != nil {
			return fmt.Errorf("record issued cert: %w", err)
		}
		fmt.Printf(" done\n")
		fmt.Printf("      installed: %s  (valid 365d)\n\n", certFile)
	}

	fmt.Println("Setup complete.")
	fmt.Println()
	fmt.Printf("Share your fingerprint (%s) with operators you want to federate with.\n", fp)
	fmt.Println("Next: swarmctl federation invite --addr /ip4/YOUR_IP/tcp/7700 > invite.json")
	return nil
}
```

- [ ] **Step 4: Wire `setup` into `cmd/swarmctl/main.go`**

Add to the `usage()` function (insert before the "All commands accept" line):

```
  swarmctl setup [--label NAME]
  swarmctl status
  swarmctl federation invite --addr MULTIADDR [--weight W] [--out FILE]
  swarmctl federation join FILE [--as NAME] [--weight W]
```

Add to the `switch` in `main()`:

```go
case "setup":
    err = cmdSetup(os.Args[2:])
case "status":
    err = cmdStatus(os.Args[2:])
case "federation":
    err = cmdFederation(os.Args[2:])
```

The full updated `main.go`:

```go
// Command swarmctl is the SwarmGuard admin CLI: node identity, Person
// identities, peer-certs, and the local trust-anchor list (spec §5.1).
package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprint(os.Stderr, `swarmctl — SwarmGuard admin CLI

Flags must come BEFORE positional args (PERSON, PEER_ID, FILE).

Usage:
  swarmctl setup [--label NAME]
  swarmctl status
  swarmctl federation invite --addr MULTIADDR [--weight W] [--out FILE]
  swarmctl federation join FILE [--as NAME] [--weight W]
  swarmctl identity                      print this node's peer ID
  swarmctl identity init --label NAME    create a Person identity + self peer-cert
  swarmctl identity show                 print Person pubkey + fingerprint
  swarmctl peer-cert PEER_ID             sign a peer-cert for another machine
  swarmctl trust add --identity ed25519:... [--weight W] [--label L] PERSON
  swarmctl trust set [--weight W] [--label L] PERSON
  swarmctl trust remove PERSON
  swarmctl trust list
  swarmctl trust export                  write this Person's bundle to stdout
  swarmctl trust import [--as NAME] [--weight W] FILE

All commands accept -config PATH (same file swarmd uses).
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "federation":
		err = cmdFederation(os.Args[2:])
	case "identity":
		err = cmdIdentity(os.Args[2:])
	case "peer-cert":
		err = cmdPeerCert(os.Args[2:])
	case "trust":
		err = cmdTrust(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "swarmctl:", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 5: Build and verify compile**

```bash
cd /root/swarmguard
make build
```

Expected: `bin/swarmd` and `bin/swarmctl` build without errors.

- [ ] **Step 6: Run tests**

```bash
go test ./cmd/swarmctl/...
```

Expected: `TestSetupPackageCompiles` passes.

- [ ] **Step 7: Commit**

```bash
git add cmd/swarmctl/setup.go cmd/swarmctl/setup_test.go cmd/swarmctl/main.go
git commit -m "feat(swarmctl): add setup wizard command"
```

---

## Task 3: `swarmctl federation invite/join`

**Files:**
- Create: `cmd/swarmctl/federation.go`
- No changes to `main.go` needed (already wired in Task 2)

- [ ] **Step 1: Write a compile-check test**

Create `cmd/swarmctl/federation_test.go`:

```go
package main

import (
	"testing"
)

// TestFederationPackageCompiles is a compile-time guard.
func TestFederationPackageCompiles(t *testing.T) {
	_ = cmdFederation
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test -run TestFederationPackageCompiles ./cmd/swarmctl/
```

Expected: `undefined: cmdFederation`

- [ ] **Step 3: Implement `cmd/swarmctl/federation.go`**

```go
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JoeRu/swarmguard/internal/federation"
	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/trust"
)

func cmdFederation(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: swarmctl federation invite|join ...")
	}
	switch args[0] {
	case "invite":
		return federationInvite(args[1:])
	case "join":
		return federationJoin(args[1:])
	default:
		return fmt.Errorf("unknown federation subcommand %q", args[0])
	}
}

func federationInvite(args []string) error {
	fset := flag.NewFlagSet("federation invite", flag.ExitOnError)
	loadCfg := addConfigFlag(fset)
	addr := fset.String("addr", "", "transport multiaddr of this node (e.g. /ip4/1.2.3.4/tcp/7700) — required")
	out := fset.String("out", "", "write invitation to FILE instead of stdout")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if *addr == "" {
		return fmt.Errorf("--addr is required: the public transport multiaddr of this node (e.g. /ip4/1.2.3.4/tcp/7700)")
	}

	cfg, err := loadCfg()
	if err != nil {
		return err
	}

	// Read label from the label file next to person.key.
	labelData, err := os.ReadFile(labelPath(cfg.TrustPersonKeyFile()))
	if err != nil {
		return fmt.Errorf("no person identity — run `swarmctl setup` first")
	}
	label := strings.TrimSpace(string(labelData))

	inv, err := federation.NewInvitation(cfg, label, *addr)
	if err != nil {
		return err
	}

	// Read fingerprint for the confirmation message.
	personPriv, err := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		return err
	}
	fp := identity.Fingerprint(identity.PersonPub(personPriv))

	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return fmt.Errorf("create %s: %w", *out, err)
		}
		defer f.Close()
		if err := federation.WriteInvitation(f, inv); err != nil {
			return err
		}
		fmt.Println()
		fmt.Printf("invitation written to %s\n", *out)
		fmt.Printf("→ send %s to the operator joining your federation\n", *out)
		fmt.Printf("→ ask them to verify fingerprint: %s\n", fp)
		return nil
	}

	// Write to stdout.
	if err := federation.WriteInvitation(os.Stdout, inv); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "→ ask the recipient to verify fingerprint: %s\n", fp)
	return nil
}

func federationJoin(args []string) error {
	fset := flag.NewFlagSet("federation join", flag.ExitOnError)
	loadCfg := addConfigFlag(fset)
	as := fset.String("as", "", "local person name (default: invitation's invited_by)")
	weight := fset.Float64("weight", 0, "trust weight (default: invitation's suggested_weight, fallback to config anchor_weight)")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl federation join FILE [--as NAME] [--weight W]")
	}

	f, err := os.Open(fset.Arg(0))
	if err != nil {
		return fmt.Errorf("open invitation: %w", err)
	}
	defer f.Close()

	inv, err := federation.ReadInvitation(f)
	if err != nil {
		return err
	}

	cfg, err := loadCfg()
	if err != nil {
		return err
	}

	// Show invitation summary.
	fmt.Println()
	fmt.Printf("Invitation from: %s\n", inv.InvitedBy)
	fmt.Printf("Bootstrap peer:  %s\n", inv.Federation.BootstrapPeer)
	fmt.Printf("Federation mode: %s\n", inv.Federation.Mode)
	fmt.Println()

	// Decode the public key for fingerprint display.
	pub, err := identity.DecodePub(inv.Trust.IdentityPubkey)
	if err != nil {
		return fmt.Errorf("decode identity pubkey: %w", err)
	}
	fp := identity.Fingerprint(pub)

	fmt.Printf("Fingerprint: %s\n", fp)
	fmt.Printf("Verify this with %s over a channel you already trust, then type 'yes' to continue: ", inv.InvitedBy)

	scanner := bufio.NewScanner(os.Stdin)
	answer := ""
	if scanner.Scan() {
		answer = strings.TrimSpace(scanner.Text())
	}
	if answer != "yes" {
		fmt.Println("aborted — import nothing.")
		return nil
	}

	// Resolve effective person name and weight.
	person := *as
	if person == "" {
		person = inv.InvitedBy
	}
	if person == "" {
		return fmt.Errorf("invitation has no person name — pass --as NAME")
	}
	w := *weight
	if w == 0 {
		w = inv.Federation.SuggestedWeight
	}
	if w == 0 {
		w = cfg.Trust.AnchorWeight
	}
	if w <= 0 || w > 1 {
		return fmt.Errorf("weight %v out of range (0,1]", w)
	}

	// Import certs (identical logic to trustImport).
	existing, err := trust.LoadCerts(cfg.TrustCertsFile())
	if err != nil {
		return err
	}
	byPeer := map[string]int{}
	for i, c := range existing {
		byPeer[c.PeerID] = i
	}
	imported := 0
	for _, c := range inv.Trust.Certs {
		if !bytes.Equal(c.PersonKey, pub) {
			fmt.Fprintf(os.Stderr, "skipping cert for %s: signed by a different identity\n", c.PeerID)
			continue
		}
		if err := identity.VerifyCert(c, time.Now()); err != nil {
			fmt.Fprintf(os.Stderr, "skipping cert for %s: %v\n", c.PeerID, err)
			continue
		}
		if i, ok := byPeer[c.PeerID]; ok {
			existing[i] = c
		} else {
			existing = append(existing, c)
		}
		imported++
	}
	if err := trust.SaveCerts(cfg.TrustCertsFile(), existing); err != nil {
		return err
	}

	if err := upsertAnchor(cfg, trust.Anchor{
		Person:         person,
		Label:          inv.Trust.Label,
		IdentityPubkey: inv.Trust.IdentityPubkey,
		Weight:         w,
		Source:         "federation-join",
	}); err != nil {
		return err
	}

	fmt.Printf("\n✓ anchored %s (weight %.2f)\n", person, w)
	fmt.Printf("✓ imported %d cert(s)\n", imported)

	// Print config snippet.
	fmt.Println()
	fmt.Println("Add to your config.yaml:")
	fmt.Println("──────────────────────────────────────────")
	fmt.Println("  federation_mode: federated")
	fmt.Println("  bootstrap_peers:")
	fmt.Printf("    - %s\n", inv.Federation.BootstrapPeer)
	fmt.Println("──────────────────────────────────────────")
	fmt.Println()
	fmt.Println("Now send your bundle so they can anchor you back:")
	fmt.Println("  swarmctl trust export > my.bundle")
	fmt.Printf("  # send my.bundle to %s\n", inv.InvitedBy)
	fmt.Printf("  # they run: swarmctl trust import my.bundle --as %s --weight %.1f\n", person, w)

	return nil
}
```

- [ ] **Step 4: Build and run tests**

```bash
cd /root/swarmguard
make build
go test ./cmd/swarmctl/...
```

Expected: builds clean, `TestFederationPackageCompiles` passes.

- [ ] **Step 5: Commit**

```bash
git add cmd/swarmctl/federation.go cmd/swarmctl/federation_test.go
git commit -m "feat(swarmctl): add federation invite/join commands"
```

---

## Task 4: `swarmctl status`

**Files:**
- Create: `cmd/swarmctl/status.go`
- No changes to `main.go` needed (already wired in Task 2)

- [ ] **Step 1: Write a compile-check test**

Create `cmd/swarmctl/status_test.go`:

```go
package main

import (
	"testing"
)

// TestStatusPackageCompiles is a compile-time guard.
func TestStatusPackageCompiles(t *testing.T) {
	_ = cmdStatus
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test -run TestStatusPackageCompiles ./cmd/swarmctl/
```

Expected: `undefined: cmdStatus`

- [ ] **Step 3: Implement `cmd/swarmctl/status.go`**

```go
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/trust"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

func cmdStatus(args []string) error {
	fset := flag.NewFlagSet("status", flag.ExitOnError)
	loadCfg := addConfigFlag(fset)
	if err := fset.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}

	// NODE section
	fmt.Println("NODE")
	nodePriv, nodeErr := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if nodeErr != nil {
		fmt.Printf("  peer ID:     not configured — run swarmctl setup\n")
		fmt.Printf("  node key:    %s  ✗\n\n", cfg.NodeKeyFile())
	} else {
		pid, err := peer.IDFromPrivateKey(nodePriv)
		if err != nil {
			return fmt.Errorf("derive peer ID: %w", err)
		}
		fmt.Printf("  peer ID:     %s\n", pid)
		fmt.Printf("  node key:    %s  ✓\n", cfg.NodeKeyFile())
	}
	fmt.Println()

	// IDENTITY section
	fmt.Println("IDENTITY")
	personPriv, personErr := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if personErr != nil {
		fmt.Println("  not configured — run swarmctl setup")
	} else {
		pub := identity.PersonPub(personPriv)
		fp := identity.Fingerprint(pub)

		personLabel := "(no label)"
		if data, err := os.ReadFile(labelPath(cfg.TrustPersonKeyFile())); err == nil {
			personLabel = string(bytes.TrimSpace(data))
		}
		fmt.Printf("  person:      %s\n", personLabel)
		fmt.Printf("  fingerprint: %s\n", fp)

		// Peer cert validity
		if certData, err := os.ReadFile(cfg.TrustPeerCertFile()); err == nil {
			var cert proto.PeerCert
			if err := json.Unmarshal(certData, &cert); err == nil {
				remaining := time.Until(cert.ValidUntil)
				days := int(remaining.Hours() / 24)
				fmt.Printf("  peer cert:   valid until %s  (%dd remaining)\n",
					cert.ValidUntil.Format("2006-01-02"), days)
			}
		} else {
			fmt.Println("  peer cert:   not found — run swarmctl setup")
		}
	}
	fmt.Println()

	// TRUST ANCHORS section
	certs, _ := trust.LoadCerts(cfg.TrustCertsFile())
	anchors, _ := trust.LoadAnchors(cfg.TrustAnchorsFile())
	now := time.Now()

	// Build the synthesized self row from the local person key (if it exists).
	type anchorRow struct {
		person string
		weight float64
		status string
		fp     string
		label  string
	}
	var rows []anchorRow

	if personErr == nil {
		pub := identity.PersonPub(personPriv)
		pubRaw := []byte(pub)
		fp := identity.Fingerprint(pub)
		// Self status: look for a valid peer cert in the cert cache.
		selfStatus := "no-certs"
		for _, c := range certs {
			if bytes.Equal(c.PersonKey, pubRaw) {
				if now.Before(c.ValidUntil) {
					selfStatus = "ok"
				} else {
					selfStatus = "certs-exp"
				}
				break
			}
		}
		selfLabel := "(no label)"
		if data, err := os.ReadFile(labelPath(cfg.TrustPersonKeyFile())); err == nil {
			selfLabel = string(bytes.TrimSpace(data))
		}
		rows = append(rows, anchorRow{
			person: selfLabel,
			weight: 1.00,
			status: selfStatus,
			fp:     fp,
			label:  "self",
		})
	}

	for _, a := range anchors {
		fp := "?"
		var pubRaw []byte
		if pub, err := identity.DecodePub(a.IdentityPubkey); err == nil {
			fp = identity.Fingerprint(pub)
			pubRaw = pub
		}
		rows = append(rows, anchorRow{
			person: a.Person,
			weight: a.Weight,
			status: anchorStatus(a, certs, pubRaw, now),
			fp:     fp,
			label:  a.Label,
		})
	}

	fmt.Printf("TRUST ANCHORS  (%d)\n", len(rows))
	if len(rows) == 0 {
		fmt.Println("  not configured — run swarmctl setup")
	} else {
		fmt.Printf("  %-12s %-7s %-10s %-22s %s\n", "PERSON", "WEIGHT", "STATUS", "FINGERPRINT", "LABEL")
		for _, r := range rows {
			fmt.Printf("  %-12s %-7.2f %-10s %-22s %s\n", r.person, r.weight, r.status, r.fp, r.label)
		}
	}
	fmt.Println()

	// BOOTSTRAP PEERS section
	fmt.Printf("BOOTSTRAP PEERS  (%d)\n", len(cfg.BootstrapPeers))
	if len(cfg.BootstrapPeers) == 0 {
		fmt.Println("  not configured — run swarmctl setup")
	} else {
		for _, p := range cfg.BootstrapPeers {
			fmt.Printf("  %s\n", p)
		}
	}
	fmt.Println()
	fmt.Println("  For live peer count: GET /api/v1/blocklist or check node logs.")

	return nil
}
```

- [ ] **Step 4: Build and run tests**

```bash
cd /root/swarmguard
make build
go test ./cmd/swarmctl/...
```

Expected: builds clean, all tests pass.

- [ ] **Step 5: Commit**

```bash
git add cmd/swarmctl/status.go cmd/swarmctl/status_test.go
git commit -m "feat(swarmctl): add status command"
```

---

## Task 5: Documentation

**Files:**
- Create: `docs/getting-started.md`
- Modify: `docs/federation-guide.md`
- Modify: `README.md`

No Go code in this task.

- [ ] **Step 1: Create `docs/getting-started.md`**

```markdown
# Getting Started with SwarmGuard

SwarmGuard is a federated IP reputation system. This guide covers three paths:
**A** — solo node, **B** — start a new federation, **C** — join an existing federation.

Run `make build` first to produce `bin/swarmd` and `bin/swarmctl`.

---

## Option A — Solo node (single operator, no federation)

1. Start swarmd once to generate the node key:
   ```bash
   ./bin/swarmd -config config.yaml
   # (Ctrl-C after it prints "peer ID: 12D3Koo...")
   ```
2. Initialise your identity:
   ```bash
   ./bin/swarmctl setup --label "MyNode" -config config.yaml
   ```
3. Set `federation_mode: solo` in `config.yaml` and restart swarmd.
4. Done. Your node scores IP reputation locally.

---

## Option B — Start a new federation (first operator)

You are creating the federation that others will join.

1. Start swarmd once to generate the node key, then Ctrl-C.
2. Initialise your identity:
   ```bash
   ./bin/swarmctl setup --label "Alice" -config config.yaml
   ```
3. Generate an invitation for each operator who will join:
   ```bash
   ./bin/swarmctl federation invite \
       --addr /ip4/YOUR_PUBLIC_IP/tcp/7700 \
       --out alice.invite \
       -config config.yaml
   ```
   Send `alice.invite` to each joining operator over Signal, encrypted email, or any channel you already trust.
4. Ask them to read back the **fingerprint** shown during `swarmctl setup`. Verify it matches the fingerprint printed during step 2 before they proceed.
5. For each reply bundle you receive from joining operators:
   ```bash
   ./bin/swarmctl trust import bob.bundle --as bob --weight 0.8 -config config.yaml
   ```
6. Set `federation_mode: federated` in `config.yaml` and restart swarmd.

---

## Option C — Join an existing federation

You received an `alice.invite` file from an existing federation operator.

1. Start swarmd once to generate the node key, then Ctrl-C.
2. Initialise your identity:
   ```bash
   ./bin/swarmctl setup --label "Bob" -config config.yaml
   ```
3. Join using the invitation:
   ```bash
   ./bin/swarmctl federation join alice.invite -config config.yaml
   ```
   You will be shown a fingerprint. **Verify it with Alice** over a channel you already trust before typing `yes`.
4. Paste the printed config snippet into `config.yaml`:
   ```yaml
   federation_mode: federated
   bootstrap_peers:
     - /ip4/ALICE_IP/tcp/7700/p2p/12D3KooW...
   ```
5. Export your own bundle and send it back to Alice:
   ```bash
   ./bin/swarmctl trust export > bob.bundle -config config.yaml
   # send bob.bundle to Alice
   # Alice runs: swarmctl trust import bob.bundle --as bob --weight 0.8
   ```
6. Restart swarmd.

---

## Checking status at any time

```bash
./bin/swarmctl status -config config.yaml
```

Shows your node identity, person fingerprint, trust anchors, and bootstrap peers.

---

## Key management reference

| File | Purpose | Command |
|---|---|---|
| `data/reputation/identity.key` | libp2p node key (created by swarmd) | auto |
| `data/reputation/person.key` | operator Ed25519 key | `swarmctl setup` |
| `data/reputation/peer.cert` | node-to-operator binding | `swarmctl setup` |
| `data/reputation/anchors.json` | trusted operators | `swarmctl trust add/import` |
| `data/reputation/imported-certs.json` | peer certs from anchored operators | `swarmctl trust import` |

All paths are configurable via `trust.*_file` in `config.yaml`. See `docs/onboarding/03-key-management.md` for the full reference.

---

## Troubleshooting

**Scores not syncing after setup**
Restart swarmd — it reads identity files on startup, not live.

**Fingerprint mismatch during join**
Stop immediately. Do not type `yes`. Contact the inviting operator on a separate channel to verify identity.

**`no person identity` error**
Run `swarmctl setup --label NAME` first.

**`node key not found` error**
Start swarmd at least once before running `swarmctl setup`. Swarmd generates the node key (`identity.key`) on first boot.

**Peer cert expired**
Re-run `swarmctl setup` — it will reissue the cert. Or use `swarmctl peer-cert <PEER_ID>` to issue a new one manually.

**Weight set to 0**
A weight of 0 means events from that operator are silently ignored. Use `swarmctl trust set --weight 0.8 PERSON` to fix it.

**Bootstrap peer not connecting**
Check that port 7700/tcp is open in your firewall and that the peer ID in `bootstrap_peers` matches the ID printed by swarmd (`peer ID: 12D3Koo...` in the startup log).
```

- [ ] **Step 2: Add preamble to `docs/federation-guide.md`**

Read the current top of `docs/federation-guide.md` and prepend:

```markdown
> For the quickest path, see [`docs/getting-started.md`](getting-started.md).
> This file covers the underlying concepts and advanced federation options.

```

(Two lines, then a blank line, then the existing content.)

- [ ] **Step 3: Update `README.md`**

Read the current `README.md`. Find the "Quick start" or scaffold section and replace it. The updated README must contain an "Install & first run" section that:

1. Points to `docs/getting-started.md` as the primary entry point
2. Shows the three-line solo setup:
   ```
   make build
   swarmctl setup --label "MyNode"
   ./bin/swarmd -config config.yaml
   ```
3. Replaces any "(currently stubs)" notes with current capability descriptions
4. Updates the federation section to mention `swarmctl setup` and `swarmctl federation invite/join` as starting points

Read README.md first, then make the targeted edits. Do not rewrite sections that are already accurate.

- [ ] **Step 4: Build check (no Go changes, but verify docs exist)**

```bash
make build
ls docs/getting-started.md docs/federation-guide.md README.md
```

Expected: all files exist, build passes.

- [ ] **Step 5: Commit**

```bash
git add docs/getting-started.md docs/federation-guide.md README.md
git commit -m "docs: add getting-started guide and update federation/README pointers"
```

---

## Verification

After all tasks are complete:

```bash
# Build
make build

# All tests pass
make test

# Smoke test setup wizard (non-interactive with --label)
mkdir -p /tmp/sg-test-data
cat > /tmp/sg-test.yaml << 'EOF'
store:
  dir: /tmp/sg-test-data
EOF
./bin/swarmd -config /tmp/sg-test.yaml -listen /ip4/127.0.0.1/tcp/0 &
sleep 1; kill %1   # let it create identity.key, then stop
./bin/swarmctl setup --label "TestOperator" -config /tmp/sg-test.yaml
./bin/swarmctl status -config /tmp/sg-test.yaml

# Smoke test federation invite (prints JSON to stdout)
./bin/swarmctl federation invite --addr /ip4/1.2.3.4/tcp/7700 -config /tmp/sg-test.yaml | head -5

# Verify usage shows new commands
./bin/swarmctl --help 2>&1 | grep -E "setup|status|federation"
```

Expected output from setup:
```
SwarmGuard setup

[1/3] Node key
      peer ID: 12D3Koo...

[2/3] Person identity
      creating person.key... done
      public key:  ed25519:AAAA...
      fingerprint: ab12 cd34 ef56 78gh

[3/3] Peer certificate
      self-certifying this node... done
      installed: /tmp/sg-test-data/peer.cert  (valid 365d)

Setup complete.

Share your fingerprint (ab12 cd34 ef56 78gh) with operators you want to federate with.
Next: swarmctl federation invite --addr /ip4/YOUR_IP/tcp/7700 > invite.json
```
