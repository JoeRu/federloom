# Social Trust Anchors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ed25519 Person identities sign peer-certs that travel on the wire, so anchoring one human's key extends trust to all their machines; un-anchored strangers are score-capped.

**Architecture:** Three keys (node libp2p key, Person identity key, peer-cert). `internal/identity` handles keys + cert issue/verify; `internal/trust` holds the anchor store + verified cert cache behind `Resolve(peerID)`; transport surfaces the gossipsub-verified publisher; the node drops spoofed reporters and verifies vouches; the reputation engine counts distinct Person groups and caps stranger contributions. `swarmctl` manages identities, certs, and anchors by editing files (atomic rename) — no daemon API.

**Tech Stack:** Go 1.22, stdlib `crypto/ed25519`, libp2p (`core/crypto`, `core/peer`, gossipsub message signing — already on by default), BadgerDB (existing store), `flag` stdlib for swarmctl subcommands (no new deps).

**Spec:** `docs/superpowers/specs/2026-06-12-social-trust-anchors-design.md`. Wire change governed by `.claude/skills/wire-protocol`.

---

## File structure

| File | Responsibility |
|---|---|
| `pkg/proto/messages.go` (modify) | `PeerCert` type, `Event.Vouch`, `SchemaVersion = 1` |
| `pkg/proto/messages_test.go` (create) | wire round-trip + backward-compat tests |
| `internal/identity/nodekey.go` (create) | persistent libp2p node key, permission checks |
| `internal/identity/person.go` (create) | Person Ed25519 key, pubkey encode/decode, fingerprint |
| `internal/identity/cert.go` (create) | `IssueCert` / `VerifyCert` |
| `internal/identity/*_test.go` (create) | unit tests for the above |
| `internal/config/config.go` (modify) | `TrustConfig` + path helper methods |
| `internal/store/store.go` (modify) | `ScoreRecord` gains `Groups`, `StrangerSeen`, `StrangerContrib` |
| `internal/reputation/engine.go` (modify) | new `Record` signature, stranger cap, group corroboration |
| `internal/trust/anchors.go` (create) | `Anchor` type, `LoadAnchors`/`SaveAnchors` (atomic) |
| `internal/trust/certs.go` (create) | `LoadCerts`/`SaveCerts` for imported-certs.json |
| `internal/trust/store.go` (create) | `Store` with `Resolve`, hot reload, cert cache |
| `internal/trust/bundle.go` (create) | `Bundle` export/import format |
| `internal/transport/gossip.go` (modify) | `ReceivedEvent{Event, From}`, verified publisher |
| `internal/node/node.go` (modify) | trust wiring, vouch attach/verify, spoof drop, `ProcessRemote` exported |
| `cmd/swarmd/main.go` (modify) | load persistent node key |
| `cmd/swarmctl/main.go` (modify) | subcommand dispatch |
| `cmd/swarmctl/common.go` (create) | config loading helper |
| `cmd/swarmctl/identity.go` (create) | `identity`, `identity init/show`, `peer-cert` |
| `cmd/swarmctl/trust.go` (create) | `trust add/set/remove/list/export/import` |
| `test/adversarial/vouch_test.go` (create) | new CI-gate scenarios |
| `test/integration/vouch_pipeline_test.go` (create) | on-wire vouch round-trip |
| docs (modify) | `docs/onboarding/03-key-management.md`, `docs/federation-guide.md`, `CHANGELOG.md` |

Run all commands from the repo root `/root/swarmguard`. The PostToolUse hook runs `gofmt` + `go vet` on every Go edit — if vet fails mid-task because a later step hasn't landed yet, finish the task's implementation steps before re-running tests.

---

### Task 1: Wire contract — `PeerCert`, `Event.Vouch`, `SchemaVersion` 1

**Files:**
- Modify: `pkg/proto/messages.go`
- Test: `pkg/proto/messages_test.go` (create)

This is a `pkg/proto` change — additive field + version bump per `.claude/skills/wire-protocol`. Old nodes ignore `vouch`; new nodes treat its absence as "stranger".

- [ ] **Step 1: Write the failing test**

Create `pkg/proto/messages_test.go`:

```go
package proto_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/pkg/proto"
)

func TestEventVouchRoundTrip(t *testing.T) {
	e := proto.Event{
		IP:         "192.0.2.1",
		Reason:     "ssh-auth-bruteforce",
		Timestamp:  time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC),
		ReporterID: "12D3KooWtest",
		Vouch: &proto.PeerCert{
			PeerID:     "12D3KooWtest",
			PersonKey:  []byte{1, 2, 3, 4},
			ValidUntil: time.Date(2027, 6, 12, 12, 0, 0, 0, time.UTC),
			Sig:        []byte{9, 8, 7},
		},
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got proto.Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Vouch == nil {
		t.Fatal("Vouch lost in round trip")
	}
	if got.Vouch.PeerID != e.Vouch.PeerID || !got.Vouch.ValidUntil.Equal(e.Vouch.ValidUntil) {
		t.Errorf("Vouch mismatch: got %+v want %+v", got.Vouch, e.Vouch)
	}
}

// TestEventLegacyDecode proves a v0 event (no vouch field) decodes with Vouch nil
// — the additive-compatibility guarantee of the SchemaVersion 0→1 bump.
func TestEventLegacyDecode(t *testing.T) {
	legacy := []byte(`{"ip":"192.0.2.1","reason":"spam","ts":"2026-06-12T12:00:00Z","port_class":"","reporter":"x","sig":null,"subnet":"","origin":null}`)
	var got proto.Event
	if err := json.Unmarshal(legacy, &got); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if got.Vouch != nil {
		t.Errorf("legacy event must have nil Vouch, got %+v", got.Vouch)
	}
}

// TestEventWithoutVouchOmitsField proves omitempty: stranger events carry no vouch key.
func TestEventWithoutVouchOmitsField(t *testing.T) {
	data, err := json.Marshal(proto.Event{IP: "192.0.2.1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if _, ok := m["vouch"]; ok {
		t.Error("vouch key present on event without vouch — omitempty missing")
	}
}

func TestSchemaVersionBumped(t *testing.T) {
	if proto.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1 (vouching added)", proto.SchemaVersion)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/proto/`
Expected: FAIL — `proto.PeerCert` undefined, `Vouch` undefined, `SchemaVersion != 1`.

- [ ] **Step 3: Implement**

In `pkg/proto/messages.go`, change the `SchemaVersion` line:

```go
// SchemaVersion is bumped on any breaking change to the wire format.
// v1: added Event.Vouch (PeerCert) — additive, v0 decoders ignore it.
const SchemaVersion = 1
```

Add to the `Event` struct after `OriginTrace`:

```go
	Vouch *PeerCert `json:"vouch,omitempty"` // present if the reporter is vouched by a Person identity (spec §5.1)
```

Add the new type after `Event`:

```go
// PeerCert binds a node's libp2p peer ID to a Person identity (spec §5.1).
// Signed by the Person identity key; a node anchors the Person's public key
// locally and every certified peer inherits that trust.
type PeerCert struct {
	PeerID     string    `json:"peer_id"`     // libp2p peer ID being vouched for
	PersonKey  []byte    `json:"person_key"`  // Ed25519 public key of the Person identity
	ValidUntil time.Time `json:"valid_until"` // cert expiry
	Sig        []byte    `json:"sig"`         // Ed25519 sig by PersonKey over the cert message (internal/identity)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/proto/`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add pkg/proto/messages.go pkg/proto/messages_test.go
git commit -m "feat(proto): add PeerCert vouching to Event, bump SchemaVersion to 1"
```

---

### Task 2: Persistent node key — `internal/identity/nodekey.go` + swarmd wiring

**Files:**
- Create: `internal/identity/nodekey.go`
- Create: `internal/identity/nodekey_test.go`
- Modify: `cmd/swarmd/main.go`
- Modify: `internal/config/config.go` (one helper method)

- [ ] **Step 1: Write the failing tests**

Create `internal/identity/nodekey_test.go`:

```go
package identity_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/swarmguard/internal/identity"
)

func TestNodeKeyStableAcrossLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")

	k1, err := identity.LoadOrCreateNodeKey(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	k2, err := identity.LoadOrCreateNodeKey(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}

	id1, _ := peer.IDFromPrivateKey(k1)
	id2, _ := peer.IDFromPrivateKey(k2)
	if id1 != id2 {
		t.Errorf("peer ID changed across loads: %s vs %s", id1, id2)
	}
}

func TestNodeKeyFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	if _, err := identity.LoadOrCreateNodeKey(path); err != nil {
		t.Fatalf("create: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestNodeKeyRejectsLooseperms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	if _, err := identity.LoadOrCreateNodeKey(path); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := identity.LoadOrCreateNodeKey(path); err == nil {
		t.Error("expected error for group/world-readable key, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/identity/`
Expected: FAIL — package contains only `doc.go`, `LoadOrCreateNodeKey` undefined.

- [ ] **Step 3: Implement**

Create `internal/identity/nodekey.go`:

```go
package identity

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/libp2p/go-libp2p/core/crypto"
)

// LoadOrCreateNodeKey returns the node's persistent libp2p identity key,
// generating an Ed25519 key at path (mode 0600) on first run. The derived
// peer ID is stable across restarts — the prerequisite for being vouched
// for and trusted by other operators (spec §5.1).
func LoadOrCreateNodeKey(path string) (crypto.PrivKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if err := checkKeyPerms(path); err != nil {
			return nil, err
		}
		priv, err := crypto.UnmarshalPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("identity: parse node key %s: %w", path, err)
		}
		return priv, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("identity: read node key %s: %w", path, err)
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return nil, fmt.Errorf("identity: generate node key: %w", err)
	}
	raw, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal node key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("identity: create key dir: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, fmt.Errorf("identity: write node key %s: %w", path, err)
	}
	return priv, nil
}

// checkKeyPerms refuses keys readable by group or others — same posture as SSH.
func checkKeyPerms(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("identity: stat %s: %w", path, err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("identity: %s has mode %v — must not be group/world-accessible, run: chmod 600 %s", path, fi.Mode().Perm(), path)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/identity/`
Expected: PASS (3 tests).

- [ ] **Step 5: Add the config path helper**

In `internal/config/config.go`, add at the end of the file (import `"path/filepath"`):

```go
// NodeKeyFile returns the path of the persistent libp2p node key.
func (c *Config) NodeKeyFile() string {
	return filepath.Join(c.Store.Dir, "identity.key")
}
```

- [ ] **Step 6: Wire into swarmd**

In `cmd/swarmd/main.go`, add to imports: `"github.com/JoeRu/swarmguard/internal/identity"`.

Replace the `t, err := transport.New(...)` block (currently lines 51–57) with:

```go
	priv, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if err != nil {
		log.Fatalf("node identity: %v", err)
	}

	t, err := transport.New(ctx, transport.Options{
		ListenAddrs: []multiaddr.Multiaddr{listenMA},
		Mode:        mode,
		PrivKey:     priv,
	})
	if err != nil {
		log.Fatalf("start transport: %v", err)
	}
```

(`transport.Options.PrivKey` already exists; `buildLibp2pOptions` already consumes it.)

- [ ] **Step 7: Run full test suite and build**

Run: `make build && go test ./...`
Expected: build OK, all tests PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/identity/ internal/config/config.go cmd/swarmd/main.go
git commit -m "feat(identity): persistent node key — stable peer ID across restarts"
```

---

### Task 3: Person identity key, cert issue/verify, fingerprint

**Files:**
- Create: `internal/identity/person.go`
- Create: `internal/identity/cert.go`
- Create: `internal/identity/person_test.go`
- Create: `internal/identity/cert_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/identity/person_test.go`:

```go
package identity_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoeRu/swarmguard/internal/identity"
)

func TestPersonKeyGenerateAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "person.key")

	priv, err := identity.GeneratePersonKey(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	loaded, err := identity.LoadPersonKey(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !priv.Equal(loaded) {
		t.Error("loaded key differs from generated key")
	}
}

func TestPersonKeyGenerateRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "person.key")
	if _, err := identity.GeneratePersonKey(path); err != nil {
		t.Fatalf("first generate: %v", err)
	}
	if _, err := identity.GeneratePersonKey(path); err == nil {
		t.Error("expected error generating over existing key, got nil")
	}
}

func TestPubKeyEncodeDecodeRoundTrip(t *testing.T) {
	priv, err := identity.GeneratePersonKey(filepath.Join(t.TempDir(), "person.key"))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub := identity.PersonPub(priv)
	enc := identity.EncodePub(pub)
	if !strings.HasPrefix(enc, "ed25519:") {
		t.Errorf("encoded pubkey %q lacks ed25519: prefix", enc)
	}
	dec, err := identity.DecodePub(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !pub.Equal(dec) {
		t.Error("decode(encode(pub)) != pub")
	}
}

func TestFingerprintFormat(t *testing.T) {
	priv, err := identity.GeneratePersonKey(filepath.Join(t.TempDir(), "person.key"))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	fp := identity.Fingerprint(identity.PersonPub(priv))
	// 8 bytes hex grouped in 4-char blocks: "ab12 cd34 ef56 7890"
	parts := strings.Split(fp, " ")
	if len(parts) != 4 {
		t.Fatalf("fingerprint %q: want 4 groups, got %d", fp, len(parts))
	}
	for _, p := range parts {
		if len(p) != 4 {
			t.Errorf("fingerprint group %q: want 4 hex chars", p)
		}
	}
}
```

Create `internal/identity/cert_test.go`:

```go
package identity_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/identity"
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/identity/`
Expected: FAIL — `GeneratePersonKey` etc. undefined.

- [ ] **Step 3: Implement person.go**

Create `internal/identity/person.go`:

```go
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// pubKeyPrefix is the textual encoding prefix for Person identity public keys.
const pubKeyPrefix = "ed25519:"

// GeneratePersonKey creates a new Person identity key at path (mode 0600).
// It refuses to overwrite an existing key — a Person identity is long-lived
// and losing it invalidates every cert it ever signed.
func GeneratePersonKey(path string) (ed25519.PrivateKey, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("identity: person key already exists at %s — refusing to overwrite", path)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate person key: %w", err)
	}
	enc := base64.StdEncoding.EncodeToString(priv.Seed())
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("identity: create key dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(enc+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("identity: write person key %s: %w", path, err)
	}
	return priv, nil
}

// LoadPersonKey reads a Person identity key, enforcing private file permissions.
func LoadPersonKey(path string) (ed25519.PrivateKey, error) {
	if err := checkKeyPerms(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: read person key %s: %w", path, err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("identity: parse person key %s: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity: person key %s: bad seed length %d", path, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PersonPub extracts the public key of a Person identity.
func PersonPub(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

// EncodePub renders a Person public key as "ed25519:<base64>".
func EncodePub(pub ed25519.PublicKey) string {
	return pubKeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// DecodePub parses "ed25519:<base64>" into a Person public key.
func DecodePub(s string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(s, pubKeyPrefix) {
		return nil, fmt.Errorf("identity: pubkey %q: missing %q prefix", s, pubKeyPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, pubKeyPrefix))
	if err != nil {
		return nil, fmt.Errorf("identity: pubkey %q: %w", s, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity: pubkey %q: bad length %d", s, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// Fingerprint returns a short human-verifiable form of a Person public key:
// the first 8 bytes of SHA-256(pub) as hex in 4-char groups, e.g. "ab12 cd34 ef56 7890".
// Operators read this aloud over a channel they already trust (spec §5.1).
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	hexs := fmt.Sprintf("%x", sum[:8])
	return strings.Join([]string{hexs[0:4], hexs[4:8], hexs[8:12], hexs[12:16]}, " ")
}
```

- [ ] **Step 4: Implement cert.go**

Create `internal/identity/cert.go`:

```go
package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
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
	if !now.Before(cert.ValidUntil) {
		return fmt.Errorf("identity: cert for %s expired at %s", cert.PeerID, cert.ValidUntil.Format(time.RFC3339))
	}
	msg := certMessage(cert.PeerID, cert.PersonKey, cert.ValidUntil)
	if !ed25519.Verify(ed25519.PublicKey(cert.PersonKey), msg, cert.Sig) {
		return fmt.Errorf("identity: cert for %s: invalid signature", cert.PeerID)
	}
	return nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/identity/`
Expected: PASS (8 tests across both files).

- [ ] **Step 6: Commit**

```bash
git add internal/identity/
git commit -m "feat(identity): Person Ed25519 keys, peer-cert issue/verify, fingerprints"
```

---

### Task 4: `TrustConfig` in `internal/config`

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/config/config_test.go`:

```go
func TestDefaultsTrust(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Trust.AnchorWeight != 0.9 {
		t.Errorf("AnchorWeight = %v, want 0.9", cfg.Trust.AnchorWeight)
	}
	if cfg.Trust.StrangerWeight != 0.3 {
		t.Errorf("StrangerWeight = %v, want 0.3", cfg.Trust.StrangerWeight)
	}
	if cfg.Trust.StrangerScoreCap != 15 {
		t.Errorf("StrangerScoreCap = %v, want 15", cfg.Trust.StrangerScoreCap)
	}
}

func TestTrustPathDefaultsDeriveFromStoreDir(t *testing.T) {
	cfg := config.Defaults()
	cfg.Store.Dir = "/var/lib/swarmguard"
	if got := cfg.TrustAnchorsFile(); got != "/var/lib/swarmguard/anchors.json" {
		t.Errorf("TrustAnchorsFile = %q", got)
	}
	if got := cfg.TrustPersonKeyFile(); got != "/var/lib/swarmguard/person.key" {
		t.Errorf("TrustPersonKeyFile = %q", got)
	}
	if got := cfg.TrustPeerCertFile(); got != "/var/lib/swarmguard/peer.cert" {
		t.Errorf("TrustPeerCertFile = %q", got)
	}
	if got := cfg.TrustCertsFile(); got != "/var/lib/swarmguard/imported-certs.json" {
		t.Errorf("TrustCertsFile = %q", got)
	}
}

func TestTrustPathOverrides(t *testing.T) {
	cfg, err := config.LoadYAML([]byte("trust:\n  anchors_file: /etc/swarmguard/anchors.json\n  stranger_score_cap: 5\n"))
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if got := cfg.TrustAnchorsFile(); got != "/etc/swarmguard/anchors.json" {
		t.Errorf("TrustAnchorsFile override = %q", got)
	}
	if cfg.Trust.StrangerScoreCap != 5 {
		t.Errorf("StrangerScoreCap = %v, want 5", cfg.Trust.StrangerScoreCap)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/`
Expected: FAIL — `cfg.Trust` undefined.

- [ ] **Step 3: Implement**

In `internal/config/config.go`:

Add field to `Config`:

```go
	Trust          TrustConfig      `yaml:"trust"`
```

Add the type after `EnforceConfig`:

```go
// TrustConfig tunes the social trust layer (spec §5.1, design doc
// docs/superpowers/specs/2026-06-12-social-trust-anchors-design.md).
// Every value is operator-overridable (Invariant 1).
type TrustConfig struct {
	AnchorsFile      string  `yaml:"anchors_file"`       // default <store.dir>/anchors.json
	PersonKeyFile    string  `yaml:"person_key_file"`    // default <store.dir>/person.key
	PeerCertFile     string  `yaml:"peer_cert_file"`     // default <store.dir>/peer.cert
	AnchorWeight     float64 `yaml:"anchor_weight"`      // default weight for a newly anchored Person
	StrangerWeight   float64 `yaml:"stranger_weight"`    // trust for un-vouched reporters
	StrangerScoreCap float64 `yaml:"stranger_score_cap"` // max total score strangers add per IP
}
```

In `Defaults()`, add:

```go
		Trust: TrustConfig{
			AnchorWeight:     0.9,
			StrangerWeight:   0.3,
			StrangerScoreCap: 15,
		},
```

Add path helpers next to `NodeKeyFile()`:

```go
// TrustAnchorsFile returns the anchors.json path (config override or store-dir default).
func (c *Config) TrustAnchorsFile() string {
	if c.Trust.AnchorsFile != "" {
		return c.Trust.AnchorsFile
	}
	return filepath.Join(c.Store.Dir, "anchors.json")
}

// TrustPersonKeyFile returns the Person identity key path.
func (c *Config) TrustPersonKeyFile() string {
	if c.Trust.PersonKeyFile != "" {
		return c.Trust.PersonKeyFile
	}
	return filepath.Join(c.Store.Dir, "person.key")
}

// TrustPeerCertFile returns the path of this node's own vouching cert.
func (c *Config) TrustPeerCertFile() string {
	if c.Trust.PeerCertFile != "" {
		return c.Trust.PeerCertFile
	}
	return filepath.Join(c.Store.Dir, "peer.cert")
}

// TrustCertsFile returns the path of the locally imported cert cache
// (seeded by `swarmctl trust import`; internal file, no config key).
func (c *Config) TrustCertsFile() string {
	return filepath.Join(c.Store.Dir, "imported-certs.json")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat(config): trust section — anchor/stranger weights, cap, key paths"
```

---

### Task 5: `ScoreRecord` gains group/stranger fields

**Files:**
- Modify: `internal/store/store.go:12-21`
- Modify: `internal/store/store_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/store/store_test.go`:

```go
func TestScoreRecordTrustFieldsRoundTrip(t *testing.T) {
	s := openTestStore(t)

	rec := store.ScoreRecord{
		Score:           42,
		Groups:          []string{"jo", "alice"},
		StrangerSeen:    true,
		StrangerContrib: 7.5,
		LastSeen:        time.Now(),
	}
	if err := s.PutScore("192.0.2.7", rec, time.Hour); err != nil {
		t.Fatalf("PutScore: %v", err)
	}
	got, err := s.GetScore("192.0.2.7")
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if len(got.Groups) != 2 || got.Groups[0] != "jo" {
		t.Errorf("Groups = %v, want [jo alice]", got.Groups)
	}
	if !got.StrangerSeen {
		t.Error("StrangerSeen lost")
	}
	if got.StrangerContrib != 7.5 {
		t.Errorf("StrangerContrib = %v, want 7.5", got.StrangerContrib)
	}
}
```

(`openTestStore` already exists in `store_test.go`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/`
Expected: FAIL — unknown fields `Groups`, `StrangerSeen`, `StrangerContrib`.

- [ ] **Step 3: Implement**

In `internal/store/store.go`, extend `ScoreRecord`:

```go
// ScoreRecord is the internal on-disk reputation record for one IP.
// ReporterIDs/Groups are tracking metadata never sent on the wire.
type ScoreRecord struct {
	Score           float64   `json:"score"`
	Corroboration   int       `json:"corroboration"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Reasons         []string  `json:"reasons"`
	ReporterIDs     []string  `json:"reporter_ids"`
	Groups          []string  `json:"groups,omitempty"`           // distinct anchored Person names that reported this IP
	StrangerSeen    bool      `json:"stranger_seen,omitempty"`    // at least one un-anchored reporter
	StrangerContrib float64   `json:"stranger_contrib,omitempty"` // cumulative score points added by strangers (capped)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/
git commit -m "feat(store): ScoreRecord tracks Person groups and capped stranger contribution"
```

---

### Task 6: Reputation engine — groups + capped strangers

**Files:**
- Modify: `internal/reputation/engine.go`
- Create: `internal/reputation/engine_test.go`

The `Record` signature changes to `(ip, reason, reporterID string, trust float64, group string, anchored bool)` and `New` gains a `strangerCap` parameter. **This breaks existing callers — they are migrated in Task 7.** In this task, only the engine package itself must compile and pass.

- [ ] **Step 1: Write the failing tests**

Create `internal/reputation/engine_test.go`:

```go
package reputation_test

import (
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
)

func openEngineCap(t *testing.T, cap float64) *reputation.Engine {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return reputation.New(s, 7*24*time.Hour, cap)
}

// TestStrangerContributionCapped: strangers can never add more than the cap,
// no matter how many of them report (spec §4.2 / design "capped strangers").
func TestStrangerContributionCapped(t *testing.T) {
	e := openEngineCap(t, 15)
	var last float64
	for i := 0; i < 100; i++ {
		var err error
		last, err = e.Record("192.0.2.1", "ssh-auth-success", "stranger", 1.0, "", false)
		if err != nil {
			t.Fatalf("Record[%d]: %v", i, err)
		}
	}
	if last > 15.0001 {
		t.Errorf("stranger-driven score = %v, want <= cap 15", last)
	}
}

// TestStrangerAtCapAddsZero: once at the cap, further stranger reports add nothing.
func TestStrangerAtCapAddsZero(t *testing.T) {
	e := openEngineCap(t, 15)
	for i := 0; i < 50; i++ {
		if _, err := e.Record("192.0.2.1", "ssh-auth-success", "s1", 1.0, "", false); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	before, _ := e.GetRecord("192.0.2.1")
	if _, err := e.Record("192.0.2.1", "ssh-auth-success", "s2", 1.0, "", false); err != nil {
		t.Fatalf("Record at cap: %v", err)
	}
	after, _ := e.GetRecord("192.0.2.1")
	if after.Score > before.Score+0.0001 {
		t.Errorf("score grew past cap: %v -> %v", before.Score, after.Score)
	}
}

// TestAnchoredNotCapped: anchored reporters are unaffected by the stranger cap.
func TestAnchoredNotCapped(t *testing.T) {
	e := openEngineCap(t, 15)
	var score float64
	for i := 0; i < 10; i++ {
		var err error
		score, err = e.Record("192.0.2.2", "ssh-auth-success", "joA", 0.9, "jo", true)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if score <= 15 {
		t.Errorf("anchored score = %v, want > stranger cap 15", score)
	}
}

// TestCorroborationCountsGroupsNotPeers: 3 machines of one Person = 1 vote.
func TestCorroborationCountsGroupsNotPeers(t *testing.T) {
	e := openEngineCap(t, 15)
	for _, peerID := range []string{"joA", "joB", "joC"} {
		if _, err := e.Record("192.0.2.3", "ssh-probe", peerID, 0.9, "jo", true); err != nil {
			t.Fatalf("Record %s: %v", peerID, err)
		}
	}
	rec, _ := e.GetRecord("192.0.2.3")
	if rec.Corroboration != 1 {
		t.Errorf("corroboration = %d, want 1 (single Person group)", rec.Corroboration)
	}
	if len(rec.ReporterIDs) != 3 {
		t.Errorf("ReporterIDs = %v, want 3 entries (audit trail)", rec.ReporterIDs)
	}
}

// TestCorroborationStrangersCountOnce: all strangers together are one vote.
func TestCorroborationStrangersCountOnce(t *testing.T) {
	e := openEngineCap(t, 15)
	for _, peerID := range []string{"s1", "s2", "s3"} {
		if _, err := e.Record("192.0.2.4", "ssh-probe", peerID, 0.3, "", false); err != nil {
			t.Fatalf("Record %s: %v", peerID, err)
		}
	}
	if _, err := e.Record("192.0.2.4", "ssh-probe", "joA", 0.9, "jo", true); err != nil {
		t.Fatalf("Record anchored: %v", err)
	}
	rec, _ := e.GetRecord("192.0.2.4")
	if rec.Corroboration != 2 {
		t.Errorf("corroboration = %d, want 2 (1 Person group + 1 stranger bucket)", rec.Corroboration)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/reputation/ -run 'TestStranger|TestAnchored|TestCorroborationCounts|TestCorroborationStrangers' 2>&1 | head -20`
Expected: FAIL (compile error — wrong arity on `New`/`Record`). The pre-existing `corroboration_test.go` will also fail to compile; that is expected until Task 7.

- [ ] **Step 3: Implement**

In `internal/reputation/engine.go`, replace the `Engine` struct, `New`, and `Record`:

```go
// Engine computes IP reputation scores using lazy decay, logistic accumulation,
// Person-group corroboration, and a cumulative cap on stranger contributions
// (spec §4.2/§8; design docs/superpowers/specs/2026-06-12-social-trust-anchors-design.md).
type Engine struct {
	store       *store.BadgerStore
	halfLife    time.Duration
	strangerCap float64
}

// New creates an Engine backed by s. halfLife drives decay; strangerCap is the
// maximum total score un-anchored reporters can add to any single IP.
func New(s *store.BadgerStore, halfLife time.Duration, strangerCap float64) *Engine {
	return &Engine{store: s, halfLife: halfLife, strangerCap: strangerCap}
}

// Record applies one observation to ip's score and returns the new score.
// trust is the reporter's resolved weight (anchor weight, or stranger weight).
// group is the anchored Person's name ("" for strangers); anchored reports
// count as distinct corroboration votes per group, strangers share one capped
// bucket that never exceeds strangerCap score points in total.
func (e *Engine) Record(ip, reason, reporterID string, trust float64, group string, anchored bool) (float64, error) {
	rec, err := e.store.GetScore(ip)
	if err != nil {
		return 0, fmt.Errorf("reputation: get %q: %w", ip, err)
	}

	now := time.Now()

	// Lazy decay: apply time-based decay since last observation.
	if !rec.LastSeen.IsZero() {
		rec.Score = DecayScore(rec.Score, rec.LastSeen, now, e.halfLife)
	}

	// Logistic accumulation: score approaches 100 asymptotically.
	contrib := trust * weightFor(reason) * (1 - rec.Score/100)
	if !anchored {
		remaining := e.strangerCap - rec.StrangerContrib
		if remaining < 0 {
			remaining = 0
		}
		if contrib > remaining {
			contrib = remaining
		}
		rec.StrangerContrib += contrib
		rec.StrangerSeen = true
	}
	rec.Score += contrib
	if rec.Score > 100 {
		rec.Score = 100
	}

	// Corroboration: distinct anchored Person groups + at most one stranger vote.
	if anchored && group != "" && !containsString(rec.Groups, group) {
		rec.Groups = append(rec.Groups, group)
	}
	rec.Corroboration = len(rec.Groups)
	if rec.StrangerSeen {
		rec.Corroboration++
	}

	// Audit trail and metadata.
	if !containsString(rec.ReporterIDs, reporterID) {
		rec.ReporterIDs = append(rec.ReporterIDs, reporterID)
	}
	rec.LastSeen = now
	if rec.FirstSeen.IsZero() {
		rec.FirstSeen = now
	}
	if !containsString(rec.Reasons, reason) {
		rec.Reasons = append(rec.Reasons, reason)
	}

	ttl := 3 * e.halfLife
	if err := e.store.PutScore(ip, rec, ttl); err != nil {
		return 0, fmt.Errorf("reputation: put %q: %w", ip, err)
	}
	return rec.Score, nil
}
```

(`Decay` and `GetRecord` are unchanged.)

- [ ] **Step 4: Run the new tests**

Run: `go test ./internal/reputation/ -run 'TestStranger|TestAnchored|TestCorroborationCounts|TestCorroborationStrangers'`
Expected: still a package compile failure from the old `corroboration_test.go` — verify the *new* logic compiles by `go vet ./internal/reputation/` showing only test-file arity errors. Proceed straight to Task 7 in the same session to restore green.

- [ ] **Step 5: Commit (engine only — repo-wide tests restored next task)**

```bash
git add internal/reputation/engine.go internal/reputation/engine_test.go
git commit -m "feat(reputation): Person-group corroboration and capped stranger contributions"
```

---

### Task 7: Migrate every existing `New`/`Record` caller

**Files:**
- Modify: `internal/reputation/corroboration_test.go`
- Modify: `test/adversarial/sybil_ingest_test.go`
- Modify: `test/adversarial/poisoning_test.go`
- Modify: `test/integration/pipeline_test.go`
- Modify: `test/integration/reputation_store_test.go`

Migration rules:
- `reputation.New(s, <halfLife>)` → `reputation.New(s, <halfLife>, 15)`
- Calls with trust `1.0` (local/ground-truth semantics) → `Record(ip, reason, peerID, 1.0, peerID, true)` — each reporter is its own anchored group, preserving the old per-reporter corroboration numbers.
- The two Sybil tests model *strangers* and get **stronger assertions** (the cap), not just a signature fix.

- [ ] **Step 1: `internal/reputation/corroboration_test.go`**

Line 18: `return reputation.New(s, 7*24*time.Hour)` → `return reputation.New(s, 7*24*time.Hour, 15)`.

All `Record` calls (lines 23, 34, 35, 47, 48, 61): append the reporter as its own group, anchored:

```go
	score, err := e.Record("1.2.3.4", "ssh-probe", "peer1", 1.0, "peer1", true)
```

(and for line 48: `"peer2", 1.0, "peer2", true`; line 61: `"peer1", 1.0, "peer1", true`). Assertions are unchanged — two distinct anchored groups still corroborate to 2.

- [ ] **Step 2: `test/adversarial/sybil_ingest_test.go`**

Lines 25 and 62: `reputation.New(s, 7*24*time.Hour, 15)`.

`TestSybilFloodScoreCapped` (line 30 call + assertions): Sybils are strangers now —

```go
		if _, err := engine.Record(ip, "ssh-probe", peerID, 0.3, "", false); err != nil {
```

Replace the three assertions at the end with the stronger post-§4.2 properties:

```go
	if rec.Score > 15.0001 {
		t.Errorf("stranger flood exceeded cap: got %.4f, want <= 15", rec.Score)
	}
	if rec.Score <= 0 {
		t.Errorf("score should be > 0 after 50 reports, got %.4f", rec.Score)
	}
	if rec.Corroboration != 1 {
		t.Errorf("corroboration: 50 strangers must count as 1 vote, got %d", rec.Corroboration)
	}
```

Update the test's doc comment to say: 50 Sybil strangers are score-capped at the stranger cap and count as a single corroboration vote (spec §4.2, social-trust design).

`TestSybilFloodHighTrustCapped` (line 67 call): even claiming maximum trust, an un-anchored reporter stays capped —

```go
		if _, err := engine.Record(ip, "ssh-auth-success", peerID, 1.0, "", false); err != nil {
```

Replace its end assertions the same way (`Score > 15.0001` errors; corroboration must be 1) and update its comment accordingly.

- [ ] **Step 3: `test/adversarial/poisoning_test.go`**

Lines 53, 96, 132: `reputation.New(s, 7*24*time.Hour, 15)`.
Lines 58, 101, 142 (all trust `1.0` — local ground-truth semantics):

```go
				score, err := engine.Record(ip, "ssh-auth-success", peerID, 1.0, peerID, true)
```

Assertions unchanged (these tests check the never-block list, which is orthogonal).

- [ ] **Step 4: `test/integration/pipeline_test.go`**

Lines 47, 87: `reputation.New(s, 7*24*time.Hour, 15)`; line 132: `reputation.New(s, 500*time.Millisecond, 15)`.
Lines 57, 97, 143:

```go
		score, err := engine.Record(ip, "ssh-auth-success", "peer1", 1.0, "peer1", true)
```

- [ ] **Step 5: `test/integration/reputation_store_test.go`**

Lines 23, 93: `reputation.New(s, 7*24*time.Hour, 15)`; line 58: `reputation.New(s, time.Second, 15)`.
Lines 25, 61, 96, 114 — append `, <reporter>, true` keeping each call's reporter as its group, e.g.:

```go
	if _, err := engine.Record("1.2.3.4", "ssh-auth-bruteforce", "peer1", 1.0, "peer1", true); err != nil {
```

(line 96 uses the loop variable: `..., reporter, 1.0, reporter, true`).

- [ ] **Step 6: Run everything**

Run: `go test ./... && make adversarial`
Expected: all PASS. (`internal/node` still compiles — it is migrated with the trust wiring in Task 10; its current 4-arg `Record` calls will fail compile **now**, so update `internal/node/node.go` lines 136 and 157 minimally in this task to keep the tree green:)

Line 136: `score, err := n.rep.Record(e.IP, e.Reason, n.selfID, 1.0, n.selfID, true)`
Line 157: `score, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, 0.3, "", false)`
Line 42: `eng := reputation.New(s, halfLife, cfg.Trust.StrangerScoreCap)`

- [ ] **Step 7: Commit**

```bash
git add internal/reputation/ internal/node/node.go test/
git commit -m "refactor(reputation): migrate all Record callers to group-aware signature"
```

---

### Task 8: `internal/trust` — anchors, cert cache, `Resolve`, hot reload

**Files:**
- Create: `internal/trust/anchors.go`
- Create: `internal/trust/certs.go`
- Create: `internal/trust/store.go`
- Create: `internal/trust/bundle.go`
- Create: `internal/trust/store_test.go`
- Delete content duplication: keep existing `internal/trust/doc.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/trust/store_test.go`:

```go
package trust_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/trust"
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
	st = trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "imported-certs.json"), 0.3)
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
	st := trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "certs.json"), 0.3)
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
	st := trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "certs.json"), 0.3)
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
	st := trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "certs.json"), 0.3)
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
	st := trust.NewStore(filepath.Join(dir, "anchors.json"), filepath.Join(dir, "certs.json"), 0.3)
	st.SetReloadInterval(0)
	if _, _, anchored := st.Resolve("12D3KooWanyone"); anchored {
		t.Error("missing anchors file must mean no anchors")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/trust/`
Expected: FAIL — types undefined.

- [ ] **Step 3: Implement anchors.go**

Create `internal/trust/anchors.go`:

```go
package trust

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Anchor is one trusted Person identity — an entry of anchors.json
// (spec §5.1/§7.3, source is always "self-added" in this phase).
// The Person is the corroboration unit: every peer they certify
// inherits Weight and counts toward the same group.
type Anchor struct {
	Person         string    `json:"person"`          // local short name, chosen by THIS operator
	Label          string    `json:"label"`           // free-text description
	IdentityPubkey string    `json:"identity_pubkey"` // "ed25519:<base64>"
	Weight         float64   `json:"weight"`          // trust weight in (0,1]
	ValidUntil     time.Time `json:"valid_until"`     // zero = no expiry
	Source         string    `json:"source"`          // "self-added"
}

// Expired reports whether the anchor itself has lapsed.
func (a Anchor) Expired(now time.Time) bool {
	return !a.ValidUntil.IsZero() && now.After(a.ValidUntil)
}

// LoadAnchors reads anchors from path. A missing file is an empty list, not an error.
func LoadAnchors(path string) ([]Anchor, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", path, err)
	}
	var anchors []Anchor
	if err := json.Unmarshal(data, &anchors); err != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", path, err)
	}
	return anchors, nil
}

// SaveAnchors writes anchors atomically (temp file + rename) so a concurrently
// reading swarmd never sees a half-written file.
func SaveAnchors(path string, anchors []Anchor) error {
	data, err := json.MarshalIndent(anchors, "", "  ")
	if err != nil {
		return fmt.Errorf("trust: marshal anchors: %w", err)
	}
	return atomicWrite(path, data)
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("trust: create dir for %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("trust: temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("trust: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("trust: close temp: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("trust: rename into %s: %w", path, err)
	}
	return nil
}
```

- [ ] **Step 4: Implement certs.go**

Create `internal/trust/certs.go`:

```go
package trust

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/JoeRu/swarmguard/pkg/proto"
)

// LoadCerts reads locally imported peer-certs (seeded by `swarmctl trust import`).
// Missing file = empty list.
func LoadCerts(path string) ([]proto.PeerCert, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", path, err)
	}
	var certs []proto.PeerCert
	if err := json.Unmarshal(data, &certs); err != nil {
		return nil, fmt.Errorf("trust: parse %s: %w", path, err)
	}
	return certs, nil
}

// SaveCerts writes the imported-cert list atomically.
func SaveCerts(path string, certs []proto.PeerCert) error {
	data, err := json.MarshalIndent(certs, "", "  ")
	if err != nil {
		return fmt.Errorf("trust: marshal certs: %w", err)
	}
	return atomicWrite(path, data)
}
```

- [ ] **Step 5: Implement store.go**

Create `internal/trust/store.go`:

```go
package trust

import (
	"log"
	"os"
	"sync"
	"time"

	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// Store answers "how much do I trust this peer?" by combining the anchored
// Person identities (anchors.json, hot-reloaded) with a cache of verified
// peer-certs (on-wire vouches + locally imported certs).
type Store struct {
	anchorsPath    string
	certsPath      string
	strangerWeight float64
	reloadEvery    time.Duration

	mu            sync.RWMutex
	anchors       map[string]Anchor         // keyed by IdentityPubkey
	certs         map[string]proto.PeerCert // peerID → verified cert
	lastCheck     time.Time
	anchorsMtime  time.Time
	certsMtime    time.Time
	loadedOnce    bool
}

// NewStore creates a Store reading anchorsPath and certsPath. strangerWeight
// is returned for any peer without a valid, anchored vouch.
func NewStore(anchorsPath, certsPath string, strangerWeight float64) *Store {
	return &Store{
		anchorsPath:    anchorsPath,
		certsPath:      certsPath,
		strangerWeight: strangerWeight,
		reloadEvery:    10 * time.Second,
		anchors:        map[string]Anchor{},
		certs:          map[string]proto.PeerCert{},
	}
}

// SetReloadInterval overrides the file re-check interval (tests use 0).
func (s *Store) SetReloadInterval(d time.Duration) { s.reloadEvery = d }

// AddCert cryptographically verifies cert and caches it (on-wire vouch path).
// Anchoring of the Person key is checked later, in Resolve.
func (s *Store) AddCert(cert proto.PeerCert, now time.Time) error {
	if err := identity.VerifyCert(cert, now); err != nil {
		return err
	}
	s.mu.Lock()
	s.certs[cert.PeerID] = cert
	s.mu.Unlock()
	return nil
}

// Resolve returns the trust weight, the corroboration group (the Person name),
// and whether peerID is currently vouched by an anchored, non-expired Person.
func (s *Store) Resolve(peerID string) (weight float64, group string, anchored bool) {
	now := time.Now()
	s.maybeReload(now)

	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, ok := s.certs[peerID]
	if !ok || now.After(cert.ValidUntil) {
		return s.strangerWeight, "", false
	}
	a, ok := s.anchors[identity.EncodePub(cert.PersonKey)]
	if !ok || a.Expired(now) {
		return s.strangerWeight, "", false
	}
	return a.Weight, a.Person, true
}

// maybeReload re-reads anchors.json and imported certs when their mtime moved.
// On a parse error after a successful load it keeps the last good state —
// the failure direction is "less trust", never "no trust we used to have".
func (s *Store) maybeReload(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loadedOnce && now.Sub(s.lastCheck) < s.reloadEvery {
		return
	}
	s.lastCheck = now

	if mt, changed := mtimeChanged(s.anchorsPath, s.anchorsMtime); changed || !s.loadedOnce {
		anchors, err := LoadAnchors(s.anchorsPath)
		switch {
		case err != nil && s.loadedOnce:
			log.Printf("trust: reload %s failed, keeping last good anchors: %v", s.anchorsPath, err)
		case err != nil:
			log.Printf("trust: WARNING — cannot load %s, starting with NO anchors: %v", s.anchorsPath, err)
			s.anchors = map[string]Anchor{}
		default:
			m := make(map[string]Anchor, len(anchors))
			for _, a := range anchors {
				m[a.IdentityPubkey] = a
			}
			s.anchors = m
			s.anchorsMtime = mt
		}
	}

	if mt, changed := mtimeChanged(s.certsPath, s.certsMtime); changed || !s.loadedOnce {
		certs, err := LoadCerts(s.certsPath)
		if err != nil {
			log.Printf("trust: reload %s failed, keeping cached certs: %v", s.certsPath, err)
		} else {
			for _, c := range certs {
				if verr := identity.VerifyCert(c, now); verr == nil {
					s.certs[c.PeerID] = c
				}
			}
			s.certsMtime = mt
		}
	}

	s.loadedOnce = true
}

// mtimeChanged stats path and reports whether its mtime differs from prev.
// A missing file reports changed=true with zero time so removals are noticed.
func mtimeChanged(path string, prev time.Time) (time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, true // missing file: always re-evaluate so removals are noticed
	}
	return fi.ModTime(), !fi.ModTime().Equal(prev)
}
```

- [ ] **Step 6: Implement bundle.go**

Create `internal/trust/bundle.go`:

```go
package trust

import (
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// Bundle is the offline exchange format produced by `swarmctl trust export`
// and consumed by `swarmctl trust import`: a Person's public identity plus
// every peer-cert they have issued. The importer chooses the local Person
// name; Label is the exporter's suggestion.
type Bundle struct {
	Person         string           `json:"person"`
	Label          string           `json:"label"`
	IdentityPubkey string           `json:"identity_pubkey"`
	Certs          []proto.PeerCert `json:"certs"`
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/trust/`
Expected: PASS (10 tests).

- [ ] **Step 8: Commit**

```bash
git add internal/trust/
git commit -m "feat(trust): anchor store with hot reload, verified cert cache, Resolve()"
```

---

### Task 9: Transport — surface the verified publisher

**Files:**
- Modify: `internal/transport/gossip.go`
- Modify: `internal/transport/gossip_test.go:62-64`
- Modify: `test/integration/cluster_test.go:72-74,101-103`

gossipsub signs messages by default; `msg.GetFrom()` is the signature-verified original publisher (not the forwarding hop, which is `msg.ReceivedFrom`).

- [ ] **Step 1: Write the failing test**

Append to `internal/transport/gossip_test.go`:

```go
// TestSubscribeSurfacesVerifiedPublisher proves the receiver learns the
// gossipsub-verified origin peer ID, which the node layer compares against
// Event.ReporterID to kill spoofing.
func TestSubscribeSurfacesVerifiedPublisher(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeA, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create nodeA: %v", err)
	}
	defer nodeA.Close()
	nodeB, err := transport.New(ctx, testOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("create nodeB: %v", err)
	}
	defer nodeB.Close()

	connect(t, nodeA, nodeB)
	time.Sleep(500 * time.Millisecond)

	if err := nodeA.Publish(ctx, proto.Event{IP: "192.0.2.9", Reason: "test"}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case got := <-nodeB.Subscribe():
		if got.From != nodeA.Host().ID().String() {
			t.Errorf("From = %q, want publisher %q", got.From, nodeA.Host().ID())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event within 3s")
	}
}
```

- [ ] **Step 2: Run tests to verify the compile failure**

Run: `go test ./internal/transport/`
Expected: FAIL — `got.From` undefined (Subscribe still returns `proto.Event`).

- [ ] **Step 3: Implement**

In `internal/transport/gossip.go`:

Add after the imports:

```go
// ReceivedEvent pairs a decoded Event with the gossipsub-verified original
// publisher. From is authenticated by libp2p message signing — the node layer
// rejects events whose ReporterID does not match it (spec §5.1 spoof guard).
type ReceivedEvent struct {
	Event proto.Event
	From  string
}
```

Change the `events` field and channel:

```go
	events   chan ReceivedEvent
```

and in `New`: `events: make(chan ReceivedEvent, 64),`

Change `Subscribe`:

```go
// Subscribe returns a channel that delivers decoded events from the network
// together with their verified publisher. Closed when the Node is closed.
func (n *Node) Subscribe() <-chan ReceivedEvent { return n.events }
```

Replace `readLoop`:

```go
func (n *Node) readLoop(ctx context.Context) {
	defer close(n.events)
	for {
		msg, err := n.sub.Next(ctx)
		if err != nil {
			return
		}
		// skip messages we published ourselves (GetFrom = verified original publisher)
		if msg.GetFrom() == n.host.ID() {
			continue
		}
		var e proto.Event
		if err := json.Unmarshal(msg.Data, &e); err != nil {
			continue
		}
		select {
		case n.events <- ReceivedEvent{Event: e, From: msg.GetFrom().String()}:
		case <-ctx.Done():
			return
		}
	}
}
```

- [ ] **Step 4: Fix the two existing consumers**

`internal/transport/gossip_test.go` `TestTwoNodeGossip` (lines 62–64):

```go
	case got := <-nodeB.Subscribe():
		if got.Event.IP != want.IP || got.Event.Reason != want.Reason {
			t.Fatalf("got %+v, want %+v", got.Event, want)
		}
```

`test/integration/cluster_test.go` — both receive loops (lines 72–74 and 101–103):

```go
		case got := <-r.Subscribe():
			if got.Event.IP != want.IP {
				t.Errorf("receiver %d: got IP %q, want %q", i, got.Event.IP, want.IP)
			}
```

`internal/node/node.go` Run loop — the remote case becomes (full compile fix lands in Task 10, but make it build now):

```go
	var remoteCh <-chan transport.ReceivedEvent
	if n.transport != nil {
		remoteCh = n.transport.Subscribe()
	}
```

and in the select:

```go
		case re, ok := <-remoteCh:
			if !ok {
				remoteCh = nil
				continue
			}
			n.ProcessRemote(re)
```

with a temporary bridge replacing the old `processRemote` (full version next task):

```go
// ProcessRemote scores one event received from the swarm. Exported so the
// adversarial suite can drive the remote path directly.
func (n *Node) ProcessRemote(re transport.ReceivedEvent) {
	e := re.Event
	if n.neverblock.Contains(e.IP) {
		return
	}
	score, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, 0.3, "", false)
	if err != nil {
		log.Printf("node: record remote %s: %v", e.IP, err)
		return
	}
	if score >= n.cfg.Reputation.BlockThreshold {
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		}
	}
}
```

(delete the old `processRemote`).

- [ ] **Step 5: Run everything**

Run: `go test ./... && make adversarial`
Expected: all PASS, including the new publisher test.

- [ ] **Step 6: Commit**

```bash
git add internal/transport/ internal/node/node.go test/integration/cluster_test.go
git commit -m "feat(transport): deliver gossipsub-verified publisher with each event"
```

---

### Task 10: Node — trust wiring, vouch attach/verify, spoof drop

**Files:**
- Modify: `internal/node/node.go`
- Create: `internal/node/node_test.go` (package `node` — internal test, builds Node directly)

- [ ] **Step 1: Write the failing tests**

Create `internal/node/node_test.go`:

```go
package node

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/enforce"
	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/reputation"
	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/internal/transport"
	"github.com/JoeRu/swarmguard/internal/trust"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// testNode builds a Node with a temp store, no transport, and a permissive
// block threshold so the enforce sink is never invoked.
func testNode(t *testing.T) (*Node, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.BlockThreshold = 1000

	s, err := store.Open(dir + "/db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ts := trust.NewStore(cfg.TrustAnchorsFile(), cfg.TrustCertsFile(), cfg.Trust.StrangerWeight)
	ts.SetReloadInterval(0)

	return &Node{
		cfg:        cfg,
		store:      s,
		rep:        reputation.New(s, 7*24*time.Hour, cfg.Trust.StrangerScoreCap),
		neverblock: enforce.NewNeverBlockList(nil),
		trust:      ts,
		selfID:     "12D3KooWself",
	}, dir
}

// TestSpoofedReporterDropped: ReporterID != verified publisher → event ignored.
func TestSpoofedReporterDropped(t *testing.T) {
	n, _ := testNode(t)
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "192.0.2.10", Reason: "ssh-probe", ReporterID: "12D3KooWvictim"},
		From:  "12D3KooWattacker",
	})
	rec, err := n.rep.GetRecord("192.0.2.10")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if !rec.LastSeen.IsZero() {
		t.Error("spoofed event reached the reputation engine")
	}
}

// TestVouchedReporterScoresAsAnchored: a valid on-wire vouch from an anchored
// Person resolves to the anchor weight and group.
func TestVouchedReporterScoresAsAnchored(t *testing.T) {
	n, dir := testNode(t)

	priv, err := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	if err != nil {
		t.Fatalf("person key: %v", err)
	}
	if err := trust.SaveAnchors(n.cfg.TrustAnchorsFile(), []trust.Anchor{{
		Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "self-added",
	}}); err != nil {
		t.Fatalf("save anchors: %v", err)
	}

	cert := identity.IssueCert(priv, "12D3KooWjoA", time.Now().Add(time.Hour))
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "192.0.2.11", Reason: "ssh-probe", ReporterID: "12D3KooWjoA", Vouch: &cert},
		From:  "12D3KooWjoA",
	})

	rec, _ := n.rep.GetRecord("192.0.2.11")
	if len(rec.Groups) != 1 || rec.Groups[0] != "jo" {
		t.Errorf("Groups = %v, want [jo]", rec.Groups)
	}
	if rec.StrangerSeen {
		t.Error("vouched reporter recorded as stranger")
	}
}

// TestVouchReplayedCertIsStranger: a cert for peer A attached by peer B is
// rejected — B stays a stranger.
func TestVouchReplayedCertIsStranger(t *testing.T) {
	n, dir := testNode(t)

	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	_ = trust.SaveAnchors(n.cfg.TrustAnchorsFile(), []trust.Anchor{{
		Person: "jo", IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Weight: 0.9, Source: "self-added",
	}})

	certForA := identity.IssueCert(priv, "12D3KooWjoA", time.Now().Add(time.Hour))
	n.ProcessRemote(transport.ReceivedEvent{
		Event: proto.Event{IP: "192.0.2.12", Reason: "ssh-probe", ReporterID: "12D3KooWeve", Vouch: &certForA},
		From:  "12D3KooWeve",
	})

	rec, _ := n.rep.GetRecord("192.0.2.12")
	if len(rec.Groups) != 0 {
		t.Errorf("replayed cert produced anchored groups: %v", rec.Groups)
	}
	if !rec.StrangerSeen {
		t.Error("event was dropped entirely; replayed-cert events should score as stranger")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/node/`
Expected: FAIL — `Node` has no `trust` field; vouch path missing (replay test fails: groups appear or stranger path differs).

- [ ] **Step 3: Implement**

In `internal/node/node.go`:

Add imports: `"os"`, `"encoding/json"`, `"time"` (already there), `"github.com/JoeRu/swarmguard/internal/identity"`, `"github.com/JoeRu/swarmguard/internal/trust"`.

Add fields to `Node`:

```go
	trust      *trust.Store
	vouch      *proto.PeerCert // this node's own peer-cert, attached to published events
```

In `New`, after `nbl := ...` and the `selfID` block, add:

```go
	ts := trust.NewStore(cfg.TrustAnchorsFile(), cfg.TrustCertsFile(), cfg.Trust.StrangerWeight)

	var vouch *proto.PeerCert
	if data, err := os.ReadFile(cfg.TrustPeerCertFile()); err == nil {
		var cert proto.PeerCert
		if jerr := json.Unmarshal(data, &cert); jerr != nil {
			log.Printf("node: ignoring malformed peer cert %s: %v", cfg.TrustPeerCertFile(), jerr)
		} else if verr := identity.VerifyCert(cert, time.Now()); verr != nil {
			log.Printf("node: ignoring invalid peer cert %s: %v", cfg.TrustPeerCertFile(), verr)
		} else if selfID != "" && cert.PeerID != selfID {
			log.Printf("node: peer cert %s is for %s, not this node (%s) — ignoring", cfg.TrustPeerCertFile(), cert.PeerID, selfID)
		} else {
			vouch = &cert
		}
	}
```

and include both in the returned struct: `trust: ts, vouch: vouch,`.

In `processLocal`, attach the vouch before publishing:

```go
	e.ReporterID = n.selfID
	e.Vouch = n.vouch
```

Replace the Task-9 bridge `ProcessRemote` with the full version:

```go
// ProcessRemote scores one event received from the swarm: it drops spoofed
// reporters, verifies any attached vouch, resolves the reporter's trust, and
// records the observation. Exported so the adversarial suite can drive the
// remote path directly.
func (n *Node) ProcessRemote(re transport.ReceivedEvent) {
	e := re.Event
	if e.ReporterID != re.From {
		log.Printf("node: drop spoofed event: reporter %q != verified publisher %q", e.ReporterID, re.From)
		return
	}
	if n.neverblock.Contains(e.IP) {
		return
	}

	if e.Vouch != nil {
		switch {
		case e.Vouch.PeerID != e.ReporterID:
			log.Printf("node: vouch for %q attached by %q — ignoring cert", e.Vouch.PeerID, e.ReporterID)
		default:
			if err := n.trust.AddCert(*e.Vouch, time.Now()); err != nil {
				log.Printf("node: invalid vouch from %q: %v", e.ReporterID, err)
			}
		}
	}

	weight, group, anchored := n.trust.Resolve(e.ReporterID)
	score, err := n.rep.Record(e.IP, e.Reason, e.ReporterID, weight, group, anchored)
	if err != nil {
		log.Printf("node: record remote %s: %v", e.IP, err)
		return
	}
	if score >= n.cfg.Reputation.BlockThreshold {
		if err := n.sink.Block(e.IP); err != nil {
			log.Printf("node: block %s: %v", e.IP, err)
		}
	}
}
```

In `processLocal`, the `Record` call stays `(e.IP, e.Reason, n.selfID, 1.0, n.selfID, true)` — the node is its own anchored group.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/node/ && go test ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/node/
git commit -m "feat(node): verify vouches, resolve trust, drop spoofed reporters"
```

---

### Task 11: swarmctl — dispatch, `identity`, `peer-cert`

**Files:**
- Modify: `cmd/swarmctl/main.go`
- Create: `cmd/swarmctl/common.go`
- Create: `cmd/swarmctl/identity.go`

swarmctl is exercised by `go build` + manual smoke commands (CLI glue over already-tested packages; per-package unit tests cover the logic).

- [ ] **Step 1: Replace `cmd/swarmctl/main.go`**

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

Usage:
  swarmctl identity                      print this node's peer ID
  swarmctl identity init --label NAME    create a Person identity + self peer-cert
  swarmctl identity show                 print Person pubkey + fingerprint
  swarmctl peer-cert PEER_ID             sign a peer-cert for another machine
  swarmctl trust add PERSON --identity ed25519:...   anchor a Person
  swarmctl trust set PERSON [--weight W] [--label L]
  swarmctl trust remove PERSON
  swarmctl trust list
  swarmctl trust export                  write this Person's bundle to stdout
  swarmctl trust import FILE [--as NAME] [--weight W]

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

- [ ] **Step 2: Create `cmd/swarmctl/common.go`**

```go
package main

import (
	"flag"

	"github.com/JoeRu/swarmguard/internal/config"
)

// addConfigFlag registers -config on fs and returns a loader that resolves
// the effective Config (defaults when no file is given — same as swarmd).
func addConfigFlag(fs *flag.FlagSet) func() (*config.Config, error) {
	path := fs.String("config", "", "path to YAML config file")
	return func() (*config.Config, error) {
		if *path == "" {
			return config.Defaults(), nil
		}
		return config.Load(*path)
	}
}
```

- [ ] **Step 3: Create `cmd/swarmctl/identity.go`**

```go
package main

import (
	"crypto/ed25519"
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

// labelPath stores the operator-chosen label next to the person key.
func labelPath(personKeyFile string) string { return personKeyFile + ".label" }

// issuedCertsPath stores every cert this Person has signed (for trust export).
func issuedCertsPath(personKeyFile string) string { return personKeyFile + ".issued.json" }

func cmdIdentity(args []string) error {
	if len(args) > 0 && args[0] == "init" {
		return identityInit(args[1:])
	}
	if len(args) > 0 && args[0] == "show" {
		return identityShow(args[1:])
	}

	fs := flag.NewFlagSet("identity", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	priv, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if err != nil {
		return err
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return err
	}
	fmt.Println(pid)
	return nil
}

func identityInit(args []string) error {
	fs := flag.NewFlagSet("identity init", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	label := fs.String("label", "", "human label for this Person identity (e.g. your name)")
	validFor := fs.Duration("valid-for", 365*24*time.Hour, "validity of the self peer-cert")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}

	priv, err := identity.GeneratePersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		return err
	}
	if *label != "" {
		if err := os.WriteFile(labelPath(cfg.TrustPersonKeyFile()), []byte(*label+"\n"), 0o644); err != nil {
			return fmt.Errorf("write label: %w", err)
		}
	}

	pub := identity.PersonPub(priv)
	fmt.Println("person identity created:", cfg.TrustPersonKeyFile())
	fmt.Println("public key: ", identity.EncodePub(pub))
	fmt.Println("fingerprint:", identity.Fingerprint(pub))

	// If this machine already has a node key, self-certify it so the local
	// swarmd publishes vouched events immediately.
	nodePriv, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if err != nil {
		fmt.Println("note: no node key yet — run `swarmctl peer-cert` after swarmd first start")
		return nil
	}
	pid, err := peer.IDFromPrivateKey(nodePriv)
	if err != nil {
		return err
	}
	cert := identity.IssueCert(priv, pid.String(), time.Now().Add(*validFor))
	if err := writeCert(cfg.TrustPeerCertFile(), cert); err != nil {
		return err
	}
	if err := appendIssuedCert(issuedCertsPath(cfg.TrustPersonKeyFile()), cert); err != nil {
		return err
	}
	fmt.Println("self peer-cert installed:", cfg.TrustPeerCertFile(), "(peer", pid.String()+")")
	return nil
}

func identityShow(args []string) error {
	fs := flag.NewFlagSet("identity show", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	priv, err := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		return err
	}
	pub := identity.PersonPub(priv)
	if data, err := os.ReadFile(labelPath(cfg.TrustPersonKeyFile())); err == nil {
		fmt.Printf("label:       %s", data)
	}
	fmt.Println("public key: ", identity.EncodePub(pub))
	fmt.Println("fingerprint:", identity.Fingerprint(pub))
	return nil
}

func cmdPeerCert(args []string) error {
	fs := flag.NewFlagSet("peer-cert", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	validFor := fs.Duration("valid-for", 365*24*time.Hour, "cert validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl peer-cert PEER_ID")
	}
	peerID := fs.Arg(0)
	if _, err := peer.Decode(peerID); err != nil {
		return fmt.Errorf("invalid peer ID %q: %w", peerID, err)
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	priv, err := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		return err
	}
	cert := identity.IssueCert(priv, peerID, time.Now().Add(*validFor))
	if err := appendIssuedCert(issuedCertsPath(cfg.TrustPersonKeyFile()), cert); err != nil {
		return err
	}
	out, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	fmt.Fprintln(os.Stderr, "→ save this JSON as peer.cert in the target node's store dir")
	return nil
}

func writeCert(path string, cert proto.PeerCert) error {
	data, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func appendIssuedCert(path string, cert proto.PeerCert) error {
	certs, err := trust.LoadCerts(path)
	if err != nil {
		return err
	}
	for i, c := range certs {
		if c.PeerID == cert.PeerID {
			certs[i] = cert
			return trust.SaveCerts(path, certs)
		}
	}
	return trust.SaveCerts(path, append(certs, cert))
}

// personPubMust loads the Person public key for self-anchor detection in trust.go.
func personPubMust(personKeyFile string) ed25519.PublicKey {
	priv, err := identity.LoadPersonKey(personKeyFile)
	if err != nil {
		return nil
	}
	return identity.PersonPub(priv)
}
```

- [ ] **Step 4: Add a temporary stub so the package builds before Task 12**

Create `cmd/swarmctl/trust.go` with just:

```go
package main

import "fmt"

func cmdTrust(args []string) error {
	return fmt.Errorf("trust commands land in the next commit")
}
```

- [ ] **Step 5: Build and smoke-test**

```bash
make build
./bin/swarmctl identity -config /dev/null 2>/dev/null || true
TMP=$(mktemp -d) && ./bin/swarmctl identity init -label "Test Op" -config <(printf 'store:\n  dir: %s\n' "$TMP")
```

Expected: `identity init` prints a pubkey + 4-group fingerprint and "self peer-cert installed" (the node key is auto-created in `$TMP`). If process substitution misbehaves under zsh, write the config to a temp file instead.

- [ ] **Step 6: Commit**

```bash
git add cmd/swarmctl/
git commit -m "feat(swarmctl): identity init/show and peer-cert signing commands"
```

---

### Task 12: swarmctl — trust add/set/remove/list/export/import

**Files:**
- Modify: `cmd/swarmctl/trust.go` (replace stub)

- [ ] **Step 1: Implement**

Replace `cmd/swarmctl/trust.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/trust"
)

func cmdTrust(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: swarmctl trust add|set|remove|list|export|import ...")
	}
	switch args[0] {
	case "add":
		return trustAdd(args[1:])
	case "set":
		return trustSet(args[1:])
	case "remove":
		return trustRemove(args[1:])
	case "list":
		return trustList(args[1:])
	case "export":
		return trustExport(args[1:])
	case "import":
		return trustImport(args[1:])
	default:
		return fmt.Errorf("unknown trust subcommand %q", args[0])
	}
}

func trustAdd(args []string) error {
	fs := flag.NewFlagSet("trust add", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	idStr := fs.String("identity", "", "Person public key (ed25519:...)")
	weight := fs.Float64("weight", 0, "trust weight in (0,1] (default: config anchor_weight)")
	label := fs.String("label", "", "free-text label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl trust add PERSON --identity ed25519:...")
	}
	person := fs.Arg(0)
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	if *weight == 0 {
		*weight = cfg.Trust.AnchorWeight
	}
	if *weight <= 0 || *weight > 1 {
		return fmt.Errorf("weight %v out of range (0,1]", *weight)
	}
	pub, err := identity.DecodePub(*idStr)
	if err != nil {
		return err
	}
	if own := personPubMust(cfg.TrustPersonKeyFile()); own != nil && bytes.Equal(own, pub) {
		fmt.Println("that is your own identity — local events already run at trust 1.0; nothing to do")
		return nil
	}
	return upsertAnchor(cfg, trust.Anchor{
		Person:         person,
		Label:          *label,
		IdentityPubkey: identity.EncodePub(pub),
		Weight:         *weight,
		Source:         "self-added",
	})
}

func trustSet(args []string) error {
	fs := flag.NewFlagSet("trust set", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	weight := fs.Float64("weight", -1, "new trust weight in (0,1]")
	label := fs.String("label", "", "new label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl trust set PERSON [--weight W] [--label L]")
	}
	person := fs.Arg(0)
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	anchors, err := trust.LoadAnchors(cfg.TrustAnchorsFile())
	if err != nil {
		return err
	}
	for i := range anchors {
		if anchors[i].Person == person {
			if *weight >= 0 {
				if *weight <= 0 || *weight > 1 {
					return fmt.Errorf("weight %v out of range (0,1]", *weight)
				}
				anchors[i].Weight = *weight
			}
			if *label != "" {
				anchors[i].Label = *label
			}
			if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), anchors); err != nil {
				return err
			}
			fmt.Printf("updated %s (weight %.2f)\n", person, anchors[i].Weight)
			return nil
		}
	}
	return fmt.Errorf("no anchored person %q — see `swarmctl trust list`", person)
}

func trustRemove(args []string) error {
	fs := flag.NewFlagSet("trust remove", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl trust remove PERSON")
	}
	person := fs.Arg(0)
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	anchors, err := trust.LoadAnchors(cfg.TrustAnchorsFile())
	if err != nil {
		return err
	}
	kept := anchors[:0]
	removed := false
	for _, a := range anchors {
		if a.Person == person {
			removed = true
			continue
		}
		kept = append(kept, a)
	}
	if !removed {
		return fmt.Errorf("no anchored person %q", person)
	}
	if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), kept); err != nil {
		return err
	}
	fmt.Printf("removed %s — all their machines now score as strangers (takes effect within 10s)\n", person)
	return nil
}

func trustList(args []string) error {
	fs := flag.NewFlagSet("trust list", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	anchors, err := trust.LoadAnchors(cfg.TrustAnchorsFile())
	if err != nil {
		return err
	}
	if len(anchors) == 0 {
		fmt.Println("no anchored persons — see `swarmctl trust add`")
		return nil
	}
	fmt.Printf("%-12s %-7s %-8s %-22s %s\n", "PERSON", "WEIGHT", "STATUS", "FINGERPRINT", "LABEL")
	for _, a := range anchors {
		status := "ok"
		if a.Expired(time.Now()) {
			status = "EXPIRED"
		}
		fp := "?"
		if pub, err := identity.DecodePub(a.IdentityPubkey); err == nil {
			fp = identity.Fingerprint(pub)
		}
		fmt.Printf("%-12s %-7.2f %-8s %-22s %s\n", a.Person, a.Weight, status, fp, a.Label)
	}
	return nil
}

func trustExport(args []string) error {
	fs := flag.NewFlagSet("trust export", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	priv, err := identity.LoadPersonKey(cfg.TrustPersonKeyFile())
	if err != nil {
		return fmt.Errorf("no person identity — run `swarmctl identity init` first: %w", err)
	}
	label := ""
	if data, err := os.ReadFile(labelPath(cfg.TrustPersonKeyFile())); err == nil {
		label = string(bytes.TrimSpace(data))
	}
	certs, err := trust.LoadCerts(issuedCertsPath(cfg.TrustPersonKeyFile()))
	if err != nil {
		return err
	}
	b := trust.Bundle{
		Person:         label,
		Label:          label,
		IdentityPubkey: identity.EncodePub(identity.PersonPub(priv)),
		Certs:          certs,
	}
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func trustImport(args []string) error {
	fs := flag.NewFlagSet("trust import", flag.ExitOnError)
	loadCfg := addConfigFlag(fs)
	as := fs.String("as", "", "local person name (default: bundle's label)")
	weight := fs.Float64("weight", 0, "trust weight (default: config anchor_weight)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: swarmctl trust import FILE [--as NAME] [--weight W]")
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var b trust.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}
	pub, err := identity.DecodePub(b.IdentityPubkey)
	if err != nil {
		return err
	}

	person := *as
	if person == "" {
		person = b.Person
	}
	if person == "" {
		return fmt.Errorf("bundle has no person name — pass --as NAME")
	}
	w := *weight
	if w == 0 {
		w = cfg.Trust.AnchorWeight
	}
	if w <= 0 || w > 1 {
		return fmt.Errorf("weight %v out of range (0,1]", w)
	}

	fmt.Println("identity:   ", b.IdentityPubkey)
	fmt.Println("fingerprint:", identity.Fingerprint(pub))
	fmt.Println("→ verify this fingerprint with", person, "over a channel you already trust")

	// Verify and merge the bundled certs into the local imported-cert cache.
	existing, err := trust.LoadCerts(cfg.TrustCertsFile())
	if err != nil {
		return err
	}
	byPeer := map[string]int{}
	for i, c := range existing {
		byPeer[c.PeerID] = i
	}
	imported := 0
	for _, c := range b.Certs {
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
		Label:          b.Label,
		IdentityPubkey: b.IdentityPubkey,
		Weight:         w,
		Source:         "self-added",
	}); err != nil {
		return err
	}
	fmt.Printf("imported %d cert(s)\n", imported)
	return nil
}

func upsertAnchor(cfg *config.Config, a trust.Anchor) error {
	anchors, err := trust.LoadAnchors(cfg.TrustAnchorsFile())
	if err != nil {
		return err
	}
	for i := range anchors {
		if anchors[i].Person == a.Person {
			anchors[i] = a
			if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), anchors); err != nil {
				return err
			}
			fmt.Printf("updated anchor %s (weight %.2f)\n", a.Person, a.Weight)
			return nil
		}
	}
	if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), append(anchors, a)); err != nil {
		return err
	}
	fmt.Printf("anchored %s (weight %.2f)\n", a.Person, a.Weight)
	return nil
}
```

- [ ] **Step 2: Build and end-to-end smoke test (two operators in two temp dirs)**

```bash
make build
JO=$(mktemp -d); ME=$(mktemp -d)
printf 'store:\n  dir: %s\n' "$JO" > "$JO/cfg.yaml"
printf 'store:\n  dir: %s\n' "$ME" > "$ME/cfg.yaml"
./bin/swarmctl identity init -label "Jo" -config "$JO/cfg.yaml"
./bin/swarmctl trust export -config "$JO/cfg.yaml" > /tmp/jo.bundle
./bin/swarmctl trust import /tmp/jo.bundle --as jo -config "$ME/cfg.yaml"
./bin/swarmctl trust list -config "$ME/cfg.yaml"
./bin/swarmctl trust set jo -weight 0.8 -config "$ME/cfg.yaml"
./bin/swarmctl trust remove jo -config "$ME/cfg.yaml"
```

Expected: init prints fingerprint; import prints the same fingerprint + "imported 1 cert(s)" + "anchored jo (weight 0.90)"; list shows jo/0.90/ok; set/remove succeed.

- [ ] **Step 3: Run full suite**

Run: `go test ./... && make build`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add cmd/swarmctl/
git commit -m "feat(swarmctl): trust anchor management — add/set/remove/list/export/import"
```

---

### Task 13: Adversarial suite — vouching scenarios (CI gate)

**Files:**
- Create: `test/adversarial/vouch_test.go`

These complement the engine-level tests: they run through `node.ProcessRemote`, i.e. the same path a hostile network hits. Build tag `adversarial` (CI gate per CLAUDE.md).

- [ ] **Step 1: Write the tests**

Create `test/adversarial/vouch_test.go`:

```go
//go:build adversarial

package adversarial

// Adversarial scenarios for the social-trust layer (spec §4.2/§5.1, design
// docs/superpowers/specs/2026-06-12-social-trust-anchors-design.md):
// Sybil floods stay under the stranger cap, one Person's machines are one
// corroboration vote, and forged/replayed/expired vouches never gain trust.

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/node"
	"github.com/JoeRu/swarmguard/internal/transport"
	"github.com/JoeRu/swarmguard/internal/trust"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// newHarness builds a full Node (no transport; block threshold set high so
// the enforce sink is never invoked) plus an anchored Person "jo", returning
// an issue() helper that signs certs with jo's identity key.
func newHarness(t *testing.T) (*node.Node, *config.Config, func(peerID string, validFor time.Duration) proto.PeerCert) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	cfg.Reputation.BlockThreshold = 1000

	joPriv, err := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	if err != nil {
		t.Fatalf("jo key: %v", err)
	}
	if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), []trust.Anchor{{
		Person:         "jo",
		IdentityPubkey: identity.EncodePub(identity.PersonPub(joPriv)),
		Weight:         0.9,
		Source:         "self-added",
	}}); err != nil {
		t.Fatalf("anchors: %v", err)
	}

	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n.CloseStores() })

	issue := func(peerID string, validFor time.Duration) proto.PeerCert {
		return identity.IssueCert(joPriv, peerID, time.Now().Add(validFor))
	}
	return n, cfg, issue
}

func remote(ip, peerID string, vouch *proto.PeerCert) transport.ReceivedEvent {
	return transport.ReceivedEvent{
		Event: proto.Event{IP: ip, Reason: "ssh-auth-bruteforce", ReporterID: peerID, Vouch: vouch},
		From:  peerID,
	}
}

// TestSybilStrangerFloodCapped: 100 un-vouched Sybils stay under the stranger
// cap and count as exactly one corroboration vote.
func TestSybilStrangerFloodCapped(t *testing.T) {
	n, cfg, _ := newHarness(t)
	const ip = "203.0.113.50"
	for i := 0; i < 100; i++ {
		n.ProcessRemote(remote(ip, fmt.Sprintf("12D3KooWsybil%03d", i), nil))
	}
	rec, err := n.GetScore(ip)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if rec.Score > cfg.Trust.StrangerScoreCap+0.0001 {
		t.Errorf("Sybil flood score %.4f exceeds cap %.1f", rec.Score, cfg.Trust.StrangerScoreCap)
	}
	if rec.Corroboration != 1 {
		t.Errorf("corroboration = %d, want 1 (all strangers share one vote)", rec.Corroboration)
	}
}

// TestAnchoredPersonCountsOnce: three machines under one identity = one vote,
// but full anchored score weight.
func TestAnchoredPersonCountsOnce(t *testing.T) {
	n, cfg, issue := newHarness(t)
	const ip = "203.0.113.51"
	for _, pid := range []string{"12D3KooWjoA", "12D3KooWjoB", "12D3KooWjoC"} {
		cert := issue(pid, time.Hour)
		n.ProcessRemote(remote(ip, pid, &cert))
	}
	rec, err := n.GetScore(ip)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if rec.Corroboration != 1 {
		t.Errorf("corroboration = %d, want 1 (single Person)", rec.Corroboration)
	}
	if rec.Score <= cfg.Trust.StrangerScoreCap {
		t.Errorf("anchored score %.4f should exceed the stranger cap %.1f", rec.Score, cfg.Trust.StrangerScoreCap)
	}
}

// TestVouchForgedSignatureIsStranger.
func TestVouchForgedSignatureIsStranger(t *testing.T) {
	n, _, issue := newHarness(t)
	cert := issue("12D3KooWmallory", time.Hour)
	cert.Sig[0] ^= 0xFF
	n.ProcessRemote(remote("203.0.113.52", "12D3KooWmallory", &cert))
	rec, _ := n.GetScore("203.0.113.52")
	if len(rec.Groups) != 0 || !rec.StrangerSeen {
		t.Errorf("forged vouch gained trust: groups=%v strangerSeen=%v", rec.Groups, rec.StrangerSeen)
	}
}

// TestVouchReplayIsStranger: stolen cert for jo's machine used by eve.
func TestVouchReplayIsStranger(t *testing.T) {
	n, _, issue := newHarness(t)
	stolen := issue("12D3KooWjoA", time.Hour)
	n.ProcessRemote(remote("203.0.113.53", "12D3KooWeve", &stolen))
	rec, _ := n.GetScore("203.0.113.53")
	if len(rec.Groups) != 0 {
		t.Errorf("replayed cert gained anchored trust: %v", rec.Groups)
	}
}

// TestExpiredVouchIsStranger.
func TestExpiredVouchIsStranger(t *testing.T) {
	n, _, issue := newHarness(t)
	cert := issue("12D3KooWjoA", -time.Minute)
	n.ProcessRemote(remote("203.0.113.54", "12D3KooWjoA", &cert))
	rec, _ := n.GetScore("203.0.113.54")
	if len(rec.Groups) != 0 {
		t.Errorf("expired vouch gained anchored trust: %v", rec.Groups)
	}
}

// TestPersonRemovalAppliesImmediately (Invariant 6: anchors locally removable).
func TestPersonRemovalAppliesImmediately(t *testing.T) {
	n, cfg, issue := newHarness(t)
	n.SetTrustReloadInterval(0)

	cert := issue("12D3KooWjoA", time.Hour)
	n.ProcessRemote(remote("203.0.113.55", "12D3KooWjoA", &cert))
	rec, _ := n.GetScore("203.0.113.55")
	if len(rec.Groups) != 1 {
		t.Fatalf("precondition failed: vouched report not anchored: %v", rec.Groups)
	}

	if err := trust.SaveAnchors(cfg.TrustAnchorsFile(), []trust.Anchor{}); err != nil {
		t.Fatalf("remove anchors: %v", err)
	}

	n.ProcessRemote(remote("203.0.113.56", "12D3KooWjoA", &cert))
	rec2, _ := n.GetScore("203.0.113.56")
	if len(rec2.Groups) != 0 {
		t.Errorf("report after removal still anchored: %v", rec2.Groups)
	}
}
```

- [ ] **Step 2: Add the three small Node accessors the suite needs**

In `internal/node/node.go` add:

```go
// GetScore exposes the raw reputation record for ip (tests, swarmctl status).
func (n *Node) GetScore(ip string) (store.ScoreRecord, error) {
	return n.rep.GetRecord(ip)
}

// SetTrustReloadInterval overrides the anchor-file re-check interval (tests).
func (n *Node) SetTrustReloadInterval(d time.Duration) {
	n.trust.SetReloadInterval(d)
}

// CloseStores releases the BadgerDB store (tests that never call Run).
func (n *Node) CloseStores() {
	n.store.Close()
}
```

- [ ] **Step 3: Run the gate**

Run: `make adversarial`
Expected: PASS — all pre-existing + 6 new scenarios.

- [ ] **Step 4: Run everything**

Run: `go test ./... && make adversarial && make fmt lint`
Expected: PASS, no vet findings.

- [ ] **Step 5: Commit**

```bash
git add test/adversarial/vouch_test.go internal/node/node.go
git commit -m "test(adversarial): vouch forging, replay, expiry, Sybil cap, person removal"
```

---

### Task 14: Integration — on-wire vouch round trip

**Files:**
- Create: `test/integration/vouch_pipeline_test.go`

- [ ] **Step 1: Write the test**

Create `test/integration/vouch_pipeline_test.go`:

```go
package integration_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/node"
	"github.com/JoeRu/swarmguard/internal/transport"
	"github.com/JoeRu/swarmguard/internal/trust"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// TestVouchTravelsOverGossip proves the full §5.1 chain across a real libp2p
// pair: A publishes an event carrying its peer-cert; B receives it with the
// verified publisher ID, verifies the vouch against its anchored Person, and
// scores the report as anchored.
func TestVouchTravelsOverGossip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeA, err := transport.New(ctx, localOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("transport A: %v", err)
	}
	defer nodeA.Close()
	nodeB, err := transport.New(ctx, localOpts(t, transport.ModeLeaf))
	if err != nil {
		t.Fatalf("transport B: %v", err)
	}
	defer nodeB.Close()

	if err := nodeA.Host().Connect(ctx, peerInfo(nodeB)); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Jo's identity vouches for transport node A.
	dir := t.TempDir()
	joPriv, err := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	if err != nil {
		t.Fatalf("jo key: %v", err)
	}
	cert := identity.IssueCert(joPriv, nodeA.Host().ID().String(), time.Now().Add(time.Hour))

	// Operator B anchors Jo.
	cfgB := config.Defaults()
	cfgB.Store.Dir = dir + "/b"
	cfgB.Reputation.BlockThreshold = 1000
	if err := trust.SaveAnchors(cfgB.TrustAnchorsFile(), []trust.Anchor{{
		Person:         "jo",
		IdentityPubkey: identity.EncodePub(identity.PersonPub(joPriv)),
		Weight:         0.9,
		Source:         "self-added",
	}}); err != nil {
		t.Fatalf("anchors: %v", err)
	}
	nb, err := node.New(cfgB, nil)
	if err != nil {
		t.Fatalf("node B: %v", err)
	}
	defer nb.CloseStores()

	// A publishes a vouched event.
	want := proto.Event{
		IP:         "198.51.100.77",
		Reason:     "smtp-auth-bruteforce",
		ReporterID: nodeA.Host().ID().String(),
		Vouch:      &cert,
	}
	if err := nodeA.Publish(ctx, want); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case re := <-nodeB.Subscribe():
		if re.From != nodeA.Host().ID().String() {
			t.Fatalf("verified publisher = %q, want %q", re.From, nodeA.Host().ID())
		}
		if re.Event.Vouch == nil {
			t.Fatal("vouch lost on the wire")
		}
		nb.ProcessRemote(re)
	case <-time.After(5 * time.Second):
		t.Fatal("no event within 5s")
	}

	rec, err := nb.GetScore(want.IP)
	if err != nil {
		t.Fatalf("GetScore: %v", err)
	}
	if len(rec.Groups) != 1 || rec.Groups[0] != "jo" {
		t.Errorf("Groups = %v, want [jo] — vouched event not scored as anchored", rec.Groups)
	}
}

func peerInfo(n *transport.Node) peer.AddrInfo {
	return peer.AddrInfo{ID: n.Host().ID(), Addrs: n.Host().Addrs()}
}
```

Add `"github.com/libp2p/go-libp2p/core/peer"` to the imports (the file's `peerInfo` helper needs it; `localOpts` comes from `cluster_test.go`, same package).

- [ ] **Step 2: Run the test**

Run: `go test ./test/integration/ -run TestVouchTravelsOverGossip -v`
Expected: PASS — verified publisher matches, vouch survives JSON, record lands in group `jo`.

- [ ] **Step 3: Run everything**

Run: `go test ./... && make adversarial`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add test/integration/vouch_pipeline_test.go
git commit -m "test(integration): vouched event travels gossipsub and scores as anchored"
```

---

### Task 15: Documentation + CHANGELOG (same PR — repo convention)

**Files:**
- Modify: `docs/onboarding/03-key-management.md`
- Modify: `docs/federation-guide.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update `docs/onboarding/03-key-management.md`**

Append a section (adapt heading level to the file's existing style):

```markdown
## Node keys, Person identities, and peer-certs

SwarmGuard separates three keys with distinct blast radii:

| Key | File (default) | Compromise means |
|---|---|---|
| Node key | `<store-dir>/identity.key` (0600) | one machine impersonated — rotate that machine |
| Person identity | `<store-dir>/person.key` (0600) | ALL your machines' vouching burned — keep it off shared boxes, back it up offline |
| Peer-cert | `<store-dir>/peer.cert` | nothing secret — it is a public, signed statement |

- The node key is created automatically on first `swarmd` start. swarmd refuses
  to start if it is group- or world-readable (`chmod 600` to fix).
- The Person identity is created once with `swarmctl identity init --label "You"`.
  It signs a certificate per machine (`swarmctl peer-cert <peer-id>`); certs
  default to one year validity — re-issue before expiry.
- **The fingerprint ritual:** before anchoring anyone, read the fingerprint
  shown by `swarmctl trust import` aloud against the one your friend gets from
  `swarmctl identity show`, over a channel you already trust (call, Signal,
  in person). Matching fingerprints = you anchored the right human.
- Removing a person (`swarmctl trust remove jo`) takes effect within ~10
  seconds for all their machines. Their past score contributions fade through
  normal decay.
```

- [ ] **Step 2: Update `docs/federation-guide.md`**

Append:

```markdown
## Pairing with a friend (social trust anchors)

Trust in SwarmGuard is granted to *people*, not machines (spec §5.1). One
anchored Person identity covers every machine they certify — including ones
they add later — and all of them together count as **one** corroboration vote.

Jo (being trusted), once:

​```bash
swarmctl identity init --label "Jo"        # Person key + self-cert for this node
swarmctl identity show                      # pubkey + fingerprint to share
swarmctl peer-cert <peer-id-of-2nd-box>     # cert for each additional machine
swarmctl trust export > jo.bundle           # optional offline bundle
​```

You (trusting Jo):

​```bash
swarmctl trust import jo.bundle --as jo     # or: swarmctl trust add jo --identity ed25519:...
# → read the printed fingerprint to Jo over a channel you already trust
swarmctl trust list
​```

From then on Jo's machines attach their certs to every report on the wire —
no re-import when Jo adds a machine. Reports from peers nobody vouched for
("strangers") still count, but all strangers combined can never add more than
`trust.stranger_score_cap` points (default 15) to any IP, and never more than
one corroboration vote: a Sybil flood cannot block anything on its own.

Re-rate or drop a person any time (lists are aids, not law — Invariant 1/6):

​```bash
swarmctl trust set jo --weight 0.5
swarmctl trust remove jo
​```
```

(Remove the zero-width characters before the backticks when writing the real file — they are only here to keep this plan's code fences intact.)

- [ ] **Step 3: Update `CHANGELOG.md`**

Add under an `## Unreleased` heading (create it if absent):

```markdown
### Added
- Social trust anchors (spec §5.1): Ed25519 Person identities sign peer-certs;
  certs travel on the wire (`Event.Vouch`); anchored Persons drive
  corroboration, strangers are score-capped (`trust.stranger_score_cap`).
- `swarmctl` identity/peer-cert/trust command set.
- Persistent node identity key — stable peer ID across restarts.

### Changed
- **Wire format:** `SchemaVersion` 0 → 1 (additive `vouch` field on events;
  v0 nodes interoperate and treat v1 senders as strangers).
- `reputation.Engine.Record` is group-aware; corroboration counts distinct
  anchored Persons plus at most one collective stranger vote.
```

- [ ] **Step 4: Run everything one last time**

Run: `make build && go test ./... && make adversarial && make fmt lint`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add docs/onboarding/03-key-management.md docs/federation-guide.md CHANGELOG.md
git commit -m "docs: key management, friend-pairing guide, changelog for trust anchors"
```

---

## Self-review checklist (run after writing, before execution)

- **Spec coverage:** identity keys (T2/T3), wire change (T1), anchor store + Resolve (T8), CLI (T11/T12), verified sender + spoof drop (T9/T10), vouch verify (T10), capped strangers + groups (T5/T6), adversarial gate (T13), on-wire round trip (T14), docs (T15). Edge cases from the spec map to tests in T8 (corrupt/missing/expired/hot-reload), T10 (replay/spoof), T13 (forge/expire/removal).
- **Known deviations from spec, accepted:** per-peer revocation is out of scope (documented); `swarmctl trust list` shows anchors, not cached certs.
- **Type consistency:** `Record(ip, reason, reporterID string, trust float64, group string, anchored bool)` used identically in T6/T7/T10/T13; `NewStore(anchorsPath, certsPath string, strangerWeight float64)` in T8/T10/T13; `ReceivedEvent{Event, From}` in T9/T10/T13/T14.
