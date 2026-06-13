package identity_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoeRu/swarmguard/internal/identity"
)

// TestPersonKeyRejectsLooseperms mirrors the node-key guard: a group/world
// readable person key must be refused on load.
func TestPersonKeyRejectsLooseperms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "person.key")
	if _, err := identity.GeneratePersonKey(path); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := identity.LoadPersonKey(path); err == nil {
		t.Error("expected error for group/world-readable person key, got nil")
	}
}

// TestPersonKeyRejectsCorruptFile proves a truncated/garbage key is an error,
// not silently accepted — the failure mode the atomic write guards against.
func TestPersonKeyRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "person.key")
	if err := os.WriteFile(path, []byte("not base64 !!!"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	if _, err := identity.LoadPersonKey(path); err == nil {
		t.Error("expected error for corrupt person key, got nil")
	}
}

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
