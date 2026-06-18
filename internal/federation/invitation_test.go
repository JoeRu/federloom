package federation_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/federation"
	"github.com/JoeRu/swarmguard/internal/identity"
)

// makeTestConfig returns a Defaults config with Store.Dir pointing to a temp directory.
func makeTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Store.Dir = dir
	return cfg
}

// setupKeys creates both the node key and the person key for a test config.
func setupKeys(t *testing.T, cfg *config.Config) {
	t.Helper()
	// Create node key (LoadOrCreate will generate it).
	_, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile())
	if err != nil {
		t.Fatalf("setupKeys: node key: %v", err)
	}
	// Generate person key.
	if _, err := identity.GeneratePersonKey(cfg.TrustPersonKeyFile()); err != nil {
		t.Fatalf("setupKeys: person key: %v", err)
	}
}

// TestInvitationRoundTrip verifies that an invitation can be created, written, and read back.
func TestInvitationRoundTrip(t *testing.T) {
	cfg := makeTestConfig(t)
	setupKeys(t, cfg)

	inv, err := federation.NewInvitation(cfg, "testlabel", "/ip4/1.2.3.4/tcp/7700")
	if err != nil {
		t.Fatalf("NewInvitation: %v", err)
	}

	var buf bytes.Buffer
	if err := federation.WriteInvitation(&buf, inv); err != nil {
		t.Fatalf("WriteInvitation: %v", err)
	}

	got, err := federation.ReadInvitation(&buf)
	if err != nil {
		t.Fatalf("ReadInvitation: %v", err)
	}

	if got.Version != 1 {
		t.Errorf("Version: got %d, want 1", got.Version)
	}
	if got.InvitedBy == "" {
		t.Error("InvitedBy is empty")
	}
	if got.Trust.IdentityPubkey == "" {
		t.Error("Trust.IdentityPubkey is empty")
	}
	if got.Federation.BootstrapPeer == "" {
		t.Error("Federation.BootstrapPeer is empty")
	}
}

// TestNewInvitationMissingPersonKey verifies that NewInvitation errors when no person key exists.
func TestNewInvitationMissingPersonKey(t *testing.T) {
	cfg := makeTestConfig(t)
	// Only create the node key, not the person key.
	if _, err := identity.LoadOrCreateNodeKey(cfg.NodeKeyFile()); err != nil {
		t.Fatalf("node key: %v", err)
	}

	_, err := federation.NewInvitation(cfg, "testlabel", "/ip4/1.2.3.4/tcp/7700")
	if err == nil {
		t.Fatal("expected error for missing person key, got nil")
	}
	if !strings.Contains(err.Error(), "swarmctl setup") {
		t.Errorf("error should mention 'swarmctl setup', got: %v", err)
	}
}

// TestReadInvitationBadVersion verifies that a version != 1 is rejected.
func TestReadInvitationBadVersion(t *testing.T) {
	bad := `{"version":2,"created_at":"2024-01-01T00:00:00Z","invited_by":"x","federation":{},"trust_bundle":{}}`
	_, err := federation.ReadInvitation(strings.NewReader(bad))
	if err == nil {
		t.Fatal("expected error for version 2, got nil")
	}
}

// TestNewInvitationAddrWithPeerID verifies that an address already containing /p2p/ is rejected.
func TestNewInvitationAddrWithPeerID(t *testing.T) {
	cfg := makeTestConfig(t)
	setupKeys(t, cfg)

	_, err := federation.NewInvitation(cfg, "testlabel", "/ip4/1.2.3.4/tcp/7700/p2p/12D3KooWTest")
	if err == nil {
		t.Fatal("expected error for addr with /p2p/ component, got nil")
	}
}

// TestInvitationBootstrapPeerContainsPeerID verifies that the BootstrapPeer includes /p2p/.
func TestInvitationBootstrapPeerContainsPeerID(t *testing.T) {
	cfg := makeTestConfig(t)
	setupKeys(t, cfg)

	inv, err := federation.NewInvitation(cfg, "testlabel", "/ip4/1.2.3.4/tcp/7700")
	if err != nil {
		t.Fatalf("NewInvitation: %v", err)
	}

	if !strings.Contains(inv.Federation.BootstrapPeer, "/p2p/") {
		t.Errorf("BootstrapPeer %q does not contain /p2p/", inv.Federation.BootstrapPeer)
	}
}

// TestInvitationSuggestedWeight verifies that AnchorWeight is reflected in SuggestedWeight,
// and survives a round-trip through JSON.
func TestInvitationSuggestedWeight(t *testing.T) {
	cfg := makeTestConfig(t)
	cfg.Trust.AnchorWeight = 0.75
	setupKeys(t, cfg)

	inv, err := federation.NewInvitation(cfg, "testlabel", "/ip4/1.2.3.4/tcp/7700")
	if err != nil {
		t.Fatalf("NewInvitation: %v", err)
	}

	if inv.Federation.SuggestedWeight != 0.75 {
		t.Errorf("SuggestedWeight: got %f, want 0.75", inv.Federation.SuggestedWeight)
	}

	var buf bytes.Buffer
	if err := federation.WriteInvitation(&buf, inv); err != nil {
		t.Fatalf("WriteInvitation: %v", err)
	}

	// Verify JSON output also has the right value (belt-and-suspenders).
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	fed, ok := raw["federation"].(map[string]interface{})
	if !ok {
		t.Fatal("federation key missing from JSON")
	}
	sw, ok := fed["suggested_weight"].(float64)
	if !ok {
		t.Fatal("suggested_weight missing from federation JSON")
	}
	if sw != 0.75 {
		t.Errorf("JSON suggested_weight: got %f, want 0.75", sw)
	}

	got, err := federation.ReadInvitation(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadInvitation: %v", err)
	}
	if got.Federation.SuggestedWeight != 0.75 {
		t.Errorf("after round-trip SuggestedWeight: got %f, want 0.75", got.Federation.SuggestedWeight)
	}

	// Ensure the .issued.json path (not TrustCertsFile) is used — presence of
	// the file should not cause errors (empty certs list is fine).
	issuedPath := cfg.TrustPersonKeyFile() + ".issued.json"
	if err := os.WriteFile(issuedPath, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write issued.json: %v", err)
	}
	inv2, err := federation.NewInvitation(cfg, "testlabel", "/ip4/1.2.3.4/tcp/7700")
	if err != nil {
		t.Fatalf("NewInvitation with issued.json present: %v", err)
	}
	_ = inv2
	_ = filepath.Join(cfg.Store.Dir, "x") // ensure import is used
}
