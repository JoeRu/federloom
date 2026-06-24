package identity_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/JoeRu/federloom/internal/identity"
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

// TestNodeKeyRejectsCorruptFile proves a truncated/garbage key file is reported
// as an error rather than silently regenerated — a regenerated identity would
// silently change the node's peer ID and break every anchor pointing at it.
func TestNodeKeyRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	if err := os.WriteFile(path, []byte("not a real key"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	if _, err := identity.LoadOrCreateNodeKey(path); err == nil {
		t.Error("expected error for corrupt key file, got nil (silent regeneration)")
	}
}
