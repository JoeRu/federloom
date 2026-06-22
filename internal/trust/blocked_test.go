package trust_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JoeRu/swarmguard/internal/trust"
)

func TestLoadBlockedPeers_MissingFile(t *testing.T) {
	peers, err := trust.LoadBlockedPeers("/nonexistent/blocked.json")
	if err != nil {
		t.Fatalf("unexpected error for missing file: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("want empty list, got %v", peers)
	}
}

func TestLoadAndSaveBlockedPeers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")

	want := []string{"12D3KooWbadpeer1", "12D3KooWbadpeer2"}
	if err := trust.SaveBlockedPeers(path, want); err != nil {
		t.Fatalf("SaveBlockedPeers: %v", err)
	}
	got, err := trust.LoadBlockedPeers(path)
	if err != nil {
		t.Fatalf("LoadBlockedPeers: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestStoreIsBlocked(t *testing.T) {
	dir := t.TempDir()
	blockedPath := filepath.Join(dir, "blocked.json")
	anchorsPath := filepath.Join(dir, "anchors.json")
	certsPath := filepath.Join(dir, "certs.json")

	if err := trust.SaveBlockedPeers(blockedPath, []string{"12D3KooWbadactor"}); err != nil {
		t.Fatalf("SaveBlockedPeers: %v", err)
	}

	s := trust.NewStore(anchorsPath, certsPath, blockedPath, 0.3)
	s.SetReloadInterval(0) // force reload on every call

	if !s.IsBlocked("12D3KooWbadactor") {
		t.Error("IsBlocked should return true for blocked peer")
	}
	if s.IsBlocked("12D3KooWgoodpeer") {
		t.Error("IsBlocked should return false for unknown peer")
	}
}

func TestStoreIsBlocked_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	s := trust.NewStore(
		filepath.Join(dir, "anchors.json"),
		filepath.Join(dir, "certs.json"),
		filepath.Join(dir, "blocked.json"), // does not exist
		0.3,
	)
	if s.IsBlocked("anyone") {
		t.Error("IsBlocked should return false when no blocked list exists")
	}
}

func TestStoreIsBlocked_HotReload(t *testing.T) {
	dir := t.TempDir()
	blockedPath := filepath.Join(dir, "blocked.json")

	s := trust.NewStore(
		filepath.Join(dir, "anchors.json"),
		filepath.Join(dir, "certs.json"),
		blockedPath,
		0.3,
	)
	s.SetReloadInterval(0)

	if s.IsBlocked("12D3KooWlater") {
		t.Fatal("should not be blocked before list is written")
	}

	if err := trust.SaveBlockedPeers(blockedPath, []string{"12D3KooWlater"}); err != nil {
		t.Fatalf("SaveBlockedPeers: %v", err)
	}
	// Force stat change by touching the file (save already does this atomically).
	fi, _ := os.Stat(blockedPath)
	_ = fi // just confirming it exists

	if !s.IsBlocked("12D3KooWlater") {
		t.Error("IsBlocked should pick up hot-reloaded blocked peer")
	}
}
