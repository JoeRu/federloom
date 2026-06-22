package discovery_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/JoeRu/swarmguard/internal/discovery"
	"github.com/JoeRu/swarmguard/internal/resources"
)

func TestLoadRelayList_Embedded(t *testing.T) {
	entries, err := discovery.LoadRelayList("", resources.RelayList)
	if err != nil {
		t.Fatalf("LoadRelayList from embedded: %v", err)
	}
	// Embedded list is empty [] — that is valid.
	_ = entries
}

func TestLoadRelayList_CustomFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relays.json")

	data, _ := json.Marshal([]discovery.RelayEntry{
		{PeerID: "12D3KooWrelay1", Addrs: []string{"/ip4/1.2.3.4/tcp/7700"}, Label: "test relay"},
	})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write relay list: %v", err)
	}

	entries, err := discovery.LoadRelayList(path, resources.RelayList)
	if err != nil {
		t.Fatalf("LoadRelayList from file: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if entries[0].PeerID != "12D3KooWrelay1" {
		t.Errorf("PeerID want 12D3KooWrelay1 got %s", entries[0].PeerID)
	}
}

func TestLoadRelayList_MissingCustomFile(t *testing.T) {
	// Missing custom file → falls back to embedded list (no error).
	entries, err := discovery.LoadRelayList("/nonexistent/relays.json", resources.RelayList)
	if err != nil {
		t.Fatalf("unexpected error for missing custom file: %v", err)
	}
	_ = entries // embedded list may be empty; that's fine
}

func TestLoadRelayList_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatalf("write bad relay list: %v", err)
	}
	_, err := discovery.LoadRelayList(path, resources.RelayList)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}
