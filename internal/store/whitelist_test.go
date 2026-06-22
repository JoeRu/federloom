package store_test

import (
	"path/filepath"
	"testing"

	"github.com/JoeRu/swarmguard/internal/store"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

func TestLoadWhitelist_MissingFile(t *testing.T) {
	wl, err := store.LoadWhitelist("/nonexistent/whitelist.json")
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if len(wl.List()) != 0 {
		t.Errorf("expected empty list, got %d entries", len(wl.List()))
	}
}

func TestWhitelistContains_CIDR(t *testing.T) {
	dir := t.TempDir()
	wl, err := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	if err != nil {
		t.Fatalf("LoadWhitelist: %v", err)
	}
	if err := wl.Add(proto.WhitelistEntry{IPOrRange: "203.0.113.0/24", Scope: "local-only", Source: "manual"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if !wl.Contains("203.0.113.1") {
		t.Error("Contains should match IP inside CIDR")
	}
	if !wl.Contains("203.0.113.254") {
		t.Error("Contains should match last IP in CIDR")
	}
	if wl.Contains("203.0.114.1") {
		t.Error("Contains should not match IP outside CIDR")
	}
}

func TestWhitelistContains_ExactIP(t *testing.T) {
	dir := t.TempDir()
	wl, _ := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	_ = wl.Add(proto.WhitelistEntry{IPOrRange: "192.168.1.5", Scope: "local-only", Source: "manual"})

	if !wl.Contains("192.168.1.5") {
		t.Error("exact IP should match")
	}
	if wl.Contains("192.168.1.6") {
		t.Error("different IP should not match")
	}
}

func TestWhitelistAdd_Idempotent(t *testing.T) {
	dir := t.TempDir()
	wl, _ := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))

	e := proto.WhitelistEntry{IPOrRange: "1.2.3.4", Scope: "local-only", Source: "manual"}
	_ = wl.Add(e)
	_ = wl.Add(e)

	if len(wl.List()) != 1 {
		t.Errorf("second Add should be no-op: got %d entries", len(wl.List()))
	}
}

func TestWhitelistRemove(t *testing.T) {
	dir := t.TempDir()
	wl, _ := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	_ = wl.Add(proto.WhitelistEntry{IPOrRange: "1.2.3.4", Scope: "local-only", Source: "manual"})
	_ = wl.Add(proto.WhitelistEntry{IPOrRange: "5.6.7.8", Scope: "local-only", Source: "manual"})

	if err := wl.Remove("1.2.3.4"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if wl.Contains("1.2.3.4") {
		t.Error("removed entry should not match")
	}
	if !wl.Contains("5.6.7.8") {
		t.Error("other entry should still match")
	}
}

func TestWhitelistRemove_Missing(t *testing.T) {
	dir := t.TempDir()
	wl, _ := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	// Remove on empty list must not error
	if err := wl.Remove("9.9.9.9"); err != nil {
		t.Errorf("Remove of missing entry should return nil, got: %v", err)
	}
}

func TestWhitelistPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.json")

	wl1, _ := store.LoadWhitelist(path)
	_ = wl1.Add(proto.WhitelistEntry{IPOrRange: "10.0.0.1", Scope: "local-only", Source: "manual"})

	wl2, err := store.LoadWhitelist(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !wl2.Contains("10.0.0.1") {
		t.Error("persisted entry must survive a reload")
	}
}

func TestWhitelistList_ReturnsCopy(t *testing.T) {
	dir := t.TempDir()
	wl, _ := store.LoadWhitelist(filepath.Join(dir, "whitelist.json"))
	_ = wl.Add(proto.WhitelistEntry{IPOrRange: "1.1.1.1", Scope: "local-only", Source: "manual"})

	list1 := wl.List()
	list1[0].IPOrRange = "9.9.9.9" // mutate the returned slice
	list2 := wl.List()
	if list2[0].IPOrRange != "1.1.1.1" {
		t.Error("List must return a copy, not a reference to internal state")
	}
}
