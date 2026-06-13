package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/identity"
	"github.com/JoeRu/swarmguard/internal/trust"
	"github.com/JoeRu/swarmguard/pkg/proto"
)

// writeCfg writes a minimal config.yaml pointing the store dir at dir and
// returns its path. swarmctl derives every trust file path from store.dir.
func writeCfg(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(p, []byte("store:\n  dir: "+dir+"\n"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	return p
}

// TestTrustAddRejectsOutOfRangeWeight locks the (0,1] weight gate.
func TestTrustAddRejectsOutOfRangeWeight(t *testing.T) {
	dir := t.TempDir()
	cfg := writeCfg(t, dir)
	priv, _ := identity.GeneratePersonKey(filepath.Join(dir, "friend.key"))
	pub := identity.EncodePub(identity.PersonPub(priv))

	if err := trustAdd([]string{"-config", cfg, "-identity", pub, "-weight", "5", "friend"}); err == nil {
		t.Error("weight 5 accepted, want out-of-range error")
	}
	if err := trustAdd([]string{"-config", cfg, "-identity", pub, "-weight", "-0.1", "friend"}); err == nil {
		t.Error("negative weight accepted, want out-of-range error")
	}
}

// TestTrustAddOwnIdentityIsNoOp proves the own-identity guard fires even when
// the person key is present (regression guard for the swallowed-error bug).
func TestTrustAddOwnIdentityIsNoOp(t *testing.T) {
	dir := t.TempDir()
	cfg := writeCfg(t, dir)
	priv, err := identity.GeneratePersonKey(filepath.Join(dir, "person.key"))
	if err != nil {
		t.Fatalf("gen person key: %v", err)
	}
	ownPub := identity.EncodePub(identity.PersonPub(priv))

	if err := trustAdd([]string{"-config", cfg, "-identity", ownPub, "me"}); err != nil {
		t.Fatalf("trustAdd own identity: %v", err)
	}
	anchors, err := trust.LoadAnchors(filepath.Join(dir, "anchors.json"))
	if err != nil {
		t.Fatalf("load anchors: %v", err)
	}
	if len(anchors) != 0 {
		t.Errorf("own identity was anchored (%d entries), want no-op", len(anchors))
	}
}

// TestTrustAddSurfacesUnreadableOwnKey: an unreadable person.key must error,
// not silently bypass the own-identity guard.
func TestTrustAddSurfacesUnreadableOwnKey(t *testing.T) {
	dir := t.TempDir()
	cfg := writeCfg(t, dir)
	if _, err := identity.GeneratePersonKey(filepath.Join(dir, "person.key")); err != nil {
		t.Fatalf("gen person key: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "person.key"), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	friend, _ := identity.GeneratePersonKey(filepath.Join(dir, "friend.key"))
	pub := identity.EncodePub(identity.PersonPub(friend))

	if err := trustAdd([]string{"-config", cfg, "-identity", pub, "friend"}); err == nil {
		t.Error("unreadable own key was silently ignored, want surfaced error")
	}
}

// TestTrustImportSkipsForeignCerts proves a tampered bundle (a cert signed by a
// different identity than the bundle's claimed pubkey) imports zero certs.
func TestTrustImportSkipsForeignCerts(t *testing.T) {
	dir := t.TempDir()
	cfg := writeCfg(t, dir)

	jo, _ := identity.GeneratePersonKey(filepath.Join(dir, "jo.key"))
	eve, _ := identity.GeneratePersonKey(filepath.Join(dir, "eve.key"))

	// Bundle claims Jo's identity but carries a cert signed by Eve.
	b := trust.Bundle{
		Person:         "jo",
		Label:          "Jo",
		IdentityPubkey: identity.EncodePub(identity.PersonPub(jo)),
		Certs: []proto.PeerCert{
			identity.IssueCert(eve, "12D3KooWeveBox", time.Now().Add(time.Hour)),
		},
	}
	bundlePath := filepath.Join(dir, "jo.bundle")
	data, _ := json.MarshalIndent(b, "", "  ")
	if err := os.WriteFile(bundlePath, data, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	if err := trustImport([]string{"-config", cfg, "-as", "jo", bundlePath}); err != nil {
		t.Fatalf("import: %v", err)
	}
	certs, _ := trust.LoadCerts(filepath.Join(dir, "imported-certs.json"))
	if len(certs) != 0 {
		t.Errorf("foreign cert was imported (%d), want 0", len(certs))
	}
}
