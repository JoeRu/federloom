package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWhitelistAddRemoveList(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("store:\n  dir: "+dir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Add an entry
	if err := cmdWhitelist([]string{"add", "--config", cfgPath, "203.0.113.0/24"}); err != nil {
		t.Fatalf("whitelist add: %v", err)
	}

	// Adding same entry again must be idempotent (no error)
	if err := cmdWhitelist([]string{"add", "--config", cfgPath, "203.0.113.0/24"}); err != nil {
		t.Fatalf("whitelist add (duplicate): %v", err)
	}

	// Remove the entry
	if err := cmdWhitelist([]string{"remove", "--config", cfgPath, "203.0.113.0/24"}); err != nil {
		t.Fatalf("whitelist remove: %v", err)
	}

	// Removing again must not error
	if err := cmdWhitelist([]string{"remove", "--config", cfgPath, "203.0.113.0/24"}); err != nil {
		t.Fatalf("whitelist remove (missing): %v", err)
	}
}

func TestWhitelistAdd_InvalidIP(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(cfgPath, []byte("store:\n  dir: "+dir+"\n"), 0o644)

	err := cmdWhitelist([]string{"add", "--config", cfgPath, "not-an-ip"})
	if err == nil {
		t.Fatal("expected error for invalid IP/CIDR, got nil")
	}
}

func TestWhitelistAdd_InvalidScope(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(cfgPath, []byte("store:\n  dir: "+dir+"\n"), 0o644)

	err := cmdWhitelist([]string{"add", "--scope", "bad-scope", "--config", cfgPath, "1.2.3.4"})
	if err == nil {
		t.Fatal("expected error for invalid scope, got nil")
	}
}
