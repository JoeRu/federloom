package main

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidateFile_GoodConfig(t *testing.T) {
	p := write(t, t.TempDir(), "config.yaml", "federation_mode: solo\nstore:\n  dir: /tmp/x\n")
	if err := validateFile(p); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestValidateFile_UnknownKeyConfig(t *testing.T) {
	p := write(t, t.TempDir(), "config.yaml", "no_such_key: true\n")
	if err := validateFile(p); err == nil {
		t.Error("config with unknown key accepted; want error")
	}
}

func TestValidateFile_GoodRules(t *testing.T) {
	p := write(t, t.TempDir(), "rules.yaml", "- name: r1\n  reason: ssh-auth-bruteforce\n  min_corroboration: 1\n  action: block\n")
	if err := validateFile(p); err != nil {
		t.Errorf("valid rules rejected: %v", err)
	}
}

func TestValidateFile_UnknownKeyRules(t *testing.T) {
	p := write(t, t.TempDir(), "rules.yaml", "- name: r1\n  bogus_field: 1\n  action: block\n")
	if err := validateFile(p); err == nil {
		t.Error("rules with unknown key accepted; want error")
	}
}

func TestValidateFile_OtherFilesSkipped(t *testing.T) {
	p := write(t, t.TempDir(), "docker-compose.yml", "services: {}\n")
	if err := validateFile(p); err != nil {
		t.Errorf("non-config file should be skipped, got: %v", err)
	}
}
