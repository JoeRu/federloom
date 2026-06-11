package config_test

import (
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
)

func TestDefaultsAreValid(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Reputation.HalfLife.Duration <= 0 {
		t.Fatal("expected positive half-life")
	}
	if cfg.Enforce.Backend == "" {
		t.Fatal("expected non-empty enforce backend")
	}
}

func TestLoadYAML(t *testing.T) {
	cfg, err := config.LoadYAML([]byte(`
reputation:
  half_life: 24h
  block_threshold: 80
  unblock_threshold: 55
  decay_interval: 30m
enforce:
  backend: nftables
  set_name: sg
ingest:
  honeypot:
    enabled: true
    log_file: /tmp/cowrie.json
    poll_interval: 500ms
store:
  dir: /tmp/sgtest
`))
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if cfg.Reputation.HalfLife.Duration != 24*time.Hour {
		t.Errorf("half_life: got %v, want 24h", cfg.Reputation.HalfLife.Duration)
	}
	if cfg.Enforce.Backend != "nftables" {
		t.Errorf("backend: got %q, want nftables", cfg.Enforce.Backend)
	}
	if !cfg.Ingest.Honeypot.Enabled {
		t.Error("expected honeypot.enabled = true")
	}
}
