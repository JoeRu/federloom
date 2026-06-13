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

func TestDefaultsOpenCanaryPollInterval(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Ingest.OpenCanary.PollInterval.Duration <= 0 {
		t.Errorf("OpenCanary default PollInterval must be > 0, got %v", cfg.Ingest.OpenCanary.PollInterval.Duration)
	}
}

func TestLoadYAMLOpenCanaryEnabled(t *testing.T) {
	raw := []byte(`
ingest:
  opencanary:
    enabled: true
    log_file: /var/log/opencanary/opencanary.log
    poll_interval: 2s
`)
	cfg, err := config.LoadYAML(raw)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if !cfg.Ingest.OpenCanary.Enabled {
		t.Error("OpenCanary.Enabled should be true")
	}
	if cfg.Ingest.OpenCanary.LogFile != "/var/log/opencanary/opencanary.log" {
		t.Errorf("LogFile: got %q, want /var/log/opencanary/opencanary.log", cfg.Ingest.OpenCanary.LogFile)
	}
	if cfg.Ingest.OpenCanary.PollInterval.Duration != 2*time.Second {
		t.Errorf("PollInterval: got %v, want 2s", cfg.Ingest.OpenCanary.PollInterval.Duration)
	}
}

func TestDefaultsTrust(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Trust.AnchorWeight != 0.9 {
		t.Errorf("AnchorWeight = %v, want 0.9", cfg.Trust.AnchorWeight)
	}
	if cfg.Trust.StrangerWeight != 0.3 {
		t.Errorf("StrangerWeight = %v, want 0.3", cfg.Trust.StrangerWeight)
	}
	if cfg.Trust.StrangerScoreCap != 15 {
		t.Errorf("StrangerScoreCap = %v, want 15", cfg.Trust.StrangerScoreCap)
	}
}

func TestTrustPathDefaultsDeriveFromStoreDir(t *testing.T) {
	cfg := config.Defaults()
	cfg.Store.Dir = "/var/lib/swarmguard"
	if got := cfg.TrustAnchorsFile(); got != "/var/lib/swarmguard/anchors.json" {
		t.Errorf("TrustAnchorsFile = %q", got)
	}
	if got := cfg.TrustPersonKeyFile(); got != "/var/lib/swarmguard/person.key" {
		t.Errorf("TrustPersonKeyFile = %q", got)
	}
	if got := cfg.TrustPeerCertFile(); got != "/var/lib/swarmguard/peer.cert" {
		t.Errorf("TrustPeerCertFile = %q", got)
	}
	if got := cfg.TrustCertsFile(); got != "/var/lib/swarmguard/imported-certs.json" {
		t.Errorf("TrustCertsFile = %q", got)
	}
}

func TestTrustPathOverrides(t *testing.T) {
	cfg, err := config.LoadYAML([]byte("trust:\n  anchors_file: /etc/swarmguard/anchors.json\n  stranger_score_cap: 5\n"))
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if got := cfg.TrustAnchorsFile(); got != "/etc/swarmguard/anchors.json" {
		t.Errorf("TrustAnchorsFile override = %q", got)
	}
	if cfg.Trust.StrangerScoreCap != 5 {
		t.Errorf("StrangerScoreCap = %v, want 5", cfg.Trust.StrangerScoreCap)
	}
}
