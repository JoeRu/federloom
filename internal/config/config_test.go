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

func TestObservabilityConfig_YAML(t *testing.T) {
	yaml := `
observability:
  prometheus_addr: ":9101"
  sqlite_path: "metrics.db"
  sqlite_retention: 360h
  score_gauge_threshold: 30
`
	cfg, err := config.LoadYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if cfg.Observability.PrometheusAddr != ":9101" {
		t.Errorf("PrometheusAddr = %q, want :9101", cfg.Observability.PrometheusAddr)
	}
	if cfg.Observability.SQLitePath != "metrics.db" {
		t.Errorf("SQLitePath = %q, want metrics.db", cfg.Observability.SQLitePath)
	}
	if cfg.Observability.SQLiteRetention.Duration != 360*time.Hour {
		t.Errorf("SQLiteRetention = %v, want 360h", cfg.Observability.SQLiteRetention.Duration)
	}
	if cfg.Observability.ScoreGaugeThreshold != 30 {
		t.Errorf("ScoreGaugeThreshold = %v, want 30", cfg.Observability.ScoreGaugeThreshold)
	}
}

func TestObservabilityConfig_Defaults(t *testing.T) {
	cfg := config.Defaults()
	// All fields zero/empty = observability disabled by default (spec §11.2).
	if cfg.Observability.PrometheusAddr != "" {
		t.Errorf("default PrometheusAddr should be empty, got %q", cfg.Observability.PrometheusAddr)
	}
	if cfg.Observability.SQLitePath != "" {
		t.Errorf("default SQLitePath should be empty, got %q", cfg.Observability.SQLitePath)
	}
}

func TestLoadYAMLMailcowConfig(t *testing.T) {
	cfg, err := config.LoadYAML([]byte(`
ingest:
  mailcow_logs:
    enabled: true
    postfix_container: mailcowdockerized-postfix-1
    dovecot_container: mailcowdockerized-dovecot-1
    poll_interval: 30s
  spamtrap:
    enabled: true
    log_file: /var/log/spamtrap.log
    poll_interval: 5s
`))
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if !cfg.Ingest.MailcowLogs.Enabled {
		t.Error("expected mailcow_logs.enabled = true")
	}
	if cfg.Ingest.MailcowLogs.PostfixContainer != "mailcowdockerized-postfix-1" {
		t.Errorf("postfix_container: got %q", cfg.Ingest.MailcowLogs.PostfixContainer)
	}
	if cfg.Ingest.MailcowLogs.DovecotContainer != "mailcowdockerized-dovecot-1" {
		t.Errorf("dovecot_container: got %q", cfg.Ingest.MailcowLogs.DovecotContainer)
	}
	if cfg.Ingest.MailcowLogs.PollInterval.Duration != 30*time.Second {
		t.Errorf("poll_interval: got %v", cfg.Ingest.MailcowLogs.PollInterval.Duration)
	}
	if !cfg.Ingest.Spamtrap.Enabled {
		t.Error("expected spamtrap.enabled = true")
	}
	if cfg.Ingest.Spamtrap.LogFile != "/var/log/spamtrap.log" {
		t.Errorf("log_file: got %q", cfg.Ingest.Spamtrap.LogFile)
	}
}

func TestDefaultsMailcowPollInterval(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Ingest.MailcowLogs.PollInterval.Duration <= 0 {
		t.Errorf("MailcowLogs default PollInterval must be > 0, got %v", cfg.Ingest.MailcowLogs.PollInterval.Duration)
	}
	if cfg.Ingest.Spamtrap.PollInterval.Duration <= 0 {
		t.Errorf("Spamtrap default PollInterval must be > 0, got %v", cfg.Ingest.Spamtrap.PollInterval.Duration)
	}
}

func TestBootstrapPeersDefaultEmpty(t *testing.T) {
	cfg := config.Defaults()
	if len(cfg.BootstrapPeers) != 0 {
		t.Errorf("Defaults().BootstrapPeers must be empty, got %v", cfg.BootstrapPeers)
	}
}

func TestBootstrapPeersFromYAML(t *testing.T) {
	raw := []byte(`
bootstrap_peers:
  - /ip4/1.2.3.4/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD
  - /ip4/5.6.7.8/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD
`)
	cfg, err := config.LoadYAML(raw)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if len(cfg.BootstrapPeers) != 2 {
		t.Fatalf("expected 2 bootstrap peers, got %d", len(cfg.BootstrapPeers))
	}
	if cfg.BootstrapPeers[0] != "/ip4/1.2.3.4/tcp/7700/p2p/12D3KooWBvpzbEBgcFbHrw3kEFjfdFB2AwimGMhMrVGQBHMpZNjD" {
		t.Errorf("unexpected peer[0]: %s", cfg.BootstrapPeers[0])
	}
}
