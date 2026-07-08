package config_test

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
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
	cfg.Store.Dir = "/var/lib/federloom"
	if got := cfg.TrustAnchorsFile(); got != "/var/lib/federloom/anchors.json" {
		t.Errorf("TrustAnchorsFile = %q", got)
	}
	if got := cfg.TrustPersonKeyFile(); got != "/var/lib/federloom/person.key" {
		t.Errorf("TrustPersonKeyFile = %q", got)
	}
	if got := cfg.TrustPeerCertFile(); got != "/var/lib/federloom/peer.cert" {
		t.Errorf("TrustPeerCertFile = %q", got)
	}
	if got := cfg.TrustCertsFile(); got != "/var/lib/federloom/imported-certs.json" {
		t.Errorf("TrustCertsFile = %q", got)
	}
}

func TestTrustPathOverrides(t *testing.T) {
	cfg, err := config.LoadYAML([]byte("trust:\n  anchors_file: /etc/federloom/anchors.json\n  stranger_score_cap: 5\n"))
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if got := cfg.TrustAnchorsFile(); got != "/etc/federloom/anchors.json" {
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

func TestDNSBLConfigDefaultDisabled(t *testing.T) {
	cfg := config.Defaults()
	if cfg.DNSBL.Addr != "" {
		t.Errorf("DNSBL.Addr must be empty by default, got %q", cfg.DNSBL.Addr)
	}
	if cfg.DNSBL.Zone != "" {
		t.Errorf("DNSBL.Zone must be empty by default, got %q", cfg.DNSBL.Zone)
	}
}

func TestDNSBLConfigFromYAML(t *testing.T) {
	raw := []byte(`
dnsbl:
  addr: ":5353"
  zone: "dnsbl.mail.example.com."
  min_score: 80
`)
	cfg, err := config.LoadYAML(raw)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if cfg.DNSBL.Addr != ":5353" {
		t.Errorf("Addr: got %q, want :5353", cfg.DNSBL.Addr)
	}
	if cfg.DNSBL.Zone != "dnsbl.mail.example.com." {
		t.Errorf("Zone: got %q, want dnsbl.mail.example.com.", cfg.DNSBL.Zone)
	}
	if cfg.DNSBL.MinScore != 80 {
		t.Errorf("MinScore: got %v, want 80", cfg.DNSBL.MinScore)
	}
}

func TestFail2BanDefaults(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Ingest.Fail2Ban.Container != "fail2ban" {
		t.Errorf("fail2ban container default: got %q, want \"fail2ban\"", cfg.Ingest.Fail2Ban.Container)
	}
	if cfg.Ingest.Fail2Ban.PollInterval.Duration != 30*time.Second {
		t.Errorf("fail2ban poll_interval default: got %v, want 30s", cfg.Ingest.Fail2Ban.PollInterval.Duration)
	}
	if cfg.Ingest.Fail2Ban.Enabled {
		t.Error("fail2ban must default to disabled")
	}
}

func TestDiscoveryDefaults(t *testing.T) {
	cfg := config.Defaults()
	if !cfg.Discovery.Advertise {
		t.Error("discovery.advertise must default to true")
	}
	if !cfg.Discovery.Discover {
		t.Error("discovery.discover must default to true")
	}
}

func TestFederationDiscountDefault(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Trust.FederationDiscount != 0.5 {
		t.Errorf("trust.federation_discount want 0.5 got %v", cfg.Trust.FederationDiscount)
	}
}

func TestTrustBlockedPeersFile(t *testing.T) {
	cfg := config.Defaults()
	cfg.Store.Dir = "/tmp/sg-test"
	want := "/tmp/sg-test/blocked-peers.json"
	if got := cfg.TrustBlockedPeersFile(); got != want {
		t.Errorf("TrustBlockedPeersFile() = %q want %q", got, want)
	}
}

func TestBlockedPeersFileOverride(t *testing.T) {
	cfg := config.Defaults()
	cfg.Trust.BlockedPeersFile = "/custom/blocked.json"
	if got := cfg.TrustBlockedPeersFile(); got != "/custom/blocked.json" {
		t.Errorf("TrustBlockedPeersFile() = %q want /custom/blocked.json", got)
	}
}

func TestEffectiveIPv6Prefix(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, 64},    // unset → default
		{64, 64},   // valid
		{56, 56},   // router allocation
		{128, 128}, // single host
		{-1, 64},   // out of range → default
		{129, 64},  // out of range → default
	}
	for _, c := range cases {
		got := config.ReputationConfig{IPv6Prefix: c.in}.EffectiveIPv6Prefix()
		if got != c.want {
			t.Errorf("EffectiveIPv6Prefix(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestDefaultsIPv6Prefix(t *testing.T) {
	if got := config.Defaults().Reputation.IPv6Prefix; got != 64 {
		t.Errorf("default IPv6Prefix = %d, want 64", got)
	}
}

func TestEffectiveBridgeSubnets(t *testing.T) {
	c := &config.Config{
		FederationSubnet:        "a",
		FederationBridgeSubnets: []string{"a", "b", "c"},
	}
	got := c.EffectiveBridgeSubnets()
	want := []string{"b", "c"} // "a" == home subnet is dropped
	if len(got) != len(want) {
		t.Fatalf("EffectiveBridgeSubnets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestEffectiveBridgeSubnetsEmpty(t *testing.T) {
	c := &config.Config{}
	if got := c.EffectiveBridgeSubnets(); len(got) != 0 {
		t.Errorf("expected no bridge subnets, got %v", got)
	}
}

// TestEffectiveBridgeSubnetsDropsDefaultAlias proves that when the home
// subnet is "" (the base topic), a bridge subnet of "default" — its documented
// synonym — is dropped too, since both map to the same gossip topic
// (transport.SubnetTopic). Without this, transport.New would try to join the
// identical topic twice and fail with "topic already exists".
func TestEffectiveBridgeSubnetsDropsDefaultAlias(t *testing.T) {
	c := &config.Config{
		FederationSubnet:        "",
		FederationBridgeSubnets: []string{"default", "b"},
	}
	got := c.EffectiveBridgeSubnets()
	want := []string{"b"}
	if len(got) != len(want) {
		t.Fatalf("EffectiveBridgeSubnets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d = %q, want %q", i, got[i], want[i])
		}
	}
}
