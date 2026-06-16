package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration for YAML unmarshalling from strings like "7d", "24h".
type Duration struct{ time.Duration }

// TaxonomyConfig maps purpose labels to lists of reason-code patterns.
// Pattern matching: exact string OR prefix ending in "*" (e.g. "smtp-*" matches any reason starting with "smtp-").
type TaxonomyConfig map[string][]string

// APIConfig controls the optional local HTTP API (spec §3).
// Addr is the only required field; empty string disables the server (same opt-in pattern as PrometheusAddr).
type APIConfig struct {
	Addr     string         `yaml:"addr"`     // e.g. ":9102"; "" = disabled
	Purpose  string         `yaml:"purpose"`  // default blocklist filter: "mail", "web", "ssh", "" = all
	Taxonomy TaxonomyConfig `yaml:"taxonomy"` // empty = use built-in default taxonomy (mail/web/ssh)
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("config: parse duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// Config is the top-level runtime configuration.
type Config struct {
	FederationMode string              `yaml:"federation_mode"`
	Store          StoreConfig         `yaml:"store"`
	Reputation     ReputationConfig    `yaml:"reputation"`
	Ingest         IngestConfig        `yaml:"ingest"`
	Enforce        EnforceConfig       `yaml:"enforce"`
	Trust          TrustConfig         `yaml:"trust"`
	Observability  ObservabilityConfig `yaml:"observability"`
	API            APIConfig           `yaml:"api"`
}

// StoreConfig configures the BadgerDB reputation store.
type StoreConfig struct {
	Dir string `yaml:"dir"`
}

// ReputationConfig tunes the scoring engine.
type ReputationConfig struct {
	HalfLife         Duration `yaml:"half_life"`
	BlockThreshold   float64  `yaml:"block_threshold"`
	UnblockThreshold float64  `yaml:"unblock_threshold"`
	DecayInterval    Duration `yaml:"decay_interval"`
	RulesFile        string   `yaml:"rules_file"` // empty = legacy threshold mode
}

// IngestConfig groups all ingest source configs.
type IngestConfig struct {
	Honeypot   HoneypotConfig   `yaml:"honeypot"`
	OpenCanary OpenCanaryConfig `yaml:"opencanary"`
	CrowdSec   CrowdSecConfig   `yaml:"crowdsec"`
}

// OpenCanaryConfig configures the OpenCanary ingest adapter.
type OpenCanaryConfig struct {
	Enabled      bool     `yaml:"enabled"`
	LogFile      string   `yaml:"log_file"`
	PollInterval Duration `yaml:"poll_interval"`
}

// HoneypotConfig configures the Cowrie ingest adapter.
type HoneypotConfig struct {
	Enabled      bool     `yaml:"enabled"`
	LogFile      string   `yaml:"log_file"`
	PollInterval Duration `yaml:"poll_interval"`
}

// CrowdSecConfig configures the CrowdSec LAPI ingest adapter.
// Two auth modes:
//   - Bouncer (api_key): read /v1/decisions only
//   - Machine (machine_id + machine_password): read /v1/decisions and /v1/alerts via JWT
type CrowdSecConfig struct {
	Enabled         bool     `yaml:"enabled"`
	LAPIURL         string   `yaml:"lapi_url"`
	APIKey          string   `yaml:"api_key"`           // bouncer key — decisions only
	MachineID       string   `yaml:"machine_id"`        // machine account — decisions + alerts
	MachinePassword string   `yaml:"machine_password"`  // machine account password
	PollInterval    Duration `yaml:"poll_interval"`
	EnableDecisions bool     `yaml:"enable_decisions"`
	EnableAlerts    bool     `yaml:"enable_alerts"`
}

// EnforceConfig selects and tunes the firewall backend.
type EnforceConfig struct {
	Backend        string   `yaml:"backend"`
	SetName        string   `yaml:"set_name"`
	Chain          string   `yaml:"chain"`
	NftHook        string   `yaml:"nft_hook"`
	ExtraWhitelist []string `yaml:"extra_whitelist"`
}

// TrustConfig tunes the social trust layer (spec §5.1, design doc
// docs/superpowers/specs/2026-06-12-social-trust-anchors-design.md).
// Every value is operator-overridable (Invariant 1).
type TrustConfig struct {
	AnchorsFile      string  `yaml:"anchors_file"`       // default <store.dir>/anchors.json
	PersonKeyFile    string  `yaml:"person_key_file"`    // default <store.dir>/person.key
	PeerCertFile     string  `yaml:"peer_cert_file"`     // default <store.dir>/peer.cert
	AnchorWeight     float64 `yaml:"anchor_weight"`      // default weight for a newly anchored Person
	StrangerWeight   float64 `yaml:"stranger_weight"`    // trust for un-vouched reporters
	StrangerScoreCap float64 `yaml:"stranger_score_cap"` // max total score strangers add per IP
}

// ObservabilityConfig controls the optional observability plane (spec §11.2).
// Both outputs are disabled by default; set non-empty values to enable.
type ObservabilityConfig struct {
	PrometheusAddr      string   `yaml:"prometheus_addr"`       // e.g. ":9101"; "" = disabled
	SQLitePath          string   `yaml:"sqlite_path"`           // path to metrics.db; "" = disabled
	SQLiteRetention     Duration `yaml:"sqlite_retention"`      // rows older than this are pruned
	ScoreGaugeThreshold float64  `yaml:"score_gauge_threshold"` // 0 = half of block_threshold
}

// Defaults returns a Config with sensible production defaults.
func Defaults() *Config {
	return &Config{
		FederationMode: "solo",
		Store:          StoreConfig{Dir: "data/reputation"},
		Reputation: ReputationConfig{
			HalfLife:         Duration{7 * 24 * time.Hour},
			BlockThreshold:   75,
			UnblockThreshold: 60,
			DecayInterval:    Duration{time.Hour},
		},
		Enforce: EnforceConfig{
			Backend: "ipset",
			SetName: "swarmguard",
			Chain:   "DOCKER-USER",
			NftHook: "input",
		},
		Ingest: IngestConfig{
			Honeypot: HoneypotConfig{
				PollInterval: Duration{time.Second},
			},
			OpenCanary: OpenCanaryConfig{
				PollInterval: Duration{time.Second},
			},
			CrowdSec: CrowdSecConfig{
				PollInterval:    Duration{30 * time.Second},
				EnableDecisions: true,
				EnableAlerts:    true,
				// Enabled: false (zero value — opt-in)
			},
		},
		Trust: TrustConfig{
			AnchorWeight:     0.9,
			StrangerWeight:   0.3,
			StrangerScoreCap: 15,
		},
	}
}

// LoadYAML unmarshals YAML bytes into a Config, applying defaults for unset fields.
func LoadYAML(data []byte) (*Config, error) {
	cfg := Defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	return cfg, nil
}

// Load reads a YAML config file from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	return LoadYAML(data)
}

// NodeKeyFile returns the path of the persistent libp2p node key.
func (c *Config) NodeKeyFile() string {
	return filepath.Join(c.Store.Dir, "identity.key")
}

// TrustAnchorsFile returns the anchors.json path (config override or store-dir default).
func (c *Config) TrustAnchorsFile() string {
	if c.Trust.AnchorsFile != "" {
		return c.Trust.AnchorsFile
	}
	return filepath.Join(c.Store.Dir, "anchors.json")
}

// TrustPersonKeyFile returns the Person identity key path.
func (c *Config) TrustPersonKeyFile() string {
	if c.Trust.PersonKeyFile != "" {
		return c.Trust.PersonKeyFile
	}
	return filepath.Join(c.Store.Dir, "person.key")
}

// TrustPeerCertFile returns the path of this node's own vouching cert.
func (c *Config) TrustPeerCertFile() string {
	if c.Trust.PeerCertFile != "" {
		return c.Trust.PeerCertFile
	}
	return filepath.Join(c.Store.Dir, "peer.cert")
}

// TrustCertsFile returns the path of the locally imported cert cache
// (seeded by `swarmctl trust import`; internal file, no config key).
func (c *Config) TrustCertsFile() string {
	return filepath.Join(c.Store.Dir, "imported-certs.json")
}

// RulesFilePath returns the path of the operator rule file. If rules_file is
// not set, it defaults to <store.dir>/rules.yaml (absent = legacy mode).
func (c *Config) RulesFilePath() string {
	if c.Reputation.RulesFile != "" {
		return c.Reputation.RulesFile
	}
	return filepath.Join(c.Store.Dir, "rules.yaml")
}
