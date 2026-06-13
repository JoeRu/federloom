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
	FederationMode string           `yaml:"federation_mode"`
	Store          StoreConfig      `yaml:"store"`
	Reputation     ReputationConfig `yaml:"reputation"`
	Ingest         IngestConfig     `yaml:"ingest"`
	Enforce        EnforceConfig    `yaml:"enforce"`
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
}

// IngestConfig groups all ingest source configs.
type IngestConfig struct {
	Honeypot   HoneypotConfig   `yaml:"honeypot"`
	OpenCanary OpenCanaryConfig `yaml:"opencanary"`
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

// EnforceConfig selects and tunes the firewall backend.
type EnforceConfig struct {
	Backend        string   `yaml:"backend"`
	SetName        string   `yaml:"set_name"`
	Chain          string   `yaml:"chain"`
	NftHook        string   `yaml:"nft_hook"`
	ExtraWhitelist []string `yaml:"extra_whitelist"`
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
