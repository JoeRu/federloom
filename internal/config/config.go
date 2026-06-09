// Package config loads SwarmGuard configuration (YAML + ENV override).
package config

// Config is the top-level runtime configuration. Fields are filled in as the
// implementation lands; see deploy/examples/*.yaml for the intended shape.
type Config struct {
	// FederationMode: "solo" | "federated" | "isolated"
	FederationMode string `yaml:"federation_mode"`
}
