package main

import (
	"flag"

	"github.com/JoeRu/federloom/internal/config"
)

// addConfigFlag registers -config on fs and returns a loader that resolves
// the effective Config (defaults when no file is given — same as federloomd).
func addConfigFlag(fs *flag.FlagSet) func() (*config.Config, error) {
	path := fs.String("config", "", "path to YAML config file")
	return func() (*config.Config, error) {
		if *path == "" {
			return config.Defaults(), nil
		}
		return config.Load(*path)
	}
}
