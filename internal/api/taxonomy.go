package api

import (
	"strings"

	"github.com/JoeRu/swarmguard/internal/config"
)

// DefaultTaxonomy maps built-in purpose labels to reason-code patterns.
// Patterns are matched as exact strings or prefix wildcards ending in "*".
var DefaultTaxonomy = config.TaxonomyConfig{
	"mail": {"smtp-*", "imap-*", "pop3-*"},
	"web":  {"http-*"},
	"ssh":  {"ssh-*"},
}

// ResolveTaxonomy returns the effective taxonomy by merging t over DefaultTaxonomy.
// Keys in t override defaults for the same purpose; new keys are additive.
// A nil/empty t returns DefaultTaxonomy unchanged.
func ResolveTaxonomy(t config.TaxonomyConfig) config.TaxonomyConfig {
	if len(t) == 0 {
		return DefaultTaxonomy
	}
	merged := make(config.TaxonomyConfig, len(DefaultTaxonomy))
	for k, v := range DefaultTaxonomy {
		merged[k] = v
	}
	for k, v := range t {
		merged[k] = v
	}
	return merged
}

// MatchesPatterns returns true if any string in reasons matches any pattern in patterns.
// A pattern matches if it equals the reason exactly, or if it ends in "*" and the
// reason starts with the prefix before the "*".
func MatchesPatterns(reasons []string, patterns []string) bool {
	for _, r := range reasons {
		for _, p := range patterns {
			if strings.HasSuffix(p, "*") {
				if strings.HasPrefix(r, p[:len(p)-1]) {
					return true
				}
			} else if r == p {
				return true
			}
		}
	}
	return false
}

// PurposePatterns returns the pattern list for the named purpose from taxonomy t
// (t should already be resolved via ResolveTaxonomy). Returns nil when purpose is ""
// (meaning "all") or when the purpose is not in the taxonomy.
func PurposePatterns(t config.TaxonomyConfig, purpose string) []string {
	if purpose == "" {
		return nil
	}
	return t[purpose]
}
