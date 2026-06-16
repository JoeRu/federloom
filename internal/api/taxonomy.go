package api

import (
	"strings"
)

// MatchesPatterns returns true if any string in reasons matches any pattern in patterns.
// A pattern matches if it equals the reason exactly, or if it ends in "*" and the
// reason starts with the prefix before the "*".
func MatchesPatterns(reasons []string, patterns []string) bool {
	for _, reason := range reasons {
		for _, pattern := range patterns {
			if strings.HasSuffix(pattern, "*") {
				// Prefix wildcard: check if reason starts with the prefix
				prefix := strings.TrimSuffix(pattern, "*")
				if strings.HasPrefix(reason, prefix) {
					return true
				}
			} else {
				// Exact match
				if reason == pattern {
					return true
				}
			}
		}
	}
	return false
}
