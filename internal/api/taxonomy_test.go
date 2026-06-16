package api

import (
	"testing"

	"github.com/JoeRu/swarmguard/internal/config"
)

func TestMatchesPatterns(t *testing.T) {
	tests := []struct {
		name     string
		reasons  []string
		patterns []string
		want     bool
	}{
		{
			name:     "exact match",
			reasons:  []string{"ssh-brute-force"},
			patterns: []string{"ssh-brute-force"},
			want:     true,
		},
		{
			name:     "prefix wildcard match",
			reasons:  []string{"smtp-auth-bruteforce"},
			patterns: []string{"smtp-*"},
			want:     true,
		},
		{
			name:     "no match",
			reasons:  []string{"http-scan"},
			patterns: []string{"ssh-*"},
			want:     false,
		},
		{
			name:     "empty reasons",
			reasons:  []string{},
			patterns: []string{"smtp-*"},
			want:     false,
		},
		{
			name:     "empty patterns",
			reasons:  []string{"smtp-auth"},
			patterns: []string{},
			want:     false,
		},
		{
			name:     "multiple reasons, one matches",
			reasons:  []string{"http-scan", "smtp-auth", "ssh-brute"},
			patterns: []string{"imap-*"},
			want:     false,
		},
		{
			name:     "multiple reasons, match second",
			reasons:  []string{"http-scan", "smtp-auth"},
			patterns: []string{"smtp-*"},
			want:     true,
		},
		{
			name:     "multiple patterns, second matches",
			reasons:  []string{"imap-login"},
			patterns: []string{"smtp-*", "imap-*"},
			want:     true,
		},
		{
			name:     "wildcard does not match different prefix",
			reasons:  []string{"smtpd-auth"},
			patterns: []string{"smtp-*"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesPatterns(tt.reasons, tt.patterns)
			if got != tt.want {
				t.Errorf("MatchesPatterns(%v, %v) = %v, want %v", tt.reasons, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestResolveTaxonomy(t *testing.T) {
	tests := []struct {
		name string
		t    config.TaxonomyConfig
		want config.TaxonomyConfig
	}{
		{
			name: "nil taxonomy returns default",
			t:    nil,
			want: config.TaxonomyConfig{
				"mail": {"smtp-*", "imap-*", "pop3-*"},
				"web":  {"http-*"},
				"ssh":  {"ssh-*"},
			},
		},
		{
			name: "empty taxonomy returns default",
			t:    config.TaxonomyConfig{},
			want: config.TaxonomyConfig{
				"mail": {"smtp-*", "imap-*", "pop3-*"},
				"web":  {"http-*"},
				"ssh":  {"ssh-*"},
			},
		},
		{
			name: "override existing key",
			t: config.TaxonomyConfig{
				"mail": {"custom-smtp-*"},
			},
			want: config.TaxonomyConfig{
				"mail": {"custom-smtp-*"},
				"web":  {"http-*"},
				"ssh":  {"ssh-*"},
			},
		},
		{
			name: "add new key",
			t: config.TaxonomyConfig{
				"dns": {"dns-query-*"},
			},
			want: config.TaxonomyConfig{
				"mail": {"smtp-*", "imap-*", "pop3-*"},
				"web":  {"http-*"},
				"ssh":  {"ssh-*"},
				"dns":  {"dns-query-*"},
			},
		},
		{
			name: "override and add",
			t: config.TaxonomyConfig{
				"mail": {"custom-mail-*"},
				"ftp":  {"ftp-*"},
			},
			want: config.TaxonomyConfig{
				"mail": {"custom-mail-*"},
				"web":  {"http-*"},
				"ssh":  {"ssh-*"},
				"ftp":  {"ftp-*"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveTaxonomy(tt.t)
			// Compare keys
			if len(got) != len(tt.want) {
				t.Errorf("ResolveTaxonomy() returned %d keys, want %d", len(got), len(tt.want))
			}
			for k, wantPatterns := range tt.want {
				gotPatterns, ok := got[k]
				if !ok {
					t.Errorf("ResolveTaxonomy() missing key %q", k)
					continue
				}
				if len(gotPatterns) != len(wantPatterns) {
					t.Errorf("ResolveTaxonomy()[%q] = %v, want %v", k, gotPatterns, wantPatterns)
				} else {
					for i, p := range gotPatterns {
						if i < len(wantPatterns) && p != wantPatterns[i] {
							t.Errorf("ResolveTaxonomy()[%q][%d] = %v, want %v", k, i, p, wantPatterns[i])
						}
					}
				}
			}
		})
	}
}

func TestPurposePatterns(t *testing.T) {
	taxonomy := ResolveTaxonomy(config.TaxonomyConfig{})

	tests := []struct {
		name    string
		purpose string
		want    []string
	}{
		{
			name:    "known purpose mail",
			purpose: "mail",
			want:    []string{"smtp-*", "imap-*", "pop3-*"},
		},
		{
			name:    "known purpose web",
			purpose: "web",
			want:    []string{"http-*"},
		},
		{
			name:    "known purpose ssh",
			purpose: "ssh",
			want:    []string{"ssh-*"},
		},
		{
			name:    "empty purpose returns nil",
			purpose: "",
			want:    nil,
		},
		{
			name:    "unknown purpose returns nil",
			purpose: "unknown",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PurposePatterns(taxonomy, tt.purpose)
			if len(got) != len(tt.want) {
				t.Errorf("PurposePatterns(%q) returned %d patterns, want %d", tt.purpose, len(got), len(tt.want))
			}
			for i, pattern := range got {
				if i < len(tt.want) && pattern != tt.want[i] {
					t.Errorf("PurposePatterns(%q)[%d] = %v, want %v", tt.purpose, i, pattern, tt.want[i])
				}
			}
		})
	}
}
