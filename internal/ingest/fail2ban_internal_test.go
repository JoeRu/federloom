package ingest

import (
	"testing"

	"github.com/JoeRu/swarmguard/internal/config"
)

// TestParseBanned exercises the parseBanned pure function directly.
func TestParseBanned(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantIPs map[string]string // ip → expected jail
		wantErr bool
	}{
		{
			name:    "empty array",
			input:   `[]`,
			wantLen: 0,
			wantIPs: map[string]string{},
		},
		{
			name:  "multi-jail",
			input: `[{"sshd": ["1.2.3.4", "5.6.7.8"]}, {"postfix-sasl": ["9.9.9.9"]}]`,
			wantIPs: map[string]string{
				"1.2.3.4": "sshd",
				"5.6.7.8": "sshd",
				"9.9.9.9": "postfix-sasl",
			},
		},
		{
			name:    "malformed json",
			input:   `{not json}`,
			wantErr: true,
		},
		{
			name:    "null ip list",
			input:   `[{"sshd": null}]`,
			wantLen: 0,
			wantIPs: map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseBanned([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Check explicit IP→jail expectations.
			for ip, wantJail := range tc.wantIPs {
				if gotJail, ok := got[ip]; !ok {
					t.Errorf("missing IP %q in result", ip)
				} else if gotJail != wantJail {
					t.Errorf("IP %q: jail got %q, want %q", ip, gotJail, wantJail)
				}
			}
			// Check total length.
			expectedLen := len(tc.wantIPs)
			if tc.wantLen > 0 {
				expectedLen = tc.wantLen
			}
			if len(got) != expectedLen {
				t.Errorf("result length: got %d, want %d", len(got), expectedLen)
			}
		})
	}
}

// TestResolveReason exercises the resolveReason method in isolation.
func TestResolveReason(t *testing.T) {
	tests := []struct {
		name        string
		jailReasons map[string]string // operator config overrides (nil = none)
		jail        string
		want        string
	}{
		{
			name: "exact built-in sshd",
			jail: "sshd",
			want: "ssh-auth-bruteforce",
		},
		{
			name: "prefix built-in sshd-aggressive",
			jail: "sshd-aggressive",
			want: "ssh-auth-bruteforce",
		},
		{
			name: "prefix built-in wp-login",
			jail: "wp-login",
			want: "http-wp-bruteforce",
		},
		{
			name:        "config override exact",
			jailReasons: map[string]string{"my-custom-jail": "custom-reason"},
			jail:        "my-custom-jail",
			want:        "custom-reason",
		},
		{
			name: "fallback unknown jail",
			jail: "unknown-jail",
			want: "fail2ban-unknown-jail",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Fail2BanConfig{
				JailReasons: tc.jailReasons,
			}
			f := &Fail2Ban{cfg: cfg}
			got := f.resolveReason(tc.jail)
			if got != tc.want {
				t.Errorf("resolveReason(%q) = %q, want %q", tc.jail, got, tc.want)
			}
		})
	}
}
