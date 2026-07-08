package netutil

import "testing"

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		name, in string
		prefix   int
		want     string
		wantErr  bool
	}{
		{"ipv4 bare", "1.2.3.4", 64, "1.2.3.4", false},
		{"ipv4-mapped", "::ffff:1.2.3.4", 64, "1.2.3.4", false},
		{"ipv6 128 to 64", "2001:db8:1:2:aaaa::1", 64, "2001:db8:1:2::/64", false},
		{"ipv6 other 128 same 64", "2001:db8:1:2:ffff::9", 64, "2001:db8:1:2::/64", false},
		{"ipv6 different 64", "2001:db8:1:3::1", 64, "2001:db8:1:3::/64", false},
		{"ipv6 prefix 56", "2001:db8:1:2:aaaa::1", 56, "2001:db8:1::/56", false},
		{"ipv6 prefix 128", "2001:db8:1:2::5", 128, "2001:db8:1:2::5/128", false},
		{"ipv6 cidr input remask 56", "2001:db8:1:2::/64", 56, "2001:db8:1::/56", false},
		{"wide ipv6 cidr contained", "2000::/3", 64, "2000::/64", false},
		{"invalid", "not-an-ip", 64, "", true},
		{"ipv4 cidr rejected", "0.0.0.0/0", 64, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormalizeIP(c.in, c.prefix)
			if c.wantErr {
				if err == nil {
					t.Fatalf("NormalizeIP(%q) = %q, want error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeIP(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("NormalizeIP(%q, %d) = %q, want %q", c.in, c.prefix, got, c.want)
			}
		})
	}
}

func TestKeyAddr(t *testing.T) {
	a, ok := KeyAddr("1.2.3.4")
	if !ok || a.String() != "1.2.3.4" {
		t.Errorf("KeyAddr(1.2.3.4) = %v,%v", a, ok)
	}
	a, ok = KeyAddr("2001:db8:1:2::/64")
	if !ok || a.String() != "2001:db8:1:2::" {
		t.Errorf("KeyAddr(/64) base = %v,%v, want 2001:db8:1:2::", a, ok)
	}
	if _, ok := KeyAddr("nonsense"); ok {
		t.Error("KeyAddr(nonsense) ok=true, want false")
	}
}
