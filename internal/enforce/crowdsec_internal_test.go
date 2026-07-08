package enforce

import "testing"

// TestCrowdSecScopeForValue lives in package enforce (white-box) because
// csScopeFor is unexported; crowdsec_test.go is package enforce_test
// (black-box, exercises the HTTP surface via mockLAPI) and cannot see it.
func TestCrowdSecScopeForValue(t *testing.T) {
	if got := csScopeFor("1.2.3.4"); got != "Ip" {
		t.Errorf("IPv4 scope = %q, want Ip", got)
	}
	if got := csScopeFor("2001:db8:1:2::/64"); got != "Range" {
		t.Errorf("IPv6 CIDR scope = %q, want Range", got)
	}
}
