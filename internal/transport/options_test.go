package transport

import "testing"

func TestNodeModeConstants(t *testing.T) {
	if ModeLeaf != 0 {
		t.Fatalf("ModeLeaf should be 0, got %d", ModeLeaf)
	}
	if ModeRelay != 1 {
		t.Fatalf("ModeRelay should be 1, got %d", ModeRelay)
	}
	if DefaultTopic != "federloom/events/v2" {
		t.Fatalf("unexpected DefaultTopic: %q", DefaultTopic)
	}
}

func TestSubnetTopic(t *testing.T) {
	base := DefaultTopic
	cases := []struct{ subnet, want string }{
		{"", base},
		{"default", base},
		{"acme", base + "/acme"},
	}
	for _, c := range cases {
		if got := SubnetTopic(base, c.subnet); got != c.want {
			t.Errorf("SubnetTopic(%q, %q) = %q, want %q", base, c.subnet, got, c.want)
		}
	}
}
