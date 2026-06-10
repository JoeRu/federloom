package transport

import "testing"

func TestNodeModeConstants(t *testing.T) {
	if ModeLeaf != 0 {
		t.Fatalf("ModeLeaf should be 0, got %d", ModeLeaf)
	}
	if ModeRelay != 1 {
		t.Fatalf("ModeRelay should be 1, got %d", ModeRelay)
	}
	if DefaultTopic != "swarmguard/events/v0" {
		t.Fatalf("unexpected DefaultTopic: %q", DefaultTopic)
	}
}
