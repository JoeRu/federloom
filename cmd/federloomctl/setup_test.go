package main

import (
	"testing"
)

// TestSetupPackageCompiles is a compile-time guard.
func TestSetupPackageCompiles(t *testing.T) {
	_ = cmdSetup
}
