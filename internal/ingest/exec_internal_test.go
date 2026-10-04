package ingest

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// TestCommandErrorIncludesOutput guards the 2026-10-03 mail.jru.me incident:
// a stale docker.sock made every fetch log only "exit status 1", hiding
// "Cannot connect to the Docker daemon".
func TestCommandErrorIncludesOutput(t *testing.T) {
	out, err := exec.CommandContext(context.Background(), "sh", "-c",
		"echo 'Cannot connect to the Docker daemon' >&2; exit 1").CombinedOutput()
	got := commandError(err, out)
	if got == nil {
		t.Fatal("expected error")
	}
	if msg := got.Error(); !strings.Contains(msg, "exit status 1") || !strings.Contains(msg, "Cannot connect to the Docker daemon") {
		t.Errorf("error = %q, want exit status and daemon message", msg)
	}
	var exitErr *exec.ExitError
	if !errors.As(got, &exitErr) {
		t.Error("wrapped error should still unwrap to *exec.ExitError")
	}
}

func TestCommandErrorUsesExitErrorStderr(t *testing.T) {
	// .Output() leaves stdout empty and puts stderr in ExitError.Stderr.
	out, err := exec.CommandContext(context.Background(), "sh", "-c",
		"echo 'No such container: x' >&2; exit 1").Output()
	if msg := commandError(err, out).Error(); !strings.Contains(msg, "No such container: x") {
		t.Errorf("error = %q, want stderr text", msg)
	}
}

func TestCommandErrorTruncatesAndPassesNil(t *testing.T) {
	if commandError(nil, []byte("ok")) != nil {
		t.Error("nil error should stay nil")
	}
	long := strings.Repeat("x", 2000)
	msg := commandError(errors.New("exit status 1"), []byte(long)).Error()
	if len(msg) > maxCommandErrorOutput+64 {
		t.Errorf("message not truncated: %d bytes", len(msg))
	}
}
