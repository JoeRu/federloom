package ingest

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// maxCommandErrorOutput caps how much command output is folded into an error,
// so a chatty failure cannot flood the log every poll.
const maxCommandErrorOutput = 512

// commandError wraps a failed external command's error with what the command
// printed. A bare *exec.ExitError reads only "exit status 1"; the reason
// ("Cannot connect to the Docker daemon", "No such container") is in the
// output. out is the CombinedOutput, or the stdout of Output(), in which case
// the stderr captured in the ExitError is used. Returns nil for a nil err.
func commandError(err error, out []byte) error {
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	var exitErr *exec.ExitError
	if msg == "" && errors.As(err, &exitErr) {
		msg = strings.TrimSpace(string(exitErr.Stderr))
	}
	if msg == "" {
		return err
	}
	if len(msg) > maxCommandErrorOutput {
		msg = "…" + msg[len(msg)-maxCommandErrorOutput:]
	}
	return fmt.Errorf("%w: %s", err, msg)
}
