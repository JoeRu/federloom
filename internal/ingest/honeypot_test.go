package ingest_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/ingest"
)

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

func TestHoneypotParsesLoginFailed(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cowrie.json")

	cfg := config.HoneypotConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	h := ingest.NewHoneypot(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := h.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		`{"eventid":"cowrie.login.failed","src_ip":"198.51.100.1","timestamp":"2026-06-10T10:00:00Z"}`,
	})

	select {
	case e := <-ch:
		if e.IP != "198.51.100.1" {
			t.Errorf("IP: got %q, want 198.51.100.1", e.IP)
		}
		if e.Reason != "ssh-auth-bruteforce" {
			t.Errorf("Reason: got %q, want ssh-auth-bruteforce", e.Reason)
		}
		if e.ReporterID != "selfpeer" {
			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestHoneypotSkipsEmptyIP(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cowrie.json")

	cfg := config.HoneypotConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	h := ingest.NewHoneypot(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch, err := h.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		`{"eventid":"cowrie.login.failed","src_ip":"","timestamp":"2026-06-10T10:00:00Z"}`,
	})

	select {
	case e := <-ch:
		t.Errorf("expected no event for empty IP, got %+v", e)
	case <-ctx.Done():
		// correct — no event emitted
	}
}

func TestHoneypotUnknownEventID(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cowrie.json")

	cfg := config.HoneypotConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	h := ingest.NewHoneypot(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := h.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		`{"eventid":"cowrie.some.new.event","src_ip":"203.0.113.5","timestamp":"2026-06-10T10:00:00Z"}`,
	})

	select {
	case e := <-ch:
		if e.Reason != "ssh-unknown" {
			t.Errorf("expected ssh-unknown for unknown eventid, got %q", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}
