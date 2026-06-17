package ingest_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/ingest"
)

func TestSpamtrapEmitsEvent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "spamtrap.log")

	cfg := config.SpamtrapConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	s := ingest.NewSpamtrap(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{"198.51.100.5"})

	select {
	case e := <-ch:
		if e.IP != "198.51.100.5" {
			t.Errorf("IP: got %q, want 198.51.100.5", e.IP)
		}
		if e.Reason != "smtp-spamtrap" {
			t.Errorf("Reason: got %q, want smtp-spamtrap", e.Reason)
		}
		if e.ReporterID != "selfpeer" {
			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestSpamtrapSkipsComments(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "spamtrap.log")

	cfg := config.SpamtrapConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	s := ingest.NewSpamtrap(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		"# this is a comment",
		"",
		"   ",
	})

	select {
	case e := <-ch:
		t.Errorf("expected no event for comment/blank lines, got %+v", e)
	case <-ctx.Done():
		// correct
	}
}

func TestSpamtrapSkipsInvalidIP(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "spamtrap.log")

	cfg := config.SpamtrapConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	s := ingest.NewSpamtrap(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{"not-an-ip", "256.1.2.3"})

	select {
	case e := <-ch:
		t.Errorf("expected no event for invalid IPs, got %+v", e)
	case <-ctx.Done():
		// correct
	}
}

func TestSpamtrapMultipleIPs(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "spamtrap.log")

	cfg := config.SpamtrapConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	s := ingest.NewSpamtrap(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		"# attacker 1",
		"198.51.100.10",
		"198.51.100.11",
	})

	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case e := <-ch:
			seen[e.IP] = true
		case <-ctx.Done():
			t.Fatalf("timed out after seeing %d events: %v", i, seen)
		}
	}
	if !seen["198.51.100.10"] || !seen["198.51.100.11"] {
		t.Errorf("missing expected IPs: got %v", seen)
	}
}
