package ingest_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/ingest"
)

func TestOpenCanaryParsesSMTPProbe(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "opencanary.log")

	cfg := config.OpenCanaryConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	o := ingest.NewOpenCanary(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := o.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		`{"src_host":"198.51.100.1","logtype":3000,"local_time":"2026-06-12 10:00:00.000000"}`,
	})

	select {
	case e := <-ch:
		if e.IP != "198.51.100.1" {
			t.Errorf("IP: got %q, want 198.51.100.1", e.IP)
		}
		if e.Reason != "smtp-probe" {
			t.Errorf("Reason: got %q, want smtp-probe", e.Reason)
		}
		if e.ReporterID != "selfpeer" {
			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestOpenCanaryParsesIMAPAuthBruteforce(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "opencanary.log")

	cfg := config.OpenCanaryConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	o := ingest.NewOpenCanary(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := o.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		`{"src_host":"203.0.113.7","logtype":2101,"local_time":"2026-06-12 10:00:01.000000"}`,
	})

	select {
	case e := <-ch:
		if e.IP != "203.0.113.7" {
			t.Errorf("IP: got %q, want 203.0.113.7", e.IP)
		}
		if e.Reason != "imap-auth-bruteforce" {
			t.Errorf("Reason: got %q, want imap-auth-bruteforce", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestOpenCanarySkipsEmptyHost(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "opencanary.log")

	cfg := config.OpenCanaryConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	o := ingest.NewOpenCanary(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch, err := o.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		`{"src_host":"","logtype":3000,"local_time":"2026-06-12 10:00:00.000000"}`,
	})

	select {
	case e := <-ch:
		t.Errorf("expected no event for empty src_host, got %+v", e)
	case <-ctx.Done():
		// correct — no event emitted
	}
}

func TestOpenCanaryUnknownLogtype(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "opencanary.log")

	cfg := config.OpenCanaryConfig{
		Enabled:      true,
		LogFile:      logPath,
		PollInterval: config.Duration{Duration: 50 * time.Millisecond},
	}
	o := ingest.NewOpenCanary(cfg, "selfpeer")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := o.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	writeLines(t, logPath, []string{
		`{"src_host":"198.51.100.2","logtype":9999,"local_time":"2026-06-12 10:00:00.000000"}`,
	})

	select {
	case e := <-ch:
		if e.Reason != "opencanary-unknown" {
			t.Errorf("Reason: got %q, want opencanary-unknown", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}
