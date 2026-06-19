package ingest_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/ingest"
)

func TestOpenCanaryParsesHTTPProbe(t *testing.T) {
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

	// logtype 3000 = LOG_HTTP_GET (OpenCanary logger.py); also fires for HTTPS GET
	// (CanaryHTTPS reuses CanaryHTTP handlers — dst_port distinguishes HTTP vs HTTPS).
	writeLines(t, logPath, []string{
		`{"src_host":"198.51.100.3","logtype":3000,"local_time":"2026-06-19 10:00:00.000000"}`,
	})

	select {
	case e := <-ch:
		if e.IP != "198.51.100.3" {
			t.Errorf("IP: got %q, want 198.51.100.3", e.IP)
		}
		if e.Reason != "http-probe" {
			t.Errorf("Reason: got %q, want http-probe", e.Reason)
		}
		if e.ReporterID != "selfpeer" {
			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestOpenCanaryParsesHTTPPostLoginAttempt(t *testing.T) {
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

	// logtype 3001 = LOG_HTTP_POST_LOGIN_ATTEMPT (OpenCanary logger.py)
	writeLines(t, logPath, []string{
		`{"src_host":"198.51.100.5","logtype":3001,"local_time":"2026-06-19 10:00:02.000000"}`,
	})

	select {
	case e := <-ch:
		if e.IP != "198.51.100.5" {
			t.Errorf("IP: got %q, want 198.51.100.5", e.IP)
		}
		if e.Reason != "http-post-login" {
			t.Errorf("Reason: got %q, want http-post-login", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestOpenCanaryParsesFTPLoginAttempt(t *testing.T) {
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

	// logtype 2000 = LOG_FTP_LOGIN_ATTEMPT (OpenCanary logger.py)
	writeLines(t, logPath, []string{
		`{"src_host":"203.0.113.7","logtype":2000,"local_time":"2026-06-19 10:00:01.000000"}`,
	})

	select {
	case e := <-ch:
		if e.IP != "203.0.113.7" {
			t.Errorf("IP: got %q, want 203.0.113.7", e.IP)
		}
		if e.Reason != "ftp-login-attempt" {
			t.Errorf("Reason: got %q, want ftp-login-attempt", e.Reason)
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
