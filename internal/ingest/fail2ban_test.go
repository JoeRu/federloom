package ingest_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/config"
	"github.com/JoeRu/federloom/internal/ingest"
)

func makeFail2BanCfg(poll time.Duration) config.Fail2BanConfig {
	return config.Fail2BanConfig{
		Enabled:      true,
		Container:    "test-fail2ban",
		PollInterval: config.Duration{Duration: poll},
	}
}

// TestFail2Ban_NewBan: a newly-banned IP emits one event with the correct reason.
func TestFail2Ban_NewBan(t *testing.T) {
	stub := func(_ context.Context, _ string) ([]byte, error) {
		return []byte(`[{"sshd": ["1.2.3.4"]}]`), nil
	}
	f := ingest.NewFail2BanWithFetcher(makeFail2BanCfg(50*time.Millisecond), "selfpeer", stub)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := f.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case e := <-ch:
		if e.IP != "1.2.3.4" {
			t.Errorf("IP: got %q, want 1.2.3.4", e.IP)
		}
		if e.Reason != "ssh-auth-bruteforce" {
			t.Errorf("Reason: got %q, want ssh-auth-bruteforce", e.Reason)
		}
		if e.ReporterID != "selfpeer" {
			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
		}
		if e.Timestamp.IsZero() {
			t.Error("Timestamp must not be zero")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

// TestFail2Ban_NoDuplicate: same IP present on every poll → only one event ever.
func TestFail2Ban_NoDuplicate(t *testing.T) {
	stub := func(_ context.Context, _ string) ([]byte, error) {
		return []byte(`[{"sshd": ["1.2.3.4"]}]`), nil
	}
	f := ingest.NewFail2BanWithFetcher(makeFail2BanCfg(50*time.Millisecond), "selfpeer", stub)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := f.Start(ctx)

	// Drain the first event.
	select {
	case <-ch:
	case <-ctx.Done():
		t.Fatal("timed out waiting for first event")
	}

	// Allow 3 more poll cycles; no second event should arrive.
	select {
	case e := <-ch:
		t.Errorf("unexpected duplicate event: IP=%s Reason=%s", e.IP, e.Reason)
	case <-time.After(200 * time.Millisecond):
		// correct — no duplicate
	}
}

// TestFail2Ban_Reban: IP unbanned then re-banned → event emitted again.
func TestFail2Ban_Reban(t *testing.T) {
	var mu sync.Mutex
	callN := 0
	stub := func(_ context.Context, _ string) ([]byte, error) {
		mu.Lock()
		n := callN
		callN++
		mu.Unlock()
		switch n {
		case 0:
			return []byte(`[{"sshd": ["1.2.3.4"]}]`), nil // banned
		case 1:
			return []byte(`[]`), nil // unbanned
		default:
			return []byte(`[{"sshd": ["1.2.3.4"]}]`), nil // re-banned
		}
	}
	f := ingest.NewFail2BanWithFetcher(makeFail2BanCfg(50*time.Millisecond), "selfpeer", stub)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := f.Start(ctx)

	// First ban event.
	select {
	case e := <-ch:
		if e.IP != "1.2.3.4" {
			t.Errorf("first ban: IP got %q, want 1.2.3.4", e.IP)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for first ban event")
	}

	// Re-ban event after unban cycle.
	select {
	case e := <-ch:
		if e.IP != "1.2.3.4" {
			t.Errorf("re-ban: IP got %q, want 1.2.3.4", e.IP)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for re-ban event")
	}
}

// TestFail2Ban_UnknownJail: unknown jail → reason is "fail2ban-<jailname>".
func TestFail2Ban_UnknownJail(t *testing.T) {
	stub := func(_ context.Context, _ string) ([]byte, error) {
		return []byte(`[{"my-custom-jail": ["2.2.2.2"]}]`), nil
	}
	f := ingest.NewFail2BanWithFetcher(makeFail2BanCfg(50*time.Millisecond), "selfpeer", stub)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := f.Start(ctx)

	select {
	case e := <-ch:
		if e.Reason != "fail2ban-my-custom-jail" {
			t.Errorf("Reason: got %q, want fail2ban-my-custom-jail", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

// TestFail2Ban_InvalidMode: unknown mode → Start returns an error.
func TestFail2Ban_InvalidMode(t *testing.T) {
	cfg := makeFail2BanCfg(50 * time.Millisecond)
	cfg.Mode = "bogus"
	f := ingest.NewFail2Ban(cfg, "selfpeer")
	if _, err := f.Start(context.Background()); err == nil {
		t.Fatal("Start: want error for mode \"bogus\", got nil")
	}
}

// TestFail2Ban_LocalModeStarts: mode "local" is accepted (fetcher wired).
func TestFail2Ban_LocalModeStarts(t *testing.T) {
	cfg := makeFail2BanCfg(time.Hour) // long poll: fetcher never actually runs
	cfg.Mode = "local"
	f := ingest.NewFail2Ban(cfg, "selfpeer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := f.Start(ctx); err != nil {
		t.Fatalf("Start: unexpected error for mode \"local\": %v", err)
	}
}

// TestFail2Ban_DockerModeDefault: empty mode behaves as docker mode (no error).
func TestFail2Ban_DockerModeDefault(t *testing.T) {
	cfg := makeFail2BanCfg(time.Hour)
	cfg.Mode = ""
	f := ingest.NewFail2Ban(cfg, "selfpeer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := f.Start(ctx); err != nil {
		t.Fatalf("Start: unexpected error for empty mode: %v", err)
	}
}
