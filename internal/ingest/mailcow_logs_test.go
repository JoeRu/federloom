package ingest_test

import (
	"context"
	"testing"
	"time"

	"github.com/JoeRu/swarmguard/internal/config"
	"github.com/JoeRu/swarmguard/internal/ingest"
)

// makeMailcow returns a MailcowLogs adapter with a stub log fetcher.
func makeMailcow(t *testing.T, stubLines func(container string) []byte) *ingest.MailcowLogs {
	t.Helper()
	cfg := config.MailcowConfig{
		Enabled:          true,
		PostfixContainer: "test-postfix",
		DovecotContainer: "test-dovecot",
		PollInterval:     config.Duration{Duration: 50 * time.Millisecond},
	}
	return ingest.NewMailcowWithFetcher(cfg, "selfpeer", func(_ context.Context, container, _ string) ([]byte, error) {
		return stubLines(container), nil
	})
}

func TestMailcowPostfixSASLLoginFailure(t *testing.T) {
	m := makeMailcow(t, func(container string) []byte {
		if container == "test-postfix" {
			return []byte("Jun 17 10:12:34 mx postfix/smtpd[123]: warning: unknown[198.51.100.1]: SASL LOGIN authentication failed: authentication failure\n")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case e := <-ch:
		if e.IP != "198.51.100.1" {
			t.Errorf("IP: got %q, want 198.51.100.1", e.IP)
		}
		if e.Reason != "smtp-auth-bruteforce" {
			t.Errorf("Reason: got %q, want smtp-auth-bruteforce", e.Reason)
		}
		if e.ReporterID != "selfpeer" {
			t.Errorf("ReporterID: got %q, want selfpeer", e.ReporterID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestMailcowPostfixSASLPlainWithHostname(t *testing.T) {
	m := makeMailcow(t, func(container string) []byte {
		if container == "test-postfix" {
			return []byte("Jun 17 10:12:34 mx postfix/smtpd[123]: warning: mail.evil.com[203.0.113.5]: SASL PLAIN authentication failed: authentication failure\n")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := m.Start(ctx)

	select {
	case e := <-ch:
		if e.IP != "203.0.113.5" {
			t.Errorf("IP: got %q, want 203.0.113.5", e.IP)
		}
		if e.Reason != "smtp-auth-bruteforce" {
			t.Errorf("Reason: got %q, want smtp-auth-bruteforce", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestMailcowDovecotIMAPAuthFailed(t *testing.T) {
	m := makeMailcow(t, func(container string) []byte {
		if container == "test-dovecot" {
			return []byte("Jun 17 10:12:34 mx dovecot: imap-login: Disconnected (auth failed, 3 attempts in 10 secs): user=<test@mail.com>, method=PLAIN, rip=198.51.100.2, lip=172.22.1.3\n")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := m.Start(ctx)

	select {
	case e := <-ch:
		if e.IP != "198.51.100.2" {
			t.Errorf("IP: got %q, want 198.51.100.2", e.IP)
		}
		if e.Reason != "imap-auth-bruteforce" {
			t.Errorf("Reason: got %q, want imap-auth-bruteforce", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestMailcowDovecotPOP3AuthFailed(t *testing.T) {
	m := makeMailcow(t, func(container string) []byte {
		if container == "test-dovecot" {
			return []byte("Jun 17 10:12:34 mx dovecot: pop3-login: Disconnected (auth failed): user=<test>, method=PLAIN, rip=203.0.113.7, lip=172.22.1.3\n")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := m.Start(ctx)

	select {
	case e := <-ch:
		if e.IP != "203.0.113.7" {
			t.Errorf("IP: got %q, want 203.0.113.7", e.IP)
		}
		if e.Reason != "pop3-auth-bruteforce" {
			t.Errorf("Reason: got %q, want pop3-auth-bruteforce", e.Reason)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}
}

func TestMailcowSkipsNonAuthLines(t *testing.T) {
	m := makeMailcow(t, func(container string) []byte {
		if container == "test-postfix" {
			return []byte("Jun 17 10:12:34 mx postfix/smtpd[123]: connect from unknown[198.51.100.1]\n")
		}
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	ch, _ := m.Start(ctx)

	select {
	case e := <-ch:
		t.Errorf("expected no event for connect line, got %+v", e)
	case <-ctx.Done():
		// correct — no event
	}
}
