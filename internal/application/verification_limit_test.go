package application

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestCryptoVerificationLimiterIsBoundedAndContextAware(t *testing.T) {
	svc := &Service{MaxConcurrentVerifications: 1}
	release, err := svc.acquireVerification(context.Background())
	if err != nil {
		t.Fatalf("acquire first slot: %v", err)
	}

	started := time.Now()
	if _, err := svc.acquireVerification(context.Background()); !errors.Is(err, ErrVerificationBusy) {
		t.Fatalf("second verifier was not rejected by the one-slot semaphore: %v", err)
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("excess verification was queued instead of rejected promptly")
	}

	release()
	releaseAgain, err := svc.acquireVerification(context.Background())
	if err != nil {
		t.Fatalf("released slot was not reusable: %v", err)
	}
	releaseAgain()
}

func TestDefaultCryptoVerificationLimitIsFinite(t *testing.T) {
	svc := &Service{}
	releases := make([]func(), 0, defaultConcurrentVerifications)
	for range defaultConcurrentVerifications {
		release, err := svc.acquireVerification(context.Background())
		if err != nil {
			t.Fatalf("acquire default slot: %v", err)
		}
		releases = append(releases, release)
	}
	if _, err := svc.acquireVerification(context.Background()); !errors.Is(err, ErrVerificationBusy) {
		t.Fatalf("default verifier limit was not finite: %v", err)
	}
	for _, release := range releases {
		release()
	}
}

func TestProviderHTTPServerPinsConnectionTimeouts(t *testing.T) {
	server := NewServer("127.0.0.1:0", http.NotFoundHandler())
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 ||
		server.WriteTimeout <= 0 || server.IdleTimeout <= 0 {
		t.Fatalf("provider HTTP timeouts are not all bounded: %+v", server)
	}
	if server.WriteTimeout != serverWriteTimeout {
		t.Fatalf("write timeout %s, want %s", server.WriteTimeout, serverWriteTimeout)
	}
}
