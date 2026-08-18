package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
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
	if server.WriteTimeout < 4*15*time.Second+10*time.Second {
		t.Fatalf("write timeout %s has no margin above four bounded Esplora calls", server.WriteTimeout)
	}
	if publishOperationTimeout >= server.WriteTimeout || publishOperationTimeout > 55*time.Second {
		t.Fatalf("publish operation timeout %s is not bounded below write timeout %s", publishOperationTimeout, server.WriteTimeout)
	}
}

func TestAuthorizerRejectsExcessCryptoWorkWithoutQueueingOrReserving(t *testing.T) {
	e := newBoundaryEnv(t)
	e.service.MaxConcurrentVerifications = 1
	release, err := e.service.acquireVerification(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	malformed := strings.Repeat("A", 512*1024)
	for _, request := range []struct {
		path string
		body string
	}{
		{path: "/v1/draft", body: fmt.Sprintf(`{"prevTxHex":%q,"vout":0,"recipientScript":"51","recipientAmount":330,"fee":0}`, malformed)},
		{path: "/v1/preflight", body: fmt.Sprintf(`{"psbt":%q}`, malformed)},
		{path: "/v1/authorize", body: fmt.Sprintf(`{"psbt":%q}`, malformed)},
	} {
		t.Run(request.path, func(t *testing.T) {
			response := postJSON(t, AuthorizerHandler(e.service), request.path, request.body)
			if response.Code != http.StatusTooManyRequests {
				t.Fatalf("excess authorizer work = %d %s", response.Code, response.Body.String())
			}
			if response.Header().Get("Retry-After") == "" {
				t.Fatal("busy response omitted Retry-After")
			}
		})
	}
	if got := e.countingSigner.callCount(); got != 0 {
		t.Fatalf("busy request reached signer %d times", got)
	}
	spent, err := e.ledger.SpentInPeriod(context.Background(), fixture.VaultID, e.ledger.PeriodStart())
	if err != nil {
		t.Fatal(err)
	}
	if spent != 0 {
		t.Fatalf("busy request reserved allowance: %d", spent)
	}
}
