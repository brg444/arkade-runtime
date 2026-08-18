package application

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

type recordingDelayedSigner struct {
	delegate   Signer
	firstDelay time.Duration
	first      atomic.Bool
	mu         sync.Mutex
	remaining  []time.Duration
}

func (s *recordingDelayedSigner) Sign(ctx context.Context, ptx *psbt.Packet) (*psbt.Packet, error) {
	if deadline, ok := ctx.Deadline(); ok {
		s.mu.Lock()
		s.remaining = append(s.remaining, time.Until(deadline))
		s.mu.Unlock()
	}
	if s.first.CompareAndSwap(false, true) && s.firstDelay > 0 {
		timer := time.NewTimer(s.firstDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.delegate == nil {
		return ptx, nil
	}
	return s.delegate.Sign(ctx, ptx)
}

func TestAuthorizeQueuedRequestGetsFreshSigningWindow(t *testing.T) {
	e := newBoundaryEnv(t)
	const signTimeout = 200 * time.Millisecond
	e.service.SignTimeout = signTimeout

	delayed := &recordingDelayedSigner{
		delegate:   e.countingSigner.delegate,
		firstDelay: 3 * signTimeout,
	}
	e.service.VaultSigner = delayed

	reqA, _ := e.requestFor(t, e.canonicalDraft(t, 90_000, 20_000, 500), e.passkeyPriv)
	reqB, _ := e.requestFor(t, e.canonicalDraft(t, 90_000, 21_000, 500), e.passkeyPriv)

	start := make(chan struct{})
	type outcome struct {
		signed string
		replay bool
		err    error
	}
	got := make([]outcome, 2)
	var wg sync.WaitGroup
	for i, req := range []AuthorizeRequest{reqA, reqB} {
		wg.Add(1)
		go func(i int, req AuthorizeRequest) {
			defer wg.Done()
			<-start
			signed, replay, err := e.service.Authorize(context.Background(), req)
			got[i] = outcome{signed: signed, replay: replay, err: err}
		}(i, req)
	}
	close(start)
	wg.Wait()

	var succeeded, timedOut int
	for i, out := range got {
		switch {
		case out.err == nil && out.signed != "" && !out.replay:
			succeeded++
		case errors.Is(out.err, context.DeadlineExceeded):
			timedOut++
		default:
			t.Fatalf("request %d: signed=%q replay=%v err=%v", i, out.signed, out.replay, out.err)
		}
	}
	if succeeded != 1 || timedOut != 1 {
		t.Fatalf("want 1 success and 1 deadline after queue wait, got succeeded=%d timedOut=%d", succeeded, timedOut)
	}

	delayed.mu.Lock()
	remainings := append([]time.Duration(nil), delayed.remaining...)
	delayed.mu.Unlock()
	if len(remainings) != 2 {
		t.Fatalf("signer saw %d contexts, want 2", len(remainings))
	}
	for i, remaining := range remainings {
		if remaining < signTimeout/2 {
			t.Fatalf("sign call %d remaining %s after queue/reservation wait, want a fresh window near %s", i, remaining, signTimeout)
		}
	}

	spent, err := e.ledger.SpentInPeriod(context.Background(), fixture.VaultID, e.ledger.PeriodStart())
	if err != nil {
		t.Fatal(err)
	}
	if spent != 42_000 {
		t.Fatalf("spent = %d, want 42000 (timed-out reservation plus completed sibling)", spent)
	}
}
