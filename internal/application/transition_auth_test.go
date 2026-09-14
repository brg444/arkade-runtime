package application

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type delayedFirstLedgerRecoveryAuthorizer struct {
	ledgerSavingsAuthorizer
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (s *delayedFirstLedgerRecoveryAuthorizer) authorizeTransition(ctx context.Context, req ledgerSavingsTransitionAuthorization) (string, error) {
	if s.calls.Add(1) == 1 {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return s.ledgerSavingsAuthorizer.authorizeTransition(ctx, req)
}

func ledgerHardwareTransitionWithFee(t *testing.T, f ledgerEnrollmentFixture, fee int64) TransitionRequest {
	t.Helper()
	auth := f.signer.request(t, "initiate", "hardware", "", 0)
	packet, err := parsePSBT(auth.retainedPSBT)
	if err != nil {
		t.Fatal(err)
	}
	packet.UnsignedTx.TxOut[0].Value = packet.Inputs[0].WitnessUtxo.Value - fee
	f.signer.approve(t, &auth, packet)
	change := uint32(0)
	return TransitionRequest{VaultID: f.start.VaultID, Purpose: "initiate", PSBT: auth.retainedPSBT, LedgerSavings: &LedgerSavingsTransitionRequest{Claimant: "hardware", Change: &change}}
}

func TestRecoveryLateSignerCannotOverwriteCompletedReplacement(t *testing.T) {
	f := ledgerEnrollmentReady(t, false)
	f.finish(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	gate := &delayedFirstLedgerRecoveryAuthorizer{ledgerSavingsAuthorizer: f.svc.keys.ledgerSavings, entered: make(chan struct{}), release: make(chan struct{})}
	f.svc.keys.ledgerSavings = gate
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(gate.release) }) })
	original := ledgerHardwareTransitionWithFee(t, f, 1000)
	late := make(chan error, 1)
	go func() { _, err := f.svc.SignTransition(ctx, original); late <- err }()
	select {
	case <-gate.entered:
	case err := <-late:
		t.Fatalf("original did not reach signer: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := f.svc.SignTransition(ctx, original); err != nil {
		t.Fatal(err)
	}
	replacement := ledgerHardwareTransitionWithFee(t, f, 1100)
	completed, err := f.svc.SignTransition(ctx, replacement)
	if err != nil {
		t.Fatal(err)
	}
	release.Do(func() { close(gate.release) })
	if err := <-late; err == nil {
		t.Fatal("late old signing completion was accepted")
	}
	replay, err := f.svc.SignTransition(ctx, replacement)
	if err != nil || !replay.Replay || replay.SignedPSBT != completed.SignedPSBT {
		t.Fatalf("late signer rolled back the cached replacement: %+v %v", replay, err)
	}
}

func TestSignTransitionOnlyVerifiedClaimantsConsumeRateLimiter(t *testing.T) {
	f := ledgerEnrollmentReady(t, false)
	f.finish(t)
	for i := 0; i < 20; i++ {
		_, _ = f.svc.SignTransition(t.Context(), TransitionRequest{VaultID: fmt.Sprintf("unknown-vault-%d", i), Purpose: "initiate"})
	}
	if len(f.svc.transitionRateHits) != 0 {
		t.Fatalf("unknown vault IDs entered rate state: %v", f.svc.transitionRateHits)
	}
	valid := f.transition(t, "initiate", "hardware", "")
	packet, err := parsePSBT(valid.PSBT)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].TaprootScriptSpendSig = nil
	invalid := valid
	invalid.PSBT, err = packet.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= maxTransitionsPerVaultPerMinute; i++ {
		if _, err := f.svc.SignTransition(t.Context(), invalid); err == nil {
			t.Fatal("transition without a claimant signature unexpectedly signed")
		}
	}
	if len(f.svc.transitionRateHits) != 0 {
		t.Fatal("unverified requests consumed the enrolled vault rate limit")
	}
	response, err := f.svc.SignTransition(t.Context(), valid)
	if err != nil || response == nil || response.SignedPSBT == "" {
		t.Fatalf("verified claimant blocked after invalid requests: %+v %v", response, err)
	}
	if hits := len(f.svc.transitionRateHits[f.start.VaultID]); hits != 1 {
		t.Fatalf("verified claimant rate hits = %d, want 1", hits)
	}
}

func TestSignTransitionNewServiceResetsQuotaAndRetriesDurablePendingRequest(t *testing.T) {
	f := ledgerEnrollmentReady(t, false)
	f.finish(t)
	req := f.transition(t, "initiate", "hardware", "")
	capability := f.svc.keys.ledgerSavings
	f.svc.keys.ledgerSavings = failingLedgerSavingsAuthorizer{capability}
	if _, err := f.svc.SignTransition(t.Context(), req); err == nil || !strings.Contains(err.Error(), "injected signer failure") {
		t.Fatalf("sign did not fail at signer: %v", err)
	}
	for i := 1; i < maxTransitionsPerVaultPerMinute; i++ {
		if err := f.svc.allowTransition(f.start.VaultID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.svc.SignTransition(t.Context(), req); err == nil || err.Error() != "too many recovery signatures" {
		t.Fatalf("old service quota not exhausted: %v", err)
	}
	f.svc.keys.ledgerSavings = capability
	f.restart(t)
	old := f.svc
	f.svc = New(Deps{Stores: old.Stores, Deployment: old.Deployment, IntegrityKey: old.CredentialIntegrityKey, Keys: old.keys,
		VaultCosignerPub: old.VaultCosignerPub, ArkadeCosignerPub: old.ArkadeCosignerPub, ArkadeCosignerOrigin: old.ArkadeCosignerOrigin, ArkadeCosignerVersion: old.ArkadeCosignerVersion, ArkResolver: old.ArkResolver})
	if err := f.svc.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	response, err := f.svc.SignTransition(t.Context(), req)
	if err != nil || response.SignedPSBT == "" || !response.Replay {
		t.Fatalf("durable pending retry after new service: %+v %v", response, err)
	}
	replay, err := f.svc.SignTransition(t.Context(), req)
	if err != nil || !replay.Replay || replay.SignedPSBT != response.SignedPSBT {
		t.Fatalf("signed replay changed result: %+v %v", replay, err)
	}
}

func TestRecoveryFeeReplacementSurvivesSigningFailureAndRestart(t *testing.T) {
	f := ledgerEnrollmentReady(t, false)
	f.finish(t)
	original := ledgerHardwareTransitionWithFee(t, f, 1000)
	first, err := f.svc.SignTransition(t.Context(), original)
	if err != nil {
		t.Fatal(err)
	}
	replacement := ledgerHardwareTransitionWithFee(t, f, 1100)
	capability := f.svc.keys.ledgerSavings
	f.svc.keys.ledgerSavings = failingLedgerSavingsAuthorizer{capability}
	if _, err := f.svc.SignTransition(t.Context(), replacement); err == nil || !strings.Contains(err.Error(), "injected signer failure") {
		t.Fatalf("replacement did not reach failing signer: %v", err)
	}
	if _, err := f.svc.SignTransition(t.Context(), original); err == nil {
		t.Fatal("superseded original replaced pending fee candidate")
	}
	f.svc.keys.ledgerSavings = capability
	f.restart(t)
	completed, err := f.svc.SignTransition(t.Context(), replacement)
	if err != nil || completed.SignedPSBT == first.SignedPSBT || !completed.Replay {
		t.Fatalf("replacement failed to resume: %+v %v", completed, err)
	}
	f.restart(t)
	replay, err := f.svc.SignTransition(t.Context(), replacement)
	if err != nil || !replay.Replay || replay.SignedPSBT != completed.SignedPSBT {
		t.Fatalf("replacement changed after restart: %+v %v", replay, err)
	}
}

func TestSignTransitionRejectsReducedDestinationAfterClaimantAuthorization(t *testing.T) {
	f := ledgerEnrollmentReady(t, false)
	f.finish(t)
	req := f.transition(t, "initiate", "hardware", "")
	packet, err := parsePSBT(req.PSBT)
	if err != nil {
		t.Fatal(err)
	}
	packet.UnsignedTx.TxOut[0].Value--
	req.PSBT, err = packet.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SignTransition(t.Context(), req); err == nil {
		t.Fatal("server accepted a destination value reduced after claimant authorization")
	}
}
