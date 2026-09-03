package application

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/ports"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func signedAbortRequest(t *testing.T, e *env, req VtxoAbortRequest) VtxoAbortRequest {
	t.Helper()
	digest, err := policy.ComputeVtxoAbortDigest(req.OperationID, req.VaultID, req.Purpose)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(e.hot, digest)
	if err != nil {
		t.Fatal(err)
	}
	req.PhoneSignature = hex.EncodeToString(sig.Serialize())
	return req
}

func TestAbortReservedOperationReleasesInputsForReselection(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	locked := strings.Repeat("aa", 32)
	resolver.vtxos = []ports.ResolvedVtxo{
		{Txid: locked, Vout: 0, ValueSats: 100_000, Script: tree.PkScript},
		{Txid: strings.Repeat("bb", 32), Vout: 0, ValueSats: 70_000, Script: tree.PkScript},
	}
	dest := mustArkadeDest(t, arkd)
	first, err := e.svc.ReserveVtxo(context.Background(), signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("41", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: dest, AmountSats: 20_000,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Inputs) != 1 || first.Inputs[0].Txid != locked {
		t.Fatalf("reserved inputs = %+v", first.Inputs)
	}

	out, err := e.svc.AbortVtxo(context.Background(), signedAbortRequest(t, e, VtxoAbortRequest{
		OperationID: first.OperationID, VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if out.State != policy.VtxoStateAborted {
		t.Fatalf("abort = %+v", out)
	}
	stored, err := e.ledger.GetVtxoOperation(context.Background(), first.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != policy.VtxoStateAborted {
		t.Fatalf("stored state = %s", stored.State)
	}

	second, err := e.svc.ReserveVtxo(context.Background(), signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("42", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: dest, AmountSats: 20_000,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Inputs) != 1 || second.Inputs[0].Txid != locked {
		t.Fatalf("re-reserve inputs = %+v", second.Inputs)
	}
}

func TestAbortRejectsSignedSubmittedFinalizedAndUnresolvedOperations(t *testing.T) {
	cases := []struct {
		state       string
		operationID string
		insertState string
		wantFence   string
	}{
		{policy.VtxoStateSigned, strings.Repeat("43", 16), policy.VtxoStateSigned, "operation already active"},
		{policy.VtxoStateSubmitted, strings.Repeat("44", 16), policy.VtxoStateSubmitted, "operation already active"},
		{policy.VtxoStateFinalized, strings.Repeat("4a", 16), policy.VtxoStateSubmitted, "already reserved"},
		{policy.VtxoStateUnresolved, strings.Repeat("4b", 16), policy.VtxoStateSubmitted, "operation already active"},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			e, resolver, arkd := vtxoTestEnv(t)
			tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
			if err != nil {
				t.Fatal(err)
			}
			locked := strings.Repeat("22", 32)
			if tc.state == policy.VtxoStateFinalized {
				locked = strings.Repeat("11", 32)
			}
			resolver.vtxos = []ports.ResolvedVtxo{{
				Txid: locked, Vout: 0, ValueSats: 20_000, Script: tree.PkScript,
			}}
			insertSpendShape(t, e, tc.operationID, strings.Repeat("ad", 32), tree.PkScript, true, tc.insertState)
			if tc.state == policy.VtxoStateFinalized || tc.state == policy.VtxoStateUnresolved {
				stored, err := e.ledger.GetVtxoOperation(context.Background(), tc.operationID)
				if err != nil {
					t.Fatal(err)
				}
				stored.State = tc.state
				if _, swapped, err := e.ledger.TransitionVtxoOperation(context.Background(), policy.VtxoStateSubmitted, stored); err != nil || !swapped {
					t.Fatalf("%s transition: swapped=%v err=%v", tc.state, swapped, err)
				}
			}
			if _, err := e.svc.AbortVtxo(context.Background(), signedAbortRequest(t, e, VtxoAbortRequest{
				OperationID: tc.operationID, VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend,
			})); err == nil || !strings.Contains(err.Error(), "not abortable") {
				t.Fatalf("%s abort = %v", tc.state, err)
			}
			_, err = e.svc.ReserveVtxo(context.Background(), signedReserveRequest(t, e, VtxoReserveRequest{
				OperationID: strings.Repeat("7d", 16), VaultID: fixture.VaultID,
				Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 10_000,
			}))
			if err == nil || !strings.Contains(err.Error(), tc.wantFence) {
				t.Fatalf("%s allowed replacement reservation = %v", tc.state, err)
			}
		})
	}
}

func TestAbortFailsClosedOnExpiryArtifactsAndBadSignature(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("dd", 32), Vout: 0, ValueSats: 40_000, Script: tree.PkScript,
	}}
	dest := mustArkadeDest(t, arkd)
	reserved, err := e.svc.ReserveVtxo(context.Background(), signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("45", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: dest, AmountSats: 10_000,
	}))
	if err != nil {
		t.Fatal(err)
	}
	badSig := signedAbortRequest(t, e, VtxoAbortRequest{
		OperationID: reserved.OperationID, VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend,
	})
	badSig.PhoneSignature = strings.Repeat("ab", 64)
	if _, err := e.svc.AbortVtxo(context.Background(), badSig); err == nil || !strings.Contains(err.Error(), "phoneSignature") {
		t.Fatalf("invalid signature = %v", err)
	}
	if _, err := e.svc.AbortVtxo(context.Background(), signedAbortRequest(t, e, VtxoAbortRequest{
		OperationID: reserved.OperationID, VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend,
	})); err != nil {
		t.Fatalf("valid abort after rejected signature: %v", err)
	}

	now := e.svc.vtxoNow().Format(timeRFC3339)
	artifact := policy.VtxoOperation{
		OperationID: strings.Repeat("46", 16), VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend,
		BundleDigest: bytesRepeat(0x33, 32), State: policy.VtxoStateReserved, AmountSats: 10_000,
		FeePolicyDigest: bytesRepeat(0x44, 32), DestScript: bytesRepeat(0x51, 34),
		UnsignedPSBT: "cHNidP8=", ExpiresAt: e.svc.vtxoNow().Add(vtxoReserveAuthorizeTimeout).Format(timeRFC3339),
		CreatedAt: now,
	}
	if err := e.ledger.ReserveVtxoOperation(context.Background(), artifact, []policy.VtxoOperationInput{{
		Txid: bytesRepeat(0x21, 32), Vout: 0, ValueSats: 20_000, Script: append([]byte(nil), tree.PkScript...),
	}}, program.PeriodAllowanceSats); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AbortVtxo(context.Background(), signedAbortRequest(t, e, VtxoAbortRequest{
		OperationID: artifact.OperationID, VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend,
	})); err == nil || !strings.Contains(err.Error(), "not abortable") {
		t.Fatalf("artifact abort = %v", err)
	}
	artifact.State = policy.VtxoStateAborted
	if _, swapped, err := e.ledger.TransitionVtxoOperation(
		context.Background(), policy.VtxoStateReserved, artifact,
	); err != nil || !swapped {
		t.Fatalf("retire artifact: swapped=%v err=%v", swapped, err)
	}

	expired := policy.VtxoOperation{
		OperationID: strings.Repeat("47", 16), VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend,
		BundleDigest: bytesRepeat(0x35, 32), State: policy.VtxoStateReserved, AmountSats: 10_000,
		FeePolicyDigest: bytesRepeat(0x44, 32), DestScript: bytesRepeat(0x51, 34),
		ExpiresAt: e.svc.vtxoNow().Add(-time.Second).Format(timeRFC3339), CreatedAt: now,
	}
	if err := e.ledger.ReserveVtxoOperation(context.Background(), expired, []policy.VtxoOperationInput{{
		Txid: bytesRepeat(0x22, 32), Vout: 0, ValueSats: 20_000, Script: append([]byte(nil), tree.PkScript...),
	}}, program.PeriodAllowanceSats); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AbortVtxo(context.Background(), signedAbortRequest(t, e, VtxoAbortRequest{
		OperationID: expired.OperationID, VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend,
	})); err == nil || !strings.Contains(err.Error(), "not abortable") {
		t.Fatalf("expired abort = %v", err)
	}
}

func TestAbortIsFailClosedUnderConcurrency(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("ee", 32), Vout: 0, ValueSats: 40_000, Script: tree.PkScript,
	}}
	reserved, err := e.svc.ReserveVtxo(context.Background(), signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("48", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 10_000,
	}))
	if err != nil {
		t.Fatal(err)
	}
	req := signedAbortRequest(t, e, VtxoAbortRequest{
		OperationID: reserved.OperationID, VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend,
	})
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := e.svc.AbortVtxo(context.Background(), req)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var successes int
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent aborts succeeded %d times", successes)
	}
}

func TestAbortHTTPRequiresPhoneSignature(t *testing.T) {
	e, resolver, arkd := vtxoTestEnv(t)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	resolver.vtxos = []ports.ResolvedVtxo{{
		Txid: strings.Repeat("ff", 32), Vout: 0, ValueSats: 40_000, Script: tree.PkScript,
	}}
	reserved, err := e.svc.ReserveVtxo(context.Background(), signedReserveRequest(t, e, VtxoReserveRequest{
		OperationID: strings.Repeat("49", 16), VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, DestAddress: mustArkadeDest(t, arkd), AmountSats: 10_000,
	}))
	if err != nil {
		t.Fatal(err)
	}
	h := testAuthorizer(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodPost, "/v1/vtxo/abort", "application/json", fixture.Origin,
		`{"operationId":"`+reserved.OperationID+`","vaultId":"`+fixture.VaultID+`","purpose":"spend","phoneSignature":"`+strings.Repeat("00", 64)+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsigned abort HTTP = %d %s", rec.Code, rec.Body.String())
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
