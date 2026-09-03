package policy

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func testVtxoOperation(vaultID, opID, purpose, state string, amount, fee int64, created time.Time) VtxoOperation {
	changeVout := uint32(1)
	return VtxoOperation{
		OperationID: opID, VaultID: vaultID, Purpose: purpose,
		BundleDigest: bytes.Repeat([]byte{0x11}, 32), State: state,
		AmountSats: amount, FeeSats: fee,
		FeePolicyDigest: bytes.Repeat([]byte{0x22}, 32),
		DestScript:      []byte{0x51}, ChangeScript: []byte{0x52}, ChangeSats: 330, ChangeVout: &changeVout,
		CheckpointPSBTs: `["cHNidP8="]`, CheckpointRequestPSBTs: "cHNidP8B",
		CheckpointTapscript: []byte{0xc0, 0x01},
		CreatedAt:           created.UTC().Format(time.RFC3339),
	}
}

func insertTestVtxoOperation(t *testing.T, led *Ledger, rec VtxoOperation) {
	t.Helper()
	if err := SealVtxoOperation(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`
INSERT INTO vtxo_operation (
  operation_id, vault_id, purpose, bundle_digest, state,
  amount_sats, fee_sats, fee_policy_digest, dest_script, change_script,
  change_sats, change_vout,
  unsigned_psbt, authorized_psbt, pending_proof_digest, authorized_pending_proof,
  checkpoint_psbts, checkpoint_request_psbts,
  checkpoint_tapscript, ark_txid, expires_at, created_at, last_dest_script,
  integrity_mac
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.OperationID, rec.VaultID, rec.Purpose, rec.BundleDigest, rec.State,
		rec.AmountSats, rec.FeeSats, rec.FeePolicyDigest, rec.DestScript, rec.ChangeScript,
		rec.ChangeSats, nullableVtxoVout(rec.ChangeVout),
		rec.UnsignedPSBT, rec.AuthorizedPSBT, nullableVtxoDigest(rec.PendingProofDigest), rec.AuthorizedPendingProof,
		rec.CheckpointPSBTs, rec.CheckpointRequestPSBTs,
		rec.CheckpointTapscript, rec.ArkTxid, rec.ExpiresAt, rec.CreatedAt,
		rec.LastDestScript, rec.IntegrityMAC,
	); err != nil {
		t.Fatal(err)
	}
}

func insertTestVtxoOperationInput(t *testing.T, led *Ledger, rec VtxoOperationInput) {
	t.Helper()
	if err := SealVtxoOperationInput(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`
INSERT INTO vtxo_operation_input (
  operation_id, txid, vout, value_sats, script, integrity_mac
) VALUES (?, ?, ?, ?, ?, ?)`,
		rec.OperationID, rec.Txid, rec.Vout, rec.ValueSats, rec.Script, rec.IntegrityMAC,
	); err != nil {
		t.Fatal(err)
	}
}

func TestVtxoOperationMACCoversPolicyFields(t *testing.T) {
	rec := testVtxoOperation("vault-a", "op-1", vtxoPurposeSpend, vtxoStateReserved, 1_000, 50, time.Unix(0, 0))
	rec.PendingProofDigest = bytes.Repeat([]byte{0x23}, 32)
	rec.AuthorizedPendingProof = "proof"
	if err := SealVtxoOperation(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVtxoOperation(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*VtxoOperation){
		func(op *VtxoOperation) { op.AmountSats++ },
		func(op *VtxoOperation) { op.FeePolicyDigest[0]++ },
		func(op *VtxoOperation) { op.ChangeSats++ },
		func(op *VtxoOperation) { op.State = vtxoStateAborted },
		func(op *VtxoOperation) { op.CheckpointPSBTs = `["other"]` },
		func(op *VtxoOperation) { op.CheckpointRequestPSBTs = "mutated" },
		func(op *VtxoOperation) { op.PendingProofDigest[0]++ },
		func(op *VtxoOperation) { op.AuthorizedPendingProof = "other-proof" },
		func(op *VtxoOperation) { op.CheckpointTapscript = []byte{0xff} },
	}
	for _, mutate := range mutations {
		copy := rec
		mutate(&copy)
		if err := VerifyVtxoOperation(&copy, testIntegrityKey()); err == nil {
			t.Fatal("mutated VTXO operation verified")
		}
	}
}

func TestVtxoOperationInputMACCoversOutpointAndValue(t *testing.T) {
	in := VtxoOperationInput{
		OperationID: "op-1", Txid: bytes.Repeat([]byte{0x22}, 32),
		Vout: 1, ValueSats: 25_000, Script: []byte{0x51, 0x20},
	}
	if err := SealVtxoOperationInput(&in, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVtxoOperationInput(&in, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	in.ValueSats++
	if err := VerifyVtxoOperationInput(&in, testIntegrityKey()); err == nil {
		t.Fatal("mutated VTXO input verified")
	}
}

func TestVtxoBundleDigestCanonicalizesInputs(t *testing.T) {
	low := bytes.Repeat([]byte{0x01}, 32)
	high := bytes.Repeat([]byte{0x02}, 32)
	a := []VtxoBundleInput{{Txid: high, Vout: 2, ValueSats: 3}, {Txid: low, Vout: 1, ValueSats: 1}}
	b := []VtxoBundleInput{{Txid: low, Vout: 1, ValueSats: 1}, {Txid: high, Vout: 2, ValueSats: 3}}
	created := "2026-08-19T12:00:00Z"
	changeVout := uint32(1)
	feePolicy := bytes.Repeat([]byte{0x33}, 32)
	spendA, err := ComputeVtxoBundleDigest(vtxoPurposeSpend, "vault-a", []byte{0, 0x51}, []byte{0, 0x52}, 10_000, 200, 5_000, &changeVout, feePolicy, a, created)
	if err != nil {
		t.Fatal(err)
	}
	spendB, err := ComputeVtxoBundleDigest(vtxoPurposeSpend, "vault-a", []byte{0, 0x51}, []byte{0, 0x52}, 10_000, 200, 5_000, &changeVout, feePolicy, b, created)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spendA, spendB) {
		t.Fatal("bundle digest depends on caller input order")
	}
	if _, err := ComputeVtxoBundleDigest("board", "vault-a", []byte{0, 0x51}, []byte{0, 0x52}, 10_000, 200, 5_000, &changeVout, feePolicy, a, created); err == nil {
		t.Fatal("unsupported purpose accepted")
	}
	hexInputs := []VtxoBundleInput{{Txid: []byte(strings.ToUpper(hex.EncodeToString(high))), Vout: 2, ValueSats: 3}, {Txid: low, Vout: 1, ValueSats: 1}}
	fromHex, err := ComputeVtxoBundleDigest(vtxoPurposeSpend, "vault-a", []byte{0, 0x51}, []byte{0, 0x52}, 10_000, 200, 5_000, &changeVout, feePolicy, hexInputs, created)
	if err != nil || !bytes.Equal(spendA, fromHex) {
		t.Fatalf("hex txid normalization: %v", err)
	}
	duplicates := []VtxoBundleInput{{Txid: low, Vout: 1}, {Txid: []byte(hex.EncodeToString(low)), Vout: 1}}
	if _, err := CanonicalVtxoBundleInputs(duplicates); err == nil {
		t.Fatal("duplicate outpoint accepted")
	}
}

func TestVtxoBundleDigestRequiresAllOrNothingEconomicChange(t *testing.T) {
	input := []VtxoBundleInput{{Txid: bytes.Repeat([]byte{0x01}, 32), ValueSats: 10_000}}
	feePolicy := bytes.Repeat([]byte{0x02}, 32)
	vout := uint32(1)
	created := "2026-08-22T12:00:00Z"
	if _, err := ComputeVtxoBundleDigest(vtxoPurposeSpend, "vault-a", []byte{0x51}, []byte{0x52}, 1_000, 0, 1, &vout, feePolicy, input, created); err == nil || !strings.Contains(err.Error(), "change shape") {
		t.Fatalf("subdust change = %v", err)
	}
	if _, err := ComputeVtxoBundleDigest(vtxoPurposeSpend, "vault-a", []byte{0x51}, nil, 1_000, 0, 330, nil, feePolicy, input, created); err == nil || !strings.Contains(err.Error(), "change shape") {
		t.Fatalf("partial change = %v", err)
	}
	if _, err := ComputeVtxoBundleDigest(vtxoPurposeSpend, "vault-a", []byte{0x51}, nil, 10_000, 0, 0, nil, feePolicy, input, created); err != nil {
		t.Fatalf("no change = %v", err)
	}
	if _, err := ComputeVtxoBundleDigest(vtxoPurposeSpend, "vault-a", []byte{0x51}, nil, 10_000, 0, 0, nil, feePolicy, nil, created); err == nil || !strings.Contains(err.Error(), "input count") {
		t.Fatalf("zero inputs = %v", err)
	}
	tooMany := make([]VtxoBundleInput, MaxVtxoOperationInputs+1)
	for i := range tooMany {
		tooMany[i] = VtxoBundleInput{Txid: bytes.Repeat([]byte{byte(i + 1)}, 32), ValueSats: 1}
	}
	if _, err := ComputeVtxoBundleDigest(vtxoPurposeSpend, "vault-a", []byte{0x51}, nil, 10_000, 0, 0, nil, feePolicy, tooMany, created); err == nil || !strings.Contains(err.Error(), "input count") {
		t.Fatalf("too many inputs = %v", err)
	}
}

func TestIntentFeePolicyDigestVector(t *testing.T) {
	digest := ComputeIntentFeePolicyDigest("5.0", "amount * 0.001", "7.0", "amount * 0.002")
	if got, want := hex.EncodeToString(digest), "0315f524ae0610202998492284c074829ab156bea680b8313adfa25bdb782fb4"; got != want {
		t.Fatalf("fee policy digest = %s, want %s", got, want)
	}
}

func TestVtxoReserveDigestWalletVector(t *testing.T) {
	destScript, err := hex.DecodeString("5120" + strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ComputeVtxoReserveDigest(
		"000102030405060708090a0b0c0d0e0f",
		"vault-vector-1",
		vtxoPurposeSpend,
		destScript,
		123456789,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(digest), "48de90168b40f88d8e705228c56f9ed83b969d319b0b8dbc3aedfe45da0c1981"; got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}

	pubRaw, _ := hex.DecodeString("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
	pub, err := schnorr.ParsePubKey(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	sigRaw, _ := hex.DecodeString("6196fc6c472bc605daa653b8a8096a171d80abdccb7faf12859776ba631cdbc20fd5e0d0509eaee085e916b1a1c83beada2290fbefcdbf746a452b5416e0a64a")
	sig, err := schnorr.ParseSignature(sigRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !sig.Verify(digest, pub) {
		t.Fatal("wallet reserve signature does not verify")
	}
}

func TestVtxoAbortDigestRejectsNonCanonicalIdentity(t *testing.T) {
	if _, err := ComputeVtxoAbortDigest("AA", "vault-vector-1", vtxoPurposeSpend); err == nil {
		t.Fatal("uppercase operation id accepted")
	}
	if _, err := ComputeVtxoAbortDigest("000102030405060708090a0b0c0d0e0f", "", vtxoPurposeSpend); err == nil {
		t.Fatal("empty vault id accepted")
	}
	if _, err := ComputeVtxoAbortDigest("000102030405060708090a0b0c0d0e0f", "vault-vector-1", "board"); err == nil {
		t.Fatal("non-spend purpose accepted")
	}
	digest, err := ComputeVtxoAbortDigest("000102030405060708090a0b0c0d0e0f", "vault-vector-1", vtxoPurposeSpend)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ComputeVtxoAbortDigest("000102030405060708090a0b0c0d0e0e", "vault-vector-1", vtxoPurposeSpend)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(digest, other) {
		t.Fatal("abort digest ignores operation id")
	}
}

func TestSpentInWindowAuthenticatesRowsBeforeStateDecision(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-a", 0x61)
	rec := testVtxoOperation("vault-a", "op-1", vtxoPurposeSpend, vtxoStateReserved, 1_000, 50, now)
	insertTestVtxoOperation(t, led, rec)
	if _, err := led.db.Exec(`UPDATE vtxo_operation SET state = ? WHERE operation_id = ?`, vtxoStateAborted, rec.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := led.SpentInPeriod(context.Background(), "vault-a", ""); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("unauthenticated state mutation did not fail closed: %v", err)
	}
}

func TestSpentInWindowCountsOnlyLiveRecentVtxoOperations(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-a", 0x62)
	insertTestVtxoOperation(t, led, testVtxoOperation("vault-a", "current", vtxoPurposeSpend, vtxoStateReserved, 1_000, 50, now))
	insertTestVtxoOperation(t, led, testVtxoOperation("vault-a", "aborted", vtxoPurposeSpend, vtxoStateAborted, 5_000, 100, now))
	insertTestVtxoOperation(t, led, testVtxoOperation("vault-a", "old", vtxoPurposeSpend, vtxoStateFinalized, 9_000, 100, now.Add(-25*time.Hour)))
	got, err := led.SpentInPeriod(context.Background(), "vault-a", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1_050 {
		t.Fatalf("spent = %d, want 1050", got)
	}
}

func TestSpentInWindowKeepsOldExecutableAuthorizationCharged(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-a", 0x60)
	old := now.Add(-25 * time.Hour)
	insertTestVtxoOperation(t, led, testVtxoOperation("vault-a", "signed-old", vtxoPurposeSpend, vtxoStateSigned, 9_000, 100, old))
	insertTestVtxoOperation(t, led, testVtxoOperation("vault-a", "submitted-old", vtxoPurposeSpend, vtxoStateSubmitted, 8_000, 100, old))
	got, err := led.SpentInPeriod(context.Background(), "vault-a", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != 17_200 {
		t.Fatalf("old executable authorizations aged out: %d", got)
	}
}

func TestConcurrentVtxoReservationsCannotOversubscribeAllowance(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-a", 0x63)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rec := testVtxoOperation("vault-a", "op-"+string(rune('a'+i)), vtxoPurposeSpend, vtxoStateReserved, 60_000, 0, now)
			rec.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
			input := VtxoOperationInput{Txid: bytes.Repeat([]byte{byte(0x30 + i)}, 32), ValueSats: 70_000, Script: []byte{0x51}}
			errs <- led.ReserveVtxoOperation(context.Background(), rec, []VtxoOperationInput{input}, 100_000)
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	var succeeded, failed int
	for err := range errs {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrPeriodAllowanceExceeded) || strings.Contains(err.Error(), "operation already active") {
			failed++
		} else {
			t.Fatalf("unexpected reservation error: %v", err)
		}
	}
	if succeeded != 1 || failed != 1 {
		t.Fatalf("succeeded=%d failed=%d", succeeded, failed)
	}
}

func TestVtxoTransitionCompareAndSwap(t *testing.T) {
	now := time.Now().UTC()
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-cas", 0x65)
	rec := testVtxoOperation("vault-cas", "cas-op", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
	input := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x65}, 32), ValueSats: 20_000, Script: []byte{0x51}}
	if err := led.ReserveVtxoOperation(context.Background(), rec, []VtxoOperationInput{input}, 100_000); err != nil {
		t.Fatal(err)
	}
	base, err := led.GetVtxoOperation(context.Background(), rec.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	type outcome struct {
		current VtxoOperation
		swapped bool
		err     error
	}
	outcomes := make(chan outcome, 2)
	for _, authorized := range []string{"authorized-a", "authorized-b"} {
		candidate := base
		candidate.State = VtxoStateSigned
		candidate.AuthorizedPSBT = authorized
		go func(next VtxoOperation) {
			<-start
			current, swapped, err := led.TransitionVtxoOperation(context.Background(), VtxoStateReserved, next)
			outcomes <- outcome{current: current, swapped: swapped, err: err}
		}(candidate)
	}
	close(start)
	var winner string
	for range 2 {
		out := <-outcomes
		if out.err != nil {
			t.Fatal(out.err)
		}
		if out.swapped {
			if winner != "" {
				t.Fatal("two state transitions swapped")
			}
			winner = out.current.AuthorizedPSBT
		}
	}
	if winner == "" {
		t.Fatal("no state transition swapped")
	}
	stored, err := led.GetVtxoOperation(context.Background(), rec.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != VtxoStateSigned || stored.AuthorizedPSBT != winner {
		t.Fatalf("stored winner = %+v, want %q", stored, winner)
	}
}

func TestSignedVtxoAndSignCountCommitAtomically(t *testing.T) {
	now := time.Now().UTC()
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-atomic", 0x66)
	rec := testVtxoOperation("vault-atomic", "atomic-op", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
	input := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x66}, 32), ValueSats: 20_000, Script: []byte{0x51}}
	if err := led.ReserveVtxoOperation(context.Background(), rec, []VtxoOperationInput{input}, 100_000); err != nil {
		t.Fatal(err)
	}
	stored, err := led.GetVtxoOperation(context.Background(), rec.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	stored.State = VtxoStateSigned
	stored.AuthorizedPSBT = "signed"
	if _, err := led.db.Exec(`DROP TABLE webauthn_sign_count`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := led.CommitSignedVtxoOperation(context.Background(), stored, []byte("credential"), 7); err == nil {
		t.Fatal("signed operation committed without its sign counter")
	}
	got, err := led.GetVtxoOperation(context.Background(), rec.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != VtxoStateReserved || got.AuthorizedPSBT != "" {
		t.Fatalf("partial signed commit survived rollback: %+v", got)
	}
}

func TestSignedVtxoCommitLoserMustMatchDurableCounter(t *testing.T) {
	now := time.Now().UTC()
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-counter-cas", 0x68)
	rec := testVtxoOperation("vault-counter-cas", "counter-cas-op", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
	input := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x68}, 32), ValueSats: 20_000, Script: []byte{0x51}}
	if err := led.ReserveVtxoOperation(context.Background(), rec, []VtxoOperationInput{input}, 100_000); err != nil {
		t.Fatal(err)
	}
	stored, err := led.GetVtxoOperation(context.Background(), rec.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	stored.State = VtxoStateSigned
	stored.AuthorizedPSBT = "signed"
	credentialID := []byte("credential")
	if _, swapped, err := led.CommitSignedVtxoOperation(context.Background(), stored, credentialID, 8); err != nil || !swapped {
		t.Fatalf("winning signed commit: swapped=%v err=%v", swapped, err)
	}
	if _, _, err := led.CommitSignedVtxoOperation(context.Background(), stored, credentialID, 7); err == nil {
		t.Fatal("CAS loser accepted a backward authenticator counter")
	}
	if _, _, err := led.CommitSignedVtxoOperation(context.Background(), stored, credentialID, 9); err == nil {
		t.Fatal("CAS loser returned success without persisting a newer authenticator counter")
	}
	current, swapped, err := led.CommitSignedVtxoOperation(context.Background(), stored, credentialID, 8)
	if err != nil || swapped || current.State != VtxoStateSigned {
		t.Fatalf("exact CAS-loser replay = %+v swapped=%v err=%v", current, swapped, err)
	}
}

func TestSignedVtxoReplayIsScopedToExactOperationAndCounter(t *testing.T) {
	now := time.Now().UTC()
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-replay", 0x67)
	rec := testVtxoOperation("vault-replay", "replay-op", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
	input := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x67}, 32), ValueSats: 20_000, Script: []byte{0x51}}
	if err := led.ReserveVtxoOperation(context.Background(), rec, []VtxoOperationInput{input}, 100_000); err != nil {
		t.Fatal(err)
	}
	stored, err := led.GetVtxoOperation(context.Background(), rec.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	stored.State = VtxoStateSigned
	stored.AuthorizedPSBT = "signed"
	credentialID := []byte("credential")
	if _, swapped, err := led.CommitSignedVtxoOperation(context.Background(), stored, credentialID, 7); err != nil || !swapped {
		t.Fatalf("commit signed operation: swapped=%v err=%v", swapped, err)
	}
	if err := led.VerifySignedVtxoReplay(context.Background(), rec.OperationID, rec.VaultID, credentialID, 7); err != nil {
		t.Fatalf("exact replay rejected: %v", err)
	}
	if err := led.VerifySignedVtxoReplay(context.Background(), rec.OperationID, rec.VaultID, credentialID, 6); err == nil {
		t.Fatal("different counter accepted for signed replay")
	}
	if err := led.VerifySignedVtxoReplay(context.Background(), rec.OperationID, "another-vault", credentialID, 7); err == nil {
		t.Fatal("cross-vault signed replay accepted")
	}
	if err := led.VerifySignedVtxoReplay(context.Background(), "another-operation", rec.VaultID, credentialID, 7); err == nil {
		t.Fatal("cross-operation signed replay accepted")
	}
}

func TestVtxoReservationRejectsMultiInputOverlap(t *testing.T) {
	now := time.Now().UTC()
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-a", 0x64)
	shared := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x44}, 32), Vout: 1, ValueSats: 20_000, Script: []byte{0x51}}
	firstOnly := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x45}, 32), Vout: 2, ValueSats: 20_000, Script: []byte{0x51}}
	secondOnly := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x46}, 32), Vout: 3, ValueSats: 20_000, Script: []byte{0x51}}
	first := testVtxoOperation("vault-a", "op-a", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
	first.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
	if err := led.ReserveVtxoOperation(context.Background(), first, []VtxoOperationInput{firstOnly, shared}, 100_000); err != nil {
		t.Fatal(err)
	}
	second := testVtxoOperation("vault-a", "op-b", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
	second.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
	if err := led.ReserveVtxoOperation(context.Background(), second, []VtxoOperationInput{secondOnly, shared}, 100_000); err == nil || !strings.Contains(err.Error(), "already reserved") {
		t.Fatalf("overlapping input accepted: %v", err)
	}
}

func TestVtxoReservationRejectsDisjointSecondOperationForEveryUnresolvedState(t *testing.T) {
	now := time.Now().UTC()
	for i, state := range []string{
		vtxoStateReserved, vtxoStateSigned, vtxoStateSubmitted, vtxoStateUnresolved,
	} {
		t.Run(state, func(t *testing.T) {
			led := openPolicyTestLedger(t, func() time.Time { return now })
			createPolicyTestVault(t, led, "vault-a", byte(0x40+i))
			existing := testVtxoOperation("vault-a", "existing", vtxoPurposeSpend, state, 10_000, 0, now)
			if state == vtxoStateReserved {
				existing.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
			}
			insertTestVtxoOperation(t, led, existing)

			candidate := testVtxoOperation("vault-a", "candidate", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
			candidate.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
			input := VtxoOperationInput{
				Txid: bytes.Repeat([]byte{byte(0x20 + i)}, 32), Vout: 1,
				ValueSats: 20_000, Script: []byte{0x51},
			}
			err := led.ReserveVtxoOperation(context.Background(), candidate, []VtxoOperationInput{input}, 100_000)
			if err == nil || !strings.Contains(err.Error(), "operation already active") {
				t.Fatalf("state %s allowed a second operation: %v", state, err)
			}
		})
	}
}

func TestVtxoReservationRejectsOverlapForEveryCountingState(t *testing.T) {
	now := time.Now().UTC()
	for i, state := range []string{
		vtxoStateReserved, vtxoStateSigned, vtxoStateSubmitted, vtxoStateFinalized,
	} {
		t.Run(state, func(t *testing.T) {
			led := openPolicyTestLedger(t, func() time.Time { return now })
			createPolicyTestVault(t, led, "vault-a", byte(0x70+i))
			input := VtxoOperationInput{
				OperationID: "existing", Txid: bytes.Repeat([]byte{byte(0x50 + i)}, 32),
				Vout: 1, ValueSats: 20_000, Script: []byte{0x51},
			}
			insertTestVtxoOperation(t, led, testVtxoOperation(
				"vault-a", input.OperationID, vtxoPurposeSpend, state, 10_000, 0, now,
			))
			insertTestVtxoOperationInput(t, led, input)

			candidate := testVtxoOperation("vault-a", "candidate", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
			err := led.ReserveVtxoOperation(context.Background(), candidate, []VtxoOperationInput{input}, 100_000)
			if err == nil || !strings.Contains(err.Error(), "already reserved") {
				t.Fatalf("state %s accepted overlapping input: %v", state, err)
			}
		})
	}
}

func TestVtxoReservationKeepsChainProvenUnresolvedRowAsGlobalFence(t *testing.T) {
	now := time.Now().UTC()
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-a", 0x7a)
	input := VtxoOperationInput{
		OperationID: "unresolved", Txid: bytes.Repeat([]byte{0x6a}, 32),
		Vout: 2, ValueSats: 20_000, Script: []byte{0x51},
	}
	insertTestVtxoOperation(t, led, testVtxoOperation(
		"vault-a", input.OperationID, vtxoPurposeSpend, vtxoStateUnresolved, 10_000, 500, now,
	))
	insertTestVtxoOperationInput(t, led, input)

	candidate := testVtxoOperation("vault-a", "candidate", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
	if err := led.ReserveVtxoOperation(context.Background(), candidate, []VtxoOperationInput{input}, 100_000); err == nil || !strings.Contains(err.Error(), "operation already active") {
		t.Fatalf("unresolved operation allowed a new reservation: %v", err)
	}
	spent, err := led.SpentInPeriod(context.Background(), "vault-a", "")
	if err != nil {
		t.Fatal(err)
	}
	if spent != 10_500 {
		t.Fatalf("unresolved allowance debit changed: %d", spent)
	}
}

func TestVtxoOverlapAllowsAuthenticatedAbortedRow(t *testing.T) {
	now := time.Now().UTC()
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-a", 0x76)
	input := VtxoOperationInput{
		OperationID: "aborted", Txid: bytes.Repeat([]byte{0x61}, 32),
		Vout: 2, ValueSats: 20_000, Script: []byte{0x51},
	}
	insertTestVtxoOperation(t, led, testVtxoOperation(
		"vault-a", input.OperationID, vtxoPurposeSpend, vtxoStateAborted, 10_000, 0, now,
	))
	insertTestVtxoOperationInput(t, led, input)

	candidate := testVtxoOperation("vault-a", "candidate", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
	if err := led.ReserveVtxoOperation(context.Background(), candidate, []VtxoOperationInput{input}, 100_000); err != nil {
		t.Fatalf("authenticated aborted input remained reserved: %v", err)
	}
}

func TestVtxoOverlapAuthenticatesCurrentOperationBeforeReplayExclusion(t *testing.T) {
	now := time.Now().UTC()
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-a", 0x77)
	input := VtxoOperationInput{
		OperationID: "current", Txid: bytes.Repeat([]byte{0x62}, 32),
		Vout: 3, ValueSats: 20_000, Script: []byte{0x51},
	}
	insertTestVtxoOperation(t, led, testVtxoOperation(
		"vault-a", input.OperationID, vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now,
	))
	insertTestVtxoOperationInput(t, led, input)

	led.mu.Lock()
	defer led.mu.Unlock()
	conn, err := led.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(context.Background(), `ROLLBACK`)
	if err := led.rejectOverlappingVtxoInputs(
		context.Background(), conn, input.OperationID, []VtxoOperationInput{input},
	); err != nil {
		t.Fatalf("authenticated current-operation replay rejected: %v", err)
	}
}

func TestVtxoOverlapFailsClosedForTamperedMatchingRows(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name   string
		mutate string
		want   string
	}{
		{
			name: "operation", mutate: `UPDATE vtxo_operation SET state = 'aborted' WHERE operation_id = 'z-tampered'`,
			want: "vtxo operation integrity",
		},
		{
			name: "input", mutate: `UPDATE vtxo_operation_input SET value_sats = value_sats + 1 WHERE operation_id = 'z-tampered'`,
			want: "vtxo operation input integrity",
		},
		{
			name: "operation vault", mutate: `UPDATE vtxo_operation SET vault_id = 'vault-b' WHERE operation_id = 'z-tampered'`,
			want: "vtxo operation integrity",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			led := openPolicyTestLedger(t, func() time.Time { return now })
			createPolicyTestVault(t, led, "vault-a", 0x78)
			createPolicyTestVault(t, led, "vault-b", 0x7b)
			input := VtxoOperationInput{
				Txid: bytes.Repeat([]byte{0x63}, 32),
				Vout: 4, ValueSats: 20_000, Script: []byte{0x51},
			}
			// The valid live match sorts first. The check must still authenticate
			// every later matching row before deciding that an overlap exists.
			for _, operationID := range []string{"a-valid", "z-tampered"} {
				insertTestVtxoOperation(t, led, testVtxoOperation(
					"vault-a", operationID, vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now,
				))
				input.OperationID = operationID
				insertTestVtxoOperationInput(t, led, input)
			}
			if _, err := led.db.Exec(test.mutate); err != nil {
				t.Fatal(err)
			}

			candidate := testVtxoOperation("vault-a", "candidate", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
			err := led.ReserveVtxoOperation(context.Background(), candidate, []VtxoOperationInput{input}, 100_000)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("tampered matching %s did not fail closed: %v", test.name, err)
			}
		})
	}
}

func TestVtxoOverlapDoesNotLoadUnrelatedVaultInputs(t *testing.T) {
	now := time.Now().UTC()
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-a", 0x79)
	unrelated := VtxoOperationInput{
		OperationID: "existing", Txid: bytes.Repeat([]byte{0x64}, 32),
		Vout: 5, ValueSats: 20_000, Script: []byte{0x51},
	}
	insertTestVtxoOperation(t, led, testVtxoOperation(
		"vault-a", unrelated.OperationID, vtxoPurposeSpend, vtxoStateFinalized, 10_000, 0, now,
	))
	insertTestVtxoOperationInput(t, led, unrelated)
	if _, err := led.db.Exec(`UPDATE vtxo_operation_input SET value_sats = value_sats + 1 WHERE operation_id = ?`, unrelated.OperationID); err != nil {
		t.Fatal(err)
	}

	candidateInput := VtxoOperationInput{
		Txid: bytes.Repeat([]byte{0x65}, 32), Vout: 6,
		ValueSats: 20_000, Script: []byte{0x51},
	}
	candidate := testVtxoOperation("vault-a", "candidate", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
	if err := led.ReserveVtxoOperation(context.Background(), candidate, []VtxoOperationInput{candidateInput}, 100_000); err != nil {
		t.Fatalf("unrelated vault input was loaded by overlap check: %v", err)
	}
}

func TestVtxoOverlapLookupAcceptsMaximumCandidateSet(t *testing.T) {
	now := time.Now().UTC()
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-a", 0x7a)
	inputs := make([]VtxoOperationInput, MaxVtxoOperationInputs)
	for i := range inputs {
		inputs[i] = VtxoOperationInput{
			Txid: bytes.Repeat([]byte{byte(i + 1)}, 32), Vout: i,
			ValueSats: 1_000, Script: []byte{0x51},
		}
	}
	candidate := testVtxoOperation("vault-a", "candidate", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
	if err := led.ReserveVtxoOperation(context.Background(), candidate, inputs, 100_000); err != nil {
		t.Fatalf("maximum candidate lookup exceeded SQLite parameter budget: %v", err)
	}
}
