package policy

import (
	"bytes"
	"context"
	"encoding/hex"
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
  unsigned_psbt, authorized_psbt, checkpoint_psbts, checkpoint_request_psbts,
  checkpoint_tapscript, ark_txid, expires_at, created_at, last_dest_script,
  integrity_mac
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.OperationID, rec.VaultID, rec.Purpose, rec.BundleDigest, rec.State,
		rec.AmountSats, rec.FeeSats, rec.FeePolicyDigest, rec.DestScript, rec.ChangeScript,
		rec.ChangeSats, nullableVtxoVout(rec.ChangeVout),
		rec.UnsignedPSBT, rec.AuthorizedPSBT, rec.CheckpointPSBTs, rec.CheckpointRequestPSBTs,
		rec.CheckpointTapscript, rec.ArkTxid, rec.ExpiresAt, rec.CreatedAt,
		rec.LastDestScript, rec.IntegrityMAC,
	); err != nil {
		t.Fatal(err)
	}
}

func TestVtxoOperationMACCoversPolicyFields(t *testing.T) {
	rec := testVtxoOperation("vault-a", "op-1", vtxoPurposeSpend, vtxoStateReserved, 1_000, 50, time.Unix(0, 0))
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
		} else if strings.Contains(err.Error(), "allowance") {
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

func TestVtxoReservationRejectsOverlappingOutpoint(t *testing.T) {
	now := time.Now().UTC()
	led := openPolicyTestLedger(t, func() time.Time { return now })
	createPolicyTestVault(t, led, "vault-a", 0x64)
	input := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x44}, 32), ValueSats: 20_000, Script: []byte{0x51}}
	for i, opID := range []string{"op-a", "op-b"} {
		rec := testVtxoOperation("vault-a", opID, vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
		rec.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
		err := led.ReserveVtxoOperation(context.Background(), rec, []VtxoOperationInput{input}, 100_000)
		if i == 0 && err != nil {
			t.Fatal(err)
		}
		if i == 1 && (err == nil || !strings.Contains(err.Error(), "already reserved")) {
			t.Fatalf("overlapping input accepted: %v", err)
		}
	}
}
