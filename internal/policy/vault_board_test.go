package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/program"
)

func openVaultBoardTestLedger(t testing.TB, now time.Time) *Ledger {
	t.Helper()
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "board.sqlite"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetIntegrityKey(testIntegrityKey()); err != nil {
		_ = ledger.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	return ledger
}

func createVaultBoardTestEnrollment(t testing.TB, ledger *Ledger, vaultID string, tag byte) VaultBoardEnrollment {
	t.Helper()
	return createVaultBoardTestEnrollmentForNetwork(t, ledger, vaultID, tag, program.NetworkMutinynet)
}

func createVaultBoardTestEnrollmentForNetwork(t testing.TB, ledger *Ledger, vaultID string, tag byte, network string) VaultBoardEnrollment {
	t.Helper()
	pins, err := program.PinsFor(network)
	if err != nil {
		t.Fatal(err)
	}
	now := ledger.NowUTC()
	tokenHash := bytes.Repeat([]byte{tag}, sha256.Size)
	if err := ledger.PutInvite(tokenHash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	input := policyTestVaultInput(t, vaultID, tag, tokenHash)
	input.Record.Network = network
	if err := SealVaultRecord(&input.Record, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	compressed := bytes.Repeat([]byte{tag + 1}, 33)
	compressed[0] = 0x02
	board := VaultBoardEnrollment{
		VaultID: vaultID, Program: program.VaultBoardV1,
		BoardingPub: compressed, CosignerPub: append([]byte(nil), compressed...), OperatorPub: append([]byte(nil), compressed...),
		ExitDelay: pins.BoardExitDelay, ExitDelayUnit: program.VaultBoardV1ExitDelayUnit,
		PkScript: append([]byte{0x51, 0x20}, bytes.Repeat([]byte{tag}, 32)...), Address: "tb1p-board-test",
	}
	if err := SealVaultBoardEnrollment(&board, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := ledger.CreateVaultWithBoard(input, board); err != nil {
		t.Fatal(err)
	}
	return board
}

func vaultBoardTestOperation(t testing.TB, ledger *Ledger, vaultID string, tag byte) VaultBoardOperation {
	t.Helper()
	txid := bytes.Repeat([]byte{tag}, 32)
	return VaultBoardOperation{
		VaultID: vaultID, Txid: txid, Vout: uint32(tag), ValueSats: 50_000,
		BoardingScript:    append([]byte{0x51, 0x20}, bytes.Repeat([]byte{tag + 1}, 32)...),
		ReceiverScript:    []byte{0x51, 0x20, tag},
		SequenceAnchorMTP: ledger.NowUTC().Add(-time.Hour).Unix(),
	}
}

func vaultBoardTestChainState(ledger *Ledger) VaultBoardChainState {
	return VaultBoardChainState{TipMTP: ledger.NowUTC().Unix()}
}

func vaultBoardRegisterRequest(ledger *Ledger, tag byte) VaultBoardRegisterRequest {
	pub := bytes.Repeat([]byte{tag + 1}, 33)
	pub[0] = 0x02
	return VaultBoardRegisterRequest{
		RequestDigest: bytes.Repeat([]byte{tag}, sha256.Size), TreeSessionPub: pub,
		ReceiverSats: 49_000, FeeSats: 1_000,
		ExpireAt: ledger.NowUTC().Add(2 * time.Minute).Unix(),
	}
}

func submitVaultBoardRegister(t testing.TB, ledger *Ledger, auth VaultBoardAuthorization) {
	t.Helper()
	if _, _, err := ledger.AppendVaultBoardDispatch(context.Background(), VaultBoardDispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: VaultBoardPhaseRegister,
		RequestDigest: append([]byte(nil), auth.RequestDigest...),
	}, vaultBoardTestChainState(ledger)); err != nil {
		t.Fatal(err)
	}
	_, _, err := ledger.AppendVaultBoardSubmission(context.Background(), VaultBoardSubmission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: VaultBoardPhaseRegister,
		RequestDigest: append([]byte(nil), auth.RequestDigest...), Outcome: VaultBoardAuthSubmitted,
		OperatorRef: "intent-test", CreatedAt: ledger.NowUTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func releaseVaultBoardAttempt(t testing.TB, ledger *Ledger, auth VaultBoardAuthorization, tag byte) {
	t.Helper()
	deleteAuth := VaultBoardAuthorization{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: VaultBoardPhaseDelete,
		RequestDigest: bytes.Repeat([]byte{tag}, sha256.Size), ExpireAt: ledger.NowUTC().Add(time.Minute).Unix(),
		CreatedAt: ledger.NowUTC().Format(time.RFC3339Nano),
	}
	stored, _, _, err := ledger.AppendVaultBoardAuthorizationAndDispatch(context.Background(), deleteAuth, vaultBoardTestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardSubmission(context.Background(), VaultBoardSubmission{
		OperationID: stored.OperationID, Attempt: stored.Attempt, Phase: VaultBoardPhaseDelete,
		RequestDigest: stored.RequestDigest, Outcome: VaultBoardAuthReleased,
		CreatedAt: ledger.NowUTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVaultBoardAttemptIsServerAllocatedAndRotatesOnlyAfterRelease(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	ledger := openVaultBoardTestLedger(t, now)
	createVaultBoardTestEnrollment(t, ledger, "vault-board", 0x21)
	op := vaultBoardTestOperation(t, ledger, "vault-board", 0x31)
	request := vaultBoardRegisterRequest(ledger, 0x41)

	storedOp, first, created, err := ledger.BeginVaultBoardAttempt(context.Background(), op, request, vaultBoardTestChainState(ledger))
	if err != nil || !created || first.Attempt != 0 {
		t.Fatalf("first attempt = %+v created=%v err=%v", first, created, err)
	}
	wantID, err := ComputeVaultBoardOperationID(op.VaultID, op.Txid, op.Vout)
	if err != nil || storedOp.OperationID != wantID {
		t.Fatalf("server operation id = %q, want %q (%v)", storedOp.OperationID, wantID, err)
	}
	_, replay, created, err := ledger.BeginVaultBoardAttempt(context.Background(), op, request, vaultBoardTestChainState(ledger))
	if err != nil || created || replay.Attempt != first.Attempt {
		t.Fatalf("exact replay = %+v created=%v err=%v", replay, created, err)
	}
	if _, _, err := ledger.AppendVaultBoardDispatch(context.Background(), VaultBoardDispatch{
		OperationID: first.OperationID, Attempt: first.Attempt, Phase: first.Phase,
		RequestDigest: first.RequestDigest,
	}, vaultBoardTestChainState(ledger)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x42), vaultBoardTestChainState(ledger)); err == nil || !strings.Contains(err.Error(), "still active") {
		t.Fatalf("rotated dispatched attempt: %v", err)
	}
	submitVaultBoardRegister(t, ledger, *first)
	releaseVaultBoardAttempt(t, ledger, *first, 0x51)
	nextRequest := vaultBoardRegisterRequest(ledger, 0x42)
	nextRequest.ReceiverSats = 48_500
	nextRequest.FeeSats = 1_500
	_, next, created, err := ledger.BeginVaultBoardAttempt(context.Background(), op, nextRequest, vaultBoardTestChainState(ledger))
	if err != nil || !created || next.Attempt != 1 {
		t.Fatalf("next attempt = %+v created=%v err=%v", next, created, err)
	}
	if _, _, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, request, vaultBoardTestChainState(ledger)); err == nil {
		t.Fatal("delayed attempt-0 replay moved the operation back to an old generation")
	}
}

func TestVaultBoardUndispatchedRegisterRotatesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ledger.sqlite")
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenLedger(dbPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	createVaultBoardTestEnrollment(t, ledger, "vault-restart", 0x71)
	op := vaultBoardTestOperation(t, ledger, "vault-restart", 0x72)
	firstRequest := vaultBoardRegisterRequest(ledger, 0x73)
	_, first, created, err := ledger.BeginVaultBoardAttempt(context.Background(), op, firstRequest, vaultBoardTestChainState(ledger))
	if err != nil || !created || first.Attempt != 0 {
		t.Fatalf("first register = %+v created=%v err=%v", first, created, err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenLedger(dbPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	secondRequest := vaultBoardRegisterRequest(restarted, 0x74)
	_, second, created, err := restarted.BeginVaultBoardAttempt(context.Background(), op, secondRequest, vaultBoardTestChainState(restarted))
	if err != nil || !created || second.Attempt != 1 {
		t.Fatalf("restarted register = %+v created=%v err=%v", second, created, err)
	}
	if _, _, err := restarted.AppendVaultBoardDispatch(context.Background(), VaultBoardDispatch{
		OperationID: second.OperationID, Attempt: second.Attempt, Phase: second.Phase,
		RequestDigest: second.RequestDigest,
	}, vaultBoardTestChainState(restarted)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := restarted.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(restarted, 0x75), vaultBoardTestChainState(restarted)); err == nil || !strings.Contains(err.Error(), "still active") {
		t.Fatalf("post-dispatch restart rotated ambiguous attempt: %v", err)
	}
}

func TestVaultBoardDispatchSeparatesSafeRetryFromAmbiguousNetworkOutcome(t *testing.T) {
	ledger := openVaultBoardTestLedger(t, time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))
	createVaultBoardTestEnrollment(t, ledger, "vault-dispatch", 0x61)
	op := vaultBoardTestOperation(t, ledger, "vault-dispatch", 0x62)
	_, auth, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x63), vaultBoardTestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardSubmission(context.Background(), VaultBoardSubmission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase,
		RequestDigest: auth.RequestDigest, Outcome: VaultBoardAuthSubmitted, OperatorRef: "intent-before-dispatch",
	}); err == nil || !strings.Contains(err.Error(), "dispatch required") {
		t.Fatalf("submission crossed missing dispatch barrier: %v", err)
	}
	dispatch := VaultBoardDispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase,
		RequestDigest: append([]byte(nil), auth.RequestDigest...),
	}
	first, created, err := ledger.AppendVaultBoardDispatch(context.Background(), dispatch, vaultBoardTestChainState(ledger))
	if err != nil || !created || first.CreatedAt == "" {
		t.Fatalf("dispatch = %+v created=%v err=%v", first, created, err)
	}
	if _, created, err := ledger.AppendVaultBoardDispatch(context.Background(), dispatch, vaultBoardTestChainState(ledger)); err != nil || created {
		t.Fatalf("exact dispatch replay created=%v err=%v", created, err)
	}
	dispatch.RequestDigest = bytes.Repeat([]byte{0x99}, sha256.Size)
	if _, _, err := ledger.AppendVaultBoardDispatch(context.Background(), dispatch, vaultBoardTestChainState(ledger)); err == nil {
		t.Fatal("changed dispatch digest was accepted")
	}
	snapshot, err := ledger.GetCurrentVaultBoardAttempt(context.Background(), auth.OperationID)
	if err != nil || snapshot.RegisterDispatch == nil || snapshot.RegisterSubmission != nil {
		t.Fatalf("ambiguous dispatch snapshot = %+v, %v", snapshot, err)
	}
}

func TestVaultBoardDefiniteRegisterRejectionAllowsFreshAttempt(t *testing.T) {
	ledger := openVaultBoardTestLedger(t, time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))
	createVaultBoardTestEnrollment(t, ledger, "vault-rejected", 0x68)
	op := vaultBoardTestOperation(t, ledger, "vault-rejected", 0x69)
	firstRequest := vaultBoardRegisterRequest(ledger, 0x6a)
	_, first, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, firstRequest, vaultBoardTestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardDispatch(context.Background(), VaultBoardDispatch{
		OperationID: first.OperationID, Attempt: first.Attempt, Phase: first.Phase,
		RequestDigest: first.RequestDigest,
	}, vaultBoardTestChainState(ledger)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardSubmission(context.Background(), VaultBoardSubmission{
		OperationID: first.OperationID, Attempt: first.Attempt, Phase: first.Phase,
		RequestDigest: first.RequestDigest, Outcome: VaultBoardAuthRejected,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, firstRequest, vaultBoardTestChainState(ledger)); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("replayed rejected request: %v", err)
	}
	_, second, created, err := ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x6b), vaultBoardTestChainState(ledger))
	if err != nil || !created || second.Attempt != first.Attempt+1 {
		t.Fatalf("fresh attempt = %+v created=%v err=%v", second, created, err)
	}
}

func TestVaultBoardRegisterCanSupersede(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 2, 30, 0, time.UTC)
	expireAt := now.Add(-30 * time.Second).Unix()
	if !VaultBoardRegisterCanSupersede(expireAt, now) {
		t.Fatal("expired register plus quarantine should supersede")
	}
	if VaultBoardRegisterCanSupersede(expireAt, now.Add(-time.Second)) {
		t.Fatal("quarantine must still block rotation")
	}
	if VaultBoardRegisterCanSupersede(0, now) {
		t.Fatal("zero expire_at must never supersede")
	}
}

func TestVaultBoardExpiredSupersessionSerializesWithFinalAuthorization(t *testing.T) {
	for _, test := range []struct {
		name          string
		finalFirst    bool
		wantFinal     bool
		wantSupersede bool
	}{
		{name: "final wins", finalFirst: true, wantFinal: true},
		{name: "supersession wins", wantSupersede: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
			clock := now
			ledger, err := OpenLedger(filepath.Join(t.TempDir(), "board.sqlite"), func() time.Time { return clock })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ledger.Close() })
			if err := ledger.SetIntegrityKey(testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			createVaultBoardTestEnrollment(t, ledger, "vault-race", 0x79)
			op := vaultBoardTestOperation(t, ledger, "vault-race", 0x7a)
			firstRequest := vaultBoardRegisterRequest(ledger, 0x7b)
			_, first, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, firstRequest, vaultBoardTestChainState(ledger))
			if err != nil {
				t.Fatal(err)
			}
			submitVaultBoardRegister(t, ledger, *first)
			clock = time.Unix(first.ExpireAt, 0).UTC().Add(vaultBoardRegisterQuarantine)
			final := VaultBoardAuthorization{
				OperationID: first.OperationID, Attempt: first.Attempt, Phase: VaultBoardPhaseFinalize,
				RequestDigest:  bytes.Repeat([]byte{0x7c}, sha256.Size),
				CommitmentTxid: strings.Repeat("a", 64), ReceiverTxid: strings.Repeat("b", 64), ReceiverVout: 1,
			}
			finalize := func() error {
				_, _, _, err := ledger.AppendVaultBoardAuthorizationAndDispatch(context.Background(), final, vaultBoardTestChainState(ledger))
				return err
			}
			supersede := func() error {
				_, _, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x7d), vaultBoardTestChainState(ledger))
				return err
			}
			var finalErr, supersedeErr error
			if test.finalFirst {
				finalErr = finalize()
				supersedeErr = supersede()
			} else {
				supersedeErr = supersede()
				finalErr = finalize()
			}
			if (finalErr == nil) != test.wantFinal || (supersedeErr == nil) != test.wantSupersede {
				t.Fatalf("final=%v supersede=%v", finalErr, supersedeErr)
			}
		})
	}
}

func TestVaultBoardSubmissionUsesServerTimestamp(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 123, time.UTC)
	ledger := openVaultBoardTestLedger(t, now)
	createVaultBoardTestEnrollment(t, ledger, "vault-result-time", 0x76)
	op := vaultBoardTestOperation(t, ledger, "vault-result-time", 0x77)
	_, auth, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x78), vaultBoardTestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardDispatch(context.Background(), VaultBoardDispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase,
		RequestDigest: auth.RequestDigest,
	}, vaultBoardTestChainState(ledger)); err != nil {
		t.Fatal(err)
	}
	proposed := VaultBoardSubmission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase,
		RequestDigest: auth.RequestDigest, Outcome: VaultBoardAuthSubmitted,
		OperatorRef: "intent-server-time", CreatedAt: "1900-01-01T00:00:00Z",
	}
	stored, created, err := ledger.AppendVaultBoardSubmission(context.Background(), proposed)
	if err != nil || !created {
		t.Fatalf("submission created=%v err=%v", created, err)
	}
	if want := now.Format(time.RFC3339Nano); stored.CreatedAt != want {
		t.Fatalf("created_at = %q, want server time %q", stored.CreatedAt, want)
	}
	proposed.CreatedAt = "2999-01-01T00:00:00Z"
	replayed, created, err := ledger.AppendVaultBoardSubmission(context.Background(), proposed)
	if err != nil || created || replayed.CreatedAt != stored.CreatedAt {
		t.Fatalf("replay = %+v created=%v err=%v", replayed, created, err)
	}
}

func TestVaultBoardDispatchDetectsDatabaseRollback(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ledger.sqlite")
	sequencePath := filepath.Join(dir, "policy-sequence")
	key := testIntegrityKey()
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenLedger(dbPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	sequence, err := OpenMonotonic(sequencePath, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	createVaultBoardTestEnrollment(t, ledger, "vault-dispatch-rollback", 0x64)
	op := vaultBoardTestOperation(t, ledger, "vault-dispatch-rollback", 0x65)
	_, auth, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x66), vaultBoardTestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	beforeDispatch, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err = OpenLedger(dbPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := ledger.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardDispatch(context.Background(), VaultBoardDispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase, RequestDigest: auth.RequestDigest,
	}, vaultBoardTestChainState(ledger)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, beforeDispatch, 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenLedger(dbPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := restored.AttachMonotonic(sequence); err == nil || !strings.Contains(err.Error(), "rolled-back database") {
		t.Fatalf("restored pre-dispatch database was accepted: %v", err)
	}
}

func TestVaultBoardRejectsCorruptRegisterPredecessor(t *testing.T) {
	ledger := openVaultBoardTestLedger(t, time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))
	createVaultBoardTestEnrollment(t, ledger, "vault-corrupt-register", 0x22)
	op := vaultBoardTestOperation(t, ledger, "vault-corrupt-register", 0x32)
	_, register, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x43), vaultBoardTestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	submitVaultBoardRegister(t, ledger, *register)
	if _, err := ledger.db.Exec(`UPDATE vault_board_authorization SET integrity_mac = ? WHERE operation_id = ? AND attempt = 0 AND phase = 'register'`, bytes.Repeat([]byte{0x99}, sha256.Size), register.OperationID); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = ledger.AppendVaultBoardAuthorizationAndDispatch(context.Background(), VaultBoardAuthorization{
		OperationID: register.OperationID, Attempt: 0, Phase: VaultBoardPhaseDelete,
		RequestDigest: bytes.Repeat([]byte{0x53}, sha256.Size), ExpireAt: ledger.NowUTC().Add(time.Minute).Unix(),
		CreatedAt: ledger.NowUTC().Format(time.RFC3339Nano),
	}, vaultBoardTestChainState(ledger))
	if err == nil || !strings.Contains(err.Error(), "integrity MAC") {
		t.Fatalf("corrupt register unlocked delete: %v", err)
	}
}

func TestVaultBoardRejectsCorruptDeletePredecessor(t *testing.T) {
	ledger := openVaultBoardTestLedger(t, time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))
	createVaultBoardTestEnrollment(t, ledger, "vault-corrupt-delete", 0x23)
	op := vaultBoardTestOperation(t, ledger, "vault-corrupt-delete", 0x33)
	_, register, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x44), vaultBoardTestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	submitVaultBoardRegister(t, ledger, *register)
	releaseVaultBoardAttempt(t, ledger, *register, 0x54)
	if _, err := ledger.db.Exec(`UPDATE vault_board_submission SET integrity_mac = ? WHERE operation_id = ? AND attempt = 0 AND phase = 'delete'`, bytes.Repeat([]byte{0x98}, sha256.Size), register.OperationID); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x45), vaultBoardTestChainState(ledger))
	if err == nil || !strings.Contains(err.Error(), "integrity MAC") {
		t.Fatalf("corrupt delete unlocked next attempt: %v", err)
	}
}

func TestVaultBoardRefusesCooperativeAuthorizationAtMaturity(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	ledger := openVaultBoardTestLedger(t, now)
	createVaultBoardTestEnrollment(t, ledger, "vault-mature", 0x24)
	op := vaultBoardTestOperation(t, ledger, "vault-mature", 0x34)
	op.SequenceAnchorMTP = now.Add(-time.Duration(program.VaultBoardV1ExitDelay) * time.Second).Unix()
	if _, _, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x46), vaultBoardTestChainState(ledger)); err == nil || !strings.Contains(err.Error(), "matured") {
		t.Fatalf("mature cooperative path accepted: %v", err)
	}
}

func TestVaultBoardMaturityUsesAuthoritativeMTPNotFundingHeaderTime(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	ledger := openVaultBoardTestLedger(t, now)
	createVaultBoardTestEnrollment(t, ledger, "vault-mtp", 0x25)
	op := vaultBoardTestOperation(t, ledger, "vault-mtp", 0x35)
	// A funding header can be ahead of its predecessor MTP. The BIP68 anchor
	// is the predecessor MTP, so consensus maturity must win even while wall
	// time and the funding header would still appear pre-maturity.
	op.SequenceAnchorMTP = now.Add(-time.Duration(program.VaultBoardV1ExitDelay) * time.Second).Unix()
	chain := VaultBoardChainState{TipMTP: op.SequenceAnchorMTP + int64(program.VaultBoardV1ExitDelay)}
	if _, _, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x47), chain); err == nil || !strings.Contains(err.Error(), "matured") {
		t.Fatalf("consensus-mature cooperative path accepted: %v", err)
	}
	if _, _, _, err := ledger.BeginVaultBoardAttempt(context.Background(), op, vaultBoardRegisterRequest(ledger, 0x48), VaultBoardChainState{}); err == nil || !strings.Contains(err.Error(), "MTP") {
		t.Fatalf("missing authoritative MTP was accepted: %v", err)
	}
}

func TestOpenLedgerRejectsVaultBoardStructuralDrift(t *testing.T) {
	mutations := []struct {
		name string
		sql  string
	}{
		{name: "column", sql: `ALTER TABLE vault_board_operation ADD COLUMN attacker TEXT`},
		{name: "index columns", sql: `DROP INDEX vault_board_operation_vault; CREATE INDEX vault_board_operation_vault ON vault_board_operation(created_at, vault_id)`},
		{name: "extra index", sql: `CREATE INDEX board_extra ON vault_board_operation(txid)`},
		{name: "trigger", sql: `CREATE TRIGGER board_erase AFTER INSERT ON vault_board_authorization BEGIN DELETE FROM vault_board_authorization; END`},
		{name: "view", sql: `CREATE VIEW board_leak AS SELECT * FROM vault_board_authorization`},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "board.sqlite")
			ledger, err := OpenLedger(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(mutation.sql); err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			_ = db.Close()
			if reopened, err := OpenLedger(path, nil); err == nil {
				_ = reopened.Close()
				t.Fatal("structurally altered v2 schema was accepted")
			}
		})
	}
}

func TestOpenLedgerRejectsVaultBoardForeignKeyDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "board.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(createVaultBoardSchema, "vault_id TEXT PRIMARY KEY REFERENCES vault(vault_id)", "vault_id TEXT PRIMARY KEY", 1)
	if _, err := db.Exec(createMultiTenantSchema + createVtxoSchema + altered); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_meta (version) VALUES (?)`, schemaVersion); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if reopened, err := OpenLedger(path, nil); err == nil {
		_ = reopened.Close()
		t.Fatal("v2 schema without enrollment foreign key was accepted")
	}
}

func TestVaultBoardSchemaIsPinnedPerDeployment(t *testing.T) {
	for _, network := range []string{program.NetworkMainnet, program.NetworkMutinynet} {
		t.Run(network, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ledger.sqlite")
			ledger, err := OpenLedgerForNetwork(path, nil, network)
			if err != nil {
				t.Fatal(err)
			}
			if err := ledger.SetIntegrityKey(testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			board := createVaultBoardTestEnrollmentForNetwork(t, ledger, "vault-network", 0x21, network)
			got, err := ledger.GetVaultBoardEnrollment(board.VaultID)
			if err != nil || got.ExitDelay != board.ExitDelay {
				t.Fatalf("boarding enrollment: %v %v", got, err)
			}
			other := program.NetworkMainnet
			if network == other {
				other = program.NetworkMutinynet
			}
			otherPins, _ := program.PinsFor(other)
			if _, err := ledger.db.Exec("UPDATE vault_board_enrollment SET exit_delay = ? WHERE vault_id = ?", otherPins.BoardExitDelay, board.VaultID); err == nil {
				t.Fatal("schema accepted other network's delay")
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := OpenLedgerForNetwork(path, nil, other); err == nil {
				reopened.Close()
				t.Fatal("opened other network's ledger")
			}
			reopened, err := OpenLedgerForNetwork(path, nil, network)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if err := reopened.SetIntegrityKey(testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			if _, err := reopened.GetVaultBoardEnrollment(board.VaultID); err != nil {
				t.Fatal(err)
			}
		})
	}
	if ledger, err := OpenLedgerForNetwork(filepath.Join(t.TempDir(), "invalid.sqlite"), nil, ""); err == nil {
		ledger.Close()
		t.Fatal("accepted empty network")
	}
}
