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

	"github.com/brg444/arkade-vault-server/internal/program"
)

func openVaultBoardV2TestLedger(t testing.TB, now time.Time) *Ledger {
	t.Helper()
	ledger, err := OpenMutinynetVaultBoardV2Ledger(filepath.Join(t.TempDir(), "board-v2.sqlite"), func() time.Time { return now })
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

func createVaultBoardV2TestEnrollment(t testing.TB, ledger *Ledger, vaultID string, tag byte) VaultBoardV2Enrollment {
	t.Helper()
	now := ledger.NowUTC()
	tokenHash := bytes.Repeat([]byte{tag}, sha256.Size)
	if err := ledger.PutInvite(tokenHash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	input := policyTestVaultInput(t, vaultID, tag, tokenHash)
	input.Record.Network = program.NetworkMutinynet
	if err := SealVaultRecord(&input.Record, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	compressed := bytes.Repeat([]byte{tag + 1}, 33)
	compressed[0] = 0x02
	board := VaultBoardV2Enrollment{
		VaultID: vaultID, Program: program.VaultBoardV2,
		BoardingPub: compressed, CosignerPub: append([]byte(nil), compressed...), OperatorPub: append([]byte(nil), compressed...),
		ExitDelay: program.VaultBoardV2ExitDelay, ExitDelayUnit: program.VaultBoardV2ExitDelayUnit,
		PkScript: append([]byte{0x51, 0x20}, bytes.Repeat([]byte{tag}, 32)...), Address: "tb1p-board-v2-test",
	}
	if err := SealVaultBoardV2Enrollment(&board, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := ledger.CreateVaultWithBoardV2(input, board); err != nil {
		t.Fatal(err)
	}
	return board
}

func vaultBoardV2TestOperation(t testing.TB, ledger *Ledger, vaultID string, tag byte) VaultBoardV2Operation {
	t.Helper()
	txid := bytes.Repeat([]byte{tag}, 32)
	return VaultBoardV2Operation{
		VaultID: vaultID, Txid: txid, Vout: uint32(tag), ValueSats: 50_000,
		BoardingScript:    append([]byte{0x51, 0x20}, bytes.Repeat([]byte{tag + 1}, 32)...),
		ReceiverScript:    []byte{0x51, 0x20, tag},
		SequenceAnchorMTP: ledger.NowUTC().Add(-time.Hour).Unix(),
	}
}

func vaultBoardV2TestChainState(ledger *Ledger) VaultBoardV2ChainState {
	return VaultBoardV2ChainState{TipMTP: ledger.NowUTC().Unix()}
}

func vaultBoardV2RegisterRequest(ledger *Ledger, tag byte) VaultBoardV2RegisterRequest {
	pub := bytes.Repeat([]byte{tag + 1}, 33)
	pub[0] = 0x02
	return VaultBoardV2RegisterRequest{
		RequestDigest: bytes.Repeat([]byte{tag}, sha256.Size), TreeSessionPub: pub,
		ReceiverSats: 49_000, FeeSats: 1_000,
		ExpireAt: ledger.NowUTC().Add(2 * time.Minute).Unix(),
	}
}

func submitVaultBoardV2Register(t testing.TB, ledger *Ledger, auth VaultBoardV2Authorization) {
	t.Helper()
	if _, _, err := ledger.AppendVaultBoardV2Dispatch(context.Background(), VaultBoardV2Dispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: VaultBoardV2PhaseRegister,
		RequestDigest: append([]byte(nil), auth.RequestDigest...),
	}, vaultBoardV2TestChainState(ledger)); err != nil {
		t.Fatal(err)
	}
	_, _, err := ledger.AppendVaultBoardV2Submission(context.Background(), VaultBoardV2Submission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: VaultBoardV2PhaseRegister,
		RequestDigest: append([]byte(nil), auth.RequestDigest...), Outcome: VaultBoardV2AuthSubmitted,
		OperatorRef: "intent-test", CreatedAt: ledger.NowUTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func releaseVaultBoardV2Attempt(t testing.TB, ledger *Ledger, auth VaultBoardV2Authorization, tag byte) {
	t.Helper()
	deleteAuth := VaultBoardV2Authorization{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: VaultBoardV2PhaseDelete,
		RequestDigest: bytes.Repeat([]byte{tag}, sha256.Size), ExpireAt: ledger.NowUTC().Add(time.Minute).Unix(),
		CreatedAt: ledger.NowUTC().Format(time.RFC3339Nano),
	}
	stored, _, err := ledger.AppendVaultBoardV2Authorization(context.Background(), deleteAuth, vaultBoardV2TestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardV2Dispatch(context.Background(), VaultBoardV2Dispatch{
		OperationID: stored.OperationID, Attempt: stored.Attempt, Phase: VaultBoardV2PhaseDelete,
		RequestDigest: append([]byte(nil), stored.RequestDigest...),
	}, vaultBoardV2TestChainState(ledger)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardV2Submission(context.Background(), VaultBoardV2Submission{
		OperationID: stored.OperationID, Attempt: stored.Attempt, Phase: VaultBoardV2PhaseDelete,
		RequestDigest: stored.RequestDigest, Outcome: VaultBoardV2AuthReleased,
		CreatedAt: ledger.NowUTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVaultBoardV2AttemptIsServerAllocatedAndRotatesOnlyAfterRelease(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	ledger := openVaultBoardV2TestLedger(t, now)
	createVaultBoardV2TestEnrollment(t, ledger, "vault-board", 0x21)
	op := vaultBoardV2TestOperation(t, ledger, "vault-board", 0x31)
	request := vaultBoardV2RegisterRequest(ledger, 0x41)

	storedOp, first, created, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, request, vaultBoardV2TestChainState(ledger))
	if err != nil || !created || first.Attempt != 0 {
		t.Fatalf("first attempt = %+v created=%v err=%v", first, created, err)
	}
	wantID, err := ComputeVaultBoardV2OperationID(op.VaultID, op.Txid, op.Vout)
	if err != nil || storedOp.OperationID != wantID {
		t.Fatalf("server operation id = %q, want %q (%v)", storedOp.OperationID, wantID, err)
	}
	_, replay, created, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, request, vaultBoardV2TestChainState(ledger))
	if err != nil || created || replay.Attempt != first.Attempt {
		t.Fatalf("exact replay = %+v created=%v err=%v", replay, created, err)
	}
	if _, _, err := ledger.AppendVaultBoardV2Dispatch(context.Background(), VaultBoardV2Dispatch{
		OperationID: first.OperationID, Attempt: first.Attempt, Phase: first.Phase,
		RequestDigest: first.RequestDigest,
	}, vaultBoardV2TestChainState(ledger)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(ledger, 0x42), vaultBoardV2TestChainState(ledger)); err == nil || !strings.Contains(err.Error(), "released") {
		t.Fatalf("rotated dispatched attempt: %v", err)
	}
	submitVaultBoardV2Register(t, ledger, *first)
	releaseVaultBoardV2Attempt(t, ledger, *first, 0x51)
	nextRequest := vaultBoardV2RegisterRequest(ledger, 0x42)
	nextRequest.ReceiverSats = 48_500
	nextRequest.FeeSats = 1_500
	_, next, created, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, nextRequest, vaultBoardV2TestChainState(ledger))
	if err != nil || !created || next.Attempt != 1 {
		t.Fatalf("next attempt = %+v created=%v err=%v", next, created, err)
	}
	if _, _, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, request, vaultBoardV2TestChainState(ledger)); err == nil {
		t.Fatal("delayed attempt-0 replay moved the operation back to an old generation")
	}
}

func TestVaultBoardV2UndispatchedRegisterRotatesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ledger.sqlite")
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenMutinynetVaultBoardV2Ledger(dbPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	createVaultBoardV2TestEnrollment(t, ledger, "vault-restart", 0x71)
	op := vaultBoardV2TestOperation(t, ledger, "vault-restart", 0x72)
	firstRequest := vaultBoardV2RegisterRequest(ledger, 0x73)
	_, first, created, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, firstRequest, vaultBoardV2TestChainState(ledger))
	if err != nil || !created || first.Attempt != 0 {
		t.Fatalf("first register = %+v created=%v err=%v", first, created, err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenMutinynetVaultBoardV2Ledger(dbPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	secondRequest := vaultBoardV2RegisterRequest(restarted, 0x74)
	_, second, created, err := restarted.BeginVaultBoardV2Attempt(context.Background(), op, secondRequest, vaultBoardV2TestChainState(restarted))
	if err != nil || !created || second.Attempt != 1 {
		t.Fatalf("restarted register = %+v created=%v err=%v", second, created, err)
	}
	if _, _, err := restarted.AppendVaultBoardV2Dispatch(context.Background(), VaultBoardV2Dispatch{
		OperationID: second.OperationID, Attempt: second.Attempt, Phase: second.Phase,
		RequestDigest: second.RequestDigest,
	}, vaultBoardV2TestChainState(restarted)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := restarted.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(restarted, 0x75), vaultBoardV2TestChainState(restarted)); err == nil || !strings.Contains(err.Error(), "released") {
		t.Fatalf("post-dispatch restart rotated ambiguous attempt: %v", err)
	}
}

func TestVaultBoardV2DispatchSeparatesSafeRetryFromAmbiguousNetworkOutcome(t *testing.T) {
	ledger := openVaultBoardV2TestLedger(t, time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))
	createVaultBoardV2TestEnrollment(t, ledger, "vault-dispatch", 0x61)
	op := vaultBoardV2TestOperation(t, ledger, "vault-dispatch", 0x62)
	_, auth, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(ledger, 0x63), vaultBoardV2TestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardV2Submission(context.Background(), VaultBoardV2Submission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase,
		RequestDigest: auth.RequestDigest, Outcome: VaultBoardV2AuthSubmitted, OperatorRef: "intent-before-dispatch",
	}); err == nil || !strings.Contains(err.Error(), "dispatch required") {
		t.Fatalf("submission crossed missing dispatch barrier: %v", err)
	}
	dispatch := VaultBoardV2Dispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase,
		RequestDigest: append([]byte(nil), auth.RequestDigest...),
	}
	first, created, err := ledger.AppendVaultBoardV2Dispatch(context.Background(), dispatch, vaultBoardV2TestChainState(ledger))
	if err != nil || !created || first.CreatedAt == "" {
		t.Fatalf("dispatch = %+v created=%v err=%v", first, created, err)
	}
	if _, created, err := ledger.AppendVaultBoardV2Dispatch(context.Background(), dispatch, vaultBoardV2TestChainState(ledger)); err != nil || created {
		t.Fatalf("exact dispatch replay created=%v err=%v", created, err)
	}
	dispatch.RequestDigest = bytes.Repeat([]byte{0x99}, sha256.Size)
	if _, _, err := ledger.AppendVaultBoardV2Dispatch(context.Background(), dispatch, vaultBoardV2TestChainState(ledger)); err == nil {
		t.Fatal("changed dispatch digest was accepted")
	}
	snapshot, err := ledger.GetCurrentVaultBoardV2Attempt(context.Background(), auth.OperationID)
	if err != nil || snapshot.RegisterDispatch == nil || snapshot.RegisterSubmission != nil {
		t.Fatalf("ambiguous dispatch snapshot = %+v, %v", snapshot, err)
	}
}

func TestVaultBoardV2DefiniteRegisterRejectionAllowsFreshAttempt(t *testing.T) {
	ledger := openVaultBoardV2TestLedger(t, time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))
	createVaultBoardV2TestEnrollment(t, ledger, "vault-rejected", 0x68)
	op := vaultBoardV2TestOperation(t, ledger, "vault-rejected", 0x69)
	firstRequest := vaultBoardV2RegisterRequest(ledger, 0x6a)
	_, first, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, firstRequest, vaultBoardV2TestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardV2Dispatch(context.Background(), VaultBoardV2Dispatch{
		OperationID: first.OperationID, Attempt: first.Attempt, Phase: first.Phase,
		RequestDigest: first.RequestDigest,
	}, vaultBoardV2TestChainState(ledger)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardV2Submission(context.Background(), VaultBoardV2Submission{
		OperationID: first.OperationID, Attempt: first.Attempt, Phase: first.Phase,
		RequestDigest: first.RequestDigest, Outcome: VaultBoardV2AuthRejected,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, firstRequest, vaultBoardV2TestChainState(ledger)); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("replayed rejected request: %v", err)
	}
	_, second, created, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(ledger, 0x6b), vaultBoardV2TestChainState(ledger))
	if err != nil || !created || second.Attempt != first.Attempt+1 {
		t.Fatalf("fresh attempt = %+v created=%v err=%v", second, created, err)
	}
}

func TestVaultBoardV2SubmissionUsesServerTimestamp(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 123, time.UTC)
	ledger := openVaultBoardV2TestLedger(t, now)
	createVaultBoardV2TestEnrollment(t, ledger, "vault-result-time", 0x76)
	op := vaultBoardV2TestOperation(t, ledger, "vault-result-time", 0x77)
	_, auth, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(ledger, 0x78), vaultBoardV2TestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardV2Dispatch(context.Background(), VaultBoardV2Dispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase,
		RequestDigest: auth.RequestDigest,
	}, vaultBoardV2TestChainState(ledger)); err != nil {
		t.Fatal(err)
	}
	proposed := VaultBoardV2Submission{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase,
		RequestDigest: auth.RequestDigest, Outcome: VaultBoardV2AuthSubmitted,
		OperatorRef: "intent-server-time", CreatedAt: "1900-01-01T00:00:00Z",
	}
	stored, created, err := ledger.AppendVaultBoardV2Submission(context.Background(), proposed)
	if err != nil || !created {
		t.Fatalf("submission created=%v err=%v", created, err)
	}
	if want := now.Format(time.RFC3339Nano); stored.CreatedAt != want {
		t.Fatalf("created_at = %q, want server time %q", stored.CreatedAt, want)
	}
	proposed.CreatedAt = "2999-01-01T00:00:00Z"
	replayed, created, err := ledger.AppendVaultBoardV2Submission(context.Background(), proposed)
	if err != nil || created || replayed.CreatedAt != stored.CreatedAt {
		t.Fatalf("replay = %+v created=%v err=%v", replayed, created, err)
	}
}

func TestVaultBoardV2DispatchDetectsDatabaseRollback(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ledger.sqlite")
	sequencePath := filepath.Join(dir, "policy-sequence")
	key := testIntegrityKey()
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	ledger, err := OpenMutinynetVaultBoardV2Ledger(dbPath, func() time.Time { return now })
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
	createVaultBoardV2TestEnrollment(t, ledger, "vault-dispatch-rollback", 0x64)
	op := vaultBoardV2TestOperation(t, ledger, "vault-dispatch-rollback", 0x65)
	_, auth, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(ledger, 0x66), vaultBoardV2TestChainState(ledger))
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
	ledger, err = OpenMutinynetVaultBoardV2Ledger(dbPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := ledger.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.AppendVaultBoardV2Dispatch(context.Background(), VaultBoardV2Dispatch{
		OperationID: auth.OperationID, Attempt: auth.Attempt, Phase: auth.Phase, RequestDigest: auth.RequestDigest,
	}, vaultBoardV2TestChainState(ledger)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, beforeDispatch, 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenMutinynetVaultBoardV2Ledger(dbPath, func() time.Time { return now })
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

func TestVaultBoardV2RejectsCorruptRegisterPredecessor(t *testing.T) {
	ledger := openVaultBoardV2TestLedger(t, time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))
	createVaultBoardV2TestEnrollment(t, ledger, "vault-corrupt-register", 0x22)
	op := vaultBoardV2TestOperation(t, ledger, "vault-corrupt-register", 0x32)
	_, register, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(ledger, 0x43), vaultBoardV2TestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	submitVaultBoardV2Register(t, ledger, *register)
	if _, err := ledger.db.Exec(`UPDATE vault_board_v2_authorization SET integrity_mac = ? WHERE operation_id = ? AND attempt = 0 AND phase = 'register'`, bytes.Repeat([]byte{0x99}, sha256.Size), register.OperationID); err != nil {
		t.Fatal(err)
	}
	_, _, err = ledger.AppendVaultBoardV2Authorization(context.Background(), VaultBoardV2Authorization{
		OperationID: register.OperationID, Attempt: 0, Phase: VaultBoardV2PhaseDelete,
		RequestDigest: bytes.Repeat([]byte{0x53}, sha256.Size), ExpireAt: ledger.NowUTC().Add(time.Minute).Unix(),
		CreatedAt: ledger.NowUTC().Format(time.RFC3339Nano),
	}, vaultBoardV2TestChainState(ledger))
	if err == nil || !strings.Contains(err.Error(), "integrity MAC") {
		t.Fatalf("corrupt register unlocked delete: %v", err)
	}
}

func TestVaultBoardV2RejectsCorruptDeletePredecessor(t *testing.T) {
	ledger := openVaultBoardV2TestLedger(t, time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))
	createVaultBoardV2TestEnrollment(t, ledger, "vault-corrupt-delete", 0x23)
	op := vaultBoardV2TestOperation(t, ledger, "vault-corrupt-delete", 0x33)
	_, register, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(ledger, 0x44), vaultBoardV2TestChainState(ledger))
	if err != nil {
		t.Fatal(err)
	}
	submitVaultBoardV2Register(t, ledger, *register)
	releaseVaultBoardV2Attempt(t, ledger, *register, 0x54)
	if _, err := ledger.db.Exec(`UPDATE vault_board_v2_submission SET integrity_mac = ? WHERE operation_id = ? AND attempt = 0 AND phase = 'delete'`, bytes.Repeat([]byte{0x98}, sha256.Size), register.OperationID); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = ledger.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(ledger, 0x45), vaultBoardV2TestChainState(ledger))
	if err == nil || !strings.Contains(err.Error(), "integrity MAC") {
		t.Fatalf("corrupt delete unlocked next attempt: %v", err)
	}
}

func TestVaultBoardV2RefusesCooperativeAuthorizationAtMaturity(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	ledger := openVaultBoardV2TestLedger(t, now)
	createVaultBoardV2TestEnrollment(t, ledger, "vault-mature", 0x24)
	op := vaultBoardV2TestOperation(t, ledger, "vault-mature", 0x34)
	op.SequenceAnchorMTP = now.Add(-time.Duration(program.VaultBoardV2ExitDelay) * time.Second).Unix()
	if _, _, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(ledger, 0x46), vaultBoardV2TestChainState(ledger)); err == nil || !strings.Contains(err.Error(), "matured") {
		t.Fatalf("mature cooperative path accepted: %v", err)
	}
}

func TestVaultBoardV2MaturityUsesAuthoritativeMTPNotFundingHeaderTime(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	ledger := openVaultBoardV2TestLedger(t, now)
	createVaultBoardV2TestEnrollment(t, ledger, "vault-mtp", 0x25)
	op := vaultBoardV2TestOperation(t, ledger, "vault-mtp", 0x35)
	// A funding header can be ahead of its predecessor MTP. The BIP68 anchor
	// is the predecessor MTP, so consensus maturity must win even while wall
	// time and the funding header would still appear pre-maturity.
	op.SequenceAnchorMTP = now.Add(-time.Duration(program.VaultBoardV2ExitDelay) * time.Second).Unix()
	chain := VaultBoardV2ChainState{TipMTP: op.SequenceAnchorMTP + int64(program.VaultBoardV2ExitDelay)}
	if _, _, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(ledger, 0x47), chain); err == nil || !strings.Contains(err.Error(), "matured") {
		t.Fatalf("consensus-mature cooperative path accepted: %v", err)
	}
	if _, _, _, err := ledger.BeginVaultBoardV2Attempt(context.Background(), op, vaultBoardV2RegisterRequest(ledger, 0x48), VaultBoardV2ChainState{}); err == nil || !strings.Contains(err.Error(), "MTP") {
		t.Fatalf("missing authoritative MTP was accepted: %v", err)
	}
}

func TestOpenVaultBoardV2LedgerRejectsStructuralDrift(t *testing.T) {
	mutations := []struct {
		name string
		sql  string
	}{
		{name: "column", sql: `ALTER TABLE vault_board_v2_operation ADD COLUMN attacker TEXT`},
		{name: "index columns", sql: `DROP INDEX vault_board_v2_operation_vault; CREATE INDEX vault_board_v2_operation_vault ON vault_board_v2_operation(created_at, vault_id)`},
		{name: "extra index", sql: `CREATE INDEX board_extra ON vault_board_v2_operation(txid)`},
		{name: "trigger", sql: `CREATE TRIGGER board_erase AFTER INSERT ON vault_board_v2_authorization BEGIN DELETE FROM vault_board_v2_authorization; END`},
		{name: "view", sql: `CREATE VIEW board_leak AS SELECT * FROM vault_board_v2_authorization`},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "board.sqlite")
			ledger, err := OpenMutinynetVaultBoardV2Ledger(path, nil)
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
			if reopened, err := OpenMutinynetVaultBoardV2Ledger(path, nil); err == nil {
				_ = reopened.Close()
				t.Fatal("structurally altered v2 schema was accepted")
			}
		})
	}
}

func TestOpenVaultBoardV2LedgerRejectsForeignKeyDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "board.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(createVaultBoardV2Schema, "vault_id TEXT PRIMARY KEY REFERENCES vault(vault_id)", "vault_id TEXT PRIMARY KEY", 1)
	if _, err := db.Exec(createMultiTenantSchema + createMainnetVtxoSchema + altered); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_meta (version) VALUES (?)`, vaultBoardV2SchemaVersion); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if reopened, err := OpenMutinynetVaultBoardV2Ledger(path, nil); err == nil {
		_ = reopened.Close()
		t.Fatal("v2 schema without enrollment foreign key was accepted")
	}
}
