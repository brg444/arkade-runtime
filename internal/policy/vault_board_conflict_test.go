package policy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func boardingConflictFixture(t *testing.T) (*Ledger, VaultBoardOperation, VaultBoardAuthorization, VaultBoardConflict) {
	t.Helper()
	l := openVaultBoardTestLedger(t, time.Date(2026, 9, 9, 6, 0, 0, 0, time.UTC))
	createVaultBoardTestEnrollment(t, l, "boarding-conflict", 0x62)
	operation := vaultBoardTestOperation(t, l, "boarding-conflict", 0x63)
	op, register, _, err := l.BeginVaultBoardAttempt(t.Context(), operation, vaultBoardRegisterRequest(l, 0x64), vaultBoardTestChainState(l))
	if err != nil {
		t.Fatal(err)
	}
	submitVaultBoardRegister(t, l, *register)
	boardHash, _ := chainhash.NewHashFromStr(hex.EncodeToString(op.Txid))
	original := wire.NewMsgTx(2)
	original.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: *boardHash, Index: op.Vout}, nil, nil))
	original.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{9}, Index: 1}, nil, nil))
	original.AddTxOut(wire.NewTxOut(49000, op.ReceiverScript))
	auth := VaultBoardAuthorization{OperationID: op.OperationID, Attempt: register.Attempt, Phase: VaultBoardPhaseFinalize, RequestDigest: bytes.Repeat([]byte{0x65}, 32), CommitmentTxid: original.TxHash().String(), ReceiverTxid: strings.Repeat("ab", 32)}
	if _, _, _, err := l.AppendVaultBoardAuthorizationAndDispatch(t.Context(), auth, vaultBoardTestChainState(l)); err != nil {
		t.Fatal(err)
	}
	conflicting := wire.NewMsgTx(2)
	conflicting.AddTxIn(wire.NewTxIn(&original.TxIn[1].PreviousOutPoint, nil, nil))
	conflicting.AddTxOut(wire.NewTxOut(200, []byte{0x51}))
	raw := func(tx *wire.MsgTx) string {
		var b bytes.Buffer
		if err := tx.Serialize(&b); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(b.Bytes())
	}
	conflict := VaultBoardConflict{OperationID: op.OperationID, Attempt: register.Attempt, RequestDigest: auth.RequestDigest, CommitmentRaw: raw(original), Evidence: BitcoinConflictEvidence{Kind: BitcoinConflictKind, CommitmentTxid: auth.CommitmentTxid, FundingTxid: original.TxIn[1].PreviousOutPoint.Hash.String(), FundingVout: 1, ConflictingTxid: conflicting.TxHash().String(), ConflictingVin: 0, BlockHash: strings.Repeat("bc", 32), BlockHeight: 100, TipHash: strings.Repeat("cd", 32), TipHeight: 105, RawTransaction: raw(conflicting)}}
	return l, *op, auth, conflict
}

func TestVaultBoardConflictIsAppendOnlyAndRequiresFreshChecks(t *testing.T) {
	l, op, auth, rec := boardingConflictFixture(t)
	before, _ := l.GetCurrentVaultBoardAttempt(t.Context(), op.OperationID)
	originalAuth, _ := json.Marshal(before.FinalAuthorization)
	count, _ := economicOutflowCount(l.db)
	if err := l.AppendVaultBoardConflict(t.Context(), rec, vaultBoardTestChainState(l)); err != nil {
		t.Fatal(err)
	}
	after, err := l.GetCurrentVaultBoardAttempt(t.Context(), op.OperationID)
	afterAuth, _ := json.Marshal(after.FinalAuthorization)
	if err != nil || len(after.Conflicts) != 1 || !bytes.Equal(originalAuth, afterAuth) || after.FinalDispatch == nil {
		t.Fatal("final authority changed")
	}
	if got, _ := economicOutflowCount(l.db); got != count+1 {
		t.Fatalf("sequence did not advance: %d -> %d", count, got)
	}
	next := vaultBoardRegisterRequest(l, 0x66)
	if _, _, _, err := l.BeginVaultBoardAttempt(t.Context(), op, next, vaultBoardTestChainState(l)); err == nil {
		t.Fatal("retained proof without current chain check rotated")
	}
	checked := vaultBoardTestChainState(l)
	checked.ConflictChecks = [][]byte{after.Conflicts[0].IntegrityMAC}
	if _, current, created, err := l.BeginVaultBoardAttempt(t.Context(), op, next, checked); err != nil || !created || current.Attempt != auth.Attempt+1 {
		t.Fatalf("new attempt %+v %v", current, err)
	}
	if _, _, _, err := l.AppendVaultBoardAuthorizationAndDispatch(t.Context(), auth, checked); err == nil {
		t.Fatal("old final replay crossed attempt fence")
	}
	// The external sequence detects deletion/rollback of the new recovery fact.
	sequence, err := OpenMonotonic(filepath.Join(t.TempDir(), "sequence"), testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	currentCount, _ := economicOutflowCount(l.db)
	if err := sequence.write(currentCount); err != nil {
		t.Fatal(err)
	}
	if err := l.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.Exec(`DELETE FROM vault_board_conflict`); err != nil {
		t.Fatal(err)
	}
	if err := l.AttachMonotonic(sequence); err == nil {
		t.Fatal("recovery evidence rollback went undetected")
	}
}

func TestVaultBoardConflictRejectsTamperingAndUnboundEvidence(t *testing.T) {
	for _, scenario := range []string{"wrong final digest", "wrong commitment", "wrong conflict raw", "shallow", "wrong input", "already submitted", "tampered stored proof"} {
		t.Run(scenario, func(t *testing.T) {
			l, op, auth, rec := boardingConflictFixture(t)
			switch scenario {
			case "wrong final digest":
				rec.RequestDigest = bytes.Repeat([]byte{4}, 32)
			case "wrong commitment":
				rec.Evidence.CommitmentTxid = strings.Repeat("11", 32)
			case "wrong conflict raw":
				rec.Evidence.RawTransaction += "00"
			case "shallow":
				rec.Evidence.TipHeight--
			case "wrong input":
				rec.Evidence.FundingVout++
			case "already submitted":
				_, _, err := l.AppendVaultBoardSubmission(t.Context(), VaultBoardSubmission{OperationID: op.OperationID, Attempt: auth.Attempt, Phase: VaultBoardPhaseFinalize, RequestDigest: auth.RequestDigest, Outcome: VaultBoardAuthSubmitted, CommitmentTxid: auth.CommitmentTxid, ReceiverTxid: auth.ReceiverTxid})
				if err != nil {
					t.Fatal(err)
				}
			case "tampered stored proof":
				if err := l.AppendVaultBoardConflict(t.Context(), rec, vaultBoardTestChainState(l)); err != nil {
					t.Fatal(err)
				}
				if _, err := l.db.Exec(`UPDATE vault_board_conflict SET integrity_mac=?`, bytes.Repeat([]byte{9}, 32)); err != nil {
					t.Fatal(err)
				}
				if _, err := l.GetCurrentVaultBoardAttempt(t.Context(), op.OperationID); err == nil {
					t.Fatal("tampered evidence loaded")
				}
				return
			}
			if err := l.AppendVaultBoardConflict(t.Context(), rec, vaultBoardTestChainState(l)); err == nil {
				t.Fatal("invalid evidence accepted")
			}
			saved, err := l.GetCurrentVaultBoardAttempt(t.Context(), op.OperationID)
			if err != nil || len(saved.Conflicts) != 0 {
				t.Fatal("rejected evidence persisted")
			}
		})
	}
}

func TestVaultBoardConflictSerializesWithLateFinalResult(t *testing.T) {
	l, op, auth, rec := boardingConflictFixture(t)
	var wg sync.WaitGroup
	start := make(chan struct{})
	result := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		result <- l.AppendVaultBoardConflict(t.Context(), rec, vaultBoardTestChainState(l))
	}()
	go func() {
		defer wg.Done()
		<-start
		_, _, err := l.AppendVaultBoardSubmission(t.Context(), VaultBoardSubmission{OperationID: op.OperationID, Attempt: auth.Attempt, Phase: VaultBoardPhaseFinalize, RequestDigest: auth.RequestDigest, Outcome: VaultBoardAuthSubmitted, CommitmentTxid: auth.CommitmentTxid, ReceiverTxid: auth.ReceiverTxid})
		result <- err
	}()
	close(start)
	wg.Wait()
	close(result)
	successes := 0
	for err := range result {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("conflict and success both accepted: %d", successes)
	}
	snapshot, err := l.GetCurrentVaultBoardAttempt(t.Context(), op.OperationID)
	if err != nil || snapshot.FinalAuthorization == nil || snapshot.FinalDispatch == nil || (len(snapshot.Conflicts) == 1) == (snapshot.FinalSubmission != nil) {
		t.Fatal("ambiguous ledger result")
	}
}

func TestVaultBoardConflictMigrationPreservesV8AndRestartEvidence(t *testing.T) {
	l, op, _, rec := boardingConflictFixture(t)
	before, _ := l.GetCurrentVaultBoardAttempt(t.Context(), op.OperationID)
	beforeJSON, _ := json.Marshal(before)
	count, _ := economicOutflowCount(l.db)
	if _, err := l.db.Exec(`DROP TABLE vault_board_conflict`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.Exec(`UPDATE schema_meta SET version=8`); err != nil {
		t.Fatal(err)
	}
	var seq int
	var name, path string
	if err := l.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	now := l.NowUTC()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	reopen := func() *Ledger {
		next, err := OpenLedger(path, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		if err := next.SetIntegrityKey(testIntegrityKey()); err != nil {
			t.Fatal(err)
		}
		return next
	}
	l = reopen()
	after, _ := l.GetCurrentVaultBoardAttempt(t.Context(), op.OperationID)
	afterJSON, _ := json.Marshal(after)
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatal("migration changed authenticated history")
	}
	if version, err := l.SchemaVersion(); err != nil || version != 9 {
		t.Fatalf("schema %d %v", version, err)
	}
	if got, _ := economicOutflowCount(l.db); got != count {
		t.Fatal("migration altered sequence")
	}
	if err := l.AppendVaultBoardConflict(t.Context(), rec, vaultBoardTestChainState(l)); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l = reopen()
	defer l.Close()
	after, err := l.GetCurrentVaultBoardAttempt(t.Context(), op.OperationID)
	if err != nil || len(after.Conflicts) != 1 || after.FinalAuthorization == nil {
		t.Fatal("restart lost authority or proof")
	}
}

func TestVaultBoardConflictDeletionCannotBeMaskedByNewFinalRows(t *testing.T) {
	l, op, auth, rec := boardingConflictFixture(t)
	if err := l.AppendVaultBoardConflict(t.Context(), rec, vaultBoardTestChainState(l)); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := l.GetCurrentVaultBoardAttempt(t.Context(), op.OperationID)
	checks := vaultBoardTestChainState(l)
	checks.ConflictChecks = [][]byte{snapshot.Conflicts[0].IntegrityMAC}
	_, register, _, err := l.BeginVaultBoardAttempt(t.Context(), op, vaultBoardRegisterRequest(l, 0x66), checks)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.AppendVaultBoardDispatch(t.Context(), VaultBoardDispatch{OperationID: op.OperationID, Attempt: register.Attempt, Phase: VaultBoardPhaseRegister, RequestDigest: register.RequestDigest}, checks); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.AppendVaultBoardSubmission(t.Context(), VaultBoardSubmission{OperationID: op.OperationID, Attempt: register.Attempt, Phase: VaultBoardPhaseRegister, RequestDigest: register.RequestDigest, Outcome: VaultBoardAuthSubmitted, OperatorRef: "new-intent"}); err != nil {
		t.Fatal(err)
	}
	sequence, err := OpenMonotonic(filepath.Join(t.TempDir(), "sequence"), testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := economicOutflowCount(l.db)
	if err := sequence.write(before); err != nil {
		t.Fatal(err)
	}
	if err := l.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.Exec(`DELETE FROM vault_board_conflict`); err != nil {
		t.Fatal(err)
	}
	auth.Attempt = register.Attempt
	auth.RequestDigest = bytes.Repeat([]byte{0x67}, 32)
	auth.CommitmentTxid = strings.Repeat("dc", 32)
	if _, _, _, err := l.AppendVaultBoardAuthorizationAndDispatch(t.Context(), auth, vaultBoardTestChainState(l)); err == nil || !strings.Contains(err.Error(), "rolled-back database") {
		t.Fatalf("new final masked deletion: %v", err)
	}
	after, _ := economicOutflowCount(l.db)
	if after != before-1 {
		t.Fatal("failed final inserted rows before detecting rollback")
	}
}

func TestVaultBoardMissingHistoricalConflictCannotHideBehindOtherOperations(t *testing.T) {
	l, op, auth, rec := boardingConflictFixture(t)
	if err := l.AppendVaultBoardConflict(t.Context(), rec, vaultBoardTestChainState(l)); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := l.GetCurrentVaultBoardAttempt(t.Context(), op.OperationID)
	checked := vaultBoardTestChainState(l)
	checked.ConflictChecks = [][]byte{snapshot.Conflicts[0].IntegrityMAC}
	_, register, _, err := l.BeginVaultBoardAttempt(t.Context(), op, vaultBoardRegisterRequest(l, 0x66), checked)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.AppendVaultBoardDispatch(t.Context(), VaultBoardDispatch{OperationID: op.OperationID, Attempt: register.Attempt, Phase: VaultBoardPhaseRegister, RequestDigest: register.RequestDigest}, checked); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.AppendVaultBoardSubmission(t.Context(), VaultBoardSubmission{OperationID: op.OperationID, Attempt: register.Attempt, Phase: VaultBoardPhaseRegister, RequestDigest: register.RequestDigest, Outcome: VaultBoardAuthSubmitted, OperatorRef: "next"}); err != nil {
		t.Fatal(err)
	}
	before, _ := economicOutflowCount(l.db)
	if _, err := l.db.Exec(`DELETE FROM vault_board_conflict`); err != nil {
		t.Fatal(err)
	}
	// Legitimate work in another vault can outgrow the total before deletion.
	createVaultBoardTestEnrollment(t, l, "unrelated-boarding", 0x72)
	other := vaultBoardTestOperation(t, l, "unrelated-boarding", 0x73)
	if _, _, _, err := l.BeginVaultBoardAttempt(t.Context(), other, vaultBoardRegisterRequest(l, 0x74), vaultBoardTestChainState(l)); err != nil {
		t.Fatal(err)
	}
	if after, _ := economicOutflowCount(l.db); after < before {
		t.Fatal("fixture failed to mask aggregate count")
	}
	if _, err := l.GetCurrentVaultBoardAttempt(t.Context(), op.OperationID); err == nil || !strings.Contains(err.Error(), "historical final") {
		t.Fatalf("missing historical conflict loaded: %v", err)
	}
	auth.Attempt = register.Attempt
	auth.RequestDigest = bytes.Repeat([]byte{0x67}, 32)
	auth.CommitmentTxid = strings.Repeat("dc", 32)
	if _, _, _, err := l.AppendVaultBoardAuthorizationAndDispatch(t.Context(), auth, vaultBoardTestChainState(l)); err == nil || !strings.Contains(err.Error(), "historical final") {
		t.Fatalf("unrelated inserts masked missing conflict: %v", err)
	}
}
