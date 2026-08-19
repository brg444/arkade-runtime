package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"math"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/brg444/arkade-vault-server/internal/program"
)

func openVtxoTestLedger(t *testing.T, clock Clock) (*Ledger, string) {
	t.Helper()
	led := openTestLedger(t, clock)
	if err := led.Enroll(validCredential(0x61)); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateIssuanceIntegrity(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateRecoverySessions(); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateAuthzHardening(); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateVtxoOperation(); err != nil {
		t.Fatal(err)
	}
	ver, err := schemaVersion(led.db)
	if err != nil || ver != schemaVersionVtxoOperation {
		t.Fatalf("schema = %d %v, want %d", ver, err, schemaVersionVtxoOperation)
	}
	return led, LegacyFirstVaultID
}

func insertTestVtxoOperation(t *testing.T, led *Ledger, rec VtxoOperation) {
	t.Helper()
	if err := SealVtxoOperation(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`
INSERT INTO vtxo_operation (
  operation_id, vault_id, purpose, bundle_digest, state,
  amount_sats, fee_sats, dest_script, change_script,
  unsigned_psbt, authorized_psbt, checkpoint_psbts, commitment_psbt,
  checkpoint_tapscript, ark_txid, expires_at, created_at, last_dest_script,
  integrity_mac
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.OperationID, rec.VaultID, rec.Purpose, rec.BundleDigest, rec.State,
		rec.AmountSats, rec.FeeSats, rec.DestScript, rec.ChangeScript,
		rec.UnsignedPSBT, rec.AuthorizedPSBT, rec.CheckpointPSBTs, rec.CommitmentPSBT,
		rec.CheckpointTapscript, rec.ArkTxid, rec.ExpiresAt, rec.CreatedAt,
		rec.LastDestScript, rec.IntegrityMAC,
	); err != nil {
		t.Fatal(err)
	}
}

func testVtxoOperation(vaultID, opID, purpose, state string, amount, fee int64, created time.Time) VtxoOperation {
	return VtxoOperation{
		OperationID:         opID,
		VaultID:             vaultID,
		Purpose:             purpose,
		BundleDigest:        bytes.Repeat([]byte{0x11}, 32),
		State:               state,
		AmountSats:          amount,
		FeeSats:             fee,
		DestScript:          []byte{0x51},
		ChangeScript:        []byte{0x52},
		CheckpointPSBTs:     `["cHNidP8="]`,
		CommitmentPSBT:      "cHNidP8B",
		CheckpointTapscript: []byte{0xc0, 0x01},
		CreatedAt:           created.UTC().Format(time.RFC3339),
	}
}

func TestVtxoOperationMACRejectsIssuanceDomainAndMutations(t *testing.T) {
	if vtxoOperationMACDomain == issuanceIntegrityDomain {
		t.Fatal("vtxo operation reused issuance-record/v3")
	}
	rec := testVtxoOperation("vault-a", "op-1", vtxoPurposeSpend, vtxoStateReserved, 1_000, 50, time.Unix(0, 0).UTC())
	if err := SealVtxoOperation(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVtxoOperation(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	issuance := IssuanceRecord{
		VaultID: rec.VaultID, Digest: rec.BundleDigest, PeriodStart: "2026-08-19",
		Recipient: rec.AmountSats, Fee: rec.FeeSats, State: stateReserved, RequestPSBT: "psbt",
		CreatedAt: rec.CreatedAt, UpdatedAt: rec.CreatedAt,
	}
	if err := SealIssuance(&issuance, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	swapped := rec
	swapped.IntegrityMAC = append([]byte(nil), issuance.IntegrityMAC...)
	if err := VerifyVtxoOperation(&swapped, testIntegrityKey()); err == nil {
		t.Fatal("issuance-record/v3 MAC verified a vtxo operation")
	}
	rec.AmountSats++
	if err := VerifyVtxoOperation(&rec, testIntegrityKey()); err == nil {
		t.Fatal("amount mutation still verified")
	}
}

func TestVtxoOperationMACCoversCheckpointFields(t *testing.T) {
	rec := testVtxoOperation("vault-a", "op-1", vtxoPurposeSpend, vtxoStateReserved, 1_000, 50, time.Unix(0, 0).UTC())
	if err := SealVtxoOperation(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	rec.CheckpointPSBTs = `["other"]`
	if err := VerifyVtxoOperation(&rec, testIntegrityKey()); err == nil {
		t.Fatal("checkpoint_psbts mutation still verified")
	}
	rec = testVtxoOperation("vault-a", "op-1", vtxoPurposeSpend, vtxoStateReserved, 1_000, 50, time.Unix(0, 0).UTC())
	if err := SealVtxoOperation(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	rec.CommitmentPSBT = "mutated"
	if err := VerifyVtxoOperation(&rec, testIntegrityKey()); err == nil {
		t.Fatal("commitment_psbt mutation still verified")
	}
	rec = testVtxoOperation("vault-a", "op-1", vtxoPurposeSpend, vtxoStateReserved, 1_000, 50, time.Unix(0, 0).UTC())
	if err := SealVtxoOperation(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	rec.CheckpointTapscript = []byte{0xff}
	if err := VerifyVtxoOperation(&rec, testIntegrityKey()); err == nil {
		t.Fatal("checkpoint_tapscript mutation still verified")
	}
}

func TestVtxoOperationInputMACRoundTrip(t *testing.T) {
	in := VtxoOperationInput{
		OperationID: "op-1",
		Txid:        bytes.Repeat([]byte{0x22}, 32),
		Vout:        1,
		ValueSats:   25_000,
		Script:      []byte{0x51, 0x20},
	}
	if err := SealVtxoOperationInput(&in, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVtxoOperationInput(&in, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	in.ValueSats++
	if err := VerifyVtxoOperationInput(&in, testIntegrityKey()); err == nil {
		t.Fatal("input value mutation still verified")
	}
}

func TestVtxoBundleDigestBindsPurposeAndLengthPrefixes(t *testing.T) {
	txid := bytes.Repeat([]byte{0x33}, 32)
	inputs := []VtxoBundleInput{{Txid: txid, Vout: 1, ValueSats: 25_000}}
	dest := []byte{0x00, 0x51}
	change := []byte{0x00, 0x52}
	created := "2026-08-19T12:00:00Z"
	spend, err := ComputeVtxoBundleDigest(vtxoPurposeSpend, "vault-a", dest, change, 10_000, 200, inputs, created)
	if err != nil {
		t.Fatal(err)
	}
	board, err := ComputeVtxoBundleDigest(vtxoPurposeBoard, "vault-a", dest, change, 10_000, 200, inputs, created)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(spend, board) {
		t.Fatal("purpose is not bound into the bundle digest")
	}
	if len(spend) != sha256.Size {
		t.Fatalf("digest length %d", len(spend))
	}
	// dest_script || 0x00 || change_script would be ambiguous; length-prefix
	// must keep dest=[0x00,0x51] distinct from dest=[0x00] + leftover.
	alt, err := ComputeVtxoBundleDigest(vtxoPurposeSpend, "vault-a", []byte{0x00}, append([]byte{0x51}, change...), 10_000, 200, inputs, created)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(spend, alt) {
		t.Fatal("0x00-separated scripts collided")
	}
}

func TestMigrateVtxoOperationFromSchema8LeavesIssuanceAlone(t *testing.T) {
	clock := newManualClock(time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC))
	led, vaultID := openVtxoTestLedger(t, clock.Now)
	if _, _, err := led.IssueForTest(context.Background(), vaultID, digest(0xaa), 10, 1, 100, func(context.Context) (string, error) {
		return "signed", nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`DROP TABLE vtxo_operation_input`); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`DROP TABLE vtxo_operation`); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`UPDATE schema_meta SET version = ?`, schemaVersionAuthzHardening); err != nil {
		t.Fatal(err)
	}
	before, err := tableColumns(led.db, "issuance")
	if err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateVtxoOperation(); err != nil {
		t.Fatal(err)
	}
	after, err := tableColumns(led.db, "issuance")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(before, ",") != strings.Join(after, ",") {
		t.Fatalf("issuance columns changed: %v -> %v", before, after)
	}
	rows, err := led.db.Query(`PRAGMA table_info(vtxo_operation)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	joined := strings.Join(names, ",")
	for _, name := range []string{"checkpoint_psbts", "commitment_psbt", "checkpoint_tapscript"} {
		if !strings.Contains(joined, name) {
			t.Fatalf("schema 9 missing %s in %v", name, names)
		}
	}
}

func TestSpentInWindowRejectsUnauthenticatedAbort(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	clock := newManualClock(now)
	led, vaultID := openVtxoTestLedger(t, clock.Now)
	rec := testVtxoOperation(vaultID, "op-1", vtxoPurposeSpend, vtxoStateReserved, 1_000, 50, now)
	insertTestVtxoOperation(t, led, rec)
	if _, err := led.db.Exec(`UPDATE vtxo_operation SET state = ? WHERE operation_id = ?`, vtxoStateAborted, rec.OperationID); err != nil {
		t.Fatal(err)
	}
	_, err := led.SpentInPeriod(context.Background(), vaultID, "")
	if err == nil || !strings.Contains(err.Error(), "vtxo operation integrity") {
		t.Fatalf("want MAC fail-closed on unauthenticated abort, got %v", err)
	}
}

func TestAbortedDoesNotCountAfterReseal(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	clock := newManualClock(now)
	led, vaultID := openVtxoTestLedger(t, clock.Now)
	rec := testVtxoOperation(vaultID, "op-1", vtxoPurposeSpend, vtxoStateAborted, 1_000, 50, now)
	insertTestVtxoOperation(t, led, rec)
	got, err := led.SpentInPeriod(context.Background(), vaultID, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("aborted counted %d", got)
	}
}

func TestPropertyL1AndVtxoOutflowWithinRolling24h(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	cfg := &quick.Config{MaxCount: 64}
	err := quick.Check(func(l1Amt, l1Fee, vAmt, vFee uint16) bool {
		if int64(l1Amt)+int64(l1Fee)+int64(vAmt)+int64(vFee) > program.PeriodAllowanceSats {
			return true
		}
		clock := newManualClock(now)
		led, vaultID := openVtxoTestLedger(t, clock.Now)
		if l1Amt > 0 || l1Fee > 0 {
			if _, _, err := led.IssueForTest(context.Background(), vaultID, digest(0xab), int64(l1Amt), int64(l1Fee), program.PeriodAllowanceSats, func(context.Context) (string, error) {
				return "signed", nil
			}); err != nil {
				t.Log(err)
				return false
			}
		}
		if vAmt > 0 || vFee > 0 {
			insertTestVtxoOperation(t, led, testVtxoOperation(vaultID, "op-prop", vtxoPurposeSpend, vtxoStateReserved, int64(vAmt), int64(vFee), now))
		}
		got, err := led.SpentInPeriod(context.Background(), vaultID, "")
		if err != nil {
			t.Log(err)
			return false
		}
		want := int64(l1Amt) + int64(l1Fee) + int64(vAmt) + int64(vFee)
		if want > math.MaxInt64 {
			return false
		}
		return got == want
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
}
