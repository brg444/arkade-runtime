package policy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

func TestDecideReplaySignOnceDest(t *testing.T) {
	next := RecoverySession{
		VaultID:    "vault-a",
		Purpose:    sessionPurposeInitiate,
		InputTxid:  "AA" + "11",
		InputVout:  0,
		DestScript: "5120ab",
	}
	action, err := DecideReplay(nil, next)
	if err != nil || action != ReplaySign {
		t.Fatalf("first sign: %v %v", action, err)
	}
	existing := &RecoverySession{
		VaultID:     "vault-a",
		Purpose:     sessionPurposeInitiate,
		InputTxid:   "aa11",
		InputVout:   0,
		DestScript:  "5120ab",
		LastSighash: "11",
		Signature:   []byte{1},
	}
	next.InputTxid = "aa11"
	next.LastSighash = "11"
	action, err = DecideReplay(existing, next)
	if err != nil || action != ReplayReplay {
		t.Fatalf("same sighash: %v %v", action, err)
	}
	next.LastSighash = "22"
	action, err = DecideReplay(existing, next)
	if err != nil || action != ReplayResign {
		t.Fatalf("fee bump: %v %v", action, err)
	}
	next.DestScript = "5120cd"
	if _, err := DecideReplay(existing, next); err == nil {
		t.Fatal("second dest accepted")
	}
	if _, err := DecideReplay(existing, RecoverySession{VaultID: "vault-a", Purpose: "claim", InputTxid: "aa11", DestScript: "5120ab"}); err == nil {
		t.Fatal("claim purpose accepted")
	}
	pending := &RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", InputVout: 0, DestScript: "5120ab", LastSighash: "11",
	}
	if _, err := DecideReplay(pending, RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", DestScript: "5120ab", LastSighash: "11",
	}); !errors.Is(err, ErrRecoveryBusy) {
		t.Fatalf("unsigned in-flight: %v", err)
	}
	action, err = DecideReplay(pending, RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", DestScript: "5120ab", LastSighash: "11", Signature: []byte{1},
	})
	if err != nil || action != ReplayResign {
		t.Fatalf("finalize pending: %v %v", action, err)
	}
}

func TestApplyRecoveryReplayRefusesSecondUnsignedWorker(t *testing.T) {
	led := openTestLedger(t, nil)
	if err := led.Enroll(validCredential(0x71)); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateRecoverySessions(); err != nil {
		t.Fatal(err)
	}
	next := RecoverySession{
		VaultID: LegacyFirstVaultID, Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", InputVout: 0, DestScript: "5120ab", LastSighash: "11",
	}
	action, stored, err := led.ApplyRecoveryReplay(next)
	if err != nil || action != ReplaySign || stored == nil {
		t.Fatalf("first: %v %v", action, err)
	}
	if _, _, err := led.ApplyRecoveryReplay(next); !errors.Is(err, ErrRecoveryBusy) {
		t.Fatalf("second unsigned: %v", err)
	}
	next.Signature = []byte("signed-psbt")
	action, stored, err = led.ApplyRecoveryReplay(next)
	if err != nil || action != ReplayResign || stored == nil || !bytes.Equal(stored.Signature, next.Signature) {
		t.Fatalf("finalize: %v %v stored=%+v", action, err, stored)
	}
}

func TestRecoverySessionMACCoversSignatureAndSighash(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, sha256.Size)
	rec := RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", DestScript: "5120ab",
		LastSighash: "11", Signature: []byte{1, 2, 3},
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:01Z",
	}
	if err := sealSession(&rec, key); err != nil {
		t.Fatal(err)
	}
	mac := append([]byte(nil), rec.IntegrityMAC...)
	rec.Signature = []byte{9, 9, 9}
	rec.IntegrityMAC = mac
	if err := verifySession(&rec, key); err == nil {
		t.Fatal("tampered signature still verified")
	}
	rec.Signature = []byte{1, 2, 3}
	rec.LastSighash = "22"
	rec.IntegrityMAC = mac
	if err := verifySession(&rec, key); err == nil {
		t.Fatal("tampered sighash still verified")
	}
	rec.LastSighash = "11"
	if err := verifySession(&rec, key); err != nil {
		t.Fatalf("honest session: %v", err)
	}
}

func TestMigrateRecoverySessionsRefusesRetiredV1Rows(t *testing.T) {
	led := openTestLedger(t, nil)
	if err := led.Enroll(validCredential(0x72)); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateRecoverySessions(); err != nil {
		t.Fatal(err)
	}
	rec := RecoverySession{
		VaultID: LegacyFirstVaultID, Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", InputVout: 0, DestScript: "5120ab",
		LastSighash: "11", Signature: []byte{1, 2, 3},
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:01Z",
	}
	rec.IntegrityMAC = sessionMAC(testIntegrityKey(), retiredSessionV1Preimage(rec))
	if _, err := led.db.Exec(
		`INSERT INTO recovery_session (vault_id, purpose, input_txid, input_vout, dest_script, last_sighash, signature, created_at, updated_at, integrity_mac)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		rec.VaultID, rec.Purpose, rec.InputTxid, rec.InputVout, rec.DestScript,
		rec.LastSighash, rec.Signature, rec.CreatedAt, rec.UpdatedAt, rec.IntegrityMAC,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`UPDATE schema_meta SET version = ?`, schemaVersionSessions); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateRecoverySessions(); err == nil {
		t.Fatal("v1 session row migrated")
	}
	ver, err := schemaVersion(led.db)
	if err != nil || ver != schemaVersionSessions {
		t.Fatalf("schema = %d %v, want %d", ver, err, schemaVersionSessions)
	}
}

func TestMigrateRecoverySessionsEmptyTableAdvancesSchema(t *testing.T) {
	led := openTestLedger(t, nil)
	if err := led.Enroll(validCredential(0x73)); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`UPDATE schema_meta SET version = ?`, schemaVersionSessions); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateRecoverySessions(); err != nil {
		t.Fatalf("empty reseal: %v", err)
	}
	ver, err := schemaVersion(led.db)
	if err != nil || ver != schemaVersionCurrent {
		t.Fatalf("schema = %d %v, want %d", ver, err, schemaVersionCurrent)
	}
}

func TestVerifySessionRejectsLegacyV1MAC(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, sha256.Size)
	rec := RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", DestScript: "5120ab",
		LastSighash: "11", Signature: []byte{1},
	}
	rec.IntegrityMAC = sessionMAC(key, retiredSessionV1Preimage(rec))
	if err := verifySession(&rec, key); err == nil {
		t.Fatal("v1 session MAC still accepted")
	}
}

// retiredSessionV1Preimage is the schema-6 session MAC payload. It exists
// only so tests can prove production verify and migrate reject it.
func retiredSessionV1Preimage(rec RecoverySession) []byte {
	var b []byte
	b = append(b, []byte("arkade-2fa-vault/recovery-session/v1")...)
	b = append(b, 0)
	b = append(b, []byte(rec.VaultID)...)
	b = append(b, 0)
	b = append(b, []byte(rec.Purpose)...)
	b = append(b, 0)
	b = append(b, []byte(rec.InputTxid)...)
	b = append(b, 0)
	b = append(b, []byte(fmt.Sprintf("%d", rec.InputVout))...)
	b = append(b, 0)
	b = append(b, []byte(rec.DestScript)...)
	return b
}
