package policy

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMonotonicRefusesRollback(t *testing.T) {
	m, err := OpenMonotonic(filepath.Join(t.TempDir(), "count"), testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Observe(0); err != nil {
		t.Fatal(err)
	}
	for _, value := range []uint64{3, 3, 5} {
		if err := m.Observe(value); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Observe(4); err == nil {
		t.Fatal("accepted a rolled-back policy sequence")
	}
}

func TestMissingSequenceCannotRebaselineNonEmptyLedger(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ledger.sqlite")
	sequencePath := filepath.Join(dir, "policy-sequence")
	key := testIntegrityKey()
	ledger, err := OpenMainnetLedger(dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	createPolicyTestVault(t, ledger, "vault-a", 0x39)
	sequence, err := OpenMonotonic(sequencePath, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	now := ledger.NowUTC()
	rec := testVtxoOperation("vault-a", "op-before-loss", vtxoPurposeSpend, vtxoStateReserved, 10_000, 0, now)
	rec.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
	input := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x49}, 32), ValueSats: 20_000, Script: []byte{0x51}}
	if err := ledger.ReserveVtxoOperation(context.Background(), rec, []VtxoOperationInput{input}, 100_000); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sequencePath); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenMainnetLedger(dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	missing, err := OpenMonotonic(sequencePath, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.AttachMonotonic(missing); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing policy sequence re-established a baseline: %v", err)
	}
}

func TestFirstVtxoReservationWithMonotonicSequenceDoesNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	led, err := OpenMainnetLedger(filepath.Join(dir, "ledger.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer led.Close()
	if err := led.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	createPolicyTestVault(t, led, "vault-a", 0x40)
	sequence, err := OpenMonotonic(filepath.Join(dir, "sequence"), testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := led.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	now := led.NowUTC()
	rec := testVtxoOperation("vault-a", "op-first", vtxoPurposeSpend, vtxoStateReserved, 10_000, 100, now)
	rec.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
	inputs := []VtxoOperationInput{{Txid: bytes.Repeat([]byte{0x41}, 32), ValueSats: 20_000, Script: []byte{0x51}}}
	done := make(chan error, 1)
	go func() { done <- led.ReserveVtxoOperation(context.Background(), rec, inputs, 100_000) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first VTXO reservation deadlocked while advancing policy sequence")
	}
}

func TestVtxoReservationDetectsDatabaseRollback(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ledger.sqlite")
	sequencePath := filepath.Join(dir, "policy-sequence")
	key := testIntegrityKey()
	ledger, err := OpenMainnetLedger(dbPath, nil)
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
	createPolicyTestVault(t, ledger, "vault-a", 0x41)
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	preReservation, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err = OpenMainnetLedger(dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := ledger.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	now := ledger.NowUTC()
	rec := testVtxoOperation("vault-a", "op-rollback", vtxoPurposeSpend, vtxoStateReserved, 10_000, 100, now)
	rec.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
	inputs := []VtxoOperationInput{{Txid: bytes.Repeat([]byte{0x42}, 32), ValueSats: 20_000, Script: []byte{0x51}}}
	if err := ledger.ReserveVtxoOperation(context.Background(), rec, inputs, 100_000); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, preReservation, 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenMainnetLedger(dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := restored.AttachMonotonic(sequence); err == nil || !strings.Contains(err.Error(), "rolled-back database") {
		t.Fatalf("restored database was accepted: %v", err)
	}
}

func TestVtxoReservationRollsBackWhenSequenceCannotAdvance(t *testing.T) {
	dir := t.TempDir()
	ledger, err := OpenMainnetLedger(filepath.Join(dir, "ledger.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := ledger.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	createPolicyTestVault(t, ledger, "vault-a", 0x42)
	sequenceDir := filepath.Join(dir, "sequence")
	if err := os.Mkdir(sequenceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sequence, err := OpenMonotonic(filepath.Join(sequenceDir, "policy-sequence"), testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(sequenceDir); err != nil {
		t.Fatal(err)
	}
	now := ledger.NowUTC()
	rec := testVtxoOperation("vault-a", "op-no-sequence", vtxoPurposeSpend, vtxoStateReserved, 10_000, 100, now)
	rec.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
	inputs := []VtxoOperationInput{{Txid: bytes.Repeat([]byte{0x43}, 32), ValueSats: 20_000, Script: []byte{0x51}}}
	if err := ledger.ReserveVtxoOperation(context.Background(), rec, inputs, 100_000); err == nil || !strings.Contains(err.Error(), "policy sequence") {
		t.Fatalf("reservation survived sequence failure: %v", err)
	}
	if _, err := ledger.GetVtxoOperation(context.Background(), rec.OperationID); err != sql.ErrNoRows {
		t.Fatalf("failed reservation was committed: %v", err)
	}
}

func TestSignCountAndVaultMapCurrentSchema(t *testing.T) {
	led := openPolicyTestLedger(t, nil)
	createPolicyTestVault(t, led, "vault-a", 0x51)
	_, credential, err := led.LoadVerifiedVault("vault-a", testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := led.AdvanceSignCount("vault-a", credential.CredentialID, 4); err != nil {
		t.Fatal(err)
	}
	if err := led.AdvanceSignCount("vault-a", credential.CredentialID, 4); err == nil {
		t.Fatal("accepted a repeated non-zero sign count")
	}
	rec := VaultMap{
		VaultID: "vault-a",
		KitHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Payload: `{"name":"arkade-vault-map"}`,
	}
	if err := led.PutVaultMap(rec); err != nil {
		t.Fatal(err)
	}
	got, err := led.GetVaultMap(rec.VaultID)
	if err != nil || got == nil || got.Payload != rec.Payload {
		t.Fatalf("vault map round trip: %+v %v", got, err)
	}
}
