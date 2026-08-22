package policy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMonotonicRefusesRollback(t *testing.T) {
	dir := t.TempDir()
	key := testIntegrityKey()
	m, err := OpenMonotonic(filepath.Join(dir, "count"), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Observe(3); err != nil {
		t.Fatal(err)
	}
	if err := m.Observe(3); err != nil {
		t.Fatal(err)
	}
	if err := m.Observe(5); err != nil {
		t.Fatal(err)
	}
	if err := m.Observe(4); err == nil {
		t.Fatal("accepted a rolled-back policy sequence")
	}
}

func TestFirstIssuanceWithMonotonicCounterDoesNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	led, err := OpenMainnetLedger(filepath.Join(dir, "ledger.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := led.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	monotonic, err := OpenMonotonic(filepath.Join(dir, "count"), testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := led.AttachMonotonic(monotonic); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := led.IssueSequential(
			context.Background(), "vault-a", digest(0x71), "request", 10, 1, 100,
			func(context.Context, string) (string, error) { return "vault-signed", nil },
			func(context.Context, string) (string, error) { return "fully-signed", nil },
		)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		if err := led.Close(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		// Do not close the ledger here: the regression holds its only
		// connection forever, and Close would hide this failure by hanging.
		t.Fatal("first issuance deadlocked while updating monotonic counter")
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
	now := time.Now().UTC()
	rec := testVtxoOperation("vault-a", "op-rollback", vtxoPurposeSpend, vtxoStateReserved, 10_000, 100, now)
	rec.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
	inputs := []VtxoOperationInput{{
		Txid: bytes.Repeat([]byte{0x42}, 32), Vout: 0, ValueSats: 20_000, Script: []byte{0x51},
	}}
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
	err = restored.AttachMonotonic(sequence)
	if err == nil || !strings.Contains(err.Error(), "rolled-back database") {
		t.Fatalf("restored pre-reservation database was accepted: %v", err)
	}
}

func TestAdvanceSignCountRejectsBackwardNonZero(t *testing.T) {
	led := openTestLedger(t, nil)
	if err := led.Enroll(validCredential(0x51)); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateAuthzHardening(); err != nil {
		t.Fatal(err)
	}
	cred := validCredential(0x51)
	if err := led.AdvanceSignCount(cred.VaultID, cred.ID, 4); err != nil {
		t.Fatal(err)
	}
	if err := led.AdvanceSignCount(cred.VaultID, cred.ID, 4); err == nil {
		t.Fatal("accepted a repeated non-zero sign count")
	}
	if err := led.AdvanceSignCount(cred.VaultID, cred.ID, 2); err == nil {
		t.Fatal("accepted a decreasing sign count")
	}
	if err := led.AdvanceSignCount(cred.VaultID, cred.ID, 9); err != nil {
		t.Fatal(err)
	}
}

func TestVaultMapRoundTrip(t *testing.T) {
	led := openTestLedger(t, nil)
	if err := led.Enroll(validCredential(0x52)); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateAuthzHardening(); err != nil {
		t.Fatal(err)
	}
	rec := VaultMap{VaultID: validCredential(0x52).VaultID, KitHash: "aa" + "11", Payload: `{"name":"arkade-vault-map"}`}
	rec.KitHash = "aa" + "11" // invalid length
	if err := led.PutVaultMap(rec); err == nil {
		t.Fatal("accepted a short kit hash")
	}
	rec.KitHash = "ab" + "cd" + "ef01" + "23" // still short
	rec.KitHash = "ab" + string(make([]byte, 0))
	rec.KitHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := led.PutVaultMap(rec); err != nil {
		t.Fatal(err)
	}
	got, err := led.GetVaultMap(rec.VaultID)
	if err != nil || got == nil || got.Payload != rec.Payload {
		t.Fatalf("round trip: %+v %v", got, err)
	}
}
