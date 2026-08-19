package policy

import (
	"path/filepath"
	"testing"
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
		t.Fatal("accepted a rolled-back issuance count")
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
