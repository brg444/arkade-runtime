package policy

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLegacyIssuanceDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(createPOCSchema, "  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),\n", "", 1)
	if legacy == createPOCSchema {
		t.Fatal("failed to strip issuance MAC from createPOCSchema")
	}
	if _, err := db.Exec(legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(createCredentialEnvelopeSchema); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
}

func openV4LegacyLedger(t *testing.T) *Ledger {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v4-legacy.sqlite")
	writeLegacyIssuanceDB(t, path)
	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	key := testIntegrityKey()
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := led.Enroll(validCredential(0x51)); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	return led
}

func TestPreV5BackupRequiresV4LegacyIssuanceAndRefusesRecreation(t *testing.T) {
	led := openV4LegacyLedger(t)
	dest := filepath.Join(t.TempDir(), "vault.sqlite.pre-v5")
	if err := led.BackupGenerationIfAbsent(dest, BackupGenerationPreV5); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatal(err)
	}
	// Existing dest is write-once.
	first, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := led.BackupGenerationIfAbsent(dest, BackupGenerationPreV5); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) && len(first) != len(second) {
		// byte-identical preferred; length match is enough to prove no rewrite
	}
	if !bytesEqual(first, second) {
		t.Fatal("valid pre-v5 backup was rewritten")
	}

	if err := led.MigrateIssuanceIntegrity(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	if err := led.BackupGenerationIfAbsent(dest, BackupGenerationPreV5); err == nil ||
		!strings.Contains(err.Error(), "already advanced") {
		t.Fatalf("recreated pre-v5 after live advanced: %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("advanced live invented a historical backup")
	}
}

func TestPreV5BackupRejectsSameIdentityV5File(t *testing.T) {
	led := openV4LegacyLedger(t)
	if err := led.MigrateIssuanceIntegrity(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	// VACUUM the now-v5 live file and present it as .pre-v5.
	forged := filepath.Join(t.TempDir(), "forged.pre-v5")
	if _, err := led.db.Exec(`VACUUM INTO ?`, forged); err != nil {
		t.Fatal(err)
	}
	if err := led.BackupGenerationIfAbsent(forged, BackupGenerationPreV5); err == nil ||
		!strings.Contains(err.Error(), "pre-v5") {
		t.Fatalf("v5 live file accepted as pre-v5: %v", err)
	}
}

func TestPreV4BackupRefusesCreateAfterV4Migrate(t *testing.T) {
	led := openV4LegacyLedger(t)
	dest := filepath.Join(t.TempDir(), "late.pre-v4")
	if err := led.BackupSQLiteIfAbsent(dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("invented a pre-v4 snapshot after live reached v4")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
