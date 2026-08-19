package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefuseLegacyDatabaseAllowsMissingAndEmpty(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.sqlite")
	if err := RefuseLegacyDatabase(missing); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty.sqlite")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RefuseLegacyDatabase(empty); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyBootSealedIssuanceLandsOnSchemaV5(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-boot.sqlite")
	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	if err := led.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.BackupSQLiteIfAbsent(path + ".pre-v4"); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.BackupGenerationIfAbsent(path+".pre-v5", BackupGenerationPreV5); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateIssuanceIntegrity(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateRecoverySessions(); err != nil {
		t.Fatal(err)
	}
	ver, err := schemaVersion(led.db)
	if err != nil || ver != schemaVersionCurrent {
		t.Fatalf("empty boot schema = %d, %v want %d", ver, err, schemaVersionCurrent)
	}
	cols, err := tableColumns(led.db, "issuance")
	if err != nil || !sameColumns(cols, issuanceColumns) {
		t.Fatalf("empty boot issuance = %v %v", cols, err)
	}
	if err := RefuseLegacyDatabase(path); err != nil {
		t.Fatalf("fresh empty v5 refused: %v", err)
	}
}

func TestRefuseLegacyDatabaseRejectsSingletonCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := led.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.Enroll(validCredential(0x71)); err != nil {
		t.Fatal(err)
	}
	if err := led.Close(); err != nil {
		t.Fatal(err)
	}
	err = RefuseLegacyDatabase(path)
	if err == nil || !strings.Contains(err.Error(), "legacy credential") {
		t.Fatalf("legacy credential accepted: %v", err)
	}
}
