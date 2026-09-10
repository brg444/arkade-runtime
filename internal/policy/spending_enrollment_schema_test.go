package policy

import (
	"bytes"
	"path/filepath"
	"testing"
)

// Migration fixtures must start with historical constraints, not merely relabel
// a current database's schema_meta row. Row bytes and MACs remain untouched.
func restoreSchemaTenConstraints(t *testing.T, l *Ledger) {
	t.Helper()
	if _, err := l.db.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatal(err)
	}
	tx, err := l.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := rebuildEnrollmentTables(tx, createMultiTenantSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE schema_meta SET version=10`); err != nil {
		t.Fatal(err)
	}
	if err := validateMultiTenantSchemaOn(tx); err != nil {
		t.Fatal(err)
	}
	if err := requireForeignKeyCheckClean(tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
}

func TestSharedSpendingMigrationPreservesAuthenticatedRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spending.sqlite")
	l, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	createPolicyTestVault(t, l, "protected-vault", 73)
	before, passBefore, err := l.LoadVerifiedVault("protected-vault", testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	restoreSchemaTenConstraints(t, l)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	after, passAfter, err := restored.LoadVerifiedVault("protected-vault", testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if VaultRecordsCanonicallyEqual(*before, *after) != nil || VaultCredentialsCanonicallyEqual(*passBefore, *passAfter) != nil || !bytes.Equal(before.IntegrityMAC, after.IntegrityMAC) || !bytes.Equal(passBefore.IntegrityMAC, passAfter.IntegrityMAC) {
		t.Fatal("migration changed authenticated enrollment")
	}
	if err := requireForeignKeysEnabled(restored.db); err != nil {
		t.Fatal(err)
	}
	if err := requireForeignKeyCheckClean(restored.db); err != nil {
		t.Fatal(err)
	}
	if version, err := restored.SchemaVersion(); err != nil || version != 11 {
		t.Fatal("wrong shared Spending schema", version, err)
	}
}
