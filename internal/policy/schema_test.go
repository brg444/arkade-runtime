package policy

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenLedgerRejectsStaleCredentialSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
CREATE TABLE credential (
  id INTEGER PRIMARY KEY,
  credential_id BLOB NOT NULL,
  p256_compressed BLOB NOT NULL,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  created_at TEXT NOT NULL
);`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_, err = OpenLedger(path, nil)
	if err == nil || !strings.Contains(err.Error(), "incompatible vault database") || !strings.Contains(err.Error(), "do not delete authoritative deployment data") {
		t.Fatalf("want stale schema error, got %v", err)
	}
}

func TestOpenLedgerRejectsV2RoleSchemaWithoutReinterpretation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "funded-v2.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// These role names intentionally model the pre-v3 credential layout. In
	// particular, hot/offline cannot be reinterpreted as PhoneRoutineBIP340
	// and the independent ExternalOwnerWallet+RecoveryKey pair.
	if _, err := db.Exec(`
CREATE TABLE credential (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  credential_id BLOB NOT NULL,
  webauthn_p256_compressed BLOB NOT NULL,
  direct_p256_compressed BLOB NOT NULL,
  hot_bip340_compressed BLOB NOT NULL,
  offline_compressed BLOB NOT NULL,
  provider_base_compressed BLOB NOT NULL,
  tweaked_provider_compressed BLOB NOT NULL,
  template_version TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  integrity_mac BLOB NOT NULL
);`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_, err = OpenLedger(path, nil)
	if err == nil || !strings.Contains(err.Error(), "incompatible vault database") ||
		!strings.Contains(err.Error(), "do not delete authoritative deployment data") {
		t.Fatalf("v2 role schema was reinterpreted or not safely rejected: %v", err)
	}
}

func TestOpenLedgerRejectsMalformedIssuanceSchemaAfterPartialCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "malformed-issuance.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE issuance (vault_id TEXT)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// The first open may create credential before CREATE TABLE issuance fails.
	if led, err := OpenLedger(path, nil); err == nil {
		_ = led.Close()
		t.Fatal("malformed preexisting issuance table accepted")
	}
	// A restart must inspect issuance itself rather than accepting its name.
	_, err = OpenLedger(path, nil)
	if err == nil || !strings.Contains(err.Error(), "issuance columns") || !strings.Contains(err.Error(), "do not delete authoritative deployment data") {
		t.Fatalf("malformed issuance schema was not rejected on restart: %v", err)
	}
}

func TestOpenLedgerRejectsIssuanceColumnsWithoutStagedStateConstraints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-staged-constraint.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(
		createPOCSchema,
		"state TEXT NOT NULL CHECK (state IN ('reserved', 'vault_signed', 'completed'))",
		"state TEXT NOT NULL",
		1,
	)
	if broken == createPOCSchema {
		t.Fatal("test failed to remove staged-state constraint")
	}
	if _, err := db.Exec(broken); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_, err = OpenLedger(path, nil)
	if err == nil || !strings.Contains(err.Error(), "issuance constraints") || !strings.Contains(err.Error(), "do not delete authoritative deployment data") {
		t.Fatalf("same-column issuance table without state constraint was accepted: %v", err)
	}
}

func TestEmptyLegacyIssuanceMigratesToMAC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-legacy-issuance.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(createPOCSchema, "  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),\n", "", 1)
	if legacy == createPOCSchema {
		t.Fatal("failed to strip issuance MAC column from createPOCSchema")
	}
	if _, err := db.Exec(legacy); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatalf("empty legacy issuance must open without mutation: %v", err)
	}
	t.Cleanup(func() { _ = led.Close() })
	cols, err := tableColumns(led.db, "issuance")
	if err != nil {
		t.Fatal(err)
	}
	if !sameColumns(cols, issuanceColumnsLegacy) {
		t.Fatalf("OpenLedger mutated issuance columns %v", cols)
	}
	if err := led.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateIssuanceIntegrity(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	cols, err = tableColumns(led.db, "issuance")
	if err != nil {
		t.Fatal(err)
	}
	if !sameColumns(cols, issuanceColumns) {
		t.Fatalf("v5 issuance columns %v, want %v", cols, issuanceColumns)
	}
}

func TestOpenLedgerDoesNotRewriteALegacyRailwaySnapshot(t *testing.T) {
	src := os.Getenv("VAULT_RAILWAY_SNAPSHOT")
	if src == "" {
		src = "/Users/alexb./tmp/vault-mutinynet-secrets/vault.railway.pr1.live.pre-v4.c5285c7.sqlite"
	}
	if _, err := os.Stat(src); err != nil {
		t.Skip("railway snapshot not present")
	}
	dst := filepath.Join(t.TempDir(), "rehearse.sqlite")
	in, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, in, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := tableColumns(mustOpenRaw(t, dst), "issuance")
	if err != nil {
		t.Fatal(err)
	}
	if !sameColumns(before, issuanceColumnsLegacy) {
		t.Fatalf("fixture issuance already sealed: %v", before)
	}
	led, err := OpenLedger(dst, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	after, err := tableColumns(led.db, "issuance")
	if err != nil {
		t.Fatal(err)
	}
	if !sameColumns(after, issuanceColumnsLegacy) {
		t.Fatalf("OpenLedger mutated issuance: %v", after)
	}
	cred, err := led.GetCredential()
	if err != nil || cred == nil {
		t.Fatal(err)
	}
	if cred.OperationalAddress != "tb1p9llcrjjkzr57py6vffwveztm0hn0hezj7wzrq5mat6nh07j37g4qh8jl0l" {
		t.Fatalf("funded address changed: %s", cred.OperationalAddress)
	}
}

func mustOpenRaw(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestNonEmptyLegacyIssuanceFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsealed-issuance.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(createPOCSchema, "  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),\n", "", 1)
	if _, err := db.Exec(legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO issuance (vault_id, arkade_sighash, period_start, recipient_amount, fee, state, request_psbt, created_at, updated_at)
		VALUES ('vault-a', ?, '2026-08-15', 1, 0, 'reserved', 'psbt', '2026-08-15T00:00:00Z', '2026-08-15T00:00:00Z')`, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatalf("OpenLedger must not rewrite unsealed issuance: %v", err)
	}
	t.Cleanup(func() { _ = led.Close() })
	if err := led.MigrateIssuanceIntegrity(testIntegrityKey()); err == nil ||
		!strings.Contains(err.Error(), "unsealed issuance") ||
		!strings.Contains(err.Error(), "do not delete authoritative deployment data") {
		t.Fatalf("unsealed issuance rows were accepted: %v", err)
	}
}
