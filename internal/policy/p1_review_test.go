package policy

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestBackupIsTakenBeforeV4MutationAndFailedMigrateRollsBack(t *testing.T) {
	key := testIntegrityKey()
	path := filepath.Join(t.TempDir(), "live.sqlite")
	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	want := validCredential(0x40)
	if err := led.Enroll(want); err != nil {
		t.Fatal(err)
	}
	if v4TableExists(led.db) {
		t.Fatal("enrollment created v4 tables before backup")
	}
	dest := path + ".pre-v4"
	if err := led.BackupSQLiteIfAbsent(dest); err != nil {
		t.Fatal(err)
	}
	if v4TableExists(led.db) {
		t.Fatal("backup mutated the live database")
	}
	backup, err := sql.Open("sqlite", dest)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	if v4TableExists(backup) {
		t.Fatal("rollback artifact is not a pristine v3 snapshot")
	}

	if err := led.MigrateLegacySingleton(bytes.Repeat([]byte{0x99}, 32)); err == nil {
		t.Fatal("wrong-key migrate succeeded")
	}
	if v4TableExists(led.db) {
		t.Fatal("failed migrate left v4 tables on the authoritative database")
	}
	got, err := led.GetCredential()
	if err != nil || got == nil || !bytes.Equal(got.IntegrityMAC, want.IntegrityMAC) {
		t.Fatalf("failed migrate changed v3: %v", err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	if !v4TableExists(led.db) {
		t.Fatal("successful migrate did not create v4 tables")
	}
}

func TestBackupRejectsUnverifiedLiveRecord(t *testing.T) {
	led := openTestLedger(t, nil)
	zeroBytes(led.integrityKey)
	led.integrityKey = nil
	want := validCredential(0x41)
	if err := led.Enroll(want); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "vault.sqlite.pre-v4")
	if err := led.BackupSQLiteIfAbsent(dest); err == nil {
		t.Fatal("backup without integrity key succeeded")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("backup file created without a verified live record")
	}
	if err := led.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`UPDATE credential SET integrity_mac = ? WHERE id = 1`, bytes.Repeat([]byte{0x00}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := led.BackupSQLiteIfAbsent(dest); err == nil || !strings.Contains(err.Error(), "live v3 credential") {
		t.Fatalf("tampered live record was backed up: %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("backup file created from a tampered live record")
	}
}

func TestBackupRejectsInvalidOrMismatchedExistingFile(t *testing.T) {
	key := testIntegrityKey()
	led := openTestLedger(t, nil)
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	want := validCredential(0x42)
	if err := led.Enroll(want); err != nil {
		t.Fatal(err)
	}

	garbage := filepath.Join(t.TempDir(), "garbage.pre-v4")
	if err := os.WriteFile(garbage, []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := led.BackupSQLiteIfAbsent(garbage); err == nil {
		t.Fatal("garbage backup dest accepted")
	}
	raw, err := os.ReadFile(garbage)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "not a sqlite database" {
		t.Fatal("invalid existing backup was overwritten")
	}

	otherPath := filepath.Join(t.TempDir(), "other.sqlite")
	other, err := OpenLedger(otherPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	if err := other.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := other.Enroll(validCredential(0x43)); err != nil {
		t.Fatal(err)
	}
	otherBackup := otherPath + ".pre-v4"
	if err := other.BackupSQLiteIfAbsent(otherBackup); err != nil {
		t.Fatal(err)
	}
	if err := led.BackupSQLiteIfAbsent(otherBackup); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("mismatched backup identity accepted: %v", err)
	}

	stale := filepath.Join(t.TempDir(), "stale.pre-v4")
	staleDB, err := sql.Open("sqlite", stale)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staleDB.Exec(`CREATE TABLE credential (id INTEGER PRIMARY KEY, p256_compressed BLOB)`); err != nil {
		t.Fatal(err)
	}
	_ = staleDB.Close()
	if err := led.BackupSQLiteIfAbsent(stale); err == nil || !strings.Contains(err.Error(), "incompatible vault database") {
		t.Fatalf("legacy-incompatible backup accepted: %v", err)
	}
}

func TestBackupSkipsEmptyLiveDatabase(t *testing.T) {
	led := openTestLedger(t, nil)
	if err := led.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "empty.pre-v4")
	if err := led.BackupSQLiteIfAbsent(dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("empty live database produced a rollback artifact")
	}
}

func TestOpenLedgerRejectsNewerAndDuplicateSchemaMeta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newer.sqlite")
	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`CREATE TABLE schema_meta (version INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`INSERT INTO schema_meta (version) VALUES (7)`); err != nil {
		t.Fatal(err)
	}
	if err := led.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = OpenLedger(path, nil)
	if err == nil || !strings.Contains(err.Error(), "newer than this binary") {
		t.Fatalf("newer schema_meta accepted: %v", err)
	}

	dup := filepath.Join(t.TempDir(), "dup.sqlite")
	dupLed, err := OpenLedger(dup, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dupLed.db.Exec(`CREATE TABLE schema_meta (version INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := dupLed.db.Exec(`INSERT INTO schema_meta (version) VALUES (4)`); err != nil {
		t.Fatal(err)
	}
	if _, err := dupLed.db.Exec(`INSERT INTO schema_meta (version) VALUES (5)`); err != nil {
		t.Fatal(err)
	}
	if err := dupLed.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = OpenLedger(dup, nil)
	if err == nil || !strings.Contains(err.Error(), "exactly one version row") {
		t.Fatalf("duplicate schema_meta accepted: %v", err)
	}
}

func TestOpenLedgerRejectsMalformedV4AndLegacyPendingSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "malformed-v4.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(createPOCSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE vault (vault_id TEXT)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(testIntegrityKey()); err == nil || !strings.Contains(err.Error(), "vault") {
		t.Fatalf("malformed vault table accepted at migrate: %v", err)
	}
	_ = led.Close()

	legacyPending := filepath.Join(t.TempDir(), "old-pending.sqlite")
	prior, err := OpenLedger(legacyPending, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureMultiTenantSchema(prior.db); err != nil {
		t.Fatal(err)
	}
	if _, err := prior.db.Exec(`DROP TABLE pending_enrollment`); err != nil {
		t.Fatal(err)
	}
	if _, err := prior.db.Exec(`
CREATE TABLE pending_enrollment (
  handle TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL UNIQUE,
  token_hash BLOB NOT NULL,
  challenge BLOB NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);`); err != nil {
		t.Fatal(err)
	}
	if err := prior.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenLedger(legacyPending, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.MigrateLegacySingleton(testIntegrityKey()); err == nil || !strings.Contains(err.Error(), "pending_enrollment") {
		t.Fatalf("pre-constraint pending_enrollment accepted at migrate: %v", err)
	}
	_ = reopened.Close()
}

func TestForeignKeyCheckRejectsOrphanRows(t *testing.T) {
	led := openTestLedger(t, nil)
	if err := ensureMultiTenantSchema(led.db); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`
INSERT INTO vault_credential (credential_id, vault_id, webauthn_p256_compressed, user_handle, resident, integrity_mac)
VALUES (?, ?, ?, NULL, 0, ?)`,
		[]byte{9, 9, 9}, "missing-vault", bytes.Repeat([]byte{0x02}, 33), bytes.Repeat([]byte{0x11}, 32),
	); err != nil {
		t.Fatal(err)
	}
	if err := ensureMultiTenantSchema(led.db); err == nil || !strings.Contains(err.Error(), "foreign key violation") {
		t.Fatalf("orphan vault_credential accepted: %v", err)
	}
}

func TestMigrationComparesCompleteCanonicalRecords(t *testing.T) {
	key := testIntegrityKey()
	led := openTestLedger(t, nil)
	want := validCredential(0x44)
	if err := led.Enroll(want); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}

	rec := vaultRecordFromCredential(want)
	rec.RecoveryKey = append([]byte(nil), rec.RecoveryKey...)
	rec.RecoveryKey[1] ^= 1
	if err := sealVaultRecord(&rec, key); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`UPDATE vault SET recovery_key_compressed = ?, integrity_mac = ? WHERE vault_id = ?`,
		rec.RecoveryKey, rec.IntegrityMAC, rec.VaultID); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err == nil || !strings.Contains(err.Error(), "recovery_key") {
		t.Fatalf("recovery key mismatch accepted: %v", err)
	}

	rec = vaultRecordFromCredential(want)
	if err := sealVaultRecord(&rec, key); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`UPDATE vault SET recovery_key_compressed = ?, integrity_mac = ? WHERE vault_id = ?`,
		rec.RecoveryKey, rec.IntegrityMAC, rec.VaultID); err != nil {
		t.Fatal(err)
	}

	cred := VaultCredential{
		CredentialID: append([]byte(nil), want.ID...),
		VaultID:      want.VaultID,
		WebAuthnP256: append([]byte(nil), want.WebAuthnP256...),
		Resident:     false,
	}
	cred.WebAuthnP256[1] ^= 1
	if err := sealVaultCredential(&cred, key); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`UPDATE vault_credential SET webauthn_p256_compressed = ?, integrity_mac = ? WHERE vault_id = ?`,
		cred.WebAuthnP256, cred.IntegrityMAC, cred.VaultID); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err == nil || !strings.Contains(err.Error(), "webauthn_p256") {
		t.Fatalf("webauthn mismatch accepted: %v", err)
	}

	got, err := led.GetCredential()
	if err != nil || got == nil || !bytes.Equal(got.IntegrityMAC, want.IntegrityMAC) {
		t.Fatalf("v3 credential changed after failed compare: %v", err)
	}
}

func TestSchemaRejectsTablesMissingCheckConstraints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-check.sqlite")
	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureMultiTenantSchema(led.db); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`DROP TABLE vault`); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`
CREATE TABLE vault (
  vault_id TEXT PRIMARY KEY,
  template_version TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  network TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  phone_routine_bip340_compressed BLOB NOT NULL,
  phone_direct_p256_compressed BLOB NOT NULL,
  external_owner_wallet_compressed BLOB NOT NULL,
  recovery_key_compressed BLOB NOT NULL,
  vault_cosigner_base_compressed BLOB NOT NULL,
  tweaked_vault_cosigner_compressed BLOB NOT NULL,
  arkade_cosigner_base_compressed BLOB NOT NULL,
  tweaked_arkade_cosigner_compressed BLOB NOT NULL,
  arkade_cosigner_origin TEXT NOT NULL,
  arkade_cosigner_version TEXT NOT NULL,
  cosigner_mode TEXT NOT NULL,
  operational_csv_type INTEGER NOT NULL,
  operational_csv_value INTEGER NOT NULL,
  savings_csv_type INTEGER NOT NULL,
  savings_csv_value INTEGER NOT NULL,
  operational_address TEXT NOT NULL,
  operational_script BLOB NOT NULL,
  savings_address TEXT NOT NULL,
  savings_script BLOB NOT NULL,
  recipient_dust_sats INTEGER NOT NULL,
  tx_recipient_cap_sats INTEGER NOT NULL,
  period_allowance_sats INTEGER NOT NULL,
  absolute_fee_cap_sats INTEGER NOT NULL,
  feerate_cap_sat_vb INTEGER NOT NULL,
  integrity_mac BLOB NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	if err := validateMultiTenantSchemaOn(led.db); err == nil || !strings.Contains(err.Error(), "CHECK") {
		t.Fatalf("vault table without CHECKs accepted: %v", err)
	}
	_ = led.Close()
}

func TestCheckParserIsQuoteAwareAndComparesExactSets(t *testing.T) {
	got := extractNormalizedChecks(`CREATE TABLE t (
  a TEXT CHECK (length(')') = 1),
  b TEXT CHECK (length(")") = 1)
)`)
	want := []string{"(length(')')=1)", `(length(")")=1)`}
	if err := sameCheckSet("t", got, want); err != nil {
		t.Fatalf("quote-aware parse: %v got=%v", err, got)
	}

	// Weakened token-hash check used to pass substring matching.
	if err := sameCheckSet("invite",
		[]string{"(length(token_hash)=32or1=1)"},
		[]string{"(length(token_hash)=32)"},
	); err == nil {
		t.Fatal("OR 1=1 weakening accepted as the required CHECK")
	}

	// Extra restrictive CHECK must be rejected even if all required ones exist.
	if err := sameCheckSet("invite",
		[]string{"(length(token_hash)=32)", "(length(expires_at)>1000)"},
		[]string{"(length(token_hash)=32)"},
	); err == nil {
		t.Fatal("unexpected extra CHECK accepted")
	}
}

func TestSchemaRejectsWeakenedAndExtraInviteChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "weak-invite.sqlite")
	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	if err := ensureMultiTenantSchema(led.db); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`DROP TABLE pending_enrollment`); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`DROP TABLE invite`); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`
CREATE TABLE invite (
  token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32 OR 1 = 1),
  expires_at TEXT NOT NULL,
  consumed_vault_id TEXT UNIQUE REFERENCES vault(vault_id),
  created_at TEXT NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	if err := matchCheckConstraints(led.db, "invite"); err == nil || !strings.Contains(err.Error(), "CHECK") {
		t.Fatalf("weakened invite CHECK accepted: %v", err)
	}

	if _, err := led.db.Exec(`DROP TABLE invite`); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`
CREATE TABLE invite (
  token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
  expires_at TEXT NOT NULL CHECK (length(expires_at) > 1000),
  consumed_vault_id TEXT UNIQUE REFERENCES vault(vault_id),
  created_at TEXT NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	if err := matchCheckConstraints(led.db, "invite"); err == nil || !strings.Contains(err.Error(), "CHECK") {
		t.Fatalf("extra restrictive invite CHECK accepted: %v", err)
	}
}

func TestRequiredChecksRejectInvalidRows(t *testing.T) {
	led := openTestLedger(t, nil)
	if err := ensureMultiTenantSchema(led.db); err != nil {
		t.Fatal(err)
	}
	// A valid parent so FK is not the reason of failure.
	if _, err := led.db.Exec(`SAVEPOINT check_probe`); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`INSERT INTO invite (token_hash, expires_at, created_at) VALUES (?, '2099-01-01T00:00:00Z', '2099-01-01T00:00:00Z')`, bytes.Repeat([]byte{1}, 16)); err == nil {
		t.Fatal("short invite token_hash passed CHECK")
	}
	if _, err := led.db.Exec(`ROLLBACK TO check_probe`); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`INSERT INTO vault_credential (credential_id, vault_id, webauthn_p256_compressed, resident, integrity_mac) VALUES (?, 'x', ?, 2, ?)`,
		[]byte{1}, bytes.Repeat([]byte{2}, 33), bytes.Repeat([]byte{3}, 32)); err == nil {
		t.Fatal("invalid resident passed CHECK")
	}
}

func TestPendingEnrollmentReplayReusesVaultIdentity(t *testing.T) {
	led := openTestLedger(t, nil)
	token := bytes.Repeat([]byte{0xab}, 32)
	now := time.Now().UTC().Format(time.RFC3339)
	if err := led.PutInvite(token, now, now); err != nil {
		t.Fatal(err)
	}
	first, err := led.ReservePendingEnrollment(PendingEnrollment{
		Handle: "handle-1", VaultID: "vault-one", TokenHash: token,
		Challenge: []byte("challenge-1"), ExpiresAt: now, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := led.ReservePendingEnrollment(PendingEnrollment{
		Handle: "handle-2", VaultID: "vault-two", TokenHash: token,
		Challenge: []byte("challenge-2"), ExpiresAt: now, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if replay.VaultID != first.VaultID || replay.Handle != first.Handle {
		t.Fatalf("replay allocated a new identity: first=%+v replay=%+v", first, replay)
	}
	if !bytes.Equal(replay.Challenge, first.Challenge) {
		t.Fatal("unexpired replay rotated the pending challenge")
	}
	var n int
	if err := led.db.QueryRow(`SELECT COUNT(*) FROM pending_enrollment`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("pending rows = %d, %v", n, err)
	}

	other := bytes.Repeat([]byte{0xcd}, 32)
	if err := led.PutInvite(other, now, now); err != nil {
		t.Fatal(err)
	}
	second, err := led.ReservePendingEnrollment(PendingEnrollment{
		Handle: "handle-3", VaultID: "vault-three", TokenHash: other,
		Challenge: []byte("challenge-3"), ExpiresAt: now, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.VaultID == first.VaultID {
		t.Fatal("distinct invites shared a pending vault id")
	}

	expired := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	if _, err := led.db.Exec(`UPDATE pending_enrollment SET expires_at = ? WHERE token_hash = ?`, expired, token); err != nil {
		t.Fatal(err)
	}
	rotated, err := led.ReservePendingEnrollment(PendingEnrollment{
		Handle: "handle-1", VaultID: "vault-one", TokenHash: token,
		Challenge: []byte("challenge-rotated"), ExpiresAt: now, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rotated.Challenge, []byte("challenge-rotated")) {
		t.Fatal("expired pending did not rotate the challenge")
	}
}

func TestPendingEnrollmentRequiresInviteAndTokenLength(t *testing.T) {
	led := openTestLedger(t, nil)
	now := time.Now().UTC().Format(time.RFC3339)
	short := bytes.Repeat([]byte{0x11}, 16)
	if _, err := led.ReservePendingEnrollment(PendingEnrollment{
		Handle: "h", VaultID: "v", TokenHash: short,
		Challenge: []byte("c"), ExpiresAt: now, CreatedAt: now,
	}); err == nil {
		t.Fatal("short token_hash accepted")
	}
	missing := bytes.Repeat([]byte{0x22}, 32)
	if _, err := led.ReservePendingEnrollment(PendingEnrollment{
		Handle: "h", VaultID: "v", TokenHash: missing,
		Challenge: []byte("c"), ExpiresAt: now, CreatedAt: now,
	}); err == nil {
		t.Fatal("pending enrollment without invite succeeded")
	}
	if _, err := led.db.Exec(`INSERT INTO pending_enrollment (handle, vault_id, token_hash, challenge, expires_at, created_at) VALUES (?,?,?,?,?,?)`,
		"h", "v", missing, []byte("c"), now, now); err == nil {
		t.Fatal("direct pending insert without invite succeeded")
	}
}
