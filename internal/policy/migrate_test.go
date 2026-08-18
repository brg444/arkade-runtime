package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func testIntegrityKey() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func TestMigrationKeepsFirstVaultDescriptorByteIdentical(t *testing.T) {
	key := testIntegrityKey()
	led := openTestLedger(t, nil)
	want := validCredential(0x31)
	envelope := testCredentialEnvelope(t, want.ID, key)
	if err := led.EnrollWithEnvelope(want, &envelope); err != nil {
		t.Fatal(err)
	}
	before, err := led.GetCredential()
	if err != nil || before == nil {
		t.Fatalf("legacy credential: %v", err)
	}

	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	got, err := led.GetCredential()
	if err != nil || got == nil {
		t.Fatalf("legacy credential after migration: %v", err)
	}
	if got.OperationalAddress != before.OperationalAddress ||
		got.SavingsAddress != before.SavingsAddress ||
		!bytes.Equal(got.OperationalScript, before.OperationalScript) ||
		!bytes.Equal(got.SavingsScript, before.SavingsScript) ||
		!bytes.Equal(got.VaultCosignerBase, before.VaultCosignerBase) ||
		!bytes.Equal(got.IntegrityMAC, before.IntegrityMAC) {
		t.Fatal("migration mutated the v3 credential row")
	}

	rec, cred, err := led.LoadVerifiedVault(LegacyFirstVaultID, key)
	if err != nil || rec == nil || cred == nil {
		t.Fatalf("v4 vault: %v", err)
	}
	if rec.CosignerMode != CosignerModeLegacyDirectV0 {
		t.Fatalf("cosigner mode = %q", rec.CosignerMode)
	}
	if rec.OperationalAddress != want.OperationalAddress ||
		rec.SavingsAddress != want.SavingsAddress ||
		!bytes.Equal(rec.OperationalScript, want.OperationalScript) ||
		!bytes.Equal(rec.SavingsScript, want.SavingsScript) ||
		!bytes.Equal(rec.VaultCosignerBase, want.VaultCosignerBase) {
		t.Fatal("v4 row is not byte-identical to the first vault descriptor")
	}
	if !bytes.Equal(cred.CredentialID, want.ID) || cred.UserHandle != nil || cred.Resident {
		t.Fatalf("historical credential rewritten: id=%x handle=%x resident=%v", cred.CredentialID, cred.UserHandle, cred.Resident)
	}
	master := testMaster(t, 0x31+5)
	if !bytes.Equal(master.PubKey().SerializeCompressed(), want.VaultCosignerBase) {
		t.Fatal("test master does not reproduce validCredential vault cosigner")
	}
	if err := VerifyVaultCosignerPub(master, *rec); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationIsIdempotentAndRepairsPartialVaultRow(t *testing.T) {
	key := testIntegrityKey()
	led := openTestLedger(t, nil)
	want := validCredential(0x32)
	if err := led.Enroll(want); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	first, _, err := led.LoadVerifiedVault(LegacyFirstVaultID, key)
	if err != nil || first == nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	second, _, err := led.LoadVerifiedVault(LegacyFirstVaultID, key)
	if err != nil || second == nil {
		t.Fatalf("second migrate: %v", err)
	}
	if !bytes.Equal(first.IntegrityMAC, second.IntegrityMAC) ||
		first.OperationalAddress != second.OperationalAddress {
		t.Fatal("second migrate changed the v4 row")
	}

	// Simulated partial: vault row present, credential/version missing.
	partial := openTestLedger(t, nil)
	if err := partial.Enroll(want); err != nil {
		t.Fatal(err)
	}
	if err := ensureMultiTenantSchema(partial.db); err != nil {
		t.Fatal(err)
	}
	rec := vaultRecordFromCredential(want)
	if err := sealVaultRecord(&rec, key); err != nil {
		t.Fatal(err)
	}
	if _, err := partial.db.Exec(`DELETE FROM schema_meta`); err != nil {
		t.Fatal(err)
	}
	if _, err := partial.db.Exec(`
INSERT INTO vault (
  vault_id, template_version, policy_version, network, rp_id, origin,
  phone_routine_bip340_compressed, phone_direct_p256_compressed,
  external_owner_wallet_compressed, recovery_key_compressed,
  vault_cosigner_base_compressed, tweaked_vault_cosigner_compressed,
  arkade_cosigner_base_compressed, tweaked_arkade_cosigner_compressed,
  arkade_cosigner_origin, arkade_cosigner_version, cosigner_mode,
  operational_csv_type, operational_csv_value, savings_csv_type, savings_csv_value,
  operational_address, operational_script, savings_address, savings_script,
  recipient_dust_sats, tx_recipient_cap_sats, period_allowance_sats,
  absolute_fee_cap_sats, feerate_cap_sat_vb, integrity_mac
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.VaultID, rec.TemplateVersion, rec.PolicyVersion, rec.Network, rec.RPID, rec.Origin,
		rec.PhoneRoutineBIP340, rec.PhoneDirectP256, rec.ExternalOwnerWallet, rec.RecoveryKey,
		rec.VaultCosignerBase, rec.TweakedVaultCosigner, rec.ArkadeCosignerBase, rec.TweakedArkadeCosigner,
		rec.ArkadeCosignerOrigin, rec.ArkadeCosignerVersion, rec.CosignerMode,
		rec.OperationalCSVType, rec.OperationalCSVValue, rec.SavingsCSVType, rec.SavingsCSVValue,
		rec.OperationalAddress, rec.OperationalScript, rec.SavingsAddress, rec.SavingsScript,
		rec.RecipientDustSats, rec.TxRecipientCapSats, rec.PeriodAllowanceSats,
		rec.AbsoluteFeeCapSats, rec.FeerateCapSatPerV, rec.IntegrityMAC,
	); err != nil {
		t.Fatal(err)
	}
	if err := partial.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	repaired, cred, err := partial.LoadVerifiedVault(LegacyFirstVaultID, key)
	if err != nil || repaired == nil || cred == nil {
		t.Fatalf("partial migrate: rec=%v cred=%v err=%v", repaired, cred, err)
	}
	if !bytes.Equal(cred.CredentialID, want.ID) {
		t.Fatal("partial migrate did not backfill vault_credential")
	}
	ver, err := schemaVersion(partial.db)
	if err != nil || ver != schemaVersionMultiTenant {
		t.Fatalf("schema version = %d, %v", ver, err)
	}
}

func TestWrongIntegrityKeyFailsClosed(t *testing.T) {
	good := testIntegrityKey()
	led := openTestLedger(t, nil)
	want := validCredential(0x33)
	if err := led.Enroll(want); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(bytes.Repeat([]byte{0x99}, 32)); err == nil {
		t.Fatal("wrong MAC key migrated the database")
	}
	got, err := led.GetCredential()
	if err != nil || got == nil || !bytes.Equal(got.IntegrityMAC, want.IntegrityMAC) {
		t.Fatalf("v3 credential changed after failed migrate: %v", err)
	}
	if v4TableExists(led.db) {
		var n int
		if err := led.db.QueryRow(`SELECT COUNT(*) FROM vault`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("vault rows after fail-closed = %d, %v", n, err)
		}
	}
	if v4TableExists(led.db) {
		ver, err := schemaVersion(led.db)
		if err != nil || ver != 0 {
			t.Fatalf("schema version after fail-closed = %d, %v", ver, err)
		}
	}

	// Tampered v3 MAC must also refuse to write v4 rows.
	if _, err := led.db.Exec(`UPDATE credential SET integrity_mac = ? WHERE id = 1`, bytes.Repeat([]byte{0x00}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(good); err == nil {
		t.Fatal("tampered v3 MAC was migrated")
	}
	if v4TableExists(led.db) {
		var n int
		if err := led.db.QueryRow(`SELECT COUNT(*) FROM vault`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("vault rows after tampered MAC = %d, %v", n, err)
		}
	}
}

func TestBackupIsWriteOnceAndPreservesLegacyCredential(t *testing.T) {
	key := testIntegrityKey()
	led := openTestLedger(t, nil)
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	want := validCredential(0x34)
	if err := led.Enroll(want); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "vault.sqlite.pre-v4")
	if err := led.BackupSQLiteIfAbsent(dest); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := led.BackupSQLiteIfAbsent(dest); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("valid existing backup was rewritten")
	}
}

func TestDualWriteEnrollSealsLegacyVaultOnly(t *testing.T) {
	key := testIntegrityKey()
	led := openTestLedger(t, nil)
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	want := validCredential(0x35)
	if err := led.Enroll(want); err != nil {
		t.Fatal(err)
	}
	rec, cred, err := led.LoadVerifiedVault(LegacyFirstVaultID, key)
	if err != nil || rec == nil || cred == nil {
		t.Fatalf("dual-write missing: %v", err)
	}
	if rec.CosignerMode != CosignerModeLegacyDirectV0 {
		t.Fatal("dual-write used the wrong cosigner mode")
	}
	other := want
	other.VaultID = "tenant-should-not-dual-write"
	if err := SealCredential(&other, key); err != nil {
		t.Fatal(err)
	}
	// Singleton enroll still occupies credential.id=1, so this must fail
	// before inventing a second v4 vault.
	if err := led.Enroll(other); err == nil {
		t.Fatal("second singleton enroll succeeded")
	}
	var n int
	if err := led.db.QueryRow(`SELECT COUNT(*) FROM vault`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("vault rows = %d, %v", n, err)
	}
}

func TestVaultRecordMACCoversIdentityPolicyAndCosignerMode(t *testing.T) {
	key := testIntegrityKey()
	base := vaultRecordFromCredential(validCredential(0x36))
	if err := sealVaultRecord(&base, key); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name string
		mut  func(*VaultRecord)
	}{
		{"vault id", func(v *VaultRecord) { v.VaultID += "-x" }},
		{"policy version", func(v *VaultRecord) { v.PolicyVersion += "-x" }},
		{"cosigner mode", func(v *VaultRecord) { v.CosignerMode = CosignerModeHKDFSHA256V1 }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			got := base
			got.IntegrityMAC = append([]byte(nil), base.IntegrityMAC...)
			test.mut(&got)
			if err := VerifyVaultRecord(&got, key); err == nil {
				t.Fatal("mutated v4 vault passed MAC verification")
			}
		})
	}
}

func TestForeignKeysRejectCredentialWithoutVault(t *testing.T) {
	led := openTestLedger(t, nil)
	if err := ensureMultiTenantSchema(led.db); err != nil {
		t.Fatal(err)
	}
	var enabled int
	if err := led.db.QueryRow(`PRAGMA foreign_keys`).Scan(&enabled); err != nil || enabled != 1 {
		t.Fatalf("PRAGMA foreign_keys = %d, %v", enabled, err)
	}
	_, err := led.db.Exec(`
INSERT INTO vault_credential (credential_id, vault_id, webauthn_p256_compressed, user_handle, resident, integrity_mac)
VALUES (?, ?, ?, NULL, 0, ?)`,
		[]byte{1, 2, 3}, "missing-vault", bytes.Repeat([]byte{0x02}, 33), bytes.Repeat([]byte{0x11}, 32),
	)
	if err == nil {
		t.Fatal("vault_credential insert without vault succeeded")
	}
}

func TestMigrationDoesNotInventHistoricalUserHandle(t *testing.T) {
	key := testIntegrityKey()
	led := openTestLedger(t, nil)
	want := validCredential(0x37)
	if err := led.Enroll(want); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	_, cred, err := led.LoadVerifiedVault(LegacyFirstVaultID, key)
	if err != nil || cred == nil {
		t.Fatal(err)
	}
	if cred.UserHandle != nil {
		t.Fatalf("invented user handle %x", cred.UserHandle)
	}
}

func TestOpenLedgerDoesNotCreateV4TablesBeforeMigration(t *testing.T) {
	led := openTestLedger(t, nil)
	if v4TableExists(led.db) {
		t.Fatal("OpenLedger created v4 tables before backup/migration")
	}
	if err := led.MigrateLegacySingleton(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"vault", "vault_credential", "vault_envelope", "invite", "pending_enrollment", "schema_meta"} {
		var name string
		if err := led.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name); err != nil {
			t.Fatalf("missing %s after migrate: %v", table, err)
		}
	}
	rec, cred, err := led.LoadVault(LegacyFirstVaultID)
	if err != nil || rec != nil || cred != nil {
		t.Fatalf("fresh ledger already had a vault: %v %v %v", rec, cred, err)
	}
}
