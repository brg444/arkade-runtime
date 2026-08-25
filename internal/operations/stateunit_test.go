package operations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/internal/authorizer"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	testCommit = "36cde909cc2ed745fef3efd4ecafc4371cfd8298"
	testImage  = "sha256:e009b5e17cc491ad9b809373e53a95848fb3f27161cddfc88d671c1c0f6c55db"
)

type restoreFixture struct {
	root         string
	databasePath string
	sequencePath string
	keyFile      string
	integrityKey []byte
}

func TestStateUnitSnapshotVerifyAndRestore(t *testing.T) {
	fixture := newRestoreFixture(t, true)
	unitParent := privateDir(t, fixture.root, "units")
	unit := filepath.Join(unitParent, "state-001")
	created := time.Date(2026, time.August, 26, 1, 2, 3, 4, time.UTC)
	manifest, err := Snapshot(SnapshotConfig{
		DatabasePath:         fixture.databasePath,
		PolicySequencePath:   fixture.sequencePath,
		VaultCosignerKeyFile: fixture.keyFile,
		OutputDirectory:      unit,
		SourceCommit:         testCommit,
		ImageDigest:          testImage,
		ServiceStopped:       true,
		Now:                  func() time.Time { return created },
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.CreatedAt != created.Format(time.RFC3339Nano) || manifest.State.EconomicOutflowCount != 1 || manifest.State.PolicySequenceCount != 1 {
		t.Fatalf("snapshot manifest = %+v", manifest)
	}
	if manifest.State.AuthenticatedRows.Vaults != 1 || manifest.State.AuthenticatedRows.VtxoOperations != 1 || manifest.State.AuthenticatedRows.VtxoInputs != 1 {
		t.Fatalf("authenticated rows = %+v", manifest.State.AuthenticatedRows)
	}
	verified, err := Verify(VerifyConfig{
		UnitDirectory:        unit,
		VaultCosignerKeyFile: fixture.keyFile,
		ExpectedCommit:       testCommit,
		ExpectedImageDigest:  testImage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified != manifest {
		t.Fatalf("verified manifest changed")
	}

	target := newRestoreFixture(t, false)
	if _, err := Restore(RestoreConfig{
		UnitDirectory:        unit,
		VaultCosignerKeyFile: fixture.keyFile,
		DatabasePath:         target.databasePath,
		PolicySequencePath:   target.sequencePath,
		ExpectedCommit:       testCommit,
		ExpectedImageDigest:  testImage,
		ServiceStopped:       true,
		Replace:              true,
	}); err != nil {
		t.Fatal(err)
	}
	summary, err := authorizer.VerifyRestoreState(target.databasePath, target.sequencePath, fixture.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if summary != manifest.State {
		t.Fatalf("restored state = %+v, want %+v", summary, manifest.State)
	}
}

func TestStateUnitRejectsTamperAndReleaseMismatch(t *testing.T) {
	fixture := newRestoreFixture(t, true)
	unit := filepath.Join(privateDir(t, fixture.root, "units"), "state-001")
	if _, err := Snapshot(SnapshotConfig{
		DatabasePath:         fixture.databasePath,
		PolicySequencePath:   fixture.sequencePath,
		VaultCosignerKeyFile: fixture.keyFile,
		OutputDirectory:      unit,
		SourceCommit:         testCommit,
		ImageDigest:          testImage,
		ServiceStopped:       true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(VerifyConfig{
		UnitDirectory:        unit,
		VaultCosignerKeyFile: fixture.keyFile,
		ExpectedCommit:       strings.Repeat("1", 40),
		ExpectedImageDigest:  testImage,
	}); err == nil || !strings.Contains(err.Error(), "source commit") {
		t.Fatalf("release mismatch accepted: %v", err)
	}
	database := filepath.Join(unit, DatabaseFileName)
	file, err := os.OpenFile(database, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("tamper")); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(VerifyConfig{
		UnitDirectory:        unit,
		VaultCosignerKeyFile: fixture.keyFile,
		ExpectedCommit:       testCommit,
		ExpectedImageDigest:  testImage,
	}); err == nil || !strings.Contains(err.Error(), "digest or size mismatch") {
		t.Fatalf("artifact tamper accepted: %v", err)
	}
}

func TestRestoreVerificationFailsClosedOnRolledBackPair(t *testing.T) {
	withOutflow := newRestoreFixture(t, true)
	emptyRoot := privateDir(t, t.TempDir(), "empty")
	emptyDatabase := filepath.Join(emptyRoot, "vault.sqlite")
	emptySequence := filepath.Join(emptyRoot, "policy-sequence")
	emptyLedger, err := policy.OpenMainnetLedger(emptyDatabase, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := emptyLedger.Close(); err != nil {
		t.Fatal(err)
	}
	sequence, err := policy.OpenMonotonic(emptySequence, withOutflow.integrityKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := sequence.Observe(0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(emptyDatabase, 0o600); err != nil {
		t.Fatal(err)
	}

	databaseBehind := privateDir(t, t.TempDir(), "database-behind")
	databasePath := filepath.Join(databaseBehind, "vault.sqlite")
	sequencePath := filepath.Join(databaseBehind, "policy-sequence")
	copyTestFile(t, emptyDatabase, databasePath)
	copyTestFile(t, withOutflow.sequencePath, sequencePath)
	if _, err := authorizer.VerifyRestoreState(databasePath, sequencePath, withOutflow.keyFile); err == nil || !strings.Contains(err.Error(), "rolled-back database") {
		t.Fatalf("rolled-back database accepted: %v", err)
	}

	sequenceBehind := privateDir(t, t.TempDir(), "sequence-behind")
	databasePath = filepath.Join(sequenceBehind, "vault.sqlite")
	sequencePath = filepath.Join(sequenceBehind, "policy-sequence")
	copyTestFile(t, withOutflow.databasePath, databasePath)
	copyTestFile(t, emptySequence, sequencePath)
	if _, err := authorizer.VerifyRestoreState(databasePath, sequencePath, withOutflow.keyFile); err == nil || !strings.Contains(err.Error(), "rolled-back sequence") {
		t.Fatalf("rolled-back sequence accepted: %v", err)
	}
}

func TestRestoreVerificationRejectsAuthenticatedRowTamper(t *testing.T) {
	fixture := newRestoreFixture(t, true)
	db, err := sql.Open("sqlite", fixture.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE vault SET savings_address = 'tampered' WHERE vault_id = 'synthetic-vault'`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.VerifyRestoreState(fixture.databasePath, fixture.sequencePath, fixture.keyFile); err == nil || !strings.Contains(err.Error(), "vault integrity MAC mismatch") {
		t.Fatalf("authenticated row tamper accepted: %v", err)
	}
}

func TestStateUnitRequiresStoppedServiceAndPrivatePaths(t *testing.T) {
	fixture := newRestoreFixture(t, false)
	unit := filepath.Join(privateDir(t, fixture.root, "units"), "state-001")
	if _, err := Snapshot(SnapshotConfig{
		DatabasePath:         fixture.databasePath,
		PolicySequencePath:   fixture.sequencePath,
		VaultCosignerKeyFile: fixture.keyFile,
		OutputDirectory:      unit,
		SourceCommit:         testCommit,
		ImageDigest:          testImage,
	}); err == nil || !strings.Contains(err.Error(), "service-stopped") {
		t.Fatalf("online snapshot accepted: %v", err)
	}
	if _, err := Restore(RestoreConfig{ServiceStopped: true}); err == nil || !strings.Contains(err.Error(), "replace") {
		t.Fatalf("restore without replace acknowledgement accepted: %v", err)
	}
}

func newRestoreFixture(t *testing.T, withOutflow bool) restoreFixture {
	t.Helper()
	root := t.TempDir()
	stateDir := privateDir(t, root, "state")
	keyDir := privateDir(t, root, "keys")
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(keyDir, "vault-cosigner.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(key.Serialize())), 0o600); err != nil {
		t.Fatal(err)
	}
	integrityKey := testCredentialIntegrityKey(key.Serialize())
	databasePath := filepath.Join(stateDir, "vault.sqlite")
	sequencePath := filepath.Join(stateDir, "policy-sequence")
	ledger, err := policy.OpenMainnetLedger(databasePath, func() time.Time {
		return time.Date(2026, time.August, 26, 1, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetIntegrityKey(integrityKey); err != nil {
		ledger.Close()
		t.Fatal(err)
	}
	sequence, err := policy.OpenMonotonic(sequencePath, integrityKey)
	if err != nil {
		ledger.Close()
		t.Fatal(err)
	}
	if err := ledger.AttachMonotonic(sequence); err != nil {
		ledger.Close()
		t.Fatal(err)
	}
	if withOutflow {
		createSyntheticOutflow(t, ledger, integrityKey)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{databasePath, sequencePath} {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return restoreFixture{
		root: root, databasePath: databasePath, sequencePath: sequencePath,
		keyFile: keyFile, integrityKey: integrityKey,
	}
}

func createSyntheticOutflow(t *testing.T, ledger *policy.Ledger, key []byte) {
	t.Helper()
	now := ledger.NowUTC()
	tokenHash := bytes.Repeat([]byte{0x42}, sha256.Size)
	if err := ledger.PutInvite(tokenHash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	record := policy.VaultRecord{
		VaultID: "synthetic-vault", TemplateVersion: "phone-hww-recovery-savings-v1",
		PolicyVersion: "vault-spending-policy-v1", Network: "mutinynet",
		RPID: "drill.invalid", Origin: "https://drill.invalid",
		PhoneBIP340: bytes.Repeat([]byte{0x02}, 33), PhoneDirectP256: bytes.Repeat([]byte{0x03}, 33),
		ExternalOwnerWallet: bytes.Repeat([]byte{0x02}, 33), RecoveryKey: bytes.Repeat([]byte{0x03}, 33),
		VaultCosignerBase: bytes.Repeat([]byte{0x02}, 33), ArkadeCosignerBase: bytes.Repeat([]byte{0x03}, 33),
		ArkadeCosignerOrigin: "https://drill.invalid", ArkadeCosignerVersion: "drill-v1",
		CosignerMode: policy.CosignerModeHKDFSHA256V1, SavingsAddress: "synthetic",
		SavingsScript: []byte{0x51}, RecipientDustSats: 330, TxRecipientCapSats: 100_000,
		PeriodAllowanceSats: 100_000, AbsoluteFeeCapSats: 1_000, FeerateCapSatPerV: 10,
	}
	credential := policy.VaultCredential{
		CredentialID: []byte("synthetic-credential"), VaultID: record.VaultID,
		WebAuthnP256: bytes.Repeat([]byte{0x02}, 33), Resident: true,
	}
	if err := policy.SealVaultRecord(&record, key); err != nil {
		t.Fatal(err)
	}
	if err := policy.SealVaultCredential(&credential, key); err != nil {
		t.Fatal(err)
	}
	if err := ledger.CreateVault(policy.CreateVaultInput{Record: record, Credential: credential, TokenHash: tokenHash}); err != nil {
		t.Fatal(err)
	}
	recordOutflow := policy.VtxoOperation{
		OperationID: "synthetic-operation", VaultID: record.VaultID,
		Purpose: policy.VtxoPurposeSpend, State: policy.VtxoStateReserved,
		BundleDigest: bytes.Repeat([]byte{0x11}, 32), FeePolicyDigest: bytes.Repeat([]byte{0x22}, 32),
		AmountSats: 1_000, FeeSats: 10, DestScript: []byte{0x51},
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	inputs := []policy.VtxoOperationInput{{
		Txid: bytes.Repeat([]byte{0x33}, 32), Vout: 0, ValueSats: 2_000, Script: []byte{0x51},
	}}
	if err := ledger.ReserveVtxoOperation(context.Background(), recordOutflow, inputs, 100_000); err != nil {
		t.Fatal(err)
	}
}

func testCredentialIntegrityKey(master []byte) []byte {
	extract := hmac.New(sha256.New, []byte("arkade-2fa-vault/vault-cosigner-scalar-hkdf-salt/v3"))
	_, _ = extract.Write(master)
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write([]byte("arkade-2fa-vault/credential-integrity-key/v3"))
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil)
}

func privateDir(t *testing.T, parent, name string) string {
	t.Helper()
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func copyTestFile(t *testing.T, source, destination string) {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
