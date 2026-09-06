package policy

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func connectorTestClock() time.Time { return time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC) }

func connectorTestEnrollment(vaultID string) ConnectorEnrollment {
	// secp256k1 generator, a fixed valid compressed point (disposable test key).
	pub, err := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	if err != nil {
		panic(err)
	}
	return ConnectorEnrollment{
		VaultID: vaultID, Type: "p2tr", Pub: pub,
		Fingerprint: 0x12345678, Path: []uint32{0x80000056, 0x80000001, 0x80000000, 0, 0},
	}
}

func connectorTestOperation(opID, vaultID string) ConnectorOperation {
	return ConnectorOperation{
		OperationID: opID, VaultID: vaultID,
		SavingsTxid: strings.Repeat("aa", 32), SavingsVout: 0,
		ConnectorTxid: strings.Repeat("bb", 32), ConnectorVout: 1,
		DestScript: strings.Repeat("cc", 25), AmountSats: 8000, FeeSats: 1000,
		ConnectorScript: bytes.Repeat([]byte{0xdd}, 34),
		CandidatePSBT:   strings.Repeat("a1", 100),
		LastSighash:     strings.Repeat("ee", 32),
	}
}

// populatedV2Database builds a schema-2 database with original Savings state
// (credential + recovery session) and Light state, mirroring the RC upgrade
// qualification: migration must preserve all of it byte-for-byte. Handles are
// closed on return; tamper tests reopen the path themselves.
func populatedV2Database(t *testing.T) (string, map[string][]byte, uint64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v2.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	if err := initializeOrValidateLegacySchema(db, createVaultBoardSchema); err != nil {
		t.Fatal(err)
	}
	if err := applyLightRenewalMigration(db); err != nil {
		t.Fatal(err)
	}
	led := &Ledger{db: db, clock: connectorTestClock, network: "mutinynet"}
	if err := led.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	vault := strings.Repeat("ab", 32)
	createPolicyTestVault(t, led, vault, 0x56)
	if err := led.PutRecoverySession(RecoverySession{
		VaultID: vault, Purpose: "initiate",
		InputTxid: strings.Repeat("09", 32), InputVout: 0,
		DestScript: strings.Repeat("08", 25), LastSighash: strings.Repeat("07", 32),
	}); err != nil {
		t.Fatal(err)
	}
	op := LightRenewalOperation{OperationID: strings.Repeat("01", 16), VaultID: vault, InputTxid: strings.Repeat("02", 32), FeeSats: 123, PlanDigest: strings.Repeat("03", 32), Plan: `{"renewal":true}`, ExpiresAt: connectorTestClock().Add(5 * time.Minute).Format(time.RFC3339)}
	if _, err := led.ReserveLightRenewal(t.Context(), op, 10000); err != nil {
		t.Fatal(err)
	}
	macs := map[string][]byte{}
	for table, query := range map[string]string{
		"vault":            `SELECT integrity_mac FROM vault WHERE vault_id='` + vault + `'`,
		"credential":       `SELECT integrity_mac FROM vault_credential WHERE vault_id='` + vault + `'`,
		"recovery_session": `SELECT integrity_mac FROM recovery_session WHERE vault_id='` + vault + `'`,
		"light_op":         `SELECT integrity_mac FROM light_renewal_operation WHERE operation_id='` + strings.Repeat("01", 16) + `'`,
	} {
		var mac []byte
		if err := db.QueryRow(query).Scan(&mac); err != nil {
			t.Fatal(table, err)
		}
		macs[table] = mac
	}
	n, err := economicOutflowCount(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := led.Close(); err != nil {
		t.Fatal(err)
	}
	return path, macs, n
}

func TestConnectorMigrationPreservesV2RecordsAndSequence(t *testing.T) {
	path, before, count := populatedV2Database(t)
	migrated, err := OpenLedger(path, connectorTestClock)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	if version, err := migrated.SchemaVersion(); err != nil || version != schemaVersion {
		t.Fatalf("migration version %d %v", version, err)
	}
	for table, query := range map[string]string{
		"vault":            `SELECT integrity_mac FROM vault WHERE vault_id='` + strings.Repeat("ab", 32) + `'`,
		"credential":       `SELECT integrity_mac FROM vault_credential WHERE vault_id='` + strings.Repeat("ab", 32) + `'`,
		"recovery_session": `SELECT integrity_mac FROM recovery_session WHERE vault_id='` + strings.Repeat("ab", 32) + `'`,
		"light_op":         `SELECT integrity_mac FROM light_renewal_operation WHERE operation_id='` + strings.Repeat("01", 16) + `'`,
	} {
		var after []byte
		if err := migrated.db.QueryRow(query).Scan(&after); err != nil {
			t.Fatal(table, err)
		}
		if !bytes.Equal(before[table], after) {
			t.Fatalf("migration changed authenticated %s", table)
		}
	}
	if n, err := economicOutflowCount(migrated.db); err != nil || n != count {
		t.Fatalf("migration changed sequence %d (was %d) %v", n, count, err)
	}
	if rec, err := migrated.GetConnectorEnrollment(strings.Repeat("ab", 32)); err != nil || rec != nil {
		t.Fatalf("legacy vault gained connector enrollment: %v %v", rec, err)
	}
}

func TestConnectorMigrationRejectsTamperedV2BeforeWriting(t *testing.T) {
	for _, mutation := range []string{
		`CREATE TABLE connector_operation (junk TEXT)`,
		`ALTER TABLE vault ADD COLUMN junk TEXT`,
		`DROP INDEX vtxo_operation_input_outpoint`,
		`CREATE TRIGGER tamper AFTER INSERT ON schema_meta BEGIN DELETE FROM vault; END`,
	} {
		t.Run(mutation, func(t *testing.T) {
			path, _, _ := populatedV2Database(t)
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			db.Close()
			if l, err := OpenLedger(path, nil); err == nil {
				l.Close()
				t.Fatal("tampered v2 migrated")
			}
			check, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer check.Close()
			var version int
			if err := check.QueryRow(`SELECT version FROM schema_meta`).Scan(&version); err != nil || version != lightSchemaVersion {
				t.Fatalf("changed refused schema: %d %v", version, err)
			}
			if hasTable(check, "connector_enrollment") {
				t.Fatal("partial migration survived")
			}
		})
	}
}

func TestConnectorSchemaRejectsDriftOnRestart(t *testing.T) {
	for _, mutation := range []string{
		`ALTER TABLE connector_operation ADD COLUMN junk TEXT`,
		`DROP TABLE connector_operation`,
		`DROP TABLE connector_enrollment`,
		`CREATE INDEX hidden_phase ON connector_operation(phase)`,
		`CREATE TRIGGER erase_ops AFTER INSERT ON connector_operation BEGIN DELETE FROM connector_operation WHERE operation_id != NEW.operation_id; END`,
	} {
		t.Run(mutation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "current.sqlite")
			l, err := OpenLedger(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			l.Close()
			if accepted, err := OpenLedger(path, nil); err == nil {
				accepted.Close()
				t.Fatal("connector schema drift accepted")
			}
		})
	}
}

func TestConnectorEnrollmentRoundTrip(t *testing.T) {
	led := openPolicyTestLedger(t, connectorTestClock)
	createPolicyTestVault(t, led, "connector-vault", 0x57)
	rec := connectorTestEnrollment("connector-vault")
	if err := SealConnectorEnrollment(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	tx, err := led.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := putConnectorEnrollmentTx(tx, rec); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := led.GetConnectorEnrollment("connector-vault")
	if err != nil || got == nil {
		t.Fatalf("enrollment read: %v %v", got, err)
	}
	if got.Type != "p2tr" || !bytes.Equal(got.Pub, rec.Pub) || got.Fingerprint != rec.Fingerprint ||
		len(got.Path) != len(rec.Path) || !bytes.Equal(got.IntegrityMAC, rec.IntegrityMAC) {
		t.Fatal("enrollment mismatch")
	}
	for i, n := range rec.Path {
		if got.Path[i] != n {
			t.Fatal("origin path mismatch")
		}
	}
	if _, err := led.db.Exec(`UPDATE connector_enrollment SET fingerprint = fingerprint + 1 WHERE vault_id = 'connector-vault'`); err != nil {
		t.Fatal(err)
	}
	if _, err := led.GetConnectorEnrollment("connector-vault"); err == nil {
		t.Fatal("tampered enrollment verified")
	}
	if missing, err := led.GetConnectorEnrollment("no-such-vault"); err != nil || missing != nil {
		t.Fatalf("missing enrollment: %v %v", missing, err)
	}
}

func TestConnectorEnrollmentParity(t *testing.T) {
	led := openPolicyTestLedger(t, connectorTestClock)
	createPolicyTestVault(t, led, "odd-vault", 0x58)
	// An odd (03-prefix) compressed key must survive byte-identically: x-only
	// equivalence would silently re-derive the even key and break P2WPKH.
	// -G shares G's x-coordinate with odd parity, so it is always on-curve.
	odd, err := hex.DecodeString("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	if err != nil {
		t.Fatal(err)
	}
	rec := connectorTestEnrollment("odd-vault")
	rec.Type, rec.Pub = "p2wpkh", odd
	if err := SealConnectorEnrollment(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	tx, err := led.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := putConnectorEnrollmentTx(tx, rec); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := led.GetConnectorEnrollment("odd-vault")
	if err != nil || got == nil || !bytes.Equal(got.Pub, odd) {
		t.Fatalf("odd key not preserved: %v %v", got, err)
	}
	even := append([]byte(nil), odd...)
	even[0] = 0x02
	if bytes.Equal(got.Pub, even) {
		t.Fatal("origin key parity normalized to even")
	}
}

func createConnectorVault(t *testing.T, led *Ledger, vaultID string, tag byte) {
	t.Helper()
	createPolicyTestVault(t, led, vaultID, tag)
	rec := connectorTestEnrollment(vaultID)
	if err := SealConnectorEnrollment(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	tx, err := led.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := putConnectorEnrollmentTx(tx, rec); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func applyConnectorOp(t *testing.T, led *Ledger, op ConnectorOperation) (ConnectorReplayAction, *ConnectorOperation) {
	t.Helper()
	action, stored, err := led.ApplyConnectorReplay(op)
	if err != nil {
		t.Fatal(err)
	}
	return action, stored
}

func TestConnectorReplayIsImmutable(t *testing.T) {
	led := openPolicyTestLedger(t, connectorTestClock)
	createConnectorVault(t, led, "connector-vault", 0x57)
	first := connectorTestOperation(strings.Repeat("0a", 16), "connector-vault")
	action, stored := applyConnectorOp(t, led, first)
	if action != ConnectorReplaySign || stored == nil || stored.Phase != ConnectorPhaseAuthorized {
		t.Fatalf("fresh authorize: %v %v", action, stored)
	}
	// Identical retry replays the same row.
	action, stored = applyConnectorOp(t, led, first)
	if action != ConnectorReplayReplay || stored == nil || stored.OperationID != first.OperationID {
		t.Fatalf("identical retry: %v %v", action, stored)
	}
	// Any change — dest, sighash, connector outpoint, candidate bytes — is
	// refused, even with no stage stored yet (absence of a saved stage never
	// proves no signature exists).
	mutations := map[string]func(*ConnectorOperation){
		"dest":        func(op *ConnectorOperation) { op.DestScript = strings.Repeat("dd", 25) },
		"sighash":     func(op *ConnectorOperation) { op.LastSighash = strings.Repeat("ff", 32) },
		"reserve":     func(op *ConnectorOperation) { op.ConnectorTxid = strings.Repeat("cc", 32) },
		"candidate":   func(op *ConnectorOperation) { op.CandidatePSBT += "00" },
		"amount":      func(op *ConnectorOperation) { op.AmountSats++ },
		"other vault": func(op *ConnectorOperation) { op.VaultID = "other" },
	}
	for name, mutate := range mutations {
		changed := first
		mutate(&changed)
		if _, _, err := led.ApplyConnectorReplay(changed); err == nil {
			t.Fatalf("changed candidate %s resigned", name)
		}
	}
	// Stored stages resume byte-for-byte.
	if _, err := led.StoreConnectorStage(first.OperationID, ConnectorPhaseGuardianSigned, strings.Repeat("ab", 100)); err != nil {
		t.Fatal(err)
	}
	action, stored = applyConnectorOp(t, led, first)
	if action != ConnectorReplayReplay || stored.GuardianPSBT != strings.Repeat("ab", 100) || stored.Phase != ConnectorPhaseGuardianSigned {
		t.Fatalf("stage resume: %v %+v", action, stored)
	}
	if _, err := led.StoreConnectorStage(first.OperationID, ConnectorPhaseEmulatorSigned, strings.Repeat("cd", 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := led.StoreConnectorStage(first.OperationID, ConnectorPhaseGuardianSigned, strings.Repeat("ab", 100)); err == nil {
		t.Fatal("phase moved backwards")
	}
	if _, err := led.StoreConnectorStage(first.OperationID, ConnectorPhaseEmulatorSigned, strings.Repeat("cd", 100)); err == nil {
		t.Fatal("duplicate terminal stage accepted")
	}
}

func TestConnectorHistoryRetainedAcrossConflicts(t *testing.T) {
	led := openPolicyTestLedger(t, connectorTestClock)
	createConnectorVault(t, led, "connector-vault", 0x57)
	first := connectorTestOperation(strings.Repeat("0a", 16), "connector-vault")
	applyConnectorOp(t, led, first)
	// A confirmed conflicting spend of the reserve resolves the first row, but
	// the row itself is retained.
	resolved, err := led.ResolveConnectorOperation(first.OperationID, ConnectorChainEvidence{
		Resolution: ConnectorResolutionConflict, ResolutionTxid: strings.Repeat("99", 32),
		ResolutionBlockHash: strings.Repeat("98", 32), ResolutionBlockHeight: 800,
	})
	if err != nil || resolved.Resolution != ConnectorResolutionConflict {
		t.Fatalf("resolve: %v %v", resolved, err)
	}
	// Same Savings, new reserve: a distinct operation is authorized with its
	// own immutable id. (Chain revalidation of the terminal row is the
	// application's duty before calling; see application tests.)
	second := connectorTestOperation(strings.Repeat("0b", 16), "connector-vault")
	second.ConnectorTxid = strings.Repeat("cc", 32)
	second.CandidatePSBT = strings.Repeat("a0", 100)
	action, stored := applyConnectorOp(t, led, second)
	if action != ConnectorReplaySign || stored.OperationID != second.OperationID {
		t.Fatalf("successor authorize: %v %v", action, stored)
	}
	// Both rows exist: history was not overwritten. The conflict scan finds both
	// operations touching the shared Savings input.
	if _, err := led.GetConnectorOperation(first.OperationID); err != nil {
		t.Fatal("first operation lost", err)
	}
	conflicts, err := led.ListConnectorConflicts("connector-vault", first.SavingsTxid, first.SavingsVout, first.ConnectorTxid, first.ConnectorVout)
	if err != nil || len(conflicts) != 2 {
		t.Fatalf("conflict scan: %v %v", conflicts, err)
	}
	seen := map[string]bool{}
	for _, row := range conflicts {
		seen[row.OperationID] = true
	}
	if !seen[first.OperationID] || !seen[second.OperationID] {
		t.Fatalf("conflict scan missing history: %v", seen)
	}
	// Tampering any listed row breaks MAC verification before state is trusted.
	if _, err := led.db.Exec(`UPDATE connector_operation SET phase = 'emulator_signed' WHERE operation_id = ?`, first.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := led.ApplyConnectorReplay(first); err == nil {
		t.Fatal("tampered conflict row trusted")
	}
}

// Incorporated supervisor reproduction: mutating stored outpoints without
// resealing must not hide a signed reservation from the conflict scan.
func TestSupervisorConnectorTamperedOutpointCannotHideReservation(t *testing.T) {
	led := openPolicyTestLedger(t, connectorTestClock)
	createConnectorVault(t, led, "connector-vault", 0x57)
	first := connectorTestOperation(strings.Repeat("0a", 16), "connector-vault")
	applyConnectorOp(t, led, first)
	if _, err := led.StoreConnectorStage(first.OperationID, ConnectorPhaseGuardianSigned, strings.Repeat("ab", 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := led.db.Exec(`UPDATE connector_operation SET savings_txid=?,connector_txid=? WHERE operation_id=?`, strings.Repeat("11", 32), strings.Repeat("22", 32), first.OperationID); err != nil {
		t.Fatal(err)
	}
	second := first
	second.OperationID = strings.Repeat("0b", 16)
	if action, _, err := led.ApplyConnectorReplay(second); err == nil {
		t.Fatalf("authorized %s after tampered outpoints hid a signed reservation", action)
	}
}

// Vault-id mutation hides the row from vault-scoped reads but cannot survive
// MAC verification: the full scan authenticates every row first. The other
// vault exists with its own valid enrollment, so the foreign key stays valid
// while the mutated row's MAC fails on the authenticated read path.
func TestConnectorTamperedVaultIDCannotHideReservation(t *testing.T) {
	led := openPolicyTestLedger(t, connectorTestClock)
	createConnectorVault(t, led, "connector-vault", 0x57)
	createConnectorVault(t, led, "other-vault", 0x58)
	first := connectorTestOperation(strings.Repeat("0a", 16), "connector-vault")
	applyConnectorOp(t, led, first)
	if _, err := led.db.Exec(`UPDATE connector_operation SET vault_id='other-vault' WHERE operation_id=?`, first.OperationID); err != nil {
		t.Fatal(err)
	}
	second := first
	second.OperationID = strings.Repeat("0b", 16)
	if _, _, err := led.ApplyConnectorReplay(second); err == nil {
		t.Fatal("authorized after tampered vault id hid a reservation")
	}
	if _, err := led.GetConnectorOperation(first.OperationID); err == nil {
		t.Fatal("tampered vault row trusted")
	}
}

func TestConnectorOutflowAdvancesSequence(t *testing.T) {
	led := openPolicyTestLedger(t, connectorTestClock)
	before, err := economicOutflowCount(led.db)
	if err != nil {
		t.Fatal(err)
	}
	createConnectorVault(t, led, "connector-vault", 0x57)
	applyConnectorOp(t, led, connectorTestOperation(strings.Repeat("0a", 16), "connector-vault"))
	after, err := economicOutflowCount(led.db)
	if err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Fatalf("sequence count %d -> %d", before, after)
	}
}
