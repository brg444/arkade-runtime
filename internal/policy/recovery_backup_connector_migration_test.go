package policy

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Capture complete SQL values, including MACs, rather than comparing just the
// decoded models. The table list is fixed test data, never caller input.
func connectorMigrationRows(t *testing.T, db *sql.DB) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	for _, table := range []string{"vault", "vault_credential", "recovery_session", "light_renewal_operation", "light_renewal_event", "connector_enrollment", "connector_operation"} {
		rows, err := db.Query(`SELECT * FROM ` + table + ` ORDER BY 1,2`)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var values [][]any
		for rows.Next() {
			row := make([]any, len(columns))
			ptrs := make([]any, len(row))
			for i := range row {
				ptrs[i] = &row[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			values = append(values, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		result[table], err = json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func TestRecoveryBackupMigrationPreservesConnectorV3Authority(t *testing.T) {
	path, _, priorCount := populatedV2Database(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	if err := validateV2Baseline(db, createVaultBoardSchema); err != nil {
		t.Fatal(err)
	}
	if err := applyConnectorMigration(db, lightSchemaVersion, connectorSchemaVersion); err != nil {
		t.Fatal(err)
	}
	if err := validateV3Baseline(db, createVaultBoardSchema); err != nil {
		t.Fatal(err)
	}
	old := &Ledger{db: db, clock: connectorTestClock, network: "mutinynet"}
	if err := old.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	sequencePath := filepath.Join(t.TempDir(), "independent-sequence")
	sequence, err := OpenMonotonic(sequencePath, testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	// Supply the authenticated sequence belonging to the populated fixture.
	// Production never reconstructs a missing sequence from a database count.
	if err := sequence.write(priorCount); err != nil {
		t.Fatal(err)
	}
	if err := old.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	renewal, err := old.GetLightRenewal(t.Context(), strings.Repeat("01", 16))
	if err != nil {
		t.Fatal(err)
	}
	appendRenewal(t, old, renewal.Operation, "register_authorized")
	vaultID := strings.Repeat("cd", 32)
	createConnectorVault(t, old, vaultID, 0x57)
	var candidates []ConnectorOperation
	var retained []*ConnectorOperation
	for i := range 5 {
		op := connectorTestOperation(strings.Repeat(fmt.Sprintf("%02x", i+10), 16), vaultID)
		op.SavingsVout, op.ConnectorVout = uint32(i), uint32(i+10)
		applyConnectorOp(t, old, op)
		if i >= 1 {
			if _, err := old.StoreConnectorStage(op.OperationID, ConnectorPhaseGuardianSigned, strings.Repeat("ab", 100)); err != nil {
				t.Fatal(err)
			}
		}
		if i >= 2 {
			if _, err := old.StoreConnectorStage(op.OperationID, ConnectorPhaseEmulatorSigned, strings.Repeat("cd", 100)); err != nil {
				t.Fatal(err)
			}
		}
		if i >= 3 {
			resolution := ConnectorResolutionConfirmed
			if i == 4 {
				resolution = ConnectorResolutionConflict
			}
			if _, err := old.ResolveConnectorOperation(op.OperationID, ConnectorChainEvidence{
				Resolution: resolution, ResolutionTxid: strings.Repeat("98", 32),
				ResolutionBlockHash: strings.Repeat("99", 32), ResolutionBlockHeight: 800,
			}); err != nil {
				t.Fatal(err)
			}
		}
		saved, err := old.GetConnectorOperation(op.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		candidates, retained = append(candidates, op), append(retained, saved)
	}
	before := connectorMigrationRows(t, db)
	count, err := economicOutflowCount(db)
	if err != nil {
		t.Fatal(err)
	}
	sequenceBefore, err := os.ReadFile(sequencePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := OpenLedger(path, connectorTestClock)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if version, err := current.SchemaVersion(); err != nil || version != recoveryBackupSchemaVersion {
		t.Fatal("migration version", version, err)
	}
	if !reflect.DeepEqual(before, connectorMigrationRows(t, current.db)) {
		t.Fatal("migration changed pre-existing row bytes or MACs")
	}
	if err := current.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	reopenedSequence, err := OpenMonotonic(sequencePath, testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := current.AttachMonotonic(reopenedSequence); err != nil {
		t.Fatal(err)
	}
	if _, err := current.GetConnectorEnrollment(vaultID); err != nil {
		t.Fatal(err)
	}
	if _, err := current.GetLightRenewal(t.Context(), renewal.Operation.OperationID); err != nil {
		t.Fatal(err)
	}
	for i, op := range candidates {
		got, err := current.GetConnectorOperation(op.OperationID)
		if err != nil || !reflect.DeepEqual(got, retained[i]) {
			t.Fatal("retained signing stage changed", i, err)
		}
		if i < 3 {
			action, replay, err := current.ApplyConnectorReplay(op)
			if err != nil || action != ConnectorReplayReplay || !reflect.DeepEqual(replay, retained[i]) {
				t.Fatal("exact stage replay lost", i, err)
			}
		} else {
			// Application revalidation supplies the positive reorg observation;
			// reopening must retain the exact signatures and restore ownership.
			if _, err := current.ResolveConnectorOperation(op.OperationID, ConnectorChainEvidence{Resolution: ConnectorResolutionNone}); err != nil {
				t.Fatal(err)
			}
		}
		changed := op
		changed.OperationID = strings.Repeat(fmt.Sprintf("%02x", i+20), 16)
		changed.CandidatePSBT += "00"
		if _, _, err := current.ApplyConnectorReplay(changed); err == nil {
			t.Fatal("migration released signed input ownership", i)
		}
	}
	if _, err := current.PutRecoveryBackup(strings.Repeat("ab", 32), 0, "encrypted-archive"); err != nil {
		t.Fatal(err)
	}
	if got, err := economicOutflowCount(current.db); err != nil || got != count {
		t.Fatal("backup changed economic count", got, count, err)
	}
	sequenceAfter, err := os.ReadFile(sequencePath)
	if err != nil || !bytes.Equal(sequenceBefore, sequenceAfter) {
		t.Fatal("migration or backup changed independent sequence", err)
	}
}

func TestRecoveryBackupMigrationRejectsOtherSchemaThreeLineage(t *testing.T) {
	for _, conflictingBackup := range []bool{false, true} {
		t.Run(fmt.Sprintf("isolated-backup=%t", conflictingBackup), func(t *testing.T) {
			path, _, _ := populatedV2Database(t)
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if conflictingBackup {
				// The isolated Light drill used schema 3 for a different layout.
				if _, err := db.Exec(strings.Replace(createRecoveryBackupSchema, "recovery_backup", "light_backup", 1)); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`UPDATE schema_meta SET version=3`); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := applyConnectorMigration(db, lightSchemaVersion, connectorSchemaVersion); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`ALTER TABLE connector_operation ADD COLUMN unexpected TEXT`); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if accepted, err := OpenLedger(path, nil); err == nil {
				accepted.Close()
				t.Fatal("unsupported schema-3 layout migrated")
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version int
			if err := db.QueryRow(`SELECT version FROM schema_meta`).Scan(&version); err != nil || version != connectorSchemaVersion {
				t.Fatal("refused migration changed version", version, err)
			}
			if hasTable(db, "light_backup") != conflictingBackup {
				t.Fatal("refused migration changed backup schema")
			}
			if hasTable(db, "connector_operation") == conflictingBackup {
				t.Fatal("refused migration changed connector schema")
			}
		})
	}
}

// The prior schema-4 was an undeployed integration artifact. Refuse its exact
// table layout without guessing a lineage or silently converting its row MACs.
func TestRecoveryBackupRefusesScratchLightOnlyV4(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scratch.sqlite")
	ledger, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.db.Exec(`ALTER TABLE recovery_backup RENAME TO light_backup`); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if accepted, err := OpenLedger(path, nil); err == nil {
		accepted.Close()
		t.Fatal("scratch schema 4 accepted")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRow(`SELECT version FROM schema_meta`).Scan(&version); err != nil || version != 4 {
		t.Fatal(version, err)
	}
	if !hasTable(db, "light_backup") || hasTable(db, "recovery_backup") {
		t.Fatal("refusal mutated tables")
	}
}
