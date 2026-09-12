package policy

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
)

// Only the current deployed schema is an upgrade source. Older program-era
// databases are outside this release's supported account model.
func initializeOrValidateSchema(db *sql.DB, boardSchema string) error {
	tables, err := applicationTables(db)
	if err != nil {
		return err
	}
	if len(tables) == 0 {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for _, ddl := range []string{createMultiTenantSchema, createVtxoSchema, boardSchema,
			createLightRenewalSchema, createRecoveryBackupSchema, createLightDelegationSchema,
			createVaultBoardConflictSchema, createLedgerSavingsSchema, createPolicySequenceBaseSchema} {
			if _, err := tx.Exec(ddl); err != nil {
				return fmt.Errorf("create vault schema: %w", err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO schema_meta(version) VALUES(?)`, schemaVersion); err != nil {
			return err
		}
		if err := validateRetainedSchema(tx, boardSchema, schemaVersion); err != nil {
			return err
		}
		return tx.Commit()
	}
	version, rows, err := schemaMetaState(db)
	if err != nil || rows != 1 {
		return fmt.Errorf("database is not the current vault baseline: invalid schema metadata")
	}
	return validateRetainedSchema(db, boardSchema, version)
}

func validateRetainedSchema(q schemaQuerier, boardSchema string, version int) error {
	if version != previousSchemaVersion && version != schemaVersion {
		return fmt.Errorf("unsupported vault schema version %d", version)
	}
	if err := validateVaultSchemaObjects(q, version == previousSchemaVersion); err != nil {
		return err
	}
	for _, check := range []func() error{
		func() error { return validateMultiTenantSchemaOn(q) },
		func() error { return validateBoardingTables(q, boardSchema) },
		func() error { return validateLightRenewalSchema(q) },
		func() error { return validateRecoveryBackupSchema(q) },
		func() error { return validateLightDelegationSchema(q) },
		func() error { return validateVaultBoardConflictSchema(q) },
		func() error { return validateLedgerSavingsSchema(q) },
		func() error { return requireForeignKeysEnabled(q) },
		func() error { return requireForeignKeyCheckClean(q) },
	} {
		if err := check(); err != nil {
			return err
		}
	}
	if version == previousSchemaVersion {
		// These are hashes of the exact normalized tables in the captured v11
		// baseline. No current path can create, read or resume their programs.
		for table, want := range map[string]string{
			"connector_enrollment": "9b5ee788bc05e37ea70e25b5a4a609d3c516d8aed02f2ba6d5865f037db45ada",
			"connector_operation":  "fac9226f11fc3b938bf1f0ba53e8794b67b011faba60770342692c6c9920c3fa",
		} {
			var ddl string
			if err := q.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&ddl); err != nil {
				return err
			}
			if fmt.Sprintf("%x", sha256.Sum256([]byte(normalizeCheck(ddl)))) != want {
				return fmt.Errorf("retirement source table %s changed", table)
			}
		}
		return nil
	}
	var ddl string
	if err := q.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='policy_sequence_base'`).Scan(&ddl); err != nil {
		return err
	}
	if normalizeCheck(ddl) != normalizeCheck(createPolicySequenceBaseSchema) {
		return fmt.Errorf("policy sequence base schema changed")
	}
	return nil
}
