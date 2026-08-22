package policy

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

var mainnetTables = []string{
	"invite",
	"issuance",
	"pending_enrollment",
	"recovery_session",
	"schema_meta",
	"vault",
	"vault_credential",
	"vault_envelope",
	"vault_map",
	"vtxo_operation",
	"vtxo_operation_input",
	"webauthn_sign_count",
}

// The transitional package still shares row validators with the v9 ledger.
// This becomes 1 when the legacy opener and migration files are deleted.
const mainnetSchemaVersion = schemaVersionCurrent

const createMainnetVtxoSchema = `
CREATE TABLE vtxo_operation (
  operation_id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('spend', 'board')),
  bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
  state TEXT NOT NULL CHECK (state IN ('reserved', 'signed', 'submitted', 'finalized', 'aborted', 'unresolved')),
  amount_sats INTEGER NOT NULL CHECK (amount_sats >= 0),
  fee_sats INTEGER NOT NULL CHECK (fee_sats >= 0),
  dest_script BLOB,
  change_script BLOB,
  unsigned_psbt TEXT,
  authorized_psbt TEXT,
  checkpoint_psbts TEXT,
  commitment_psbt TEXT,
  checkpoint_tapscript BLOB,
  ark_txid TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  last_dest_script BLOB,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
CREATE TABLE vtxo_operation_input (
  operation_id TEXT NOT NULL REFERENCES vtxo_operation(operation_id),
  txid BLOB NOT NULL CHECK (length(txid) = 32),
  vout INTEGER NOT NULL CHECK (vout >= 0),
  value_sats INTEGER NOT NULL CHECK (value_sats >= 0),
  script BLOB,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  PRIMARY KEY (operation_id, txid, vout)
);
CREATE INDEX vtxo_operation_vault_state_created ON vtxo_operation(vault_id, state, created_at);
CREATE INDEX vtxo_operation_input_outpoint ON vtxo_operation_input(txid, vout, operation_id);
`

// OpenMainnetLedger opens the fresh mainnet persistence baseline. It never
// interprets or changes an older database. A non-empty file must already be the
// exact baseline created by this function.
func OpenMainnetLedger(path string, clock Clock) (*Ledger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("database path required")
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA synchronous = FULL`,
		`PRAGMA foreign_keys = ON`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if err := initializeOrValidateMainnetSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Ledger{db: db, clock: clock}, nil
}

func initializeOrValidateMainnetSchema(db *sql.DB) error {
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
		if _, err := tx.Exec(createMultiTenantSchema + createSealedIssuanceTable + createMainnetVtxoSchema); err != nil {
			return fmt.Errorf("create mainnet schema: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_meta (version) VALUES (?)`, mainnetSchemaVersion); err != nil {
			return fmt.Errorf("create mainnet schema version: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		tables = append([]string(nil), mainnetTables...)
	}
	if !sameStrings(tables, mainnetTables) {
		return fmt.Errorf("database is not the mainnet v2 baseline: tables %v", tables)
	}
	ver, rows, err := schemaMetaState(db)
	if err != nil {
		return err
	}
	if rows != 1 || ver != mainnetSchemaVersion {
		return fmt.Errorf("database is not the mainnet v2 baseline: schema version %d", ver)
	}
	if err := validateMultiTenantSchemaOn(db); err != nil {
		return fmt.Errorf("mainnet schema: %w", err)
	}
	if cols, err := tableColumns(db, "issuance"); err != nil || !sameColumns(cols, issuanceColumns) {
		return fmt.Errorf("mainnet schema: issuance table mismatch")
	}
	for _, table := range []string{"vtxo_operation", "vtxo_operation_input"} {
		if !hasTable(db, table) {
			return fmt.Errorf("mainnet schema: %s missing", table)
		}
	}
	if err := requireForeignKeysEnabled(db); err != nil {
		return err
	}
	return requireForeignKeyCheckClean(db)
}

func applicationTables(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func sameStrings(left, right []string) bool {
	a := append([]string(nil), left...)
	b := append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
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
