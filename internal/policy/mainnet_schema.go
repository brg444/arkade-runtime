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

const mainnetSchemaVersion = 1

const createMainnetVtxoSchema = `
CREATE TABLE vtxo_operation (
  operation_id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL REFERENCES vault(vault_id),
  purpose TEXT NOT NULL CHECK (purpose = 'spend'),
  bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
  state TEXT NOT NULL CHECK (state IN ('reserved', 'signed', 'submitted', 'finalized', 'aborted', 'unresolved')),
  amount_sats INTEGER NOT NULL CHECK (amount_sats >= 0),
  fee_sats INTEGER NOT NULL CHECK (fee_sats >= 0),
  fee_policy_digest BLOB NOT NULL CHECK (length(fee_policy_digest) = 32),
  dest_script BLOB,
  change_script BLOB,
  change_sats INTEGER NOT NULL CHECK (change_sats >= 0),
  change_vout INTEGER CHECK (change_vout >= 0),
  unsigned_psbt TEXT,
  authorized_psbt TEXT,
  pending_proof_digest BLOB CHECK (pending_proof_digest IS NULL OR length(pending_proof_digest) = 32),
  authorized_pending_proof TEXT,
  checkpoint_psbts TEXT,
  checkpoint_request_psbts TEXT,
  checkpoint_tapscript BLOB,
  ark_txid TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  last_dest_script BLOB,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  CHECK (
    (change_sats = 0 AND change_vout IS NULL AND (change_script IS NULL OR length(change_script) = 0))
    OR (change_sats >= 330 AND change_vout = 1 AND change_script IS NOT NULL AND length(change_script) > 0)
  ),
  CHECK (
    (pending_proof_digest IS NULL AND (authorized_pending_proof IS NULL OR length(authorized_pending_proof) = 0))
    OR (length(pending_proof_digest) = 32 AND authorized_pending_proof IS NOT NULL AND length(authorized_pending_proof) > 0)
  )
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
CREATE INDEX vtxo_operation_vault_state_expiry ON vtxo_operation(vault_id, state, expires_at);
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
		if _, err := tx.Exec(createMultiTenantSchema + createMainnetVtxoSchema); err != nil {
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
	if err := validateApplicationObjects(db); err != nil {
		return err
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
	if err := requireForeignKeysEnabled(db); err != nil {
		return err
	}
	return requireForeignKeyCheckClean(db)
}

func validateApplicationObjects(db *sql.DB) error {
	want := append([]string(nil), mainnetTables...)
	want = append(want,
		"index:vault_credential_vault",
		"index:vtxo_operation_input_outpoint",
		"index:vtxo_operation_vault_state_created",
		"index:vtxo_operation_vault_state_expiry",
	)
	for i, name := range want {
		if !strings.Contains(name, ":") {
			want[i] = "table:" + name
		}
	}
	rows, err := db.Query(`
SELECT type, name
  FROM sqlite_master
 WHERE name NOT LIKE 'sqlite_%'
   AND type IN ('table', 'index', 'trigger', 'view')
   AND (type != 'index' OR sql IS NOT NULL)
 ORDER BY type, name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var kind, name string
		if err := rows.Scan(&kind, &name); err != nil {
			return err
		}
		got = append(got, kind+":"+name)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !sameStrings(got, want) {
		return fmt.Errorf("database is not the mainnet v2 baseline: objects %v", got)
	}
	return nil
}

func hasTable(db *sql.DB, table string) bool {
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
	return err == nil && name == table
}

func knownSchemaTable(table string) bool {
	for _, known := range mainnetTables {
		if table == known {
			return true
		}
	}
	return false
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
