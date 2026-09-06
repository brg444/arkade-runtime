package policy

import (
	"database/sql"
	"fmt"
	"strings"
)

// createConnectorSchema adds only the Savings connector stores. Existing rows,
// canonical MAC preimages, and the independent economic sequence remain
// byte-identical. Unlike boarding authorizations, connector operations retain
// exact signed PSBT stages: the RC contract requires resuming the same durable
// operation and signing result after a lost response or restart.
//
// Conflict discovery scans and MAC-verifies every row before Go filters by
// vault and outpoint, and single operations load by primary key, so no
// secondary indexes are defined.
const createConnectorSchema = `
CREATE TABLE connector_enrollment (
  vault_id TEXT PRIMARY KEY REFERENCES vault(vault_id),
  connector_type TEXT NOT NULL CHECK (connector_type IN ('p2tr', 'p2wpkh')),
  connector_pub BLOB NOT NULL CHECK (length(connector_pub) = 33),
  fingerprint INTEGER NOT NULL CHECK (fingerprint >= 0 AND fingerprint <= 4294967295),
  path TEXT NOT NULL CHECK (length(path) > 0 AND length(path) <= 512),
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
CREATE TABLE connector_operation (
  operation_id TEXT PRIMARY KEY CHECK (length(operation_id) = 32),
  vault_id TEXT NOT NULL REFERENCES connector_enrollment(vault_id),
  savings_txid TEXT NOT NULL CHECK (length(savings_txid) = 64),
  savings_vout INTEGER NOT NULL CHECK (savings_vout >= 0 AND savings_vout <= 4294967295),
  connector_txid TEXT NOT NULL CHECK (length(connector_txid) = 64),
  connector_vout INTEGER NOT NULL CHECK (connector_vout >= 0 AND connector_vout <= 4294967295),
  dest_script TEXT NOT NULL CHECK (length(dest_script) > 0 AND length(dest_script) <= 20000),
  amount_sats INTEGER NOT NULL CHECK (amount_sats >= 0),
  fee_sats INTEGER NOT NULL CHECK (fee_sats >= 0),
  connector_script BLOB NOT NULL CHECK (length(connector_script) IN (22, 34)),
  candidate_psbt TEXT NOT NULL CHECK (length(candidate_psbt) > 0 AND length(candidate_psbt) <= 131072),
  last_sighash TEXT NOT NULL CHECK (length(last_sighash) = 64),
  guardian_psbt TEXT NOT NULL CHECK (length(guardian_psbt) <= 131072),
  emulator_psbt TEXT NOT NULL CHECK (length(emulator_psbt) <= 131072),
  phase TEXT NOT NULL CHECK (phase IN ('authorized', 'guardian_signed', 'emulator_signed')),
  resolution TEXT NOT NULL CHECK (resolution IN ('none', 'confirmed', 'conflicted')),
  resolution_txid TEXT NOT NULL CHECK (length(resolution_txid) IN (0, 64)),
  resolution_block_hash TEXT NOT NULL CHECK (length(resolution_block_hash) IN (0, 64)),
  resolution_block_height INTEGER NOT NULL CHECK (resolution_block_height >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
`

// applyConnectorMigration creates the connector stores and advances the
// schema version. Outpoint ownership is enforced in code under the ledger
// mutex, never by schema UNIQUE constraints, so confirmed-conflict resolution
// followed by same-Savings/new-reserve retry keeps full history.
func applyConnectorMigration(db *sql.DB, fromVersion, toVersion int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(createConnectorSchema); err != nil {
		return fmt.Errorf("create connector store: %w", err)
	}
	if _, err = tx.Exec(`UPDATE schema_meta SET version=? WHERE version=?`, toVersion, fromVersion); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func validateConnectorSchema(db *sql.DB) error {
	for _, statement := range strings.Split(strings.TrimSpace(createConnectorSchema), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		fields := strings.Fields(statement)
		if fields[0] == "CREATE" && fields[1] == "TABLE" {
			var actual string
			if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, fields[2]).Scan(&actual); err != nil {
				return err
			}
			if normalizeCheck(actual) != normalizeCheck(statement) {
				return fmt.Errorf("connector table %s changed", fields[2])
			}
		}
	}
	return nil
}
