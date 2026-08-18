package policy

import (
	"database/sql"
	"fmt"
	"os"
)

// RefuseLegacyDatabase fails before OpenLedger when path already holds
// singleton-credential or legacy-direct custody state. Missing or unused
// files are allowed so a new service can initialize.
func RefuseLegacyDatabase(path string) error {
	if path == "" {
		return fmt.Errorf("database path required")
	}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Size() == 0 {
		return nil
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("legacy database: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := refuseLegacyRows(db); err != nil {
		return err
	}
	return nil
}

func refuseLegacyRows(db *sql.DB) error {
	if hasTable(db, "credential") {
		n, err := countRows(db, "credential")
		if err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("legacy credential rows present; this service is fresh-only")
		}
	}
	if hasTable(db, "vault") {
		var n int
		err := db.QueryRow(`SELECT COUNT(*) FROM vault WHERE cosigner_mode = ?`, CosignerModeLegacyDirectV0).Scan(&n)
		if err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("legacy-direct vault rows present; this service is fresh-only")
		}
	}
	if hasTable(db, "schema_meta") {
		ver, n, err := schemaMetaState(db)
		if err != nil {
			return err
		}
		if n == 1 && ver < schemaVersionIssuanceMAC {
			vaults, err := countRows(db, "vault")
			if err != nil {
				return err
			}
			if vaults > 0 {
				return fmt.Errorf("schema v%d is not a fresh database; this service is fresh-only", ver)
			}
		}
	}
	return nil
}

func hasTable(db *sql.DB, name string) bool {
	var got string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&got)
	return err == nil && got == name
}

func countRows(db *sql.DB, table string) (int, error) {
	if !knownSchemaTable(table) {
		return 0, fmt.Errorf("unknown table")
	}
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n)
	return n, err
}
