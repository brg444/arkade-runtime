package policy

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"

	"sort"
	"testing"
)

func migrationFingerprints(t *testing.T, db *sql.DB) map[string][32]byte {
	t.Helper()
	rows, err := db.Query(`SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_meta' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	ddl := map[string]string{}
	for rows.Next() {
		var name, statement string
		if err := rows.Scan(&name, &statement); err != nil {
			t.Fatal(err)
		}
		ddl[name] = statement
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	result := map[string][32]byte{}
	for name, statement := range ddl {
		// Names have been returned by SQLite, quote them as identifiers.
		quoted := `"`
		for _, ch := range name {
			if ch == '"' {
				quoted += `""`
			} else {
				quoted += string(ch)
			}
		}
		quoted += `"`
		r, err := db.Query(`SELECT * FROM ` + quoted)
		if err != nil {
			t.Fatal(err)
		}
		cols, err := r.Columns()
		if err != nil {
			t.Fatal(err)
		}
		records := []string{}
		for r.Next() {
			values := make([]any, len(cols))
			refs := make([]any, len(cols))
			for i := range values {
				refs[i] = &values[i]
			}
			if err := r.Scan(refs...); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			records = append(records, string(encoded))
		}
		if err := r.Err(); err != nil {
			t.Fatal(err)
		}
		r.Close()
		sort.Strings(records)
		encoded, err := json.Marshal([]any{statement, cols, records})
		if err != nil {
			t.Fatal(err)
		}
		result[name] = sha256.Sum256(encoded)
		rowBytes, err := json.Marshal([]any{cols, records})
		if err != nil {
			t.Fatal(err)
		}
		result[name+":rows"] = sha256.Sum256(rowBytes)
	}
	return result
}
