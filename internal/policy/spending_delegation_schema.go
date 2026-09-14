package policy

import (
	"fmt"
	"strings"
)

const createSpendingDelegationSchema = `
CREATE TABLE light_delegation_operation (
 operation_id TEXT PRIMARY KEY,
 vault_id TEXT NOT NULL REFERENCES vault(vault_id),
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 131072),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
CREATE TABLE light_delegation_event (
 operation_id TEXT NOT NULL REFERENCES light_delegation_operation(operation_id),
 phase TEXT NOT NULL,
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 8000000),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
 PRIMARY KEY (operation_id,phase)
);
`

func validateSpendingDelegationSchema(db schemaQuerier) error {
	for _, statement := range strings.Split(strings.TrimSpace(createSpendingDelegationSchema), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		name := strings.Fields(statement)[2]
		var actual string
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&actual); err != nil {
			return err
		}
		if normalizeCheck(actual) != normalizeCheck(statement) {
			return fmt.Errorf("Light delegation schema changed")
		}
	}
	return nil
}
