package policy

import (
	"fmt"
	"strings"
)

const createSpendingRenewalSchema = `
CREATE TABLE light_renewal_operation (
 operation_id TEXT PRIMARY KEY,
 vault_id TEXT NOT NULL REFERENCES vault(vault_id),
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 16384),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
CREATE TABLE light_renewal_event (
 operation_id TEXT NOT NULL REFERENCES light_renewal_operation(operation_id),
 phase TEXT NOT NULL CHECK (phase IN ('register_authorized','register_dispatched','register_result','final_authorized','final_dispatched','final_result','confirmed','delete_authorized','delete_dispatched','delete_result','released','cancelled')),
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 1048576),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
 PRIMARY KEY (operation_id, phase)
);
`

func validateSpendingRenewalSchema(db schemaQuerier) error {
	for _, statement := range strings.Split(strings.TrimSpace(createSpendingRenewalSchema), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		fields := strings.Fields(statement)
		name := fields[2]
		var actual string
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&actual); err != nil {
			return err
		}
		if normalizeCheck(actual) != normalizeCheck(statement) {
			return fmt.Errorf("Light renewal table %s changed", name)
		}
	}
	return nil
}
