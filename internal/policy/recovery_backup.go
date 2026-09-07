package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
)

// The application checks the encrypted envelope; this store treats its payload
// as opaque bytes and fences writers by revision. It never decrypts the archive.
const MaxRecoveryBackupBytes = 3_000_000
const createRecoveryBackupSchema = `CREATE TABLE recovery_backup (
 vault_id TEXT PRIMARY KEY REFERENCES vault(vault_id),
 revision INTEGER NOT NULL CHECK (revision > 0),
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 3000000),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
)`

type RecoveryBackup struct {
	Revision uint64 `json:"revision"`
	Payload  string `json:"payload"`
}

// Called only after the exact connector-v3 baseline has been validated.
func applyRecoveryBackupMigration(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(createRecoveryBackupSchema); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE schema_meta SET version=? WHERE version=?`, recoveryBackupSchemaVersion, connectorSchemaVersion)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("Recovery backup migration requires connector schema 3")
	}
	return tx.Commit()
}

func validateRecoveryBackupSchema(db *sql.DB) error {
	var actual string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE name='recovery_backup' AND type='table'`).Scan(&actual); err != nil {
		return err
	}
	if normalizeCheck(actual) != normalizeCheck(createRecoveryBackupSchema) {
		return fmt.Errorf("Recovery backup schema changed")
	}
	return nil
}
func recoveryBackupMAC(id string, rec RecoveryBackup, key []byte) []byte {
	raw, _ := json.Marshal(struct {
		Domain, VaultID string
		Backup          RecoveryBackup
	}{"vaulted/recovery-backup-store/v1", id, rec})
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(raw)
	return h.Sum(nil)
}
func readRecoveryBackup(q queryRower, id string, key []byte) (*RecoveryBackup, error) {
	var rec RecoveryBackup
	var mac []byte
	err := q.QueryRow(`SELECT revision,payload,integrity_mac FROM recovery_backup WHERE vault_id=?`, id).Scan(&rec.Revision, &rec.Payload, &mac)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(mac, recoveryBackupMAC(id, rec, key)) {
		return nil, fmt.Errorf("Recovery backup MAC mismatch")
	}
	return &rec, nil
}
func (l *Ledger) GetRecoveryBackup(id string) (*RecoveryBackup, error) {
	if l == nil || len(l.integrityKey) != 32 {
		return nil, fmt.Errorf("backup ledger required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return readRecoveryBackup(l.db, id, l.integrityKey)
}
func (l *Ledger) PutRecoveryBackup(id string, expected uint64, payload string) (*RecoveryBackup, error) {
	if l == nil || len(l.integrityKey) != 32 || len(id) == 0 || len(id) > 128 || len(payload) == 0 || len(payload) > MaxRecoveryBackupBytes || expected >= 1<<53-1 {
		return nil, fmt.Errorf("invalid Recovery backup")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	old, err := readRecoveryBackup(tx, id, l.integrityKey)
	if err != nil {
		return nil, err
	}
	current := uint64(0)
	if old != nil {
		current = old.Revision
	}
	// A lost successful response can retry exactly the same write safely.
	if old != nil && current == expected+1 && old.Payload == payload {
		return old, nil
	}
	if current != expected {
		return nil, fmt.Errorf("Recovery backup changed on another device; reopen with your passkey")
	}
	rec := RecoveryBackup{Revision: expected + 1, Payload: payload}
	_, err = tx.Exec(`INSERT INTO recovery_backup(vault_id,revision,payload,integrity_mac) VALUES(?,?,?,?) ON CONFLICT(vault_id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload,integrity_mac=excluded.integrity_mac`, id, rec.Revision, rec.Payload, recoveryBackupMAC(id, rec, l.integrityKey))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &rec, nil
}
