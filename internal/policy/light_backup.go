package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
)

// The payload is an opaque, client-encrypted archive. No owner key, PRF or
// passkey recovery secret is accepted by this store. Revisions fence writers.
const MaxLightBackupBytes = 3_000_000
const createLightBackupSchema = `CREATE TABLE light_backup (
 vault_id TEXT PRIMARY KEY REFERENCES vault(vault_id),
 revision INTEGER NOT NULL CHECK (revision > 0),
 payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 3000000),
 integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
)`

type LightBackup struct {
	Revision uint64 `json:"revision"`
	Payload  string `json:"payload"`
}

// Called only after the exact connector-v3 baseline has been validated.
func applyLightBackupMigration(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(createLightBackupSchema); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE schema_meta SET version=? WHERE version=?`, lightBackupSchemaVersion, connectorSchemaVersion)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("Light backup migration requires connector schema 3")
	}
	return tx.Commit()
}

func validateLightBackupSchema(db *sql.DB) error {
	var actual string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE name='light_backup' AND type='table'`).Scan(&actual); err != nil {
		return err
	}
	if normalizeCheck(actual) != normalizeCheck(createLightBackupSchema) {
		return fmt.Errorf("Light backup schema changed")
	}
	return nil
}
func lightBackupMAC(id string, rec LightBackup, key []byte) []byte {
	raw, _ := json.Marshal(struct {
		Domain, VaultID string
		Backup          LightBackup
	}{"vaulted-light/backup-store/v1", id, rec})
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(raw)
	return h.Sum(nil)
}
func readLightBackup(q queryRower, id string, key []byte) (*LightBackup, error) {
	var rec LightBackup
	var mac []byte
	err := q.QueryRow(`SELECT revision,payload,integrity_mac FROM light_backup WHERE vault_id=?`, id).Scan(&rec.Revision, &rec.Payload, &mac)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(mac, lightBackupMAC(id, rec, key)) {
		return nil, fmt.Errorf("Light backup MAC mismatch")
	}
	return &rec, nil
}
func (l *Ledger) GetLightBackup(id string) (*LightBackup, error) {
	if l == nil || len(l.integrityKey) != 32 {
		return nil, fmt.Errorf("backup ledger required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return readLightBackup(l.db, id, l.integrityKey)
}
func (l *Ledger) PutLightBackup(id string, expected uint64, payload string) (*LightBackup, error) {
	if l == nil || len(l.integrityKey) != 32 || len(id) != 64 || len(payload) == 0 || len(payload) > MaxLightBackupBytes || expected >= 1<<53-1 {
		return nil, fmt.Errorf("invalid Light backup")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	old, err := readLightBackup(tx, id, l.integrityKey)
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
		return nil, fmt.Errorf("Light backup changed on another device; reopen with your passkey")
	}
	rec := LightBackup{Revision: expected + 1, Payload: payload}
	_, err = tx.Exec(`INSERT INTO light_backup(vault_id,revision,payload,integrity_mac) VALUES(?,?,?,?) ON CONFLICT(vault_id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload,integrity_mac=excluded.integrity_mac`, id, rec.Revision, rec.Payload, lightBackupMAC(id, rec, l.integrityKey))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &rec, nil
}
