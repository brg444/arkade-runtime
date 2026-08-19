package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// VaultMap is the authenticated public recovery map for one vault.
type VaultMap struct {
	VaultID string
	KitHash string
	Payload string
}

func (l *Ledger) PutVaultMap(rec VaultMap) error {
	if l == nil || len(l.integrityKey) != sha256.Size {
		return fmt.Errorf("map ledger required")
	}
	rec.VaultID = strings.TrimSpace(rec.VaultID)
	rec.KitHash = strings.ToLower(strings.TrimSpace(rec.KitHash))
	if rec.VaultID == "" || len(rec.KitHash) != 64 || rec.Payload == "" || len(rec.Payload) > 98304 {
		return fmt.Errorf("vault map required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock().UTC().Format(time.RFC3339Nano)
	mac := vaultMapMAC(rec, l.integrityKey)
	_, err := l.db.Exec(
		`INSERT INTO vault_map (vault_id, kit_hash, payload, updated_at, integrity_mac)
		 VALUES (?,?,?,?,?)
		 ON CONFLICT(vault_id) DO UPDATE SET
		   kit_hash=excluded.kit_hash,
		   payload=excluded.payload,
		   updated_at=excluded.updated_at,
		   integrity_mac=excluded.integrity_mac`,
		rec.VaultID, rec.KitHash, rec.Payload, now, mac,
	)
	return err
}

func (l *Ledger) GetVaultMap(vaultID string) (*VaultMap, error) {
	if l == nil || len(l.integrityKey) != sha256.Size {
		return nil, fmt.Errorf("map ledger required")
	}
	vaultID = strings.TrimSpace(vaultID)
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	var rec VaultMap
	var mac []byte
	err := l.db.QueryRow(
		`SELECT vault_id, kit_hash, payload, integrity_mac FROM vault_map WHERE vault_id=?`,
		vaultID,
	).Scan(&rec.VaultID, &rec.KitHash, &rec.Payload, &mac)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(mac, vaultMapMAC(rec, l.integrityKey)) {
		return nil, fmt.Errorf("vault map MAC mismatch")
	}
	return &rec, nil
}

func vaultMapMAC(rec VaultMap, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(vaultMapMACDomain))
	_, _ = h.Write([]byte(rec.VaultID))
	_, _ = h.Write([]byte(rec.KitHash))
	_, _ = h.Write([]byte(rec.Payload))
	return h.Sum(nil)
}
