package policy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// LedgerSavingsEnrollment is additive to VaultRecord: its Guardian and account
// origins never replace the original Spending authorities or scalar domain.
type LedgerSavingsEnrollment struct {
	VaultID        string
	ContextJSON    []byte
	DescriptorHash string
	IntegrityMAC   []byte
}

func ledgerSavingsMAC(key []byte, domain string, fields ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, field := range append([][]byte{[]byte(domain)}, fields...) {
		var size [4]byte
		binary.LittleEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write(field)
	}
	return mac.Sum(nil)
}
func SealLedgerSavingsEnrollment(rec *LedgerSavingsEnrollment, key []byte) error {
	if rec == nil || len(key) != 32 {
		return fmt.Errorf("Ledger Savings integrity key required")
	}
	if err := validateLedgerSavingsEnrollment(*rec); err != nil {
		return err
	}
	rec.IntegrityMAC = ledgerSavingsMAC(key, "vaulted/ledger-guardian-savings-v1/enrollment", []byte(rec.VaultID), rec.ContextJSON, []byte(rec.DescriptorHash))
	return nil
}
func validateLedgerSavingsEnrollment(rec LedgerSavingsEnrollment) error {
	if len(rec.ContextJSON) == 0 || len(rec.ContextJSON) > 8192 || len(rec.DescriptorHash) != 64 {
		return fmt.Errorf("Ledger Savings enrollment bounds")
	}
	if raw, err := hex.DecodeString(rec.DescriptorHash); err != nil || len(raw) != 32 || hex.EncodeToString(raw) != rec.DescriptorHash {
		return fmt.Errorf("Ledger Savings descriptor hash must be canonical")
	}
	// Persistence bounds and authenticates opaque immutable contract bytes. The
	// application reconstructs the named Savings contract after MAC verification.
	var identity struct {
		VaultID string `json:"vaultId"`
	}
	if err := json.Unmarshal(rec.ContextJSON, &identity); err != nil {
		return err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, rec.ContextJSON); err != nil {
		return err
	}
	if identity.VaultID != rec.VaultID || !bytes.Equal(compact.Bytes(), rec.ContextJSON) {
		return fmt.Errorf("Ledger Savings immutable context identity")
	}
	return nil
}
func verifyLedgerSavingsEnrollment(rec LedgerSavingsEnrollment, key []byte) error {
	want := ledgerSavingsMAC(key, "vaulted/ledger-guardian-savings-v1/enrollment", []byte(rec.VaultID), rec.ContextJSON, []byte(rec.DescriptorHash))
	if len(key) != 32 || !hmac.Equal(rec.IntegrityMAC, want) {
		return fmt.Errorf("Ledger Savings enrollment MAC mismatch")
	}
	return validateLedgerSavingsEnrollment(rec)
}
func putLedgerSavingsEnrollmentTx(tx *sql.Tx, rec LedgerSavingsEnrollment) error {
	if err := validateLedgerSavingsEnrollment(rec); err != nil {
		return err
	}
	if len(rec.IntegrityMAC) != 32 {
		return fmt.Errorf("Ledger Savings enrollment MAC required")
	}
	_, err := tx.Exec(`INSERT INTO ledger_savings_enrollment(vault_id,context_json,descriptor_hash,integrity_mac) VALUES(?,?,?,?)`, rec.VaultID, rec.ContextJSON, rec.DescriptorHash, rec.IntegrityMAC)
	return err
}
func (l *Ledger) GetLedgerSavingsEnrollment(vaultID string) (*LedgerSavingsEnrollment, error) {
	var rec LedgerSavingsEnrollment
	err := l.db.QueryRow(`SELECT vault_id,context_json,descriptor_hash,integrity_mac FROM ledger_savings_enrollment WHERE vault_id=?`, vaultID).Scan(&rec.VaultID, &rec.ContextJSON, &rec.DescriptorHash, &rec.IntegrityMAC)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := verifyLedgerSavingsEnrollment(rec, l.integrityKey); err != nil {
		return nil, err
	}
	return &rec, nil
}

// LedgerSavingsRecovery retains each reservation and completion as a separate
// authenticated event. Counting immutable events advances the independent
// sequence for replacements and completions as well as the first signature.
type LedgerSavingsRecovery struct {
	RecoverySession
	CandidatePSBT string
	DirectProof   []byte
}

func validateLedgerSavingsRecovery(rec LedgerSavingsRecovery) error {
	if err := requireSessionPurpose(rec.Purpose); err != nil {
		return err
	}
	if rec.VaultID == "" || len(rec.InputTxid) != 64 || rec.InputVout < 0 || uint64(rec.InputVout) > uint64(^uint32(0)) || len(rec.DestScript) != 68 || len(rec.LastSighash) != 64 || len(rec.CandidatePSBT) == 0 || len(rec.CandidatePSBT) > 131072 || len(rec.Signature) > 131072 || (len(rec.DirectProof) != 0 && len(rec.DirectProof) != 64) {
		return fmt.Errorf("Ledger Savings recovery bounds")
	}
	for _, value := range []string{rec.InputTxid, rec.DestScript, rec.LastSighash} {
		decoded, err := hex.DecodeString(value)
		if err != nil || hex.EncodeToString(decoded) != value {
			return fmt.Errorf("Ledger Savings recovery encoding must be canonical")
		}
	}
	return nil
}
func (l *Ledger) ApplyLedgerSavingsRecovery(next LedgerSavingsRecovery) (ReplayAction, *LedgerSavingsRecovery, error) {
	if len(l.integrityKey) != 32 {
		return "", nil, fmt.Errorf("Ledger Savings integrity key required")
	}
	if err := validateLedgerSavingsRecovery(next); err != nil {
		return "", nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	if err := l.observeEconomicOutflowsLocked(tx); err != nil {
		return "", nil, err
	}
	// Every row is authenticated before filtering, so changed vault/outpoint or
	// timestamps cannot hide a conflicting committed signing authority.
	rows, err := tx.Query(`SELECT event_id,vault_id,record,integrity_mac FROM ledger_savings_recovery_event ORDER BY event_id`)
	if err != nil {
		return "", nil, err
	}
	var existing *LedgerSavingsRecovery
	var lastID int64
	for rows.Next() {
		var id int64
		var vaultID string
		var raw, mac []byte
		if err := rows.Scan(&id, &vaultID, &raw, &mac); err != nil {
			rows.Close()
			return "", nil, err
		}
		encodedID := binary.LittleEndian.AppendUint64(nil, uint64(id))
		want := ledgerSavingsMAC(l.integrityKey, "vaulted/ledger-guardian-savings-v1/recovery-event", encodedID, []byte(vaultID), raw)
		if !hmac.Equal(mac, want) {
			rows.Close()
			return "", nil, fmt.Errorf("Ledger Savings recovery event MAC mismatch")
		}
		var event LedgerSavingsRecovery
		if err := json.Unmarshal(raw, &event); err != nil {
			rows.Close()
			return "", nil, err
		}
		if err := validateLedgerSavingsRecovery(event); err != nil {
			rows.Close()
			return "", nil, err
		}
		if event.VaultID != vaultID || id <= lastID {
			rows.Close()
			return "", nil, fmt.Errorf("Ledger Savings recovery event identity mismatch")
		}
		lastID = id
		if event.VaultID == next.VaultID && event.InputTxid == next.InputTxid && event.InputVout == next.InputVout && event.Purpose == next.Purpose {
			cp := event
			existing = &cp
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", nil, err
	}
	rows.Close()
	var previous *RecoverySession
	if existing != nil {
		previous = &existing.RecoverySession
	}
	if len(next.Signature) > 0 && (existing == nil || next.CandidatePSBT != existing.CandidatePSBT || !bytes.Equal(next.DirectProof, existing.DirectProof)) {
		return "", nil, fmt.Errorf("Ledger Savings completion must match the durable candidate")
	}
	action, err := DecideReplay(previous, next.RecoverySession)
	if err != nil {
		return "", nil, err
	}
	if action == ReplayReplay || (existing != nil && len(existing.Signature) == 0 && len(next.Signature) == 0 && existing.LastSighash == next.LastSighash) {
		if err := l.observeEconomicOutflowsLocked(tx); err != nil {
			return "", nil, err
		}
		return action, existing, nil
	}
	now := l.clock().UTC().Format(time.RFC3339Nano)
	next.CreatedAt = now
	next.UpdatedAt = now
	next.IntegrityMAC = nil
	if existing != nil {
		next.CreatedAt = existing.CreatedAt
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return "", nil, err
	}
	if lastID == int64(^uint64(0)>>1) {
		return "", nil, fmt.Errorf("Ledger Savings event ID overflow")
	}
	id := lastID + 1
	mac := ledgerSavingsMAC(l.integrityKey, "vaulted/ledger-guardian-savings-v1/recovery-event", binary.LittleEndian.AppendUint64(nil, uint64(id)), []byte(next.VaultID), raw)
	if _, err := tx.Exec(`INSERT INTO ledger_savings_recovery_event(event_id,vault_id,record,integrity_mac)VALUES(?,?,?,?)`, id, next.VaultID, raw, mac); err != nil {
		return "", nil, err
	}
	// Commit first, then synchronously observe the durable event count. Failure
	// refuses signatures; an exact retry repairs/checks the sequence before use.
	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	if err := l.observeEconomicOutflowsLocked(l.db); err != nil {
		return "", nil, err
	}
	return action, &next, nil
}
