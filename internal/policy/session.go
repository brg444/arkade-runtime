package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	sessionPurposeInitiate = "initiate"
	sessionPurposeClawback = "clawback"
)

// RecoverySession is one sign-once dest for initiate or clawback.
type RecoverySession struct {
	VaultID      string
	Purpose      string
	InputTxid    string
	InputVout    int
	DestScript   string
	LastSighash  string
	Signature    []byte
	CreatedAt    string
	UpdatedAt    string
	IntegrityMAC []byte
}

type ReplayAction string

const (
	ReplaySign   ReplayAction = "sign"
	ReplayReplay ReplayAction = "replay"
	ReplayResign ReplayAction = "resign"
)

func requireSessionPurpose(purpose string) error {
	if purpose != sessionPurposeInitiate && purpose != sessionPurposeClawback {
		return fmt.Errorf("purpose must be initiate or clawback")
	}
	return nil
}

func canonicalSession(rec RecoverySession) []byte {
	var b []byte
	b = append(b, []byte(sessionMACDomain)...)
	b = append(b, 0)
	b = append(b, []byte(rec.VaultID)...)
	b = append(b, 0)
	b = append(b, []byte(rec.Purpose)...)
	b = append(b, 0)
	b = append(b, []byte(rec.InputTxid)...)
	b = append(b, 0)
	b = append(b, []byte(fmt.Sprintf("%d", rec.InputVout))...)
	b = append(b, 0)
	b = append(b, []byte(rec.DestScript)...)
	return b
}

func sealSession(rec *RecoverySession, integrityKey []byte) error {
	if rec == nil || len(integrityKey) != sha256.Size {
		return fmt.Errorf("recovery session seal required")
	}
	mac := hmac.New(sha256.New, integrityKey)
	_, _ = mac.Write(canonicalSession(*rec))
	rec.IntegrityMAC = mac.Sum(nil)
	return nil
}

func verifySession(rec *RecoverySession, integrityKey []byte) error {
	if rec == nil || len(rec.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("recovery session MAC missing")
	}
	var tmp RecoverySession = *rec
	if err := sealSession(&tmp, integrityKey); err != nil {
		return err
	}
	if !hmac.Equal(rec.IntegrityMAC, tmp.IntegrityMAC) {
		return fmt.Errorf("recovery session MAC mismatch")
	}
	return nil
}

// DecideReplay matches the wallet oracle: same dest may fee-bump; second dest or input set is refused.
func DecideReplay(existing *RecoverySession, next RecoverySession) (ReplayAction, error) {
	if err := requireSessionPurpose(next.Purpose); err != nil {
		return "", err
	}
	next.InputTxid = strings.ToLower(strings.TrimSpace(next.InputTxid))
	next.DestScript = strings.ToLower(strings.TrimSpace(next.DestScript))
	if next.VaultID == "" || next.InputTxid == "" || next.DestScript == "" {
		return "", fmt.Errorf("recovery session dest and outpoint required")
	}
	if existing == nil {
		return ReplaySign, nil
	}
	if existing.DestScript != next.DestScript {
		return "", fmt.Errorf("second dest for this outpoint")
	}
	if existing.InputTxid != next.InputTxid || existing.InputVout != next.InputVout {
		return "", fmt.Errorf("overlapping input set for this outpoint")
	}
	if next.LastSighash != "" && existing.LastSighash == next.LastSighash && len(existing.Signature) > 0 {
		return ReplayReplay, nil
	}
	return ReplayResign, nil
}

func (l *Ledger) GetRecoverySession(vaultID, txid string, vout int, purpose string) (*RecoverySession, error) {
	if err := requireSessionPurpose(purpose); err != nil {
		return nil, err
	}
	row := RecoverySession{}
	err := l.db.QueryRow(
		`SELECT vault_id, purpose, input_txid, input_vout, dest_script, IFNULL(last_sighash,''), signature, created_at, updated_at, integrity_mac
		 FROM recovery_session WHERE vault_id=? AND input_txid=? AND input_vout=? AND purpose=?`,
		vaultID, strings.ToLower(txid), vout, purpose,
	).Scan(&row.VaultID, &row.Purpose, &row.InputTxid, &row.InputVout, &row.DestScript, &row.LastSighash, &row.Signature, &row.CreatedAt, &row.UpdatedAt, &row.IntegrityMAC)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := verifySession(&row, l.integrityKey); err != nil {
		return nil, err
	}
	return &row, nil
}

func (l *Ledger) PutRecoverySession(rec RecoverySession) error {
	if err := requireSessionPurpose(rec.Purpose); err != nil {
		return err
	}
	now := l.clock().UTC().Format(time.RFC3339Nano)
	if rec.CreatedAt == "" {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now
	rec.InputTxid = strings.ToLower(strings.TrimSpace(rec.InputTxid))
	rec.DestScript = strings.ToLower(strings.TrimSpace(rec.DestScript))
	if err := sealSession(&rec, l.integrityKey); err != nil {
		return err
	}
	_, err := l.db.Exec(
		`INSERT INTO recovery_session (vault_id, purpose, input_txid, input_vout, dest_script, last_sighash, signature, created_at, updated_at, integrity_mac)
		 VALUES (?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(vault_id, input_txid, input_vout, purpose) DO UPDATE SET
		   dest_script=excluded.dest_script,
		   last_sighash=excluded.last_sighash,
		   signature=excluded.signature,
		   updated_at=excluded.updated_at,
		   integrity_mac=excluded.integrity_mac`,
		rec.VaultID, rec.Purpose, rec.InputTxid, rec.InputVout, rec.DestScript, rec.LastSighash, rec.Signature, rec.CreatedAt, rec.UpdatedAt, rec.IntegrityMAC,
	)
	return err
}

func (l *Ledger) ApplyRecoveryReplay(next RecoverySession) (ReplayAction, *RecoverySession, error) {
	existing, err := l.GetRecoverySession(next.VaultID, next.InputTxid, next.InputVout, next.Purpose)
	if err != nil {
		return "", nil, err
	}
	action, err := DecideReplay(existing, next)
	if err != nil {
		return "", nil, err
	}
	if action == ReplayReplay {
		return action, existing, nil
	}
	if existing != nil {
		next.CreatedAt = existing.CreatedAt
		if next.Signature == nil {
			next.Signature = existing.Signature
		}
		if next.LastSighash == "" {
			next.LastSighash = existing.LastSighash
		}
	}
	if err := l.PutRecoverySession(next); err != nil {
		return "", nil, err
	}
	stored, err := l.GetRecoverySession(next.VaultID, next.InputTxid, next.InputVout, next.Purpose)
	return action, stored, err
}
