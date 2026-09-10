package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
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

// ErrRecoveryBusy rejects a conflicting pending retry or a signing completion
// whose sighash no longer matches the current reservation. An identical pending
// retry may safely re-sign.
var ErrRecoveryBusy = errors.New("recovery session already in progress")

func requireSessionPurpose(purpose string) error {
	if purpose != sessionPurposeInitiate && purpose != sessionPurposeClawback {
		return fmt.Errorf("purpose must be initiate or clawback")
	}
	return nil
}

func canonicalSession(rec RecoverySession) ([]byte, error) {
	out := make([]byte, 0, 256)
	var err error
	out, err = appendCredentialField(out, []byte(sessionMACDomain))
	if err != nil {
		return nil, err
	}
	for _, field := range [][]byte{
		[]byte(rec.VaultID), []byte(rec.Purpose), []byte(rec.InputTxid),
		[]byte(rec.DestScript), []byte(rec.LastSighash), rec.Signature,
		[]byte(rec.CreatedAt), []byte(rec.UpdatedAt),
	} {
		out, err = appendCredentialField(out, field)
		if err != nil {
			return nil, err
		}
	}
	if rec.InputVout < 0 {
		return nil, fmt.Errorf("recovery session vout")
	}
	out = binary.LittleEndian.AppendUint32(out, uint32(rec.InputVout))
	return out, nil
}

func sessionMAC(integrityKey, payload []byte) []byte {
	mac := hmac.New(sha256.New, integrityKey)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func sealSession(rec *RecoverySession, integrityKey []byte) error {
	if rec == nil || len(integrityKey) != sha256.Size {
		return fmt.Errorf("recovery session seal required")
	}
	payload, err := canonicalSession(*rec)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = sessionMAC(integrityKey, payload)
	return nil
}

func verifySession(rec *RecoverySession, integrityKey []byte) error {
	if rec == nil || len(rec.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("recovery session MAC missing")
	}
	payload, err := canonicalSession(*rec)
	if err != nil {
		return err
	}
	if hmac.Equal(rec.IntegrityMAC, sessionMAC(integrityKey, payload)) {
		return nil
	}
	return fmt.Errorf("recovery session MAC mismatch")
}

// DecideReplay permits an unsigned replacement for the same destination, while
// signed completions must match the reserved sighash and exact retries replay.
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
	if len(existing.Signature) == 0 {
		if existing.LastSighash == "" || next.LastSighash == "" || existing.LastSighash != next.LastSighash {
			return "", ErrRecoveryBusy
		}
		return ReplayResign, nil
	}
	if next.LastSighash != "" && existing.LastSighash == next.LastSighash && len(existing.Signature) > 0 {
		return ReplayReplay, nil
	}
	// A signing completion may only finalize the currently reserved sighash.
	// A late completion of an earlier attempt cannot replace a newer signed
	// transaction. New candidates enter through the unsigned reservation step.
	if len(next.Signature) != 0 {
		return "", ErrRecoveryBusy
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
	l.mu.Lock()
	defer l.mu.Unlock()
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
		if next.LastSighash == "" {
			next.LastSighash = existing.LastSighash
		}
		// A stored PSBT belongs only to its own sighash. A replacement must
		// remain unsigned until that exact candidate has been signed; carrying
		// the old PSBT forward makes a retry replay the wrong transaction.
		if next.Signature == nil && next.LastSighash == existing.LastSighash {
			next.Signature = existing.Signature
		}
	}
	if err := l.PutRecoverySession(next); err != nil {
		return "", nil, err
	}
	stored, err := l.GetRecoverySession(next.VaultID, next.InputTxid, next.InputVout, next.Purpose)
	return action, stored, err
}
