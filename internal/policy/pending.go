package policy

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
)

// PendingEnrollment is one in-flight WebAuthn create ceremony bound to a
// single invite. Replay of start must reuse this vault identity.
type PendingEnrollment struct {
	Handle    string
	VaultID   string
	TokenHash []byte
	Challenge []byte
	ExpiresAt string
	CreatedAt string
}

func validatePendingEnrollment(p PendingEnrollment) error {
	if p.Handle == "" || p.VaultID == "" {
		return fmt.Errorf("pending enrollment handle and vault id required")
	}
	if len(p.TokenHash) != sha256.Size {
		return fmt.Errorf("pending enrollment token_hash must be 32 bytes")
	}
	if len(p.Challenge) == 0 {
		return fmt.Errorf("pending enrollment challenge required")
	}
	if p.ExpiresAt == "" || p.CreatedAt == "" {
		return fmt.Errorf("pending enrollment timestamps required")
	}
	return nil
}

// ReservePendingEnrollment inserts a pending row for an unused invite or
// returns the existing vault identity when the same token_hash is replayed.
func (l *Ledger) ReservePendingEnrollment(p PendingEnrollment) (*PendingEnrollment, error) {
	if err := validatePendingEnrollment(p); err != nil {
		return nil, err
	}
	if err := ensureMultiTenantSchema(l.db); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	got, err := reservePendingEnrollmentTx(tx, p)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return got, nil
}

func reservePendingEnrollmentTx(tx *sql.Tx, p PendingEnrollment) (*PendingEnrollment, error) {
	inv, err := getInvite(tx, p.TokenHash)
	if err != nil {
		return nil, err
	}
	if inv == nil || inv.ConsumedVaultID != "" {
		return nil, fmt.Errorf("invite not available")
	}
	if inv.ExpiresAt != "" && inv.ExpiresAt < p.CreatedAt {
		return nil, fmt.Errorf("invite expired")
	}
	existing, err := getPendingByTokenHashTx(tx, p.TokenHash)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if existing.ExpiresAt != "" && existing.ExpiresAt >= p.CreatedAt {
			return existing, nil
		}
		if _, err := tx.Exec(
			`UPDATE pending_enrollment SET challenge = ?, expires_at = ? WHERE token_hash = ? AND challenge = ?`,
			p.Challenge, p.ExpiresAt, p.TokenHash, existing.Challenge,
		); err != nil {
			return nil, err
		}
		existing.Challenge = append([]byte(nil), p.Challenge...)
		existing.ExpiresAt = p.ExpiresAt
		return existing, nil
	}
	if _, err := tx.Exec(`
INSERT INTO pending_enrollment (handle, vault_id, token_hash, challenge, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?)`,
		p.Handle, p.VaultID, p.TokenHash, p.Challenge, p.ExpiresAt, p.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("pending enrollment: %w", err)
	}
	return &PendingEnrollment{
		Handle:    p.Handle,
		VaultID:   p.VaultID,
		TokenHash: append([]byte(nil), p.TokenHash...),
		Challenge: append([]byte(nil), p.Challenge...),
		ExpiresAt: p.ExpiresAt,
		CreatedAt: p.CreatedAt,
	}, nil
}

// GetPendingByHandle loads one in-flight enrollment. Missing rows return (nil, nil).
func (l *Ledger) GetPendingByHandle(handle string) (*PendingEnrollment, error) {
	if handle == "" {
		return nil, fmt.Errorf("pending enrollment handle required")
	}
	if err := ensureMultiTenantSchema(l.db); err != nil {
		return nil, err
	}
	var p PendingEnrollment
	err := l.db.QueryRow(`
SELECT handle, vault_id, token_hash, challenge, expires_at, created_at
  FROM pending_enrollment WHERE handle = ?`, handle).Scan(
		&p.Handle, &p.VaultID, &p.TokenHash, &p.Challenge, &p.ExpiresAt, &p.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func getPendingByTokenHashTx(tx *sql.Tx, tokenHash []byte) (*PendingEnrollment, error) {
	var p PendingEnrollment
	err := tx.QueryRow(`
SELECT handle, vault_id, token_hash, challenge, expires_at, created_at
  FROM pending_enrollment WHERE token_hash = ?`, tokenHash).Scan(
		&p.Handle, &p.VaultID, &p.TokenHash, &p.Challenge, &p.ExpiresAt, &p.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}
