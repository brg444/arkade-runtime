package policy

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

	"github.com/brg444/arkade-vault-server/internal/program"
)

// CreateVaultInput is one new tenant: sealed vault + credential + optional
// envelope, plus the invite token hash to consume atomically.
type CreateVaultInput struct {
	Record     VaultRecord
	Credential VaultCredential
	Envelope   *CredentialEnvelope
	TokenHash  []byte
	// Pending, when set, is consumed in the same transaction as the invite.
	// The row must still match handle, token hash, vault id, challenge, and expiry.
	Pending *PendingEnrollment
}

// CreateVault inserts vault, credential, and envelope and consumes the invite
// in one transaction. The UPDATE is a compare-and-swap on
// consumed_vault_id IS NULL; exactly one invite row must change.
func (l *Ledger) CreateVault(in CreateVaultInput) error {
	return l.createVault(in, nil)
}

// CreateVaultWithBoard atomically persists identity and boarding enrollment.
func (l *Ledger) CreateVaultWithBoard(in CreateVaultInput, board VaultBoardEnrollment) error {
	return l.createVault(in, &board)
}

func (l *Ledger) createVault(in CreateVaultInput, board *VaultBoardEnrollment) error {
	if err := validateCreateVaultInput(in); err != nil {
		return err
	}
	if board != nil && (board.VaultID != in.Record.VaultID || len(board.IntegrityMAC) != sha256.Size) {
		return fmt.Errorf("vault-board-v1 enrollment mismatch")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var consumed sql.NullString
	var expires string
	err = tx.QueryRow(`SELECT consumed_vault_id, expires_at FROM invite WHERE token_hash = ?`, in.TokenHash).Scan(&consumed, &expires)
	if err != nil {
		return fmt.Errorf("invite: %w", err)
	}
	if consumed.Valid {
		return fmt.Errorf("invite already consumed")
	}
	if expires != "" && expires < l.clock().UTC().Format(time.RFC3339) {
		return fmt.Errorf("invite expired")
	}
	if err := consumePendingEnrollmentTx(tx, in.Pending, l.clock().UTC()); err != nil {
		return err
	}

	if err := insertVaultTx(tx, in.Record, in.Credential, in.Envelope); err != nil {
		return fmt.Errorf("create vault: %w", err)
	}
	if board != nil {
		if err := PutVaultBoardEnrollmentTx(tx, *board); err != nil {
			return fmt.Errorf("create vault board: %w", err)
		}
	}
	res, err := tx.Exec(`
UPDATE invite SET consumed_vault_id = ?
 WHERE token_hash = ? AND consumed_vault_id IS NULL`,
		in.Record.VaultID, in.TokenHash,
	)
	if err != nil {
		return fmt.Errorf("consume invite: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("invite consume cas failed")
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return requireForeignKeyCheckClean(l.db)
}

// PutInvite stores an unused invitation. PR2 HTTP minting is still gated.
func (l *Ledger) PutInvite(tokenHash []byte, expiresAt, createdAt string) error {
	if len(tokenHash) != sha256.Size {
		return fmt.Errorf("invite token_hash must be 32 bytes")
	}
	if expiresAt == "" || createdAt == "" {
		return fmt.Errorf("invite timestamps required")
	}
	_, err := l.db.Exec(`INSERT INTO invite (token_hash, expires_at, created_at) VALUES (?, ?, ?)`,
		tokenHash, expiresAt, createdAt)
	return err
}

func validateCreateVaultInput(in CreateVaultInput) error {
	if in.Record.VaultID == "" {
		return fmt.Errorf("create vault requires a new opaque vault id")
	}
	if in.Record.CosignerMode != CosignerModeHKDFSHA256V1 {
		return fmt.Errorf("new vaults must use %s", CosignerModeHKDFSHA256V1)
	}
	if err := program.ValidateProtectionTierRecovery(in.Record.ProtectionTier, len(in.Record.RecoveryKey) > 0); err != nil {
		return fmt.Errorf("new vault protection tier: %w", err)
	}
	if in.Credential.VaultID != in.Record.VaultID {
		return fmt.Errorf("credential vault id mismatch")
	}
	if len(in.TokenHash) != sha256.Size {
		return fmt.Errorf("invite token_hash must be 32 bytes")
	}
	if len(in.Record.IntegrityMAC) != sha256.Size || len(in.Credential.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("vault and credential integrity MACs required")
	}
	if in.Pending != nil {
		if in.Pending.Handle == "" || in.Pending.VaultID != in.Record.VaultID {
			return fmt.Errorf("pending enrollment does not match vault")
		}
		if len(in.Pending.Challenge) == 0 || len(in.Pending.TokenHash) != sha256.Size || len(in.Pending.PolicyDigest) != sha256.Size {
			return fmt.Errorf("pending enrollment challenge required")
		}
		if in.Pending.ProtectionTier != in.Record.ProtectionTier {
			return fmt.Errorf("pending enrollment protection tier mismatch")
		}
		if !bytes.Equal(in.Pending.TokenHash, in.TokenHash) {
			return fmt.Errorf("pending enrollment token mismatch")
		}
	}
	return nil
}

func consumePendingEnrollmentTx(tx *sql.Tx, pending *PendingEnrollment, now time.Time) error {
	if pending == nil {
		return nil
	}
	if pending.ExpiresAt != "" && pending.ExpiresAt < now.Format(time.RFC3339) {
		return fmt.Errorf("pending enrollment expired")
	}
	res, err := tx.Exec(`
DELETE FROM pending_enrollment
 WHERE handle = ? AND token_hash = ? AND vault_id = ? AND challenge = ? AND protection_tier = ? AND policy_digest = ? AND expires_at = ?`,
		pending.Handle, pending.TokenHash, pending.VaultID, pending.Challenge, pending.ProtectionTier, pending.PolicyDigest, pending.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("consume pending enrollment: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("pending enrollment changed")
	}
	return nil
}

// ListVaultIDs returns every persisted tenant id in stable order.
func (l *Ledger) ListVaultIDs() ([]string, error) {
	rows, err := l.db.Query(`SELECT vault_id FROM vault ORDER BY vault_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
