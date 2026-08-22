package policy

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"
)

// Invite is one unused or consumed enrollment token hash.
type Invite struct {
	TokenHash       []byte
	ExpiresAt       string
	ConsumedVaultID string // empty when unused; never returned on GET /v1/invite
	CreatedAt       string
}

// GetInvite loads an invite by token hash. Missing rows return (nil, nil).
func (l *Ledger) GetInvite(tokenHash []byte) (*Invite, error) {
	if len(tokenHash) != sha256.Size {
		return nil, fmt.Errorf("invite token_hash must be 32 bytes")
	}
	return getInvite(l.db, tokenHash)
}

func getInvite(q queryRower, tokenHash []byte) (*Invite, error) {
	var inv Invite
	var consumed sql.NullString
	err := q.QueryRow(
		`SELECT token_hash, expires_at, consumed_vault_id, created_at FROM invite WHERE token_hash = ?`,
		tokenHash,
	).Scan(&inv.TokenHash, &inv.ExpiresAt, &consumed, &inv.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if consumed.Valid {
		inv.ConsumedVaultID = consumed.String
	}
	return &inv, nil
}

// Usable reports whether the invite is unconsumed and unexpired at now.
func (inv *Invite) Usable(now time.Time) bool {
	if inv == nil || inv.ConsumedVaultID != "" {
		return false
	}
	if inv.ExpiresAt == "" {
		return false
	}
	return inv.ExpiresAt >= now.UTC().Format(time.RFC3339)
}
