package policy

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// IssueEnrollmentSession uses the existing one-time enrollment ledger so open
// admission preserves atomic completion and duplicate-finish reconciliation.
// Issuance limits are durable and shared by every request to this ledger.
func (l *Ledger) IssueEnrollmentSession(hash []byte, now time.Time) (time.Time, error) {
	if len(hash) != sha256.Size {
		return time.Time{}, fmt.Errorf("enrollment token hash must be 32 bytes")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()
	// Keep consumed tokens for lost-response reconciliation. Only expired,
	// unused admission records and their unusable challenges can be removed.
	cutoff := now.UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	if _, err := tx.Exec(`DELETE FROM pending_enrollment WHERE token_hash IN
		(SELECT token_hash FROM invite WHERE consumed_vault_id IS NULL AND expires_at < ?)`, cutoff); err != nil {
		return time.Time{}, err
	}
	if _, err := tx.Exec(`DELETE FROM invite WHERE consumed_vault_id IS NULL AND expires_at < ?`, cutoff); err != nil {
		return time.Time{}, err
	}
	var recent, active int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM invite WHERE created_at >= ?`, now.UTC().Add(-time.Minute).Format(time.RFC3339)).Scan(&recent); err != nil {
		return time.Time{}, err
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM invite WHERE consumed_vault_id IS NULL AND expires_at >= ?`, now.UTC().Format(time.RFC3339)).Scan(&active); err != nil {
		return time.Time{}, err
	}
	if recent >= 30 || active >= 1000 {
		return time.Time{}, fmt.Errorf("setup is busy; try again shortly")
	}
	expires := now.UTC().Add(10 * time.Minute)
	if _, err := tx.Exec(`INSERT INTO invite (token_hash, expires_at, created_at) VALUES (?, ?, ?)`, hash, expires.Format(time.RFC3339), now.UTC().Format(time.RFC3339)); err != nil {
		return time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, err
	}
	return expires, nil
}
