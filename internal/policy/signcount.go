package policy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"time"
)

// AdvanceSignCount persists a monotonically increasing authenticator counter.
func (l *Ledger) AdvanceSignCount(vaultID string, credentialID []byte, incoming uint32) error {
	if l == nil {
		return fmt.Errorf("sign count ledger required")
	}
	if vaultID == "" || len(credentialID) == 0 {
		return fmt.Errorf("sign count identity required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.integrityKey) != sha256.Size {
		return fmt.Errorf("sign count ledger required")
	}
	return l.advanceSignCountLocked(l.db, vaultID, credentialID, incoming)
}

func (l *Ledger) advanceSignCountLocked(q queryContext, vaultID string, credentialID []byte, incoming uint32) error {
	var stored uint32
	var mac []byte
	err := q.QueryRowContext(context.Background(),
		`SELECT sign_count, integrity_mac FROM webauthn_sign_count WHERE vault_id=? AND credential_id=?`,
		vaultID, credentialID,
	).Scan(&stored, &mac)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil {
		if err := verifySignCountMAC(vaultID, credentialID, stored, mac, l.integrityKey); err != nil {
			return err
		}
		if incoming == 0 && stored > 0 {
			return fmt.Errorf("webauthn sign count went backwards")
		}
		if incoming > 0 && incoming < stored {
			return fmt.Errorf("webauthn sign count went backwards")
		}
		if incoming > 0 && incoming == stored {
			return fmt.Errorf("webauthn sign count went backwards")
		}
		if incoming == 0 && stored == 0 {
			return nil
		}
	}
	now := l.clock().UTC().Format(time.RFC3339Nano)
	sealed := signCountMAC(vaultID, credentialID, incoming, l.integrityKey)
	_, err = q.ExecContext(context.Background(),
		`INSERT INTO webauthn_sign_count (vault_id, credential_id, sign_count, updated_at, integrity_mac)
		 VALUES (?,?,?,?,?)
		 ON CONFLICT(vault_id, credential_id) DO UPDATE SET
		   sign_count=excluded.sign_count,
		   updated_at=excluded.updated_at,
		   integrity_mac=excluded.integrity_mac`,
		vaultID, credentialID, incoming, now, sealed,
	)
	return err
}

func (l *Ledger) verifySignCountReplayLocked(q queryContext, vaultID string, credentialID []byte, incoming uint32) error {
	var stored uint32
	var mac []byte
	if err := q.QueryRowContext(context.Background(),
		`SELECT sign_count, integrity_mac FROM webauthn_sign_count WHERE vault_id=? AND credential_id=?`,
		vaultID, credentialID,
	).Scan(&stored, &mac); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("webauthn sign count replay state missing")
		}
		return err
	}
	if err := verifySignCountMAC(vaultID, credentialID, stored, mac, l.integrityKey); err != nil {
		return err
	}
	if incoming != stored {
		return fmt.Errorf("webauthn sign count replay mismatch")
	}
	return nil
}

func signCountMAC(vaultID string, credentialID []byte, count uint32, key []byte) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], count)
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(signCountMACDomain))
	_, _ = h.Write([]byte(vaultID))
	_, _ = h.Write(credentialID)
	_, _ = h.Write(buf[:])
	return h.Sum(nil)
}

func verifySignCountMAC(vaultID string, credentialID []byte, count uint32, mac, key []byte) error {
	if !hmac.Equal(mac, signCountMAC(vaultID, credentialID, count, key)) {
		return fmt.Errorf("webauthn sign count MAC mismatch")
	}
	return nil
}
