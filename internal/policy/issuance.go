package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	issuanceIntegrityDomain = "arkade-2fa-vault/issuance-record/v3"
	issuanceMACSalt         = "arkade-2fa-vault/issuance-mac/v3"
	issuanceCanonicalVer    = 3
	issuanceWindow          = 24 * time.Hour
)

// Issuance MAC limitation: the MAC authenticates each stored row. It does not
// detect deletion of a row or restoring an older SQLite file. A monotonic
// value outside this database would be required to notice those events.

// IssuanceRecord is one per-vault allowance row. The MAC covers every
// persisted field, including created_at and period_start, so a SQLite-only
// edit cannot refill a tenant.
type IssuanceRecord struct {
	VaultID      string
	Digest       []byte
	PeriodStart  string
	Recipient    int64
	Fee          int64
	State        string
	RequestPSBT  string
	VaultPSBT    string
	SignedPSBT   string
	CreatedAt    string
	UpdatedAt    string
	IntegrityMAC []byte
}

// DeriveIssuanceMACKey is domain-separated per vault. A's key cannot verify B.
func DeriveIssuanceMACKey(integrityKey []byte, vaultID string) ([]byte, error) {
	if len(integrityKey) != sha256.Size {
		return nil, fmt.Errorf("issuance integrity key must be 32 bytes")
	}
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	mac := hmac.New(sha256.New, []byte(issuanceMACSalt))
	_, _ = mac.Write(integrityKey)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(vaultID))
	return mac.Sum(nil), nil
}

// SealIssuance authenticates one issuance row under the per-vault MAC key.
func SealIssuance(rec *IssuanceRecord, integrityKey []byte) error {
	if rec == nil {
		return fmt.Errorf("issuance record required")
	}
	mac, err := issuanceMAC(*rec, integrityKey)
	if err != nil {
		return err
	}
	rec.IntegrityMAC = mac
	return nil
}

// VerifyIssuance rejects a missing, malformed, or modified issuance row.
func VerifyIssuance(rec *IssuanceRecord, integrityKey []byte) error {
	if rec == nil || len(rec.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("issuance integrity MAC missing or malformed")
	}
	want, err := issuanceMAC(*rec, integrityKey)
	if err != nil {
		return err
	}
	defer zeroBytes(want)
	if !hmac.Equal(rec.IntegrityMAC, want) {
		return fmt.Errorf("issuance integrity MAC mismatch")
	}
	return nil
}

func issuanceMAC(rec IssuanceRecord, integrityKey []byte) ([]byte, error) {
	key, err := DeriveIssuanceMACKey(integrityKey, rec.VaultID)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	payload, err := canonicalIssuance(rec)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

func canonicalIssuance(rec IssuanceRecord) ([]byte, error) {
	if rec.VaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	if len(rec.Digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes")
	}
	if rec.Recipient < 0 || rec.Fee < 0 {
		return nil, fmt.Errorf("negative issuance amount")
	}
	out := make([]byte, 0, 512)
	var err error
	out, err = appendCredentialField(out, []byte(issuanceIntegrityDomain))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, issuanceCanonicalVer)
	for _, field := range [][]byte{
		[]byte(rec.VaultID), rec.Digest, []byte(rec.PeriodStart),
		[]byte(rec.State), []byte(rec.RequestPSBT), []byte(rec.VaultPSBT),
		[]byte(rec.SignedPSBT), []byte(rec.CreatedAt), []byte(rec.UpdatedAt),
	} {
		out, err = appendCredentialField(out, field)
		if err != nil {
			zeroBytes(out)
			return nil, err
		}
	}
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.Recipient))
	out = binary.LittleEndian.AppendUint64(out, uint64(rec.Fee))
	return out, nil
}

func issuanceCreatedInWindow(createdAt string, now time.Time) (bool, error) {
	ts, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return false, fmt.Errorf("issuance created_at: %w", err)
	}
	return !now.After(ts.Add(issuanceWindow)), nil
}
