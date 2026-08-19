package policy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
)

const (
	CredentialEnvelopeVersion = 1
	credentialEnvelopeDomain  = "arkade-2fa-vault/credential-envelope/v1"
	vaultEnvelopeDomain       = "arkade-2fa-vault/vault-envelope/v4"
	vaultEnvelopeMACSalt      = "arkade-2fa-vault/vault-envelope-mac/v4"
	credentialEnvelopeNonce   = 12
	credentialEnvelopeCipher  = 48
	credentialEnvelopeBinding = 16 * 1024
	credentialEnvelopeSig     = 64
)

// CredentialEnvelope is the browser's PRF-encrypted 32-byte
// PhoneRoutineBIP340 scalar. The authorizer never receives the PRF output or
// plaintext scalar. Its MAC prevents a database-only writer from replacing
// the recovery material served to another device.
type CredentialEnvelope struct {
	Version      uint32
	Binding      string
	Nonce        []byte
	Ciphertext   []byte
	DirectSig    []byte
	PhoneSig     []byte
	IntegrityMAC []byte
}

// SealCredentialEnvelope binds the encrypted envelope to the immutable
// credential ID. The same authorizer-only integrity key used for the v3
// descriptor is domain separated here.
func SealCredentialEnvelope(envelope *CredentialEnvelope, credentialID, key []byte) error {
	if envelope == nil {
		return fmt.Errorf("credential envelope required")
	}
	mac, err := credentialEnvelopeMAC(*envelope, credentialID, key)
	if err != nil {
		return err
	}
	envelope.IntegrityMAC = mac
	return nil
}

// VerifyCredentialEnvelope rejects malformed or modified recovery material.
func VerifyCredentialEnvelope(envelope *CredentialEnvelope, credentialID, key []byte) error {
	if envelope == nil || len(envelope.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("credential envelope integrity MAC missing or malformed")
	}
	want, err := credentialEnvelopeMAC(*envelope, credentialID, key)
	if err != nil {
		return err
	}
	defer zeroBytes(want)
	if !hmac.Equal(envelope.IntegrityMAC, want) {
		return fmt.Errorf("credential envelope integrity MAC mismatch")
	}
	return nil
}

func credentialEnvelopeMAC(envelope CredentialEnvelope, credentialID, key []byte) ([]byte, error) {
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("credential integrity key must be 32 bytes")
	}
	if err := validateCredentialEnvelope(envelope); err != nil {
		return nil, err
	}
	payload := make([]byte, 0, 4+len(credentialEnvelopeDomain)+4+len(credentialID)+4+len(envelope.Binding)+4+len(envelope.Nonce)+4+len(envelope.Ciphertext)+4+len(envelope.DirectSig)+4+len(envelope.PhoneSig))
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(credentialEnvelopeDomain)))
	payload = append(payload, credentialEnvelopeDomain...)
	payload = binary.LittleEndian.AppendUint32(payload, envelope.Version)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(credentialID)))
	payload = append(payload, credentialID...)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(envelope.Binding)))
	payload = append(payload, envelope.Binding...)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(envelope.Nonce)))
	payload = append(payload, envelope.Nonce...)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(envelope.Ciphertext)))
	payload = append(payload, envelope.Ciphertext...)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(envelope.DirectSig)))
	payload = append(payload, envelope.DirectSig...)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(envelope.PhoneSig)))
	payload = append(payload, envelope.PhoneSig...)
	defer zeroBytes(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

// DeriveVaultEnvelopeMACKey is per-vault. A's envelope key cannot verify B.
func DeriveVaultEnvelopeMACKey(integrityKey []byte, vaultID string) ([]byte, error) {
	if len(integrityKey) != sha256.Size {
		return nil, fmt.Errorf("credential integrity key must be 32 bytes")
	}
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	mac := hmac.New(sha256.New, []byte(vaultEnvelopeMACSalt))
	_, _ = mac.Write(integrityKey)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(vaultID))
	return mac.Sum(nil), nil
}

// SealVaultEnvelope authenticates a tenant recovery envelope. The first
// vault keeps SealCredentialEnvelope (v3 domain, no vault id).
func SealVaultEnvelope(envelope *CredentialEnvelope, vaultID string, credentialID, integrityKey []byte) error {
	if envelope == nil {
		return fmt.Errorf("credential envelope required")
	}
	mac, err := vaultEnvelopeMAC(*envelope, vaultID, credentialID, integrityKey)
	if err != nil {
		return err
	}
	envelope.IntegrityMAC = mac
	return nil
}

// VerifyVaultEnvelope rejects a tenant envelope sealed under another vault.
func VerifyVaultEnvelope(envelope *CredentialEnvelope, vaultID string, credentialID, integrityKey []byte) error {
	if envelope == nil || len(envelope.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("credential envelope integrity MAC missing or malformed")
	}
	want, err := vaultEnvelopeMAC(*envelope, vaultID, credentialID, integrityKey)
	if err != nil {
		return err
	}
	defer zeroBytes(want)
	if !hmac.Equal(envelope.IntegrityMAC, want) {
		return fmt.Errorf("credential envelope integrity MAC mismatch")
	}
	return nil
}

func vaultEnvelopeMAC(envelope CredentialEnvelope, vaultID string, credentialID, integrityKey []byte) ([]byte, error) {
	key, err := DeriveVaultEnvelopeMACKey(integrityKey, vaultID)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	if err := validateCredentialEnvelope(envelope); err != nil {
		return nil, err
	}
	payload := make([]byte, 0, 8+len(vaultEnvelopeDomain)+len(vaultID)+len(credentialID)+len(envelope.Binding)+len(envelope.Nonce)+len(envelope.Ciphertext)+len(envelope.DirectSig)+len(envelope.PhoneSig))
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(vaultEnvelopeDomain)))
	payload = append(payload, vaultEnvelopeDomain...)
	payload = binary.LittleEndian.AppendUint32(payload, envelope.Version)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(vaultID)))
	payload = append(payload, vaultID...)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(credentialID)))
	payload = append(payload, credentialID...)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(envelope.Binding)))
	payload = append(payload, envelope.Binding...)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(envelope.Nonce)))
	payload = append(payload, envelope.Nonce...)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(envelope.Ciphertext)))
	payload = append(payload, envelope.Ciphertext...)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(envelope.DirectSig)))
	payload = append(payload, envelope.DirectSig...)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(len(envelope.PhoneSig)))
	payload = append(payload, envelope.PhoneSig...)
	defer zeroBytes(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

func validateCredentialEnvelope(envelope CredentialEnvelope) error {
	if envelope.Version != CredentialEnvelopeVersion {
		return fmt.Errorf("credential envelope version must be %d", CredentialEnvelopeVersion)
	}
	if len(envelope.Binding) == 0 || len(envelope.Binding) > credentialEnvelopeBinding {
		return fmt.Errorf("credential envelope binding must be 1..%d bytes", credentialEnvelopeBinding)
	}
	if len(envelope.Nonce) != credentialEnvelopeNonce {
		return fmt.Errorf("credential envelope nonce must be %d bytes", credentialEnvelopeNonce)
	}
	if len(envelope.Ciphertext) != credentialEnvelopeCipher {
		return fmt.Errorf("credential envelope ciphertext must be %d bytes", credentialEnvelopeCipher)
	}
	if len(envelope.DirectSig) != credentialEnvelopeSig {
		return fmt.Errorf("credential envelope direct signature must be %d bytes", credentialEnvelopeSig)
	}
	if len(envelope.PhoneSig) != credentialEnvelopeSig {
		return fmt.Errorf("credential envelope phone signature must be %d bytes", credentialEnvelopeSig)
	}
	if len(envelope.IntegrityMAC) != 0 && len(envelope.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("credential envelope integrity MAC must be 32 bytes")
	}
	return nil
}

// GetCredentialEnvelope returns the singleton encrypted envelope, if one has
// been enrolled. Callers must verify its MAC before exposing it.
func (l *Ledger) GetCredentialEnvelope() (*CredentialEnvelope, error) {
	var envelope CredentialEnvelope
	err := l.db.QueryRow(`
SELECT version, binding, nonce, ciphertext, direct_signature, phone_signature, integrity_mac
  FROM credential_envelope WHERE id = 1`).Scan(
		&envelope.Version, &envelope.Binding, &envelope.Nonce, &envelope.Ciphertext,
		&envelope.DirectSig, &envelope.PhoneSig, &envelope.IntegrityMAC,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := validateCredentialEnvelope(envelope); err != nil {
		return nil, err
	}
	return &envelope, nil
}

// StoreCredentialEnvelopeIfAbsent performs the authenticated migration used
// by an already-enrolled browser. Exact retries are idempotent; a different
// envelope can never replace the first one.
func (l *Ledger) StoreCredentialEnvelopeIfAbsent(envelope CredentialEnvelope) error {
	if err := validateCredentialEnvelope(envelope); err != nil {
		return err
	}
	if len(envelope.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("credential envelope integrity MAC must be 32 bytes")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cred, err := loadCredential(l.db)
	if err != nil {
		return err
	}
	if cred == nil {
		return fmt.Errorf("not enrolled")
	}
	if err := VerifyCredentialEnvelope(&envelope, cred.ID, l.integrityKey); err != nil {
		return err
	}
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existing CredentialEnvelope
	err = tx.QueryRow(`SELECT version, binding, nonce, ciphertext, direct_signature, phone_signature, integrity_mac FROM credential_envelope WHERE id = 1`).Scan(
		&existing.Version, &existing.Binding, &existing.Nonce, &existing.Ciphertext,
		&existing.DirectSig, &existing.PhoneSig, &existing.IntegrityMAC,
	)
	if err == nil {
		if existing.Version == envelope.Version && existing.Binding == envelope.Binding && bytes.Equal(existing.Nonce, envelope.Nonce) &&
			bytes.Equal(existing.Ciphertext, envelope.Ciphertext) && bytes.Equal(existing.DirectSig, envelope.DirectSig) &&
			bytes.Equal(existing.PhoneSig, envelope.PhoneSig) && bytes.Equal(existing.IntegrityMAC, envelope.IntegrityMAC) {
			if err := syncLegacyVaultEnvelopeTx(tx, envelope); err != nil {
				return err
			}
			return tx.Commit()
		}
		return fmt.Errorf("credential envelope locked")
	}
	if err != sql.ErrNoRows {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO credential_envelope (id, version, binding, nonce, ciphertext, direct_signature, phone_signature, integrity_mac) VALUES (1, ?, ?, ?, ?, ?, ?, ?)`,
		envelope.Version, envelope.Binding, envelope.Nonce, envelope.Ciphertext, envelope.DirectSig, envelope.PhoneSig, envelope.IntegrityMAC,
	); err != nil {
		return fmt.Errorf("credential envelope locked or failed: %w", err)
	}
	if err := syncLegacyVaultEnvelopeTx(tx, envelope); err != nil {
		return err
	}
	return tx.Commit()
}

func syncLegacyVaultEnvelopeTx(tx *sql.Tx, envelope CredentialEnvelope) error {
	if !v4TableExists(tx) {
		return nil
	}
	vault, err := getVaultTx(tx, LegacyFirstVaultID)
	if err != nil || vault == nil {
		return err
	}
	existing, err := getVaultEnvelopeTx(tx, LegacyFirstVaultID)
	if err != nil {
		return err
	}
	if existing != nil {
		if envelopesEqual(*existing, envelope) {
			return nil
		}
		return fmt.Errorf("vault envelope locked")
	}
	if err := insertVaultEnvelopeTx(tx, LegacyFirstVaultID, envelope); err != nil {
		return fmt.Errorf("legacy vault envelope dual-write: %w", err)
	}
	return nil
}
