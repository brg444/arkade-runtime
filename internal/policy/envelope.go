package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	CredentialEnvelopeVersion = 2
	credentialEnvelopeDomain  = "arkade-vault/credential-envelope/v2"
	vaultEnvelopeDomain       = "arkade-vault/vault-envelope/v2"
	vaultEnvelopeMACSalt      = "arkade-vault/vault-envelope-mac/v2"
	credentialEnvelopeNonce   = 12
	credentialEnvelopeCipher  = 48
	credentialEnvelopeBinding = 16 * 1024
	credentialEnvelopeSig     = 64
)

// CredentialEnvelope is the browser's PRF-encrypted 32-byte
// PhoneBIP340 scalar. The authorizer never receives the PRF output or
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

// SealVaultEnvelope authenticates a Vault recovery envelope.
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
