package v5

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// RecoveryPoPDigest is tagged_hash(PopTag, vaultId ‖ handle ‖ x-only ‖ hash ‖ template).
func RecoveryPoPDigest(vaultID, handle, recoveryXOnly, descriptorHash string) ([]byte, error) {
	vaultID = strings.TrimSpace(strings.ToLower(vaultID))
	handle = strings.TrimSpace(handle)
	if handle == "" {
		handle = "-"
	}
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	recovery, err := decodeExact(recoveryXOnly, 32)
	if err != nil {
		return nil, fmt.Errorf("recoveryXOnly: %w", err)
	}
	hash, err := decodeExact(descriptorHash, 32)
	if err != nil {
		return nil, fmt.Errorf("descriptorHash: %w", err)
	}
	var parts [][]byte
	appendBytes(&parts, []byte(vaultID))
	appendBytes(&parts, []byte(handle))
	appendBytes(&parts, recovery)
	appendBytes(&parts, hash)
	appendBytes(&parts, []byte(Template))
	return taggedSHA256(PopTag, concatParts(parts)), nil
}

// VerifyRecoveryPoP checks a BIP340 recovery signature over the enrollment digest.
func VerifyRecoveryPoP(pub *btcec.PublicKey, vaultID, handle, descriptorHash, sigHex string) error {
	if pub == nil {
		return fmt.Errorf("recovery key required")
	}
	digest, err := RecoveryPoPDigest(vaultID, handle, RecoveryXOnly(pub), descriptorHash)
	if err != nil {
		return err
	}
	raw, err := hex.DecodeString(sigHex)
	if err != nil || len(raw) != 64 {
		return fmt.Errorf("recoveryPoP must be a 64-byte BIP340 signature")
	}
	sig, err := schnorr.ParseSignature(raw)
	if err != nil || !sig.Verify(digest, pub) {
		return fmt.Errorf("recoveryPoP invalid")
	}
	return nil
}

// SignRecoveryPoP is used by tests and local tooling.
func SignRecoveryPoP(priv *btcec.PrivateKey, vaultID, handle, descriptorHash string) (string, error) {
	if priv == nil {
		return "", fmt.Errorf("recovery key required")
	}
	digest, err := RecoveryPoPDigest(vaultID, handle, RecoveryXOnly(priv.PubKey()), descriptorHash)
	if err != nil {
		return "", err
	}
	sig, err := schnorr.Sign(priv, digest)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig.Serialize()), nil
}

func decodeExact(value string, n int) ([]byte, error) {
	if value != strings.ToLower(value) {
		return nil, fmt.Errorf("must be lowercase hex")
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != n {
		return nil, fmt.Errorf("want %d bytes", n)
	}
	return raw, nil
}
