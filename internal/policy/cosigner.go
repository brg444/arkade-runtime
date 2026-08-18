package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	// CosignerModeLegacyDirectV0 is the first Mutinynet vault: the process
	// VaultCosigner master scalar is used on-chain as-is.
	CosignerModeLegacyDirectV0 = "legacy-direct-v0"
	// CosignerModeHKDFSHA256V1 is used for every vault created after the
	// multi-tenant migration. The on-chain VaultCosigner is derived below.
	CosignerModeHKDFSHA256V1 = "hkdf-sha256-v1"

	vaultCosignerHKDFSalt = "arkade-2fa-vault/vault-cosigner/hkdf-sha256-v1"
	vaultCosignerHKDFInfo = "vault-cosigner/v1"
	// LegacyFirstVaultID is the opaque instance id of the funded Mutinynet
	// singleton. It is not a UUID and must never be reinterpreted as 16 bytes.
	LegacyFirstVaultID = "operational-vault-v1"
)

// DeriveVaultCosignerScalar returns the secp256k1 scalar for vaultID.
//
//	legacy-direct-v0: copy of master (first vault only).
//	hkdf-sha256-v1: RFC 5869 HKDF-SHA256
//	  IKM  = 32-byte master scalar
//	  salt = vaultCosignerHKDFSalt (UTF-8)
//	  info = "vault-cosigner/v1" || 0x00 || vaultID (UTF-8 opaque) || 0x00 || counter
//	  L    = 32; one-block expand (info || 0x01)
//	  counter 0..255 until OKM is in 1..n-1.
func DeriveVaultCosignerScalar(master *btcec.PrivateKey, vaultID, mode string) (*btcec.PrivateKey, error) {
	if master == nil {
		return nil, fmt.Errorf("vault cosigner master required")
	}
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	switch mode {
	case CosignerModeLegacyDirectV0:
		if vaultID != LegacyFirstVaultID {
			return nil, fmt.Errorf("legacy-direct-v0 is only valid for %s", LegacyFirstVaultID)
		}
		priv, _ := btcec.PrivKeyFromBytes(master.Serialize())
		return priv, nil
	case CosignerModeHKDFSHA256V1:
		if vaultID == LegacyFirstVaultID {
			return nil, fmt.Errorf("%s must use %s", LegacyFirstVaultID, CosignerModeLegacyDirectV0)
		}
		return deriveHKDFVaultCosigner(master, vaultID)
	default:
		return nil, fmt.Errorf("unknown cosigner mode")
	}
}

func deriveHKDFVaultCosigner(master *btcec.PrivateKey, vaultID string) (*btcec.PrivateKey, error) {
	ikm := master.Serialize()
	defer zeroBytes(ikm)
	extract := hmac.New(sha256.New, []byte(vaultCosignerHKDFSalt))
	_, _ = extract.Write(ikm)
	prk := extract.Sum(nil)
	defer zeroBytes(prk)
	n := btcec.S256().N
	for counter := 0; counter <= 255; counter++ {
		info := make([]byte, 0, len(vaultCosignerHKDFInfo)+3+len(vaultID))
		info = append(info, vaultCosignerHKDFInfo...)
		info = append(info, 0)
		info = append(info, vaultID...)
		info = append(info, 0, byte(counter))
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{1})
		okm := expand.Sum(nil)
		if scalarInRange(okm, n) {
			priv, _ := btcec.PrivKeyFromBytes(okm)
			zeroBytes(okm)
			if priv == nil {
				continue
			}
			return priv, nil
		}
		zeroBytes(okm)
	}
	return nil, fmt.Errorf("hkdf-sha256-v1 produced no valid secp256k1 scalar")
}

// VerifyVaultCosignerPub checks the persisted compressed VaultCosigner
// against the scalar derived from master, vault id, and cosigner_mode.
func VerifyVaultCosignerPub(master *btcec.PrivateKey, rec VaultRecord) error {
	derived, err := DeriveVaultCosignerScalar(master, rec.VaultID, rec.CosignerMode)
	if err != nil {
		return err
	}
	got := derived.PubKey().SerializeCompressed()
	if !hmac.Equal(got, rec.VaultCosignerBase) {
		return fmt.Errorf("stored vault cosigner pubkey does not match %s derivation", rec.CosignerMode)
	}
	return nil
}

func scalarInRange(raw []byte, n *big.Int) bool {
	if len(raw) != 32 {
		return false
	}
	x := new(big.Int).SetBytes(raw)
	if x.Sign() <= 0 || x.Cmp(n) >= 0 {
		return false
	}
	return true
}
