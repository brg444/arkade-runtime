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

	// CosignerModeVtxoHKDFSHA256V1 is the VTXO VaultCosigner domain. It is
	// not a rotation of hkdf-sha256-v1.
	CosignerModeVtxoHKDFSHA256V1 = "vtxo-hkdf-sha256-v1"
	vtxoVaultCosignerHKDFSalt    = "arkade-2fa-vault/vtxo-vault-cosigner/hkdf-sha256-v1"
	vtxoVaultCosignerHKDFInfo    = "vtxo-vault-cosigner/v1"

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

// DeriveVtxoVaultCosignerScalar returns the even-Y secp256k1 scalar for a
// VTXO VaultCosigner. The preimage does not include a collaborative leaf or
// ArkScriptHash; those would circularly depend on this key.
//
//	vtxo-hkdf-sha256-v1: RFC 5869 HKDF-SHA256
//	  IKM  = 32-byte master scalar
//	  salt = vtxoVaultCosignerHKDFSalt (UTF-8)
//	  info = "vtxo-vault-cosigner/v1" || 0x00 || vaultID (UTF-8 opaque)
//	         || 0x00 || policyVersion || 0x00 || network
//	         || 0x00 || advertisedServerPub33 || 0x00 || counter
//	  L    = 32; one-block expand (info || 0x01)
//	  counter 0..255 until OKM is in 1..n-1.
//	  even-Y: negate the scalar when the derived pubkey is odd-Y.
func DeriveVtxoVaultCosignerScalar(master *btcec.PrivateKey, vaultID, policyVersion, network string, advertisedServerPub []byte) (*btcec.PrivateKey, error) {
	if master == nil {
		return nil, fmt.Errorf("vault cosigner master required")
	}
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	if policyVersion == "" {
		return nil, fmt.Errorf("policy version required")
	}
	if network != "mutinynet" && network != "regtest" {
		return nil, fmt.Errorf("unsupported network")
	}
	if len(advertisedServerPub) != 33 || (advertisedServerPub[0] != 0x02 && advertisedServerPub[0] != 0x03) {
		return nil, fmt.Errorf("advertised server pub must be 33-byte compressed secp256k1")
	}
	if _, err := btcec.ParsePubKey(advertisedServerPub); err != nil {
		return nil, fmt.Errorf("advertised server pub must be 33-byte compressed secp256k1")
	}
	return deriveVtxoHKDFVaultCosigner(master, vaultID, policyVersion, network, advertisedServerPub)
}

func deriveVtxoHKDFVaultCosigner(master *btcec.PrivateKey, vaultID, policyVersion, network string, advertisedServerPub []byte) (*btcec.PrivateKey, error) {
	ikm := master.Serialize()
	defer zeroBytes(ikm)
	extract := hmac.New(sha256.New, []byte(vtxoVaultCosignerHKDFSalt))
	_, _ = extract.Write(ikm)
	prk := extract.Sum(nil)
	defer zeroBytes(prk)
	n := btcec.S256().N
	for counter := 0; counter <= 255; counter++ {
		info := vtxoVaultCosignerInfo(vaultID, policyVersion, network, advertisedServerPub, byte(counter))
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
			return evenYPrivateKey(priv), nil
		}
		zeroBytes(okm)
	}
	return nil, fmt.Errorf("vtxo-hkdf-sha256-v1 produced no valid secp256k1 scalar")
}

func vtxoVaultCosignerInfo(vaultID, policyVersion, network string, advertisedServerPub []byte, counter byte) []byte {
	info := make([]byte, 0, len(vtxoVaultCosignerHKDFInfo)+len(vaultID)+len(policyVersion)+len(network)+len(advertisedServerPub)+6)
	info = append(info, vtxoVaultCosignerHKDFInfo...)
	info = append(info, 0)
	info = append(info, vaultID...)
	info = append(info, 0)
	info = append(info, policyVersion...)
	info = append(info, 0)
	info = append(info, network...)
	info = append(info, 0)
	info = append(info, advertisedServerPub...)
	info = append(info, 0, counter)
	return info
}

func evenYPrivateKey(priv *btcec.PrivateKey) *btcec.PrivateKey {
	if priv.PubKey().SerializeCompressed()[0] != 0x03 {
		return priv
	}
	key := priv.Key
	key.Negate()
	return &btcec.PrivateKey{Key: key}
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
