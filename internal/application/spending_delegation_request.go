package application

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const maxSpendingRenewalPlans = 50

type spendingDelegationInput struct {
	OperationID    string              `json:"operationId"`
	Intent         lightDelegateIntent `json:"intent"`
	ForfeitTxs     []string            `json:"forfeitTxs"`
	DeleteIntent   lightDelegateIntent `json:"deleteIntent"`
	ExpiresAt      int64               `json:"expiresAt"`
	OwnerSignature string              `json:"ownerSignature"`
}

type spendingDelegationAuthorization struct {
	WebAuthnAssertionRequest
	DirectSig string `json:"directSig"`
}

type spendingDelegationSetRequest struct {
	Program        string                           `json:"program"`
	DescriptorHash string                           `json:"descriptorHash"`
	VaultID        string                           `json:"vaultId"`
	SetID          string                           `json:"setId"`
	Plans          []spendingDelegationInput        `json:"plans"`
	OwnerSignature string                           `json:"ownerSignature"`
	Authorization  *spendingDelegationAuthorization `json:"authorization,omitempty"`
}

func spendingDelegationDigest(purpose string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("vaulted-vtxo/delegate-"+purpose+"/v1:"), raw...))
	return digest[:], nil
}

func (r spendingDelegationSetRequest) digest() ([]byte, error) {
	return spendingDelegationDigest("schedule-set", struct {
		Program        string                    `json:"program"`
		DescriptorHash string                    `json:"descriptorHash"`
		VaultID        string                    `json:"vaultId"`
		SetID          string                    `json:"setId"`
		Plans          []spendingDelegationInput `json:"plans"`
	}{r.Program, r.DescriptorHash, r.VaultID, r.SetID, r.Plans})
}

func (r spendingDelegationSetRequest) planDigest(p spendingDelegationInput) ([]byte, error) {
	return spendingDelegationDigest("schedule", struct {
		Program        string              `json:"program"`
		DescriptorHash string              `json:"descriptorHash"`
		VaultID        string              `json:"vaultId"`
		OperationID    string              `json:"operationId"`
		Intent         lightDelegateIntent `json:"intent"`
		ForfeitTxs     []string            `json:"forfeitTxs"`
		DeleteIntent   lightDelegateIntent `json:"deleteIntent"`
		ExpiresAt      int64               `json:"expiresAt"`
	}{r.Program, r.DescriptorHash, r.VaultID, p.OperationID, p.Intent, p.ForfeitTxs, p.DeleteIntent, p.ExpiresAt})
}

func verifyRenewalOwner(owner string, digest []byte, signature string) error {
	raw, err := hex.DecodeString(signature)
	if err != nil || len(raw) != 64 || hex.EncodeToString(raw) != signature {
		return fmt.Errorf("renewal owner signature encoding")
	}
	keyBytes, err := hex.DecodeString(owner)
	if err != nil {
		return err
	}
	pub, err := schnorr.ParsePubKey(keyBytes)
	if err != nil {
		return err
	}
	sig, err := schnorr.ParseSignature(raw)
	if err != nil || !sig.Verify(digest, pub) {
		return fmt.Errorf("renewal owner authorization required")
	}
	return nil
}

// This checks only the exact owner-authorized envelope. It grants no Guardian
// authority: enrollment, PSBTs, WebAuthn/direct authorization and atomic ledger
// acceptance are separate mandatory checks before scheduling.
func (r spendingDelegationSetRequest) verifyOwner(binding spendingRenewalBinding) ([]byte, error) {
	hash, err := binding.digest()
	if err != nil {
		return nil, err
	}
	if r.Program != binding.Program || r.VaultID != binding.VaultID || r.DescriptorHash != hash {
		return nil, fmt.Errorf("renewal set enrollment mismatch")
	}
	if _, err := canonicalVtxoOperationID(r.SetID); err != nil {
		return nil, err
	}
	if len(r.Plans) == 0 || len(r.Plans) > maxSpendingRenewalPlans {
		return nil, fmt.Errorf("renewal set size")
	}
	seen := map[string]bool{}
	for _, p := range r.Plans {
		if _, err := canonicalVtxoOperationID(p.OperationID); err != nil {
			return nil, err
		}
		if seen[p.OperationID] || len(p.ForfeitTxs) != 1 || p.ExpiresAt <= 0 || p.ExpiresAt > (1<<53)-1 {
			return nil, fmt.Errorf("renewal plan identity or bounds")
		}
		seen[p.OperationID] = true
		digest, err := r.planDigest(p)
		if err != nil {
			return nil, err
		}
		if err := verifyRenewalOwner(binding.OwnerPub, digest, p.OwnerSignature); err != nil {
			return nil, err
		}
	}
	digest, err := r.digest()
	if err != nil {
		return nil, err
	}
	if err := verifyRenewalOwner(binding.OwnerPub, digest, r.OwnerSignature); err != nil {
		return nil, err
	}
	return digest, nil
}
