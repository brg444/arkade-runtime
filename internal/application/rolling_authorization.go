package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

type rollingAuthorizationRequest struct {
	VaultID     string `json:"vaultId"`
	OperationID string `json:"operationId"`
	WebAuthnAssertionRequest
	DirectSig string `json:"directSig"`
}

// authorizeRollingOperation is the application boundary used by the new
// contract's explicit workflow. Profile enrollment and release admission must
// construct the manager; no generic HTTP signing route is exposed here.
func (s *Service) authorizeRollingOperation(ctx context.Context, manager *RollingOperations, req rollingAuthorizationRequest) (RollingAuthorization, error) {
	if manager == nil || req.VaultID != manager.vault || isNilInterface(s.keys.rollingOperation) {
		return RollingAuthorization{}, fmt.Errorf("rolling authorization scope required")
	}
	record, err := manager.operation(ctx, req.OperationID)
	if err != nil {
		return RollingAuthorization{}, err
	}
	credential, err := s.loadVerifiedCredentialFor(req.VaultID)
	if err != nil {
		return RollingAuthorization{}, err
	}
	if credential == nil {
		return RollingAuthorization{}, fmt.Errorf("rolling vault is not enrolled")
	}
	c := manager.contract
	pins, err := program.PinsFor(credential.Network)
	if err != nil || c.ExitDelaySeconds != pins.PolicyExitDelay {
		return RollingAuthorization{}, fmt.Errorf("rolling recovery delay differs from release")
	}

	if !sameXOnlyPub(credential.PhoneBIP340, c.Keys.User.SerializeCompressed()) || credential.ProtectionTier != c.Tier || credential.Network != record.Enrollment.Network {
		return RollingAuthorization{}, fmt.Errorf("rolling owner or protection tier differs from enrollment")
	}
	if c.Tier != "light" && !sameXOnlyPub(credential.ExternalOwnerWallet, c.Keys.Hardware.SerializeCompressed()) {
		return RollingAuthorization{}, fmt.Errorf("rolling hardware recovery differs from enrollment")
	}
	if c.Tier == "advanced" && !sameXOnlyPub(credential.RecoveryKey, c.Keys.Recovery.SerializeCompressed()) {
		return RollingAuthorization{}, fmt.Errorf("rolling recovery key differs from enrollment")
	}
	if c.Parameters.Budget > credential.PeriodAllowanceSats || c.Parameters.RecipientCap > credential.TxRecipientCapSats || c.Parameters.FeeCap > credential.AbsoluteFeeCapSats || c.Parameters.FeerateCap > credential.FeerateCapSatPerV {
		return RollingAuthorization{}, fmt.Errorf("rolling policy exceeds enrolled limits")
	}
	digest, err := rolling.AuthorizationDigest(c, req.VaultID, req.OperationID)
	if err != nil {
		return RollingAuthorization{}, err
	}
	credentialID, count, err := s.verifyVtxoAuthorization(ctx, req.VaultID, digest[:], req.WebAuthnAssertionRequest, req.DirectSig)
	if err != nil {
		return RollingAuthorization{}, err
	}
	timeout := s.SignTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	signCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	authorized, err := s.keys.rollingOperation.authorizeRollingOperation(signCtx, req.VaultID, req.OperationID)
	if err != nil {
		return RollingAuthorization{}, err
	}
	created, err := time.Parse(time.RFC3339, record.Operation.CreatedAt)
	if err != nil {
		return RollingAuthorization{}, err
	}
	built, err := record.Operation.Proposal.Rebuild(c, created.Unix())
	if err != nil {
		return RollingAuthorization{}, err
	}
	if authorized.OperationID != req.OperationID || authorized.Message != record.Operation.Proposal.Message || len(authorized.CheckpointPSBTs) != len(built.Checkpoints) {
		return RollingAuthorization{}, fmt.Errorf("rolling key response identity")
	}
	expected := schnorr.SerializePubKey(c.Keys.Guardian)
	originals := []string{}
	original, err := built.Transaction.B64Encode()
	if err != nil {
		return RollingAuthorization{}, err
	}
	originals = append(originals, original)
	for _, cp := range built.Checkpoints {
		raw, e := cp.B64Encode()
		if e != nil {
			return RollingAuthorization{}, e
		}
		originals = append(originals, raw)
	}
	signed := append([]string{authorized.TransactionPSBT}, authorized.CheckpointPSBTs...)
	for i, raw := range signed {
		if err = requireOnlyVaultSignatureAdded(originals[i], raw, expected); err != nil {
			return RollingAuthorization{}, err
		}
		packet, e := parsePSBT(raw)
		if e != nil {
			return RollingAuthorization{}, e
		}
		for index, input := range packet.Inputs {
			if len(input.TaprootScriptSpendSig) != 1 || len(input.TaprootLeafScript) != 1 {
				return RollingAuthorization{}, fmt.Errorf("rolling signature shape")
			}
			sig := input.TaprootScriptSpendSig[0]
			leaf := input.TaprootLeafScript[0].Script
			hash := txscript.NewBaseTapLeaf(leaf).TapHash()
			if sig.SigHash != input.SighashType || !bytes.Equal(sig.LeafHash, hash[:]) {
				return RollingAuthorization{}, fmt.Errorf("rolling signature context")
			}
			if e = verifySchnorrOnInputWithSighash(packet, index, sig.Signature, expected, leaf, input.SighashType); e != nil {
				return RollingAuthorization{}, e
			}
		}
	}
	evidence, err := json.Marshal(authorized)
	if err != nil {
		return RollingAuthorization{}, err
	}
	retained, err := manager.store.CommitRollingAuthorization(ctx, policy.RollingEvent{OperationID: req.OperationID, Phase: "authorized", Evidence: string(evidence)}, credentialID, count)
	if err != nil {
		return RollingAuthorization{}, err
	}
	var result RollingAuthorization
	if err = json.Unmarshal([]byte(retained.Evidence), &result); err != nil {
		return RollingAuthorization{}, err
	}
	return result, nil
}
