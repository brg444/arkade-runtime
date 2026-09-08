package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

type rollingCleanupAuthorization struct {
	OperationID string `json:"operationId"`
	Proof       string `json:"proof"`
	Message     string `json:"message"`
	ExpiresAt   int64  `json:"expiresAt"`
}

func (k *fileBackedVaultKeys) rollingKeyOperation(ctx context.Context, vault, id string) (policy.RollingSnapshot, *rolling.Contract, rollingJournal, error) {
	store, _, err := k.rollingDependencies()
	if err != nil {
		return policy.RollingSnapshot{}, nil, nil, err
	}
	records, err := store.RollingOperations(ctx, vault)
	if err != nil {
		return policy.RollingSnapshot{}, nil, nil, err
	}
	for _, record := range records {
		if record.Operation.OperationID != id {
			continue
		}
		if record.Operation.VaultID != vault || record.Enrollment.VaultID != vault {
			break
		}
		if _, aborted := record.Events["aborted"]; aborted {
			break
		}
		c, err := rolling.DecodeDescriptor([]byte(record.Enrollment.Descriptor))
		if err != nil {
			return policy.RollingSnapshot{}, nil, nil, err
		}
		return record, c, store, nil
	}
	return policy.RollingSnapshot{}, nil, nil, fmt.Errorf("rolling key operation scope missing")
}

// authorizeRollingCleanup accepts neither a source set nor a PSBT. An exact
// abandoned registration and its immutable deadline must already be retained
// behind the ledger's mutually exclusive cleanup/final-authority fence.
func (k *fileBackedVaultKeys) authorizeRollingCleanup(ctx context.Context, vault, id string) (rollingCleanupAuthorization, error) {
	record, c, store, err := k.rollingKeyOperation(ctx, vault, id)
	if err != nil {
		return rollingCleanupAuthorization{}, err
	}
	pending, ok := record.Events["cleanup_pending"]
	if !ok || record.Operation.Proposal.Kind != rolling.RenewalOperation {
		return rollingCleanupAuthorization{}, fmt.Errorf("retained rolling cleanup fence required")
	}
	if _, final := record.Events["final_authorized"]; final {
		return rollingCleanupAuthorization{}, fmt.Errorf("rolling final authority excludes cleanup")
	}
	var deadline policy.RollingCleanupDeadline
	created, err := time.Parse(time.RFC3339, pending.CreatedAt)
	if err != nil || json.Unmarshal([]byte(pending.Evidence), &deadline) != nil || deadline.ExpiresAt != created.Unix()+rolling.CleanupLifetimeSeconds-1 {
		return rollingCleanupAuthorization{}, fmt.Errorf("rolling cleanup deadline binding")
	}
	now := store.NowUTC().Unix()
	if now < created.Unix() || now >= deadline.ExpiresAt {
		return rollingCleanupAuthorization{}, fmt.Errorf("rolling cleanup authority expired or clock moved backward")
	}
	proof, err := rolling.BuildCleanup(c, record.Operation.Proposal.Sources, created.Unix(), deadline.ExpiresAt)
	if err != nil {
		return rollingCleanupAuthorization{}, err
	}
	raw, err := proof.Proof.B64Encode()
	if err != nil {
		return rollingCleanupAuthorization{}, err
	}
	result := rollingCleanupAuthorization{OperationID: id, Message: proof.Message, ExpiresAt: deadline.ExpiresAt}
	err = k.withMaster(func(master *btcec.PrivateKey) error {
		key, err := deriveRollingKey(master, rollingKeyContext{vault: vault, network: record.Enrollment.Network, operator: c.Keys.Operator.SerializeCompressed()}, false)
		if err != nil {
			return err
		}
		defer key.Key.Zero()
		result.Proof, err = signExactArkStageWithSighash(ctx, raw, key, schnorr.SerializePubKey(c.Keys.Guardian), c.Cleanup.Script, txscript.SigHashAll)
		return err
	})
	return result, err
}

// prepareRollingCleanup keeps the signed proof inside the journal before the
// scheduler can dispatch it. An expired retry never extends the old deadline.
// This private adapter deliberately exposes no HTTP deletion/signing route.
func (s *Service) prepareRollingCleanup(ctx context.Context, manager *RollingOperations, id string) (rollingCleanupAuthorization, error) {
	if manager == nil || isNilInterface(s.keys.rollingOperation) {
		return rollingCleanupAuthorization{}, fmt.Errorf("rolling cleanup dependencies required")
	}
	if _, err := manager.operation(ctx, id); err != nil {
		return rollingCleanupAuthorization{}, err
	}
	pending, err := manager.store.BeginRollingCleanup(ctx, id)
	if err != nil {
		return rollingCleanupAuthorization{}, err
	}
	authorized, err := s.keys.rollingOperation.authorizeRollingCleanup(ctx, manager.vault, id)
	if err != nil {
		return rollingCleanupAuthorization{}, err
	}
	record, err := manager.operation(ctx, id)
	if err != nil {
		return rollingCleanupAuthorization{}, err
	}
	if err = verifyRollingCleanupAuthorization(manager.contract, record, pending, authorized); err != nil {
		return rollingCleanupAuthorization{}, err
	}
	raw, err := json.Marshal(authorized)
	if err != nil {
		return rollingCleanupAuthorization{}, err
	}
	event, err := manager.store.AppendRollingEvent(ctx, policy.RollingEvent{OperationID: id, Phase: "cleanup_authorized", Evidence: string(raw)})
	if err != nil {
		return rollingCleanupAuthorization{}, err
	}
	var retained rollingCleanupAuthorization
	if err = json.Unmarshal([]byte(event.Evidence), &retained); err != nil {
		return rollingCleanupAuthorization{}, err
	}
	return retained, nil
}

func verifyRollingCleanupAuthorization(c *rolling.Contract, record policy.RollingSnapshot, pending policy.RollingEvent, authorized rollingCleanupAuthorization) error {
	var deadline policy.RollingCleanupDeadline
	created, err := time.Parse(time.RFC3339, pending.CreatedAt)
	if err != nil || json.Unmarshal([]byte(pending.Evidence), &deadline) != nil || deadline.ExpiresAt != created.Unix()+rolling.CleanupLifetimeSeconds-1 {
		return fmt.Errorf("rolling cleanup deadline binding")
	}
	if authorized.OperationID != record.Operation.OperationID || authorized.ExpiresAt != deadline.ExpiresAt {
		return fmt.Errorf("rolling cleanup response identity")
	}
	built, err := rolling.BuildCleanup(c, record.Operation.Proposal.Sources, created.Unix(), deadline.ExpiresAt)
	if err != nil {
		return err
	}
	if authorized.Message != built.Message {
		return fmt.Errorf("rolling cleanup response message")
	}
	original, err := built.Proof.B64Encode()
	if err != nil {
		return err
	}
	expected := schnorr.SerializePubKey(c.Keys.Guardian)
	if err = requireOnlyVaultSignatureAdded(original, authorized.Proof, expected); err != nil {
		return err
	}
	packet, err := parsePSBT(authorized.Proof)
	if err != nil {
		return err
	}
	hash := txscript.NewBaseTapLeaf(c.Cleanup.Script).TapHash()
	for index, input := range packet.Inputs {
		if input.SighashType != txscript.SigHashAll || len(input.TaprootScriptSpendSig) != 1 {
			return fmt.Errorf("rolling cleanup signature shape")
		}
		sig := input.TaprootScriptSpendSig[0]
		if sig.SigHash != txscript.SigHashAll || !bytes.Equal(sig.LeafHash, hash[:]) {
			return fmt.Errorf("rolling cleanup signature context")
		}
		if err = verifySchnorrOnInputWithSighash(packet, index, sig.Signature, expected, c.Cleanup.Script, txscript.SigHashAll); err != nil {
			return err
		}
	}
	return nil
}
