package application

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

const rollingReceiptKeyScope = rolling.RollingProgram + "/finalization-receipt-v1"
const rollingDelegateKeyScope = rolling.RollingProgram + "/renewal-delegate-v1"

type rollingKeyContext struct {
	vault, network string
	operator       []byte
}

type rollingJournal interface {
	RollingReceiptStore
	RollingHistory(context.Context, string) (policy.RollingHistory, error)
	NowUTC() time.Time
}

type rollingOperationAuthorizer interface {
	prepareRollingTree(context.Context, string, string) (rollingPreparedTree, error)
	signRollingTree(context.Context, string, string) (rollingSignedTree, error)
	authorizeRollingFinal(context.Context, string, string) (rollingFinalAuthorization, error)
	authorizeRollingCleanup(context.Context, string, string) (rollingCleanupAuthorization, error)
	rollingPublic(rollingKeyContext) (*btcec.PublicKey, *btcec.PublicKey, error)
	rollingDelegatePublic(rollingKeyContext) (*btcec.PublicKey, error)
	authorizeRollingOperation(context.Context, string, string) (RollingAuthorization, error)
	authorizeRollingRenewal(context.Context, string, string) (RollingAuthorization, error)
	issueRollingReceipt(context.Context, string, uint64) (rolling.FinalizationReceipt, error)
}

// RollingAuthorization contains only signatures for a reconstructed, retained
// operation. The wallet supplies its own signatures and submits through
// the qualified Emulator; the journal commits these bytes before release.
type RollingAuthorization struct {
	OperationID     string   `json:"operationId"`
	Message         string   `json:"message,omitempty"`
	TransactionPSBT string   `json:"transactionPsbt"`
	CheckpointPSBTs []string `json:"checkpointPsbts"`
}

func (k *fileBackedVaultKeys) bindRollingJournal(store rollingJournal, resolver ports.ArkResolver) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rollingStore = store
	k.rollingResolver = resolver
}

func (k *fileBackedVaultKeys) rollingDependencies() (rollingJournal, ports.ArkResolver, error) {
	if k == nil {
		return nil, nil, fmt.Errorf("rolling key backend unavailable")
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if isNilInterface(k.rollingStore) || isNilInterface(k.rollingResolver) {
		return nil, nil, fmt.Errorf("rolling journal and resolver required")
	}
	return k.rollingStore, k.rollingResolver, nil
}

func deriveRollingKey(master *btcec.PrivateKey, scope rollingKeyContext, receipt bool) (*btcec.PrivateKey, error) {
	program := rolling.RollingProgram
	if receipt {
		program = rollingReceiptKeyScope
	}
	return policy.DeriveVtxoVaultCosignerScalar(master, scope.vault, program, scope.network, scope.operator)
}

func deriveRollingDelegateKey(master *btcec.PrivateKey, scope rollingKeyContext) (*btcec.PrivateKey, error) {
	return policy.DeriveVtxoVaultCosignerScalar(master, scope.vault, rollingDelegateKeyScope, scope.network, scope.operator)
}

func (k *fileBackedVaultKeys) rollingDelegatePublic(scope rollingKeyContext) (*btcec.PublicKey, error) {
	var result *btcec.PublicKey
	err := k.withMaster(func(master *btcec.PrivateKey) error {
		key, err := deriveRollingDelegateKey(master, scope)
		if err != nil {
			return err
		}
		defer key.Key.Zero()
		// The shared derivation returns the even lift. Commit that exact
		// compressed identity; tree signing must not accept its opposite parity.
		result = key.PubKey()
		return nil
	})
	return result, err
}

func (k *fileBackedVaultKeys) rollingPublic(scope rollingKeyContext) (guardian, receipt *btcec.PublicKey, err error) {
	err = k.withMaster(func(master *btcec.PrivateKey) error {
		g, e := deriveRollingKey(master, scope, false)
		if e != nil {
			return e
		}
		defer g.Key.Zero()
		r, e := deriveRollingKey(master, scope, true)
		if e != nil {
			return e
		}
		defer r.Key.Zero()
		guardian, receipt = g.PubKey(), r.PubKey()
		return nil
	})
	return
}

// No PSBT, digest, policy, key or observation time is accepted from the caller.
// The only signing target is the exact semantic operation in the bound journal.
func (k *fileBackedVaultKeys) authorizeRollingOperation(ctx context.Context, vault, id string) (RollingAuthorization, error) {
	store, _, err := k.rollingDependencies()
	if err != nil {
		return RollingAuthorization{}, err
	}
	records, err := store.RollingOperations(ctx, vault)
	if err != nil {
		return RollingAuthorization{}, err
	}
	var selected *policy.RollingSnapshot
	for i := range records {
		if records[i].Operation.OperationID == id {
			if selected != nil {
				return RollingAuthorization{}, fmt.Errorf("ambiguous rolling operation")
			}
			selected = &records[i]
		}
	}
	if selected == nil || selected.Operation.VaultID != vault || selected.Enrollment.VaultID != vault {
		return RollingAuthorization{}, fmt.Errorf("rolling signing reservation missing")
	}
	if _, aborted := selected.Events["aborted"]; aborted {
		return RollingAuthorization{}, fmt.Errorf("rolling operation aborted")
	}
	if _, cleanup := selected.Events["cleanup_pending"]; cleanup {
		return RollingAuthorization{}, fmt.Errorf("rolling cleanup excludes registration authority")
	}
	kind := selected.Operation.Proposal.Kind
	if kind != rolling.PaymentOperation && kind != rolling.CreditOperation && kind != rolling.RenewalOperation {
		return RollingAuthorization{}, fmt.Errorf("unsupported rolling signing operation")
	}
	if kind == rolling.RenewalOperation {
		if err = rolling.CheckRenewalTime(selected.Operation.Proposal.Message, store.NowUTC().Unix()); err != nil {
			return RollingAuthorization{}, err
		}
	}
	c, err := rolling.DecodeDescriptor([]byte(selected.Enrollment.Descriptor))
	if err != nil {
		return RollingAuthorization{}, err
	}
	created, err := time.Parse(time.RFC3339, selected.Operation.CreatedAt)
	if err != nil {
		return RollingAuthorization{}, err
	}
	built, err := selected.Operation.Proposal.Rebuild(c, created.Unix())
	if err != nil {
		return RollingAuthorization{}, err
	}
	if built.Transaction.UnsignedTx.TxHash().String() != id {
		return RollingAuthorization{}, fmt.Errorf("rolling signing identity mismatch")
	}
	leaf := c.Spend.Script
	sighash := txscript.SigHashDefault
	if selected.Operation.Proposal.Kind == rolling.CreditOperation {
		leaf = c.Credit.Script
	}
	if kind == rolling.RenewalOperation {
		leaf, sighash = c.Renew.Script, txscript.SigHashAll
	}
	result := RollingAuthorization{OperationID: id, Message: selected.Operation.Proposal.Message, CheckpointPSBTs: make([]string, len(built.Checkpoints))}
	err = k.withMaster(func(master *btcec.PrivateKey) error {
		scope := rollingKeyContext{vault: vault, network: selected.Enrollment.Network, operator: c.Keys.Operator.SerializeCompressed()}
		key, e := deriveRollingKey(master, scope, false)
		if e != nil {
			return e
		}
		defer key.Key.Zero()
		expected := schnorr.SerializePubKey(c.Keys.Guardian)
		if !bytes.Equal(schnorr.SerializePubKey(key.PubKey()), expected) {
			return fmt.Errorf("rolling Guardian scope mismatch")
		}
		raw, e := built.Transaction.B64Encode()
		if e != nil {
			return e
		}
		result.TransactionPSBT, e = signExactArkStageWithSighash(ctx, raw, key, expected, leaf, sighash)
		if e != nil {
			return e
		}
		for i, checkpoint := range built.Checkpoints {
			raw, e = checkpoint.B64Encode()
			if e != nil {
				return e
			}
			result.CheckpointPSBTs[i], e = signExactArkStage(ctx, raw, key, expected, leaf)
			if e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return RollingAuthorization{}, err
	}
	return result, nil
}

func (k *fileBackedVaultKeys) issueRollingReceipt(ctx context.Context, vault string, sequence uint64) (rolling.FinalizationReceipt, error) {
	store, resolver, err := k.rollingDependencies()
	if err != nil {
		return rolling.FinalizationReceipt{}, err
	}
	history, err := store.RollingHistory(ctx, vault)
	if err != nil {
		return rolling.FinalizationReceipt{}, err
	}
	if history.Enrollment.VaultID != vault {
		return rolling.FinalizationReceipt{}, fmt.Errorf("rolling receipt enrollment mismatch")
	}
	c, err := rolling.DecodeDescriptor([]byte(history.Enrollment.Descriptor))
	if err != nil {
		return rolling.FinalizationReceipt{}, err
	}
	source, err := NewRollingReceiptSource(store, vault, c, resolver)
	if err != nil {
		return rolling.FinalizationReceipt{}, err
	}
	var result rolling.FinalizationReceipt
	err = k.withMaster(func(master *btcec.PrivateKey) error {
		scope := rollingKeyContext{vault: vault, network: history.Enrollment.Network, operator: c.Keys.Operator.SerializeCompressed()}
		key, e := deriveRollingKey(master, scope, true)
		if e != nil {
			return e
		}
		defer key.Key.Zero()
		issuer, e := rolling.NewReceiptIssuer(c, key, source, store.NowUTC)
		if e != nil {
			return e
		}
		defer issuer.Close()
		result, e = issuer.Issue(ctx, sequence)
		return e
	})
	if err != nil {
		return rolling.FinalizationReceipt{}, err
	}
	return result, nil
}
