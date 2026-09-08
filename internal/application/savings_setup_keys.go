package application

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
)

type savingsSetupAuthorization struct {
	context             savingsSetupContext
	plan                savingsSetupPlan
	registrationPSBT    string
	registrationMessage string
	final               *lightRenewalFinalEvidence
	deletion            *lightDelegateIntent
}
type savingsSetupAuthorizer interface {
	authorizeSavingsSetup(context.Context, savingsSetupAuthorization) (string, error)
}

func (k KeyCapabilities) savingsSetupAuthorization(ctx context.Context, r savingsSetupAuthorization) (string, error) {
	if isNilInterface(k.savingsSetup) {
		return "", fmt.Errorf("Savings setup capability unavailable")
	}
	return k.savingsSetup.authorizeSavingsSetup(ctx, r)
}
func (k *fileBackedVaultKeys) authorizeSavingsSetup(ctx context.Context, r savingsSetupAuthorization) (string, error) {
	if r.final != nil && r.deletion != nil {
		return "", fmt.Errorf("Savings setup signing phase conflict")
	}
	registration, err := verifySavingsSetupRegistration(r.registrationPSBT, r.registrationMessage, r.plan, r.context)
	if err != nil {
		return "", err
	}
	raw, indexes, sighash := registration.CanonicalPSBT, []int{0, 1}, txscript.SigHashAll
	if r.final != nil {
		final, err := verifySavingsSetupFinal(*r.final, r.plan, r.context, registration)
		if err != nil {
			return "", err
		}
		raw, indexes, sighash = final.CanonicalForfeitPSBT, []int{0}, txscript.SigHashDefault
	}
	if r.deletion != nil {
		if err := verifyRenewalDelete(*r.deletion, r.plan.batchInput(), r.context.spending); err != nil {
			return "", err
		}
		raw = r.deletion.Proof
	}
	var signed string
	err = k.withRenewalKey(ctx, r.context.spending, func(key *btcec.PrivateKey) error {
		var err error
		signed, err = signExactVaultBoardStage(ctx, raw, key, mustDecodeRenewalHex(r.context.spending.Binding.CosignerPub), r.context.spending.Tree.SpendLeaf, indexes, sighash)
		return err
	})
	return signed, err
}
