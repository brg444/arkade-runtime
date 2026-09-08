package application

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
)

type bitcoinPaymentAuthorization struct {
	context             bitcoinPaymentContext
	plan                bitcoinPaymentPlan
	registrationPSBT    string
	registrationMessage string
	final               *lightRenewalFinalEvidence
	deletion            *lightDelegateIntent
}
type bitcoinPaymentAuthorizer interface {
	authorizeBitcoinPayment(context.Context, bitcoinPaymentAuthorization) (string, error)
}

func (k KeyCapabilities) bitcoinPaymentAuthorization(ctx context.Context, r bitcoinPaymentAuthorization) (string, error) {
	if isNilInterface(k.bitcoinPayment) {
		return "", fmt.Errorf("Savings setup capability unavailable")
	}
	return k.bitcoinPayment.authorizeBitcoinPayment(ctx, r)
}
func (k *fileBackedVaultKeys) authorizeBitcoinPayment(ctx context.Context, r bitcoinPaymentAuthorization) (string, error) {
	if r.final != nil && r.deletion != nil {
		return "", fmt.Errorf("Savings setup signing phase conflict")
	}
	registration, err := verifyBitcoinPaymentRegistration(r.registrationPSBT, r.registrationMessage, r.plan, r.context)
	if err != nil {
		return "", err
	}
	raw, indexes, sighash := registration.CanonicalPSBT, []int{0, 1}, txscript.SigHashAll
	if r.final != nil {
		final, err := verifyBitcoinPaymentFinal(*r.final, r.plan, r.context, registration)
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
