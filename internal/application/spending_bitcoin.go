package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// An ordered output plan is shared by ordinary Bitcoin sends and signer setup.
// Outputs are never merged: two equal approval outputs must remain two UTXOs.
type bitcoinPaymentOutput struct {
	Script     string `json:"script"`
	AmountSats int64  `json:"amountSats"`
}

func validateBitcoinOutputs(outputs []bitcoinPaymentOutput) (int64, error) {
	if len(outputs) < 1 || len(outputs) > 2 {
		return 0, fmt.Errorf("Bitcoin payment requires one or two outputs")
	}
	var amount int64
	for _, o := range outputs {
		script, err := hex.DecodeString(o.Script)
		if err != nil || hex.EncodeToString(script) != o.Script {
			return 0, fmt.Errorf("Bitcoin destination script is invalid")
		}
		dust := int64(330)
		switch txscript.GetScriptClass(script) {
		case txscript.PubKeyHashTy:
			dust = 546
		case txscript.ScriptHashTy:
			dust = 540
		case txscript.WitnessV0PubKeyHashTy, txscript.WitnessV0ScriptHashTy, txscript.WitnessV1TaprootTy:
		default:
			return 0, fmt.Errorf("Bitcoin destination must be a standard payment address")
		}
		if o.AmountSats < dust || o.AmountSats > 21_000_000*100_000_000 {
			return 0, fmt.Errorf("Bitcoin payment amount is invalid or below dust")
		}
		amount += o.AmountSats
	}
	if amount > 21_000_000*100_000_000 {
		return 0, fmt.Errorf("Bitcoin payment amount is too large")
	}
	return amount, nil
}
func (p bitcoinPaymentPlan) onchainOutputs() []bitcoinPaymentOutput {
	if p.Outputs != nil {
		return p.Outputs
	}
	outputs := make([]bitcoinPaymentOutput, p.ReserveCount)
	for i := range outputs {
		outputs[i] = bitcoinPaymentOutput{p.ReserveScript, p.ReserveSats}
	}
	return outputs
}
func (p bitcoinPaymentPlan) principal() int64 {
	var amount int64
	for _, output := range p.onchainOutputs() {
		amount += output.AmountSats
	}
	return amount
}
func (p bitcoinPaymentPlan) kind() string {
	if p.Outputs != nil {
		return policy.SpendingBitcoinBatchKind
	}
	return policy.SavingsSetupBatchKind
}
func (p bitcoinPaymentPlan) bitcoinDigest(c bitcoinPaymentContext) ([]byte, error) {
	if err := c.spending.validateTree(); err != nil {
		return nil, err
	}
	b := c.spending.Binding
	amount, err := validateBitcoinOutputs(p.Outputs)
	if err != nil {
		return nil, err
	}
	if _, err := canonicalVtxoOperationID(p.OperationID); err != nil {
		return nil, err
	}
	if p.VaultID != b.VaultID || p.DescriptorHash != c.spending.DescriptorHash ||
		p.EnrollmentDigest != "" || p.ReserveScript != "" || p.ReserveSats != 0 || p.ReserveCount != 0 ||
		requireTxid(p.Txid) != nil || requireTxid(p.FeePolicyDigest) != nil ||
		p.ValueSats < 330 || p.ValueSats > 21_000_000*100_000_000 ||
		p.ChangeSats < 330 || p.ChangeSats > p.ValueSats || p.FeeSats < 0 || p.FeeSats > 5000 ||
		p.FeeSats > b.SpendingPolicy.AbsoluteFeeCapSats || amount > b.SpendingPolicy.TxRecipientCapSats ||
		p.ChangeSats+amount+p.FeeSats != p.ValueSats || p.RegisterExpireAt <= 0 || p.RegisterExpireAt > (1<<53)-1 {
		return nil, fmt.Errorf("Bitcoin payment plan changed or exceeds policy")
	}
	return setupDigest("bitcoin-plan", p)
}

type spendingBitcoinPrepareRequest struct {
	VaultID        string                 `json:"vaultId"`
	OperationID    string                 `json:"operationId"`
	Txid           string                 `json:"txid"`
	Vout           uint32                 `json:"vout"`
	Outputs        []bitcoinPaymentOutput `json:"outputs"`
	ExpiresAt      int64                  `json:"expiresAt"`
	OwnerSignature string                 `json:"ownerSignature,omitempty"`
}

func (r spendingBitcoinPrepareRequest) digest() ([]byte, error) {
	if !policy.ValidDelegationVaultID("vault-policy-v1", r.VaultID) || len(r.VaultID) > 256 || requireTxid(r.Txid) != nil {
		return nil, fmt.Errorf("Bitcoin payment identity")
	}
	if _, err := canonicalVtxoOperationID(r.OperationID); err != nil {
		return nil, err
	}
	if _, err := validateBitcoinOutputs(r.Outputs); err != nil {
		return nil, err
	}
	if r.ExpiresAt <= 0 || r.ExpiresAt > (1<<53)-1 {
		return nil, fmt.Errorf("Bitcoin payment expiry")
	}
	r.OwnerSignature = ""
	return setupDigest("bitcoin-prepare", r)
}
func (s *Service) prepareSpendingBitcoin(ctx context.Context, r spendingBitcoinPrepareRequest) (bitcoinPaymentPrepared, error) {
	c, err := s.bitcoinPaymentContext(r.VaultID, true)
	if err != nil {
		return bitcoinPaymentPrepared{}, err
	}
	digest, err := r.digest()
	if err != nil {
		return bitcoinPaymentPrepared{}, err
	}
	key, err := schnorr.ParsePubKey(mustDecodeRenewalHex(c.spending.Binding.OwnerPub))
	if err != nil {
		return bitcoinPaymentPrepared{}, err
	}
	raw, err := hex.DecodeString(r.OwnerSignature)
	if err != nil || hex.EncodeToString(raw) != r.OwnerSignature {
		return bitcoinPaymentPrepared{}, fmt.Errorf("Bitcoin payment owner signature")
	}
	sig, err := schnorr.ParseSignature(raw)
	if err != nil || !sig.Verify(digest, key) {
		return bitcoinPaymentPrepared{}, fmt.Errorf("Bitcoin payment owner authorization required")
	}
	if prior, err := s.Stores.LightRenewal.GetLightRenewal(ctx, r.OperationID); err != nil {
		return bitcoinPaymentPrepared{}, err
	} else if prior != nil {
		prepared, err := bitcoinPaymentSnapshot(prior, c)
		if err != nil {
			return bitcoinPaymentPrepared{}, err
		}
		p := prepared.Plan
		if p.VaultID != r.VaultID || p.Txid != r.Txid || p.Vout != r.Vout || p.RegisterExpireAt != r.ExpiresAt || !reflect.DeepEqual(p.Outputs, r.Outputs) {
			return bitcoinPaymentPrepared{}, fmt.Errorf("Bitcoin payment already bound")
		}
		return prepared, nil
	}
	if r.ExpiresAt <= s.vtxoNow().Unix() || r.ExpiresAt > s.vtxoNow().Add(5*time.Minute).Unix() {
		return bitcoinPaymentPrepared{}, fmt.Errorf("Bitcoin payment expired; check its status before retrying")
	}
	v, err := s.liveRenewalInput(ctx, c.spending.Tree, r.Txid, r.Vout)
	if err != nil {
		return bitcoinPaymentPrepared{}, err
	}
	p := bitcoinPaymentPlan{OperationID: r.OperationID, VaultID: r.VaultID, DescriptorHash: c.spending.DescriptorHash, Txid: r.Txid, Vout: r.Vout, ValueSats: int64(v.ValueSats), Outputs: r.Outputs, RegisterExpireAt: r.ExpiresAt}
	return s.reserveBitcoinPlan(ctx, v, p, c)
}
