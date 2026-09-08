package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type savingsSetupPrepareRequest struct {
	VaultID        string `json:"vaultId"`
	OperationID    string `json:"operationId"`
	Txid           string `json:"txid"`
	Vout           uint32 `json:"vout"`
	ReserveCount   int    `json:"reserveCount"`
	ExpiresAt      int64  `json:"expiresAt"`
	OwnerSignature string `json:"ownerSignature"`
}

func (r savingsSetupPrepareRequest) digest() ([]byte, error) {
	if (!policy.ValidDelegationVaultID("vault-policy-v1", r.VaultID) || len(r.VaultID) > 256) || requireTxid(r.Txid) != nil {
		return nil, fmt.Errorf("Savings setup identity")
	}
	if _, err := canonicalVtxoOperationID(r.OperationID); err != nil {
		return nil, err
	}
	if r.ReserveCount < 1 || r.ReserveCount > 2 || r.ExpiresAt <= 0 {
		return nil, fmt.Errorf("Savings setup output count")
	}
	return setupDigest("prepare", struct {
		VaultID      string `json:"vaultId"`
		OperationID  string `json:"operationId"`
		Txid         string `json:"txid"`
		Vout         uint32 `json:"vout"`
		ReserveCount int    `json:"reserveCount"`
		ExpiresAt    int64  `json:"expiresAt"`
	}{r.VaultID, r.OperationID, r.Txid, r.Vout, r.ReserveCount, r.ExpiresAt})
}

type savingsSetupPrepared struct {
	Plan       savingsSetupPlan `json:"plan"`
	PlanDigest string           `json:"planDigest"`
	State      string           `json:"state"`
}

func (s *Service) savingsSetupContext(vault string) (savingsSetupContext, error) {
	spending, err := s.spendingRenewalContext(vault)
	if err != nil {
		return savingsSetupContext{}, err
	}
	cred, err := s.loadVerifiedCredentialFor(vault)
	if err != nil {
		return savingsSetupContext{}, err
	}
	if _, err := s.rebuildConnectorFamily(cred); err != nil {
		return savingsSetupContext{}, err
	}
	in, origin, err := s.connectorFamilyParameters(cred)
	if err != nil {
		return savingsSetupContext{}, err
	}
	c := savingsSetupContext{spending: renewalContract{spendingRenewalContext: spending}, savings: in, origin: origin}
	_, _, err = c.family()
	return c, err
}

func (s *Service) savingsSetupFee(ctx context.Context, v ports.ResolvedVtxo, p savingsSetupPlan, c savingsSetupContext) (uint64, string, error) {
	fees, err := s.ArkResolver.IntentFeePolicy(ctx)
	if err != nil {
		return 0, "", err
	}
	estimator, digest, err := newVtxoFeeEstimator(fees)
	if err != nil {
		return 0, "", err
	}
	outputs := []arkfee.Output{}
	for i := 0; i < p.ReserveCount; i++ {
		outputs = append(outputs, arkfee.Output{Amount: uint64(p.ReserveSats), Script: p.ReserveScript})
	}
	release, err := s.acquireFeeSelection(ctx)
	if err != nil {
		return 0, "", err
	}
	defer release()
	amount, err := estimator.Eval([]arkfee.OffchainInput{resolvedArkFeeInput(v)}, nil, []arkfee.Output{{Amount: uint64(p.ChangeSats), Script: c.spending.Binding.ScriptPubKey}}, outputs)
	if err != nil {
		return 0, "", err
	}
	fee, err := exactFeeSats(amount)
	return fee, hex.EncodeToString(digest), err
}

func (s *Service) prepareSavingsSetup(ctx context.Context, r savingsSetupPrepareRequest) (savingsSetupPrepared, error) {
	c, err := s.savingsSetupContext(r.VaultID)
	if err != nil {
		return savingsSetupPrepared{}, err
	}
	digest, err := r.digest()
	if err != nil {
		return savingsSetupPrepared{}, err
	}
	key, err := schnorr.ParsePubKey(mustDecodeRenewalHex(c.spending.Binding.OwnerPub))
	if err != nil {
		return savingsSetupPrepared{}, err
	}
	sigBytes, err := hex.DecodeString(r.OwnerSignature)
	if err != nil || hex.EncodeToString(sigBytes) != r.OwnerSignature {
		return savingsSetupPrepared{}, fmt.Errorf("Savings setup owner signature")
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil || !sig.Verify(digest, key) {
		return savingsSetupPrepared{}, fmt.Errorf("Savings setup owner authorization required")
	}
	if prior, err := s.Stores.LightRenewal.GetLightRenewal(ctx, r.OperationID); err != nil {
		return savingsSetupPrepared{}, err
	} else if prior != nil {
		prepared, err := savingsSetupSnapshot(prior, c)
		if err != nil {
			return savingsSetupPrepared{}, err
		}
		p := prepared.Plan
		if p.VaultID != r.VaultID || p.Txid != r.Txid || p.Vout != r.Vout || p.ReserveCount != r.ReserveCount || p.RegisterExpireAt != r.ExpiresAt {
			return savingsSetupPrepared{}, fmt.Errorf("Savings setup operation already bound")
		}
		return prepared, nil
	}
	if r.ExpiresAt <= s.vtxoNow().Unix() || r.ExpiresAt > s.vtxoNow().Add(5*time.Minute).Unix() {
		return savingsSetupPrepared{}, fmt.Errorf("Savings setup request expired; check its status before retrying")
	}
	family, enrollment, err := c.family()
	if err != nil {
		return savingsSetupPrepared{}, err
	}
	amount, max := int64(1000), 1
	if c.savings.TemplateVersion == connector.DualTemplate {
		amount, max = 500, 2
	}
	if r.ReserveCount > max {
		return savingsSetupPrepared{}, fmt.Errorf("Savings setup output count does not match enrollment")
	}
	v, err := s.liveRenewalInput(ctx, c.spending.Tree, r.Txid, r.Vout)
	if err != nil {
		return savingsSetupPrepared{}, err
	}
	p := savingsSetupPlan{OperationID: r.OperationID, VaultID: r.VaultID, DescriptorHash: c.spending.DescriptorHash, EnrollmentDigest: enrollment, Txid: r.Txid, Vout: r.Vout, ValueSats: int64(v.ValueSats), ReserveScript: hex.EncodeToString(family.Rules.ConnectorScript), ReserveSats: amount, ReserveCount: r.ReserveCount, RegisterExpireAt: r.ExpiresAt}
	p.ChangeSats = p.ValueSats - amount*int64(r.ReserveCount)
	stable := false
	for i := 0; i < 8; i++ {
		if p.ChangeSats < 330 {
			return savingsSetupPrepared{}, fmt.Errorf("Spending output is too small for signer setup and protected change")
		}
		fee, feeDigest, err := s.savingsSetupFee(ctx, v, p, c)
		if err != nil {
			return savingsSetupPrepared{}, err
		}
		if fee > 5000 || fee > uint64(c.spending.Binding.SpendingPolicy.AbsoluteFeeCapSats) {
			return savingsSetupPrepared{}, fmt.Errorf("Savings setup fee exceeds policy")
		}
		p.FeeSats, p.FeePolicyDigest = int64(fee), feeDigest
		next := p.ValueSats - amount*int64(r.ReserveCount) - p.FeeSats
		if next == p.ChangeSats {
			stable = true
			break
		}
		p.ChangeSats = next
	}
	if !stable {
		return savingsSetupPrepared{}, fmt.Errorf("Savings setup fee did not converge")
	}
	digest, err = p.digest(c)
	if err != nil {
		return savingsSetupPrepared{}, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return savingsSetupPrepared{}, err
	}
	op := policy.LightRenewalOperation{OperationID: p.OperationID, VaultID: p.VaultID, InputTxid: p.Txid, InputVout: p.Vout, FeeSats: p.FeeSats, PlanDigest: hex.EncodeToString(digest), Plan: string(raw), ExpiresAt: time.Unix(p.RegisterExpireAt, 0).UTC().Format(time.RFC3339), Kind: policy.SavingsSetupBatchKind, AmountSats: amount * int64(r.ReserveCount)}
	saved, err := s.Stores.LightRenewal.ReserveLightRenewal(ctx, op, c.spending.Binding.SpendingPolicy.PeriodAllowanceSats)
	if err != nil {
		return savingsSetupPrepared{}, mapLedgerBusy(err)
	}
	return savingsSetupSnapshot(saved, c)
}

func savingsSetupSnapshot(s *policy.LightRenewalSnapshot, c savingsSetupContext) (savingsSetupPrepared, error) {
	var p savingsSetupPlan
	if s == nil || s.Operation.Kind != policy.SavingsSetupBatchKind || json.Unmarshal([]byte(s.Operation.Plan), &p) != nil {
		return savingsSetupPrepared{}, fmt.Errorf("Savings setup operation required")
	}
	digest, err := p.digest(c)
	if err != nil || hex.EncodeToString(digest) != s.Operation.PlanDigest || p.OperationID != s.Operation.OperationID || p.VaultID != s.Operation.VaultID || p.Txid != s.Operation.InputTxid || p.Vout != s.Operation.InputVout || p.FeeSats != s.Operation.FeeSats || p.ReserveSats*int64(p.ReserveCount) != s.Operation.AmountSats || time.Unix(p.RegisterExpireAt, 0).UTC().Format(time.RFC3339) != s.Operation.ExpiresAt {
		return savingsSetupPrepared{}, fmt.Errorf("Savings setup stored plan mismatch")
	}
	return savingsSetupPrepared{p, s.Operation.PlanDigest, lightRenewalState(s)}, nil
}

func (s *Service) requireFreshSavingsSetup(ctx context.Context, p savingsSetupPlan, c savingsSetupContext) error {
	if p.RegisterExpireAt-s.vtxoNow().Unix() < 15 {
		return fmt.Errorf("Savings setup authorization expired")
	}
	v, err := s.liveRenewalInput(ctx, c.spending.Tree, p.Txid, p.Vout)
	if err != nil || int64(v.ValueSats) != p.ValueSats {
		return fmt.Errorf("Savings setup input unavailable")
	}
	fee, digest, err := s.savingsSetupFee(ctx, v, p, c)
	if err != nil || int64(fee) != p.FeeSats || digest != p.FeePolicyDigest {
		return fmt.Errorf("Savings setup fee changed")
	}
	return nil
}
