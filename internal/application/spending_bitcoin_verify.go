package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const savingsSetupDomain = "vaulted-vtxo/savings-setup/"

// One live Spending input, protected change, and an ordered Bitcoin output plan.
// Reserve fields remain only to verify legacy signed setup records byte-for-byte;
// canonical Bitcoin payments require these fields to be empty and bind Outputs.
type bitcoinPaymentPlan struct {
	OperationID      string                 `json:"operationId"`
	VaultID          string                 `json:"vaultId"`
	DescriptorHash   string                 `json:"descriptorHash"`
	EnrollmentDigest string                 `json:"enrollmentDigest"`
	Txid             string                 `json:"txid"`
	Vout             uint32                 `json:"vout"`
	ValueSats        int64                  `json:"valueSats"`
	ChangeSats       int64                  `json:"changeSats"`
	ReserveScript    string                 `json:"reserveScript"`
	ReserveSats      int64                  `json:"reserveSats"`
	ReserveCount     int                    `json:"reserveCount"`
	FeeSats          int64                  `json:"feeSats"`
	FeePolicyDigest  string                 `json:"feePolicyDigest"`
	RegisterExpireAt int64                  `json:"registerExpireAt"`
	Outputs          []bitcoinPaymentOutput `json:"outputs,omitempty"`
}

type bitcoinPaymentContext struct {
	spending renewalContract
	savings  savings.FamilyInput
	origin   connector.KeyOrigin
}

func (c bitcoinPaymentContext) family() (*connector.Family, string, error) {
	if err := c.spending.validateTree(); err != nil {
		return nil, "", err
	}
	b := c.spending.Binding
	if c.spending.legacyLight || c.savings.VaultID != b.VaultID || c.savings.Network != b.Network ||
		c.savings.ProtectionTier != b.ProtectionTier || !sameDelegationBytes(c.savings.SpendingPolicy, b.SpendingPolicy) ||
		c.savings.Phone == nil || hex.EncodeToString(c.savings.Phone.SerializeCompressed()[1:]) != b.OwnerPub ||
		c.savings.Hardware == nil || !bytes.Equal(c.origin.PublicKey, c.savings.Hardware.SerializeCompressed()) {
		return nil, "", fmt.Errorf("Savings setup enrollment binding")
	}
	if c.spending.vaultParams == nil || !bytes.Equal(schnorr.SerializePubKey(c.savings.Hardware), c.spending.vaultParams.ExitHardwarePub) {
		return nil, "", fmt.Errorf("Savings setup hardware binding")
	}
	var recovery []byte
	if c.savings.Recovery != nil {
		recovery = schnorr.SerializePubKey(c.savings.Recovery)
	}
	if !bytes.Equal(recovery, c.spending.vaultParams.ExitRecoveryPub) {
		return nil, "", fmt.Errorf("Savings setup recovery binding")
	}
	kind, err := c.origin.Kind()
	if err != nil {
		return nil, "", err
	}
	family, err := connector.BuildFamily(c.savings, kind)
	if err != nil {
		return nil, "", err
	}
	digest, err := connector.EnrollmentDigest(c.savings, c.origin)
	return family, digest, err
}

func setupDigest(phase string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte(savingsSetupDomain+phase+"/v1:"), raw...))
	return digest[:], nil
}

func (p bitcoinPaymentPlan) digest(c bitcoinPaymentContext) ([]byte, error) {
	if p.Outputs != nil {
		return p.bitcoinDigest(c)
	}
	f, enrollment, err := c.family()
	if err != nil {
		return nil, err
	}
	amount, count := int64(1000), 1
	if c.savings.TemplateVersion == connector.DualTemplate {
		amount, count = 500, 2
	}
	b := c.spending.Binding
	if _, err := canonicalVtxoOperationID(p.OperationID); err != nil {
		return nil, err
	}
	if p.VaultID != b.VaultID || p.DescriptorHash != c.spending.DescriptorHash || p.EnrollmentDigest != enrollment ||
		requireTxid(p.Txid) != nil || requireTxid(p.FeePolicyDigest) != nil ||
		p.ReserveScript != hex.EncodeToString(f.Rules.ConnectorScript) || p.ReserveSats != amount ||
		p.ReserveCount < 1 || p.ReserveCount > count || p.ValueSats < 330 || p.ValueSats > 21_000_000*100_000_000 ||
		p.ChangeSats < 330 || p.ChangeSats > p.ValueSats || p.FeeSats < 0 || p.FeeSats > 5000 ||
		p.FeeSats > b.SpendingPolicy.AbsoluteFeeCapSats || p.ReserveSats*int64(p.ReserveCount) > b.SpendingPolicy.TxRecipientCapSats ||
		p.ChangeSats+p.ReserveSats*int64(p.ReserveCount)+p.FeeSats != p.ValueSats ||
		p.RegisterExpireAt <= 0 || p.RegisterExpireAt > (1<<53)-1 {
		return nil, fmt.Errorf("Savings setup plan changed or exceeds policy")
	}
	return setupDigest("plan", p)
}

func (p bitcoinPaymentPlan) batchInput() lightRenewalPlan {
	return lightRenewalPlan{bitcoinPayment: true, Txid: p.Txid, Vout: p.Vout, ValueSats: p.ValueSats, ReceiverSats: p.ChangeSats}
}

func (p bitcoinPaymentPlan) outputs(c bitcoinPaymentContext) []*wire.TxOut {
	outputs := []*wire.TxOut{{Value: p.ChangeSats, PkScript: c.spending.Tree.PkScript}}
	for _, output := range p.onchainOutputs() {
		outputs = append(outputs, &wire.TxOut{Value: output.AmountSats, PkScript: mustDecodeRenewalHex(output.Script)})
	}
	return outputs
}

func verifyBitcoinPaymentRegistration(raw, message string, p bitcoinPaymentPlan, c bitcoinPaymentContext) (verifiedLightRenewalRegistration, error) {
	digest, err := p.digest(c)
	if err != nil {
		return verifiedLightRenewalRegistration{}, err
	}
	var registration intent.RegisterMessage
	if err := registration.Decode(message); err != nil {
		return verifiedLightRenewalRegistration{}, err
	}
	canonical, err := registration.Encode()
	if err != nil || canonical != message || registration.ValidAt != 0 || registration.ExpireAt != p.RegisterExpireAt ||
		len(registration.CosignersPublicKeys) != 1 || len(registration.OnchainOutputIndexes) != len(p.onchainOutputs()) {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Savings setup register conditions")
	}
	for i, index := range registration.OnchainOutputIndexes {
		if index != i+1 {
			return verifiedLightRenewalRegistration{}, fmt.Errorf("Savings setup onchain output indexes")
		}
	}
	session, err := hex.DecodeString(registration.CosignersPublicKeys[0])
	if err != nil || len(session) != 33 || hex.EncodeToString(session) != registration.CosignersPublicKeys[0] {
		return verifiedLightRenewalRegistration{}, fmt.Errorf("Savings setup tree session")
	}
	if _, err := btcec.ParsePubKey(session); err != nil {
		return verifiedLightRenewalRegistration{}, err
	}
	if err := verifySpendingBatchIntentProof(raw, message, p.batchInput(), c.spending, p.outputs(c)); err != nil {
		return verifiedLightRenewalRegistration{}, err
	}
	request, err := setupDigest("register", lightRenewalRegistrationEvidence{raw, message})
	return verifiedLightRenewalRegistration{PlanDigest: digest, RequestDigest: request, TreeSession: session, CanonicalPSBT: raw, Message: message}, err
}

func verifyBitcoinPaymentFinal(e lightRenewalFinalEvidence, p bitcoinPaymentPlan, c bitcoinPaymentContext, r verifiedLightRenewalRegistration) (verifiedLightRenewalFinal, error) {
	digest, err := p.digest(c)
	if err != nil {
		return verifiedLightRenewalFinal{}, err
	}
	return verifySpendingBatchFinal(e, p.batchInput(), c.spending, r, txscript.SigHashDefault, digest, savingsSetupDomain+"final/v1:", p.outputs(c)[1:])
}
