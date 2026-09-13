package application

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// This domain is part of current Bitcoin payment signatures and remains fixed.
const bitcoinPaymentDomain = "vaulted-vtxo/savings-setup/"

// One live Spending input, protected change, and an ordered Bitcoin output plan.
// The retained signed encoding includes empty reserve fields. Only explicit
// Bitcoin output plans are accepted; those fields must remain zero or empty.
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
}

func bitcoinPaymentDigest(phase string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte(bitcoinPaymentDomain+phase+"/v1:"), raw...))
	return digest[:], nil
}

func (p bitcoinPaymentPlan) batchInput() spendingRenewalPlan {
	return spendingRenewalPlan{bitcoinPayment: true, Txid: p.Txid, Vout: p.Vout, ValueSats: p.ValueSats, ReceiverSats: p.ChangeSats}
}

func (p bitcoinPaymentPlan) outputs(c bitcoinPaymentContext) []*wire.TxOut {
	outputs := []*wire.TxOut{{Value: p.ChangeSats, PkScript: c.spending.Tree.PkScript}}
	for _, output := range p.Outputs {
		outputs = append(outputs, &wire.TxOut{Value: output.AmountSats, PkScript: mustDecodeRenewalHex(output.Script)})
	}
	return outputs
}

func verifyBitcoinPaymentRegistration(raw, message string, p bitcoinPaymentPlan, c bitcoinPaymentContext) (verifiedSpendingRenewalRegistration, error) {
	digest, err := p.digest(c)
	if err != nil {
		return verifiedSpendingRenewalRegistration{}, err
	}
	var registration intent.RegisterMessage
	if err := registration.Decode(message); err != nil {
		return verifiedSpendingRenewalRegistration{}, err
	}
	canonical, err := registration.Encode()
	if err != nil || canonical != message || registration.ValidAt != 0 || registration.ExpireAt != p.RegisterExpireAt ||
		len(registration.CosignersPublicKeys) != 1 || len(registration.OnchainOutputIndexes) != len(p.Outputs) {
		return verifiedSpendingRenewalRegistration{}, fmt.Errorf("Bitcoin payment register conditions")
	}
	for i, index := range registration.OnchainOutputIndexes {
		if index != i+1 {
			return verifiedSpendingRenewalRegistration{}, fmt.Errorf("Bitcoin payment onchain output indexes")
		}
	}
	session, err := hex.DecodeString(registration.CosignersPublicKeys[0])
	if err != nil || len(session) != 33 || hex.EncodeToString(session) != registration.CosignersPublicKeys[0] {
		return verifiedSpendingRenewalRegistration{}, fmt.Errorf("Bitcoin payment tree session")
	}
	if _, err := btcec.ParsePubKey(session); err != nil {
		return verifiedSpendingRenewalRegistration{}, err
	}
	if err := verifySpendingBatchIntentProof(raw, message, p.batchInput(), c.spending, p.outputs(c)); err != nil {
		return verifiedSpendingRenewalRegistration{}, err
	}
	request, err := bitcoinPaymentDigest("register", spendingRenewalRegistrationEvidence{raw, message})
	return verifiedSpendingRenewalRegistration{PlanDigest: digest, RequestDigest: request, TreeSession: session, CanonicalPSBT: raw, Message: message}, err
}

func verifyBitcoinPaymentFinal(e spendingRenewalFinalEvidence, p bitcoinPaymentPlan, c bitcoinPaymentContext, r verifiedSpendingRenewalRegistration) (verifiedSpendingRenewalFinal, error) {
	digest, err := p.digest(c)
	if err != nil {
		return verifiedSpendingRenewalFinal{}, err
	}
	return verifySpendingBatchFinal(e, p.batchInput(), c.spending, r, txscript.SigHashDefault, digest, bitcoinPaymentDomain+"final/v1:", p.outputs(c)[1:])
}
