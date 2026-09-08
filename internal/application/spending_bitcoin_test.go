package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"net/http"
	"strings"
	"testing"
	"time"
)

func bitcoinFundingFixture(t *testing.T, network, tier string, count int) (*env, bitcoinPaymentContext, bitcoinPaymentPrepared, spendingBitcoinPrepareRequest) {
	t.Helper()
	e, _, set := spendingDelegationFixture(t, network, tier, true)
	c, err := e.svc.bitcoinPaymentContext(set.VaultID, true)
	if err != nil {
		t.Fatal(err)
	}
	coins, err := e.svc.ArkResolver.SpendableVtxos(t.Context(), c.spending.Tree.PkScript)
	if err != nil {
		t.Fatal(err)
	}
	outputs := []bitcoinPaymentOutput{{"0014" + strings.Repeat("43", 20), 1500}}
	if count == 2 {
		outputs = []bitcoinPaymentOutput{{"0014" + strings.Repeat("43", 20), 500}, {"0014" + strings.Repeat("43", 20), 500}}
	}
	request := spendingBitcoinPrepareRequest{VaultID: set.VaultID, OperationID: strings.Repeat("67", 16), Txid: coins[0].Txid, Vout: coins[0].Vout, Outputs: outputs, ExpiresAt: e.svc.vtxoNow().Add(4 * time.Minute).Unix()}
	digest, err := request.digest()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(e.hot, digest)
	if err != nil {
		t.Fatal(err)
	}
	request.OwnerSignature = hex.EncodeToString(sig.Serialize())
	prepared, err := e.svc.prepareSpendingBitcoin(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	return e, c, prepared, request
}
func TestSpendingBitcoinPrepareBindsArbitraryRecipientAndDuplicateOutputs(t *testing.T) {
	for _, network := range []string{"mainnet", "mutinynet"} {
		for _, tier := range []string{"standard", "advanced"} {
			for _, count := range []int{1, 2} {
				t.Run(network+"/"+tier+"/"+string(rune('0'+count)), func(t *testing.T) {
					e, c, prepared, r := bitcoinFundingFixture(t, network, tier, count)
					p := prepared.Plan
					if len(p.onchainOutputs()) != count || len(p.outputs(c)) != count+1 {
						t.Fatal("output count changed")
					}
					used, err := e.ledger.SpentInPeriod(t.Context(), r.VaultID, "")
					if err != nil || used != p.principal()+p.FeeSats {
						t.Fatalf("outflow %d %v", used, err)
					}
					replay, err := e.svc.prepareSpendingBitcoin(t.Context(), r)
					if err != nil || replay.PlanDigest != prepared.PlanDigest {
						t.Fatalf("retry %v", err)
					}
					r.Outputs = append([]bitcoinPaymentOutput(nil), r.Outputs...)
					r.Outputs[0].AmountSats++
					if _, err := e.svc.prepareSpendingBitcoin(t.Context(), r); err == nil {
						t.Fatal("changed signed destination amount accepted")
					}
					digest, _ := r.digest()
					sig, _ := schnorr.Sign(e.hot, digest)
					r.OwnerSignature = hex.EncodeToString(sig.Serialize())
					if _, err := e.svc.prepareSpendingBitcoin(t.Context(), r); err == nil {
						t.Fatal("operation rebound with fresh signature")
					}
					session, _ := btcec.NewPrivateKey()
					registration := setupRegistrationFixture(t, e, c, p, session, p.outputs(c))
					if _, err := verifyBitcoinPaymentRegistration(registration.PSBT, registration.Message, p, c); err != nil {
						t.Fatal(err)
					}
					for _, kind := range []string{"destination", "amount", "change", "merge"} {
						outputs := p.outputs(c)
						switch kind {
						case "destination":
							outputs[1].PkScript = c.spending.Tree.PkScript
						case "amount":
							outputs[1].Value++
						case "change":
							outputs[0].PkScript = outputs[1].PkScript
						case "merge":
							outputs = outputs[:len(outputs)-1]
						}
						changed := setupRegistrationFixture(t, e, c, p, session, outputs)
						if _, err := verifyBitcoinPaymentRegistration(changed.PSBT, changed.Message, p, c); err == nil {
							t.Fatalf("accepted %s", kind)
						}
					}
				})
			}
		}
	}
}
func TestSpendingBitcoinRejectsUnsafeOutputsAndPolicyBypass(t *testing.T) {
	_, c, prepared, _ := bitcoinFundingFixture(t, "mainnet", "standard", 1)
	for _, o := range []bitcoinPaymentOutput{{"6a", 500}, {"0014" + strings.Repeat("43", 20), 329}, {"0014" + strings.Repeat("43", 20), -1}, {"5120" + strings.Repeat("EE", 32), 1000}} {
		if _, err := validateBitcoinOutputs([]bitcoinPaymentOutput{o}); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
	for _, change := range []string{"cap", "fee", "change", "legacy"} {
		p := prepared.Plan
		p.Outputs = append([]bitcoinPaymentOutput(nil), p.Outputs...)
		switch change {
		case "cap":
			p.Outputs[0].AmountSats = c.spending.Binding.SpendingPolicy.TxRecipientCapSats + 1
			p.ChangeSats = p.ValueSats - p.principal() - p.FeeSats
		case "fee":
			p.FeeSats = 5001
			p.ChangeSats = p.ValueSats - p.principal() - p.FeeSats
		case "change":
			p.ChangeSats = 0
		case "legacy":
			p.ReserveCount = 1
		}
		if _, err := p.digest(c); err == nil {
			t.Fatal("accepted " + change)
		}
	}
	// New output-plan authorization cannot be replayed as a fixed signer setup.
	p := prepared.Plan
	newDigest, _ := p.digest(c)
	oldDigest, _ := setupDigest("plan", p)
	if hex.EncodeToString(newDigest) == hex.EncodeToString(oldDigest) {
		t.Fatal("domain collision")
	}
	raw, _ := json.Marshal(p)
	if !strings.Contains(string(raw), `"outputs"`) {
		t.Fatal("missing destination authority")
	}
}

func TestSpendingBitcoinRejectedRegistrationReportsReasonAndReleasesAllowance(t *testing.T) {
	e, c, prepared, _ := bitcoinFundingFixture(t, "mainnet", "standard", 1)
	session, _ := btcec.NewPrivateKey()
	request := setupRegistrationFixture(t, e, c, prepared.Plan, session, prepared.Plan.outputs(c))
	operator := &lightRenewalTestOperator{registerErr: vaultBoardOperatorRejection{status: http.StatusBadRequest, reason: "input already spent"}}
	e.svc.lightRenewalOperatorDial = func(context.Context) (lightRenewalOperator, error) { return operator, nil }
	result, err := e.svc.registerBitcoinPayment(t.Context(), request)
	if err != nil || result.State != "rejected" || result.Reason != "input already spent" {
		t.Fatalf("result %+v, %v", result, err)
	}
	used, err := e.ledger.SpentInPeriod(t.Context(), request.VaultID, "")
	if err != nil || used != 0 {
		t.Fatalf("rejected payment retained allowance: %d %v", used, err)
	}
	if _, err := e.svc.registerBitcoinPayment(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if operator.registers != 1 {
		t.Fatal("rejected registration dispatched twice")
	}
}
