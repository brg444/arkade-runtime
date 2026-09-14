package application

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type spendingRenewalProofFixture struct {
	env      *env
	plan     spendingRenewalPlan
	contract renewalContract
	tree     *vtxoPolicyTree
	owner    *btcec.PrivateKey
	message  string
}

func newSpendingRenewalProofFixture(t *testing.T) spendingRenewalProofFixture {
	t.Helper()
	return newSpendingRenewalProofFixtureForAccount(t, deployment.NetworkMutinynet, "light")
}
func newSpendingRenewalProofFixtureForAccount(t *testing.T, network, tier string) spendingRenewalProofFixture {
	t.Helper()
	var e *env
	var id string
	if tier == "light" {
		f := newSpendingOnlyFixtureForNetwork(t, true, network)
		status, err := f.env.svc.FinishEnrollment(t.Context(), f.token, f.request)
		if err != nil {
			t.Fatal(err)
		}
		e, id = f.env, status.VaultID
	} else {
		f := ledgerEnrollmentReadyForNetwork(t, tier == "advanced", network)
		status := f.finish(t)
		e = &env{svc: f.svc, ledger: f.ledger, dbPath: f.dbPath, hot: f.hot, p256: f.pass, direct: f.signer.direct, credID: mustDecode(t, f.request.CredentialID)}
		id = status.VaultID
	}
	tree, err := e.svc.buildVtxoPolicyTree(id, e.svc.snapshot(id))
	if err != nil {
		t.Fatal(err)
	}
	context, err := e.svc.spendingRenewalContext(id)
	if err != nil {
		t.Fatal(err)
	}
	c := renewalContract{context}
	plan := spendingRenewalPlan{OperationID: strings.Repeat("18", 16), VaultID: c.Binding.VaultID, DescriptorHash: c.DescriptorHash, Txid: strings.Repeat("51", 32), Vout: 3, ValueSats: 80000, ReceiverSats: 79900, FeeSats: 100, FeePolicyDigest: strings.Repeat("67", 32), RegisterExpireAt: time.Now().Add(time.Minute).Unix()}
	session, _ := btcec.NewPrivateKey()
	message, err := (intent.RegisterMessage{BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister}, OnchainOutputIndexes: []int{}, ExpireAt: plan.RegisterExpireAt, CosignersPublicKeys: []string{hex.EncodeToString(session.PubKey().SerializeCompressed())}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return spendingRenewalProofFixture{e, plan, c, tree, e.hot, message}
}
func (f spendingRenewalProofFixture) proof(t *testing.T) *psbt.Packet {
	t.Helper()
	hash, err := chainhash.NewHashFromStr(f.plan.Txid)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := intent.New(f.message, []intent.Input{{OutPoint: &wire.OutPoint{Hash: *hash, Index: f.plan.Vout}, Sequence: wire.MaxTxInSequenceNum, WitnessUtxo: &wire.TxOut{Value: f.plan.ValueSats, PkScript: f.tree.PkScript}}}, []*wire.TxOut{{Value: f.plan.ReceiverSats, PkScript: f.tree.PkScript}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range proof.Inputs {
		proof.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{ControlBlock: f.tree.SpendControl, Script: f.tree.SpendLeaf, LeafVersion: txscript.BaseLeafVersion}}
		if i == 1 {
			if err := txutils.SetArkPsbtField(&proof.Packet, i, txutils.VtxoTaprootTreeField, txutils.TapTree(f.tree.RevealedScripts)); err != nil {
				t.Fatal(err)
			}
		}
		sig, err := signTapLeafAtWithSighash(&proof.Packet, i, f.owner, f.tree.SpendLeaf, txscript.SigHashAll)
		if err != nil {
			t.Fatal(err)
		}
		proof.Inputs[i].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
	}
	return &proof.Packet
}
func TestSpendingRenewalRegistrationBindsOwnerAndSameWallet(t *testing.T) {
	f := newSpendingRenewalProofFixture(t)
	raw, err := f.proof(t).B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifyRenewalRegistration(raw, f.message, f.plan, f.contract, 0, f.plan.RegisterExpireAt, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := f.plan.digestForContract(f.contract)
	if err != nil || !bytes.Equal(result.PlanDigest, digest) || len(result.RequestDigest) != 32 || len(result.TreeSession) != 33 || result.CanonicalPSBT != raw {
		t.Fatal("renewal binding changed")
	}
	// Renewed principal is not a recipient payment and can exceed the payment cap.
	if f.plan.ReceiverSats <= f.contract.Binding.SpendingPolicy.TxRecipientCapSats {
		t.Fatal("fixture does not exercise full-balance renewal")
	}
	for name, mutate := range map[string]func(*spendingRenewalPlan){
		"wallet":     func(p *spendingRenewalPlan) { p.VaultID = strings.Repeat("aa", 32) },
		"descriptor": func(p *spendingRenewalPlan) { p.DescriptorHash = strings.Repeat("aa", 32) },
		"outpoint":   func(p *spendingRenewalPlan) { p.Vout++ },
		"principal":  func(p *spendingRenewalPlan) { p.ValueSats++ },
		"receiver":   func(p *spendingRenewalPlan) { p.ReceiverSats--; p.FeeSats++ },
		"expiry":     func(p *spendingRenewalPlan) { p.RegisterExpireAt++ },
		"fee cap":    func(p *spendingRenewalPlan) { p.FeeSats = 5001; p.ReceiverSats = p.ValueSats - p.FeeSats },
	} {
		t.Run(name, func(t *testing.T) {
			p := f.plan
			mutate(&p)
			if _, err := verifyRenewalRegistration(raw, f.message, p, f.contract, 0, p.RegisterExpireAt, nil); err == nil {
				t.Fatal("changed renewal accepted")
			}
		})
	}
}
func TestSpendingRenewalRejectsPaymentAndProofSubstitution(t *testing.T) {
	f := newSpendingRenewalProofFixture(t)
	for name, mutate := range map[string]func(*psbt.Packet){
		"missing owner":     func(p *psbt.Packet) { p.Inputs[1].TaprootScriptSpendSig = nil },
		"synthetic owner":   func(p *psbt.Packet) { p.Inputs[0].TaprootScriptSpendSig = nil },
		"external receiver": func(p *psbt.Packet) { p.UnsignedTx.TxOut[0].PkScript = []byte{txscript.OP_TRUE} },
		"another output": func(p *psbt.Packet) {
			p.UnsignedTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{txscript.OP_TRUE}})
			p.Outputs = append(p.Outputs, psbt.POutput{})
		},
		"amount":           func(p *psbt.Packet) { p.Inputs[1].WitnessUtxo.Value++ },
		"synthetic amount": func(p *psbt.Packet) { p.Inputs[0].WitnessUtxo.Value = 1 },
		"sequence":         func(p *psbt.Packet) { p.UnsignedTx.TxIn[1].Sequence-- },
		"sighash":          func(p *psbt.Packet) { p.Inputs[1].SighashType = txscript.SigHashSingle },
		"tree":             func(p *psbt.Packet) { p.Inputs[1].Unknowns = nil },
		"message":          func(p *psbt.Packet) { p.Unknowns[0].Value = []byte("other") },
	} {
		t.Run(name, func(t *testing.T) {
			p := f.proof(t)
			mutate(p)
			raw, err := p.B64Encode()
			if err != nil {
				return
			}
			if _, err := verifyRenewalRegistration(raw, f.message, f.plan, f.contract, 0, f.plan.RegisterExpireAt, nil); err == nil {
				t.Fatal("invalid renewal accepted")
			}
		})
	}
}
