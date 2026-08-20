package application

import (
	"context"
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestSignExactArkStageSignsEachInputWithoutPrevoutVerify(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	closure := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{priv.PubKey()}}
	tree := &arkscript.TapscriptsVtxoScript{Closures: []arkscript.Closure{closure}}
	tapKey, tapTree, err := tree.TapTree()
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := arkscript.P2TRScript(tapKey)
	if err != nil {
		t.Fatal(err)
	}
	script, err := closure.Script()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(script).TapHash())
	if err != nil {
		t.Fatal(err)
	}
	const n = 3
	tx := wire.NewMsgTx(2)
	for i := 0; i < n; i++ {
		var h chainhash.Hash
		h[0] = byte(i + 1)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: h, Index: 0}, Sequence: wire.MaxTxInSequenceNum})
	}
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: pkScript})
	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range packet.Inputs {
		packet.Inputs[i].WitnessUtxo = &wire.TxOut{Value: 2000, PkScript: pkScript}
		packet.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: proof.ControlBlock,
			Script:       script,
			LeafVersion:  txscript.BaseLeafVersion,
		}}
	}
	raw, err := packet.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseAndVerifyPrevout(raw); err == nil {
		t.Fatal("fixture unexpectedly has a verified prevout")
	}
	signed, err := signExactArkStage(context.Background(), raw, priv, schnorr.SerializePubKey(priv.PubKey()), script)
	if err != nil {
		t.Fatal(err)
	}
	out, err := parsePSBT(signed)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Inputs) != n {
		t.Fatalf("inputs = %d", len(out.Inputs))
	}
	for i, in := range out.Inputs {
		if len(in.TaprootScriptSpendSig) != 1 {
			t.Fatalf("input %d sigs = %d", i, len(in.TaprootScriptSpendSig))
		}
		if got := in.TaprootScriptSpendSig[0].XOnlyPubKey; string(got) != string(schnorr.SerializePubKey(priv.PubKey())) {
			t.Fatalf("input %d signed unexpected key", i)
		}
	}
}
