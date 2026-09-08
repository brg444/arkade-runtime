package allowancedraft

import (
	"bytes"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// This verifies the ordinary Bitcoin leaf threshold. It does not exercise
// native VTXO checkpoints, the emulator signing API, or intent finalization.
func TestBitcoinSpendRequiresAllFourSigners(t *testing.T) {
	f := newFixture(t)
	f.spend(State{10000, 5}, []int64{20000}, 1000, 100)
	check(t, f.evaluate(true, nil))
	key := func(n byte) *btcec.PrivateKey {
		priv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{n}, 32))
		return priv
	}
	keys := []*btcec.PrivateKey{key(1), key(2), arkade.ComputeArkadeScriptPrivateKey(key(3), arkade.ArkadeScriptHash(f.scripts.Spend)), key(4)}
	leaf := f.leaves[0]
	hashes := txscript.NewTxSigHashes(f.tx, f)
	for i, in := range f.tx.TxIn {
		prev := f.FetchPrevOutput(in.PreviousOutPoint)
		var witness wire.TxWitness
		for k := len(keys) - 1; k >= 0; k-- {
			sig, err := txscript.RawTxInTapscriptSignature(f.tx, hashes, i, prev.Value, prev.PkScript, txscript.NewBaseTapLeaf(leaf.Script), txscript.SigHashDefault, keys[k])
			check(t, err)
			witness = append(witness, sig)
		}
		f.tx.TxIn[i].Witness = append(witness, leaf.Script, leaf.ControlBlock)
	}
	verify := func(tx *wire.MsgTx, index int) error {
		prev := f.FetchPrevOutput(tx.TxIn[index].PreviousOutPoint)
		vm, err := txscript.NewEngine(prev.PkScript, tx, index, txscript.StandardVerifyFlags, nil, txscript.NewTxSigHashes(tx, f), prev.Value, f)
		if err != nil {
			return err
		}
		return vm.Execute()
	}
	for i := range f.tx.TxIn {
		check(t, verify(f.tx, i))
	}
	for index, name := range []string{"Operator", "emulator", "Guardian", "user"} {
		t.Run("missing "+name, func(t *testing.T) {
			tx := f.tx.Copy()
			tx.TxIn[0].Witness[index] = nil
			if err := verify(tx, 0); err == nil {
				t.Fatalf("payment passed without %s", name)
			}
		})
	}
	t.Run("recipient substitution after signing", func(t *testing.T) {
		tx := f.tx.Copy()
		tx.TxOut[1].Value++
		if err := verify(tx, 0); err == nil {
			t.Fatal("modified payment retained valid signatures")
		}
	})
}
