package allowancedraft

import (
	"testing"
	"time"

	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// Even if the public emulator adds its forfeit signature using an earlier
// proof, a new Guardian signature is required at the Operator admission gate.
// This is a closure/signature regression, not a claim that the public
// SubmitFinalization replay has been exercised against a running service.
func TestRollingRenewalRequiresFreshGuardianForfeit(t *testing.T) {
	_, c, paid, _, _ := nativeRollingPayment(t)
	source := rolling.Source{Previous: paid.Transaction.UnsignedTx}
	now := time.Now().Unix()
	registration, err := rolling.BuildRenewal(c, []rolling.Source{source}, HistoryProof{}, 0, now, now+600)
	check(t, err)
	emu := arkade.ComputeArkadeScriptPrivateKey(privateKey(3), arkade.ArkadeScriptHash(c.Programs.Renew))
	signPacketSkipping(t, &registration.Proof.Packet, []*btcec.PublicKey{testKey(4)}, privateKey(2), emu)

	connector := wire.OutPoint{Hash: chainhash.Hash{19}, Index: 0}
	forfeit, err := tree.BuildForfeitTx(
		[]*wire.OutPoint{{Hash: source.Previous.TxHash(), Index: source.Index}, &connector},
		[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
		[]*wire.TxOut{source.Previous.TxOut[0], wire.NewTxOut(330, c.PkScript)}, c.PkScript, 0,
	)
	check(t, err)
	forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{c.Renew}
	fetch, err := txutils.GetPrevOutputFetcher(forfeit)
	check(t, err)
	hashes := txscript.NewTxSigHashes(forfeit.UnsignedTx, fetch)
	leaf := txscript.NewBaseTapLeaf(c.Renew.Script)
	hash := leaf.TapHash()
	sign := func(key *btcec.PrivateKey) *psbt.TaprootScriptSpendSig {
		sig, err := txscript.RawTxInTapscriptSignature(forfeit.UnsignedTx, hashes, 0, forfeit.Inputs[0].WitnessUtxo.Value, forfeit.Inputs[0].WitnessUtxo.PkScript, leaf, txscript.SigHashDefault, key)
		check(t, err)
		return &psbt.TaprootScriptSpendSig{XOnlyPubKey: schnorr.SerializePubKey(key.PubKey()), LeafHash: hash[:], Signature: sig, SigHash: txscript.SigHashDefault}
	}
	emuSig := sign(emu)
	forfeit.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{emuSig}
	verify := func() error {
		_, err := scriptlib.VerifyTapscriptSigs(forfeit, fetch, scriptlib.WithSkipPublicKeys(testKey(4)))
		return err
	}
	if err = verify(); err == nil {
		t.Fatal("emulator-only forfeit accepted")
	}
	forfeit.Inputs[0].TaprootScriptSpendSig = append(forfeit.Inputs[0].TaprootScriptSpendSig, registration.Proof.Inputs[1].TaprootScriptSpendSig[0])
	if err = verify(); err == nil {
		t.Fatal("registration Guardian signature transferred to forfeit")
	}
	forfeit.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{emuSig, sign(privateKey(2))}
	check(t, verify())
}
