package vault

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

// VerifySchnorrOnSubmittedTx hashes the submitted packet's WitnessUtxo
// amount/script and leaf. Callers must bind that prevout with
// RequireVerifiedPrevout before treating a successful verify as authorization.
func VerifySchnorrOnSubmittedTx(ptx *psbt.Packet, sig, wantXOnly, leafScript []byte) error {
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return fmt.Errorf("exactly one submitted input required")
	}
	if len(sig) != 64 {
		return fmt.Errorf("signature length")
	}
	prev := ptx.Inputs[0].WitnessUtxo
	if prev == nil {
		return fmt.Errorf("witness utxo required")
	}
	fetcher := NewPrevFetcher(ptx.UnsignedTx.TxIn[0].PreviousOutPoint, prev)
	digest, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher),
		txscript.SigHashDefault, ptx.UnsignedTx, 0, fetcher, txscript.NewBaseTapLeaf(leafScript),
	)
	if err != nil {
		return err
	}
	parsed, err := schnorr.ParseSignature(sig)
	if err != nil {
		return err
	}
	pub, err := schnorr.ParsePubKey(wantXOnly)
	if err != nil {
		return err
	}
	if !parsed.Verify(digest, pub) {
		return fmt.Errorf("invalid")
	}
	return nil
}
