package provider

import (
	"bytes"
	"fmt"

	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

// verifyPhoneRoutineSignature requires a BIP342 SIGHASH_DEFAULT signature
// from the enrolled PhoneRoutineBIP340 key over the exact routine leaf and
// transaction. This browser-held software key is independent of WebAuthn and
// PhoneDirectP256; it is not an authenticator-resident Bitcoin key.
func verifyPhoneRoutineSignature(ptx *psbt.Packet, op *vault.Built) error {
	if op == nil || op.Leaves.Routine == nil || op.Record.PhoneRoutineBIP340 == nil {
		return fmt.Errorf("operational vault not ready")
	}
	if ptx.Inputs[0].WitnessUtxo == nil {
		return fmt.Errorf("missing witness utxo")
	}
	wantPub := schnorr.SerializePubKey(op.Record.PhoneRoutineBIP340)
	wantLeaf := op.Leaves.Routine.Hash
	if len(ptx.Inputs[0].TaprootScriptSpendSig) != 1 || ptx.Inputs[0].TaprootScriptSpendSig[0] == nil {
		return fmt.Errorf("expected exactly one PhoneRoutineBIP340 signature")
	}
	s := ptx.Inputs[0].TaprootScriptSpendSig[0]
	if !bytes.Equal(s.XOnlyPubKey, wantPub) || !bytes.Equal(s.LeafHash, wantLeaf) {
		return fmt.Errorf("unexpected taproot signature")
	}
	if s.SigHash != txscript.SigHashDefault {
		return fmt.Errorf("PhoneRoutineBIP340 signature sighash")
	}
	sig := s.Signature
	if len(sig) != 64 {
		return fmt.Errorf("missing PhoneRoutineBIP340 signature")
	}
	prev := ptx.Inputs[0].WitnessUtxo
	fetcher := vault.NewPrevFetcher(ptx.UnsignedTx.TxIn[0].PreviousOutPoint, prev)
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)
	leaf := txscript.NewBaseTapLeaf(op.Leaves.Routine.Script)
	digest, err := txscript.CalcTapscriptSignaturehash(
		sigHashes, txscript.SigHashDefault, ptx.UnsignedTx, 0, fetcher, leaf,
	)
	if err != nil {
		return fmt.Errorf("PhoneRoutineBIP340 sighash: %w", err)
	}
	parsed, err := schnorr.ParseSignature(sig)
	if err != nil {
		return fmt.Errorf("PhoneRoutineBIP340 signature: %w", err)
	}
	pub, err := schnorr.ParsePubKey(wantPub)
	if err != nil {
		return err
	}
	if !parsed.Verify(digest, pub) {
		return fmt.Errorf("PhoneRoutineBIP340 signature invalid")
	}
	return nil
}
