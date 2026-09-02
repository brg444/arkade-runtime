package application

import (
	"context"
	"fmt"
	"reflect"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

// Signer adds the tweaked Provider signature after the Arkade script succeeds.
type Signer interface {
	Sign(ctx context.Context, ptx *psbt.Packet) (*psbt.Packet, error)
}

// LocalSigner is the policy-agnostic final-sign primitive. It runs only inside
// the protected authorizer process after Service has validated policy and
// durably reserved allowance; it is never a network service. The script binds
// the packet witness to the current Arkade sighash, while this primitive does
// not verify WebAuthn or enforce budget.
type LocalSigner struct {
	Priv *btcec.PrivateKey
}

func (s LocalSigner) Sign(_ context.Context, ptx *psbt.Packet) (*psbt.Packet, error) {
	if s.Priv == nil {
		return nil, fmt.Errorf("local signer missing private key")
	}
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("exactly one input required")
	}
	if ptx.Inputs[0].WitnessUtxo == nil {
		return nil, fmt.Errorf("witness utxo required")
	}
	if len(ptx.Inputs[0].TaprootLeafScript) == 0 || ptx.Inputs[0].TaprootLeafScript[0] == nil {
		return nil, fmt.Errorf("taproot leaf script required")
	}
	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return nil, err
	}
	if len(packet) != 1 {
		return nil, fmt.Errorf("expected one emulator entry")
	}
	script, err := arkade.ReadArkadeScript(ptx, s.Priv.PubKey(), packet[0])
	if err != nil {
		return nil, err
	}
	prevTx, err := vault.RequireVerifiedPrevout(ptx)
	if err != nil {
		return nil, err
	}
	prev := ptx.Inputs[0].WitnessUtxo
	fetcher := vault.NewPrevFetcher(ptx.UnsignedTx.TxIn[0].PreviousOutPoint, prev).WithPrevTx(prevTx)
	if err := script.Execute(ptx.UnsignedTx, fetcher, 0); err != nil {
		return nil, fmt.Errorf("arkade script: %w", err)
	}

	tweak := script.Hash()
	key := arkade.ComputeArkadeScriptPrivateKey(s.Priv, tweak)
	if key == nil {
		return nil, fmt.Errorf("arkade tweak is degenerate")
	}
	defer key.Key.Zero()
	if ptx.Inputs[0].SighashType != txscript.SigHashDefault {
		return nil, fmt.Errorf("unsupported sighash")
	}
	if err := arkade.VerifyTaprootLeafCommitment(prev.PkScript, ptx.Inputs[0].TaprootLeafScript[0]); err != nil {
		return nil, err
	}
	leaf := txscript.NewBaseTapLeaf(ptx.Inputs[0].TaprootLeafScript[0].Script)
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)
	sig, err := txscript.RawTxInTapscriptSignature(
		ptx.UnsignedTx, sigHashes, 0, prev.Value, prev.PkScript, leaf, txscript.SigHashDefault, key,
	)
	if err != nil {
		return nil, err
	}
	if len(sig) == 65 {
		sig = sig[:64]
	}
	h := leaf.TapHash()
	ptx.Inputs[0].TaprootScriptSpendSig = append(ptx.Inputs[0].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
		Signature:   sig,
		XOnlyPubKey: schnorr.SerializePubKey(key.PubKey()),
		LeafHash:    h[:],
		SigHash:     txscript.SigHashDefault,
	})
	return ptx, nil
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
