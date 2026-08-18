package application

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sync/atomic"

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

// LocalSigner is the policy-agnostic final-sign primitive. Mutinynet uses it
// only inside the protected authorizer process, after Service has validated
// policy and durably reserved allowance; it is never a network service.
// Regtest tests may also select it explicitly. The script binds the packet
// witness to the current Arkade sighash; this primitive itself does not verify
// WebAuthn or enforce budget.
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

// RemoteSigner calls the private regtest Emulator SubmitOnchainTx endpoint.
// Expected tweaked keys are supplied per SignExpected call. They are never
// stored on the adapter.
type RemoteSigner struct {
	Client    RemoteTransport
	successes atomic.Uint64
}

// RemoteTransport is the regtest-only Emulator method used by RemoteSigner.
// Keeping it narrow prevents the production authorizer from importing gRPC.
type RemoteTransport interface {
	SubmitOnchainTx(context.Context, string) (string, error)
}

// BindExpectedSigner is retained so older callers compile. It must not store
// a process-wide expected key; SignExpected receives the key per call.
func (s *RemoteSigner) BindExpectedSigner([]byte) {}

// BindExpectedProvider is retained for the regtest demo compatibility layer.
func (s *RemoteSigner) BindExpectedProvider(expected []byte) {
	s.BindExpectedSigner(expected)
}

// SuccessfulCalls counts responses that passed exact transaction and pinned
// signer-signature verification and were reconstructed as original+sig.
func (s *RemoteSigner) SuccessfulCalls() uint64 {
	if s == nil {
		return 0
	}
	return s.successes.Load()
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

func (s *RemoteSigner) Sign(ctx context.Context, ptx *psbt.Packet) (*psbt.Packet, error) {
	return nil, fmt.Errorf("remote signer expected key must be supplied per call")
}

func (s *RemoteSigner) SignExpected(ctx context.Context, ptx *psbt.Packet, expected []byte) (*psbt.Packet, error) {
	if s == nil {
		return nil, fmt.Errorf("remote signer required")
	}
	if isNilInterface(s.Client) {
		return nil, fmt.Errorf("remote signer missing client")
	}
	if len(expected) != 32 {
		return nil, fmt.Errorf("remote signer missing expected key")
	}
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("exactly one input required")
	}
	for _, sig := range ptx.Inputs[0].TaprootScriptSpendSig {
		if sig != nil && bytes.Equal(sig.XOnlyPubKey, expected) {
			return nil, fmt.Errorf("expected emulator signature is already present")
		}
	}
	encoded, err := ptx.B64Encode()
	if err != nil {
		return nil, err
	}
	signed, err := s.Client.SubmitOnchainTx(ctx, encoded)
	if err != nil {
		return nil, err
	}
	out, err := psbt.NewFromRawBytes(bytes.NewReader([]byte(signed)), true)
	if err != nil {
		return nil, err
	}
	signerSig, err := extractVerifiedSignerSig(ptx, out, expected)
	if err != nil {
		return nil, err
	}
	clone, err := clonePacket(ptx)
	if err != nil {
		return nil, err
	}
	if clone == nil || len(clone.Inputs) != 1 {
		return nil, fmt.Errorf("cloned packet missing input")
	}
	clone.Inputs[0].TaprootScriptSpendSig = append(clone.Inputs[0].TaprootScriptSpendSig, signerSig)
	s.successes.Add(1)
	return clone, nil
}
