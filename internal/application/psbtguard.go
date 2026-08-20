package application

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// signExactStage gives one signer a clone of the exact stored stage, imports
// only its single valid expected signature, and discards every other response
// mutation. This wrapper protects both the in-process primitive and the
// hostile public Emulator response with the same delta invariant.
type expectedKeySigner interface {
	SignExpected(ctx context.Context, ptx *psbt.Packet, expectedXOnly []byte) (*psbt.Packet, error)
}

func signWithExpected(ctx context.Context, signer Signer, ptx *psbt.Packet, expectedXOnly []byte) (*psbt.Packet, error) {
	if es, ok := signer.(expectedKeySigner); ok {
		return es.SignExpected(ctx, ptx, expectedXOnly)
	}
	return signer.Sign(ctx, ptx)
}

func parsePSBT(raw string) (*psbt.Packet, error) {
	if raw == "" {
		return nil, fmt.Errorf("psbt required")
	}
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	if err != nil {
		return nil, fmt.Errorf("psbt: %w", err)
	}
	if ptx == nil || ptx.UnsignedTx == nil {
		return nil, fmt.Errorf("psbt required")
	}
	if len(ptx.Inputs) != len(ptx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("psbt input count")
	}
	return ptx, nil
}

func signExactStage(
	ctx context.Context,
	stored string,
	signer Signer,
	expectedXOnly []byte,
	role string,
) (string, error) {
	if isNilInterface(signer) {
		return "", fmt.Errorf("%s signer required", role)
	}
	submitted, _, err := parseAndVerifyPrevout(stored)
	if err != nil {
		return "", fmt.Errorf("%s stored stage: %w", role, err)
	}
	work, err := clonePacket(submitted)
	if err != nil {
		return "", err
	}
	response, err := signWithExpected(ctx, signer, work, expectedXOnly)
	if err != nil {
		return "", fmt.Errorf("%s: %w", role, err)
	}
	added, err := extractVerifiedSignerSig(submitted, response, expectedXOnly)
	if err != nil {
		return "", fmt.Errorf("%s response: %w", role, err)
	}
	out, err := clonePacket(submitted)
	if err != nil {
		return "", err
	}
	out.Inputs[0].TaprootScriptSpendSig = append(out.Inputs[0].TaprootScriptSpendSig, added)
	return out.B64Encode()
}

// signExactArkStage adds exactly one TaprootScriptSpendSig for expectedXOnly
// on every input whose collaborative leaf commits that key. It does not call
// parseAndVerifyPrevout / RequireVerifiedPrevout and does not assume a
// single input. Existing signatures are left untouched.
func signExactArkStage(
	ctx context.Context,
	stored string,
	priv *btcec.PrivateKey,
	expectedXOnly []byte,
	expectedLeaf []byte,
) (string, error) {
	return signExactArkStageWithSighash(ctx, stored, priv, expectedXOnly, expectedLeaf, txscript.SigHashDefault)
}

func signExactArkStageWithSighash(
	ctx context.Context,
	stored string,
	priv *btcec.PrivateKey,
	expectedXOnly []byte,
	expectedLeaf []byte,
	wantSigHash txscript.SigHashType,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if priv == nil {
		return "", fmt.Errorf("vtxo vault cosigner required")
	}
	if len(expectedXOnly) != 32 {
		return "", fmt.Errorf("expected signer x-only key")
	}
	if !bytes.Equal(schnorr.SerializePubKey(priv.PubKey()), expectedXOnly) {
		return "", fmt.Errorf("signer key mismatch")
	}
	submitted, err := parsePSBT(stored)
	if err != nil {
		return "", err
	}
	if len(submitted.UnsignedTx.TxIn) == 0 {
		return "", fmt.Errorf("psbt input required")
	}
	work, err := clonePacket(submitted)
	if err != nil {
		return "", err
	}
	out, err := clonePacket(submitted)
	if err != nil {
		return "", err
	}
	if len(expectedLeaf) == 0 {
		return "", fmt.Errorf("expected leaf required")
	}
	signed := 0
	for i := range work.Inputs {
		in := work.Inputs[i]
		if len(in.TaprootLeafScript) != 1 || in.TaprootLeafScript[0] == nil {
			return "", fmt.Errorf("exactly one tapleaf required")
		}
		leaf := in.TaprootLeafScript[0]
		if !bytes.Equal(leaf.Script, expectedLeaf) {
			return "", fmt.Errorf("unexpected tapleaf")
		}
		if in.SighashType != wantSigHash {
			return "", fmt.Errorf("unexpected input sighash")
		}
		added, err := signTapLeafAtWithSighash(work, i, priv, expectedLeaf, wantSigHash)
		if err != nil {
			return "", err
		}
		if err := verifySchnorrOnInputWithSighash(submitted, i, added.Signature, expectedXOnly, expectedLeaf, wantSigHash); err != nil {
			return "", fmt.Errorf("vtxo vault signature invalid")
		}
		out.Inputs[i].TaprootScriptSpendSig = append(out.Inputs[i].TaprootScriptSpendSig, added)
		signed++
	}
	if signed == 0 {
		return "", fmt.Errorf("collaborative leaf missing")
	}
	return out.B64Encode()
}

// signExactStageAt inserts one expected Taproot script-spend signature at
// inputIndex. It does not assume len(TxIn)==1 and does not call
// parseAndVerifyPrevout.
func signExactStageAt(
	ctx context.Context,
	stored string,
	priv *btcec.PrivateKey,
	expectedXOnly []byte,
	inputIndex int,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if priv == nil {
		return "", fmt.Errorf("signer required")
	}
	if len(expectedXOnly) != 32 {
		return "", fmt.Errorf("expected signer x-only key")
	}
	if !bytes.Equal(schnorr.SerializePubKey(priv.PubKey()), expectedXOnly) {
		return "", fmt.Errorf("signer key mismatch")
	}
	submitted, err := parsePSBT(stored)
	if err != nil {
		return "", err
	}
	if inputIndex < 0 || inputIndex >= len(submitted.Inputs) {
		return "", fmt.Errorf("input index")
	}
	in := submitted.Inputs[inputIndex]
	if in.WitnessUtxo == nil || len(in.TaprootLeafScript) != 1 || in.TaprootLeafScript[0] == nil {
		return "", fmt.Errorf("submitted input missing leaf commitment")
	}
	leafScript := in.TaprootLeafScript[0].Script
	added, err := signTapLeafAt(submitted, inputIndex, priv, leafScript)
	if err != nil {
		return "", err
	}
	if err := verifySchnorrOnInput(submitted, inputIndex, added.Signature, expectedXOnly, leafScript); err != nil {
		return "", fmt.Errorf("signer signature invalid")
	}
	out, err := clonePacket(submitted)
	if err != nil {
		return "", err
	}
	out.Inputs[inputIndex].TaprootScriptSpendSig = append(out.Inputs[inputIndex].TaprootScriptSpendSig, added)
	return out.B64Encode()
}

func collaborativeLeafAt(ptx *psbt.Packet, idx int, expectedXOnly []byte) *psbt.TaprootTapLeafScript {
	if ptx == nil || idx < 0 || idx >= len(ptx.Inputs) {
		return nil
	}
	in := ptx.Inputs[idx]
	if in.WitnessUtxo == nil {
		return nil
	}
	for _, leaf := range in.TaprootLeafScript {
		if leaf == nil {
			continue
		}
		closure, err := decodeMultisigLeaf(leaf.Script)
		if err != nil || closure == nil {
			continue
		}
		for _, pub := range closure.PubKeys {
			if pub != nil && bytes.Equal(schnorr.SerializePubKey(pub), expectedXOnly) {
				return leaf
			}
		}
	}
	return nil
}

func decodeMultisigLeaf(script []byte) (*txscriptMultisig, error) {
	if len(script) == 0 {
		return nil, fmt.Errorf("leaf script")
	}
	// arkscript is imported by callers via vtxo_tree; keep this helper local
	// by using the same DecodeClosure path through a thin wrapper below.
	return decodeArkMultisig(script)
}

type txscriptMultisig struct {
	PubKeys []*btcec.PublicKey
}

func decodeArkMultisig(script []byte) (*txscriptMultisig, error) {
	closure, err := arkscript.DecodeClosure(script)
	if err != nil {
		return nil, err
	}
	switch c := closure.(type) {
	case *arkscript.MultisigClosure:
		return &txscriptMultisig{PubKeys: c.PubKeys}, nil
	case *arkscript.CSVMultisigClosure:
		return &txscriptMultisig{PubKeys: c.PubKeys}, nil
	case *arkscript.CLTVMultisigClosure:
		return &txscriptMultisig{PubKeys: c.PubKeys}, nil
	default:
		return nil, fmt.Errorf("not a collaborative leaf")
	}
}

func signTapLeafAt(ptx *psbt.Packet, idx int, priv *btcec.PrivateKey, leafScript []byte) (*psbt.TaprootScriptSpendSig, error) {
	return signTapLeafAtWithSighash(ptx, idx, priv, leafScript, txscript.SigHashDefault)
}

func signTapLeafAtWithSighash(ptx *psbt.Packet, idx int, priv *btcec.PrivateKey, leafScript []byte, sigHash txscript.SigHashType) (*psbt.TaprootScriptSpendSig, error) {
	if ptx == nil || idx < 0 || idx >= len(ptx.Inputs) || idx >= len(ptx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("input index")
	}
	prev := ptx.Inputs[idx].WitnessUtxo
	if prev == nil {
		return nil, fmt.Errorf("witness utxo required")
	}
	fetcher := multiWitnessFetcher(ptx)
	leaf := txscript.NewBaseTapLeaf(leafScript)
	sig, err := txscript.RawTxInTapscriptSignature(
		ptx.UnsignedTx, txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher),
		idx, prev.Value, prev.PkScript, leaf, sigHash, priv,
	)
	if err != nil {
		return nil, err
	}
	if len(sig) == 65 {
		sig = sig[:64]
	}
	h := leaf.TapHash()
	return &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: schnorr.SerializePubKey(priv.PubKey()),
		LeafHash:    h[:],
		Signature:   sig,
		SigHash:     sigHash,
	}, nil
}

func verifySchnorrOnInput(ptx *psbt.Packet, idx int, sig, wantXOnly, leafScript []byte) error {
	return verifySchnorrOnInputWithSighash(ptx, idx, sig, wantXOnly, leafScript, txscript.SigHashDefault)
}

func verifySchnorrOnInputWithSighash(ptx *psbt.Packet, idx int, sig, wantXOnly, leafScript []byte, sigHash txscript.SigHashType) error {
	if ptx == nil || ptx.UnsignedTx == nil || idx < 0 || idx >= len(ptx.Inputs) || idx >= len(ptx.UnsignedTx.TxIn) {
		return fmt.Errorf("input index")
	}
	if len(sig) != 64 {
		return fmt.Errorf("signature length")
	}
	prev := ptx.Inputs[idx].WitnessUtxo
	if prev == nil {
		return fmt.Errorf("witness utxo required")
	}
	fetcher := multiWitnessFetcher(ptx)
	digest, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher),
		sigHash, ptx.UnsignedTx, idx, fetcher, txscript.NewBaseTapLeaf(leafScript),
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

func multiWitnessFetcher(ptx *psbt.Packet) txscript.PrevOutputFetcher {
	prevs := make(map[wire.OutPoint]*wire.TxOut, len(ptx.Inputs))
	for i, in := range ptx.UnsignedTx.TxIn {
		if i < len(ptx.Inputs) && ptx.Inputs[i].WitnessUtxo != nil {
			prevs[in.PreviousOutPoint] = ptx.Inputs[i].WitnessUtxo
		}
	}
	return txscript.NewMultiPrevOutFetcher(prevs)
}

func verifyExactRoutineSignatures(ptx *psbt.Packet, op *vault.Built, pubs ...*btcec.PublicKey) error {
	if ptx == nil || ptx.UnsignedTx == nil || op == nil || op.Leaves.Routine == nil || len(ptx.Inputs) != 1 || len(ptx.UnsignedTx.TxIn) != 1 {
		return fmt.Errorf("routine signature stage inputs")
	}
	if len(pubs) == 0 || len(ptx.Inputs[0].TaprootScriptSpendSig) != len(pubs) {
		return fmt.Errorf("expected exactly %d routine signatures", len(pubs))
	}
	if ptx.Inputs[0].WitnessUtxo == nil || len(ptx.Inputs[0].TaprootLeafScript) != 1 || ptx.Inputs[0].TaprootLeafScript[0] == nil {
		return fmt.Errorf("routine leaf commitment required")
	}
	leaf := txscript.NewBaseTapLeaf(op.Leaves.Routine.Script)
	leafHash := leaf.TapHash()
	expected := make(map[string][]byte, len(pubs))
	for _, pub := range pubs {
		if pub == nil {
			return fmt.Errorf("routine signer key required")
		}
		xonly := schnorr.SerializePubKey(pub)
		if _, duplicate := expected[string(xonly)]; duplicate {
			return fmt.Errorf("duplicate routine signer identity")
		}
		expected[string(xonly)] = xonly
	}
	for _, sig := range ptx.Inputs[0].TaprootScriptSpendSig {
		if sig == nil || sig.SigHash != txscript.SigHashDefault || !bytes.Equal(sig.LeafHash, leafHash[:]) {
			return fmt.Errorf("malformed routine signature")
		}
		xonly, ok := expected[string(sig.XOnlyPubKey)]
		if !ok {
			return fmt.Errorf("unexpected or duplicate routine signature")
		}
		if err := verifySignerSig(ptx, sig, xonly, leaf); err != nil {
			return err
		}
		delete(expected, string(sig.XOnlyPubKey))
	}
	if len(expected) != 0 {
		return fmt.Errorf("missing routine signature")
	}
	return nil
}

func clonePacket(p *psbt.Packet) (*psbt.Packet, error) {
	if p == nil {
		return nil, fmt.Errorf("psbt required")
	}
	encoded, err := p.B64Encode()
	if err != nil {
		return nil, err
	}
	return psbt.NewFromRawBytes(strings.NewReader(encoded), true)
}

func cloneSpendSig(s *psbt.TaprootScriptSpendSig) *psbt.TaprootScriptSpendSig {
	if s == nil {
		return nil
	}
	return &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: append([]byte(nil), s.XOnlyPubKey...),
		LeafHash:    append([]byte(nil), s.LeafHash...),
		Signature:   append([]byte(nil), s.Signature...),
		SigHash:     s.SigHash,
	}
}

// extractVerifiedSignerSig returns the single new expected Taproot script
// spend signature from a signer response. Verification is against the
// immutable submitted packet, not the response's possibly mutated fields.
func extractVerifiedSignerSig(submitted, response *psbt.Packet, expectedXOnly []byte) (*psbt.TaprootScriptSpendSig, error) {
	if submitted == nil || submitted.UnsignedTx == nil || len(submitted.Inputs) != 1 || len(submitted.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("exactly one submitted input required")
	}
	if response == nil || response.UnsignedTx == nil || len(response.Inputs) != 1 || len(response.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("malformed signed psbt")
	}
	if len(expectedXOnly) != 32 {
		return nil, fmt.Errorf("expected signer x-only key")
	}
	in := submitted.Inputs[0]
	if in.WitnessUtxo == nil || len(in.TaprootLeafScript) != 1 || in.TaprootLeafScript[0] == nil {
		return nil, fmt.Errorf("submitted input missing leaf commitment")
	}
	leaf := txscript.NewBaseTapLeaf(in.TaprootLeafScript[0].Script)
	leafHash := leaf.TapHash()

	var extras []*psbt.TaprootScriptSpendSig
	matched := make([]bool, len(in.TaprootScriptSpendSig))
	for _, s := range response.Inputs[0].TaprootScriptSpendSig {
		if i := indexOriginalSig(in.TaprootScriptSpendSig, s); i >= 0 && !matched[i] {
			matched[i] = true
			continue
		}
		extras = append(extras, s)
	}

	var found *psbt.TaprootScriptSpendSig
	for _, extra := range extras {
		if extra == nil || len(extra.Signature) != 64 {
			continue
		}
		if !bytes.Equal(extra.XOnlyPubKey, expectedXOnly) {
			continue
		}
		if !bytes.Equal(extra.LeafHash, leafHash[:]) {
			continue
		}
		if extra.SigHash != txscript.SigHashDefault {
			continue
		}
		if err := verifySignerSig(submitted, extra, expectedXOnly, leaf); err != nil {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("expected exactly one new signer signature, got extra")
		}
		found = extra
	}
	if found == nil {
		return nil, fmt.Errorf("expected exactly one new signer signature")
	}
	return cloneSpendSig(found), nil
}

func verifySignerSig(submitted *psbt.Packet, found *psbt.TaprootScriptSpendSig, expectedXOnly []byte, leaf txscript.TapLeaf) error {
	if err := vault.VerifySchnorrOnSubmittedTx(submitted, found.Signature, expectedXOnly, leaf.Script); err != nil {
		return fmt.Errorf("signer signature invalid")
	}
	return nil
}

func indexOriginalSig(before []*psbt.TaprootScriptSpendSig, s *psbt.TaprootScriptSpendSig) int {
	if s == nil {
		return -1
	}
	for i, want := range before {
		if want == nil {
			continue
		}
		if bytes.Equal(s.XOnlyPubKey, want.XOnlyPubKey) &&
			bytes.Equal(s.LeafHash, want.LeafHash) &&
			bytes.Equal(s.Signature, want.Signature) &&
			s.SigHash == want.SigHash {
			return i
		}
	}
	return -1
}
