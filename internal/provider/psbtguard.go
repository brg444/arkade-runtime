package provider

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
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
	prev := submitted.Inputs[0].WitnessUtxo
	fetcher := vault.NewPrevFetcher(submitted.UnsignedTx.TxIn[0].PreviousOutPoint, prev)
	digest, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(submitted.UnsignedTx, fetcher),
		txscript.SigHashDefault, submitted.UnsignedTx, 0, fetcher, leaf,
	)
	if err != nil {
		return err
	}
	sig, err := schnorr.ParseSignature(found.Signature)
	if err != nil {
		return err
	}
	pub, err := schnorr.ParsePubKey(expectedXOnly)
	if err != nil {
		return err
	}
	if !sig.Verify(digest, pub) {
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
