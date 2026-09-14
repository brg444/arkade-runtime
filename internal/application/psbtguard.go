package application

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

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

// signExactVaultBoardStage adds the scoped VaultBoardCosigner signature to
// only the already-validated inputs named by the semantic boarding operation.
// It deliberately cannot discover or select inputs on its own.
func signExactVaultBoardStage(
	ctx context.Context, stored string, priv *btcec.PrivateKey, expectedXOnly, expectedLeaf []byte,
	inputIndexes []int, wantSigHash txscript.SigHashType,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if priv == nil || len(expectedXOnly) != schnorr.PubKeyBytesLen ||
		!bytes.Equal(schnorr.SerializePubKey(priv.PubKey()), expectedXOnly) {
		return "", fmt.Errorf("vault-board-v1 signer key mismatch")
	}
	if len(expectedLeaf) == 0 || len(inputIndexes) == 0 {
		return "", fmt.Errorf("vault-board-v1 authorization required")
	}
	submitted, err := parsePSBT(stored)
	if err != nil {
		return "", err
	}
	work, err := clonePacket(submitted)
	if err != nil {
		return "", err
	}
	out, err := clonePacket(submitted)
	if err != nil {
		return "", err
	}
	seen := make(map[int]struct{}, len(inputIndexes))
	for _, idx := range inputIndexes {
		if idx < 0 || idx >= len(work.Inputs) || idx >= len(work.UnsignedTx.TxIn) {
			return "", fmt.Errorf("vault-board-v1 input index")
		}
		if _, ok := seen[idx]; ok {
			return "", fmt.Errorf("vault-board-v1 duplicate input index")
		}
		seen[idx] = struct{}{}
		in := work.Inputs[idx]
		if len(in.TaprootLeafScript) != 1 || in.TaprootLeafScript[0] == nil ||
			!bytes.Equal(in.TaprootLeafScript[0].Script, expectedLeaf) || in.SighashType != wantSigHash {
			return "", fmt.Errorf("vault-board-v1 collaborative leaf")
		}
		for _, existing := range in.TaprootScriptSpendSig {
			if existing != nil && bytes.Equal(existing.XOnlyPubKey, expectedXOnly) {
				return "", fmt.Errorf("vault-board-v1 signature already present")
			}
		}
		added, err := signTapLeafAtWithSighash(work, idx, priv, expectedLeaf, wantSigHash)
		if err != nil {
			return "", err
		}
		if err := verifySchnorrOnInputWithSighash(submitted, idx, added.Signature, expectedXOnly, expectedLeaf, wantSigHash); err != nil {
			return "", fmt.Errorf("vault-board-v1 signature invalid")
		}
		out.Inputs[idx].TaprootScriptSpendSig = append(out.Inputs[idx].TaprootScriptSpendSig, added)
	}
	return out.B64Encode()
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

// requirePresentDefaultTaprootSignature verifies that the expected signer already has a
// valid DEFAULT signature on the given input of the submitted snapshot.
func requirePresentDefaultTaprootSignature(ptx *psbt.Packet, index int, expectedXOnly, leafScript []byte) error {
	if ptx == nil || index < 0 || index >= len(ptx.Inputs) {
		return fmt.Errorf("input index")
	}
	leaf := txscript.NewBaseTapLeaf(leafScript)
	leafHash := leaf.TapHash()
	for _, existing := range ptx.Inputs[index].TaprootScriptSpendSig {
		if existing == nil || len(existing.Signature) != 64 {
			continue
		}
		if !bytes.Equal(existing.XOnlyPubKey, expectedXOnly) || !bytes.Equal(existing.LeafHash, leafHash[:]) {
			continue
		}
		if existing.SigHash != txscript.SigHashDefault {
			continue
		}
		return verifySchnorrOnInputWithSighash(ptx, index, existing.Signature, expectedXOnly, leafScript, txscript.SigHashDefault)
	}
	return fmt.Errorf("expected signer signature missing")
}
