package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type lightDelegateIntent struct {
	Proof   string `json:"proof"`
	Message string `json:"message"`
}
type lightDelegationRequest struct {
	VaultID        string              `json:"vaultId"`
	OperationID    string              `json:"operationId"`
	Intent         lightDelegateIntent `json:"intent"`
	ForfeitTxs     []string            `json:"forfeitTxs"`
	DeleteIntent   lightDelegateIntent `json:"deleteIntent"`
	ExpiresAt      int64               `json:"expiresAt"`
	OwnerSignature string              `json:"ownerSignature"`
}
type lightDelegationPlan struct {
	Request        lightDelegationRequest `json:"request"`
	Renewal        lightRenewalPlan       `json:"renewal"`
	ValidAt        int64                  `json:"validAt"`
	InputExpiresAt int64                  `json:"inputExpiresAt"`
}

func delegationDigest(domain string, value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte("vaulted-light/delegate-"+domain+"/v1:"), raw...))
	return sum[:], nil
}
func lightDelegationRequestDigest(r lightDelegationRequest) ([]byte, error) {
	return delegationDigest("schedule", struct {
		VaultID      string              `json:"vaultId"`
		OperationID  string              `json:"operationId"`
		Intent       lightDelegateIntent `json:"intent"`
		ForfeitTxs   []string            `json:"forfeitTxs"`
		DeleteIntent lightDelegateIntent `json:"deleteIntent"`
		ExpiresAt    int64               `json:"expiresAt"`
	}{r.VaultID, r.OperationID, r.Intent, r.ForfeitTxs, r.DeleteIntent, r.ExpiresAt})
}
func verifyDelegationOwner(d light.Descriptor, digest []byte, encoded string) error {
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 64 || hex.EncodeToString(raw) != encoded {
		return fmt.Errorf("Light delegation owner signature")
	}
	pub, err := schnorr.ParsePubKey(mustDecodeRenewalHex(d.OwnerPub))
	if err != nil {
		return err
	}
	sig, err := schnorr.ParseSignature(raw)
	if err != nil || !sig.Verify(digest, pub) {
		return fmt.Errorf("Light delegation owner authorization required")
	}
	return nil
}

// Validate the original SDK bytes; neither proof timestamps nor signed outputs
// are rewritten. The separate owner's envelope bounds journal authorization.
func verifyLightDelegationRequest(r lightDelegationRequest, d light.Descriptor, tree *vtxoPolicyTree, forfeitScript []byte) (lightDelegationPlan, error) {
	var out lightDelegationPlan
	if _, err := canonicalVtxoOperationID(r.OperationID); err != nil {
		return out, err
	}
	if r.VaultID != d.VaultID || r.ExpiresAt <= 0 || r.ExpiresAt > (1<<53)-1 || len(r.ForfeitTxs) != 1 {
		return out, fmt.Errorf("Light delegation scope")
	}
	digest, err := lightDelegationRequestDigest(r)
	if err != nil {
		return out, err
	}
	if err := verifyDelegationOwner(d, digest, r.OwnerSignature); err != nil {
		return out, err
	}
	var message intent.RegisterMessage
	if err := message.Decode(r.Intent.Message); err != nil {
		return out, err
	}
	if message.ValidAt <= 0 || message.ValidAt > (1<<53)-1 || r.ExpiresAt <= message.ValidAt || r.ExpiresAt > message.ValidAt+86400 {
		return out, fmt.Errorf("Light delegation lifetime")
	}
	p, err := parseCanonicalVaultBoardPSBT(r.Intent.Proof, maxVaultBoardProofBytes)
	if err != nil {
		return out, err
	}
	if len(p.Inputs) != 2 || len(p.UnsignedTx.TxIn) != 2 || len(p.UnsignedTx.TxOut) != 1 || p.Inputs[1].WitnessUtxo == nil {
		return out, fmt.Errorf("Light delegation requires one output")
	}
	previous := p.UnsignedTx.TxIn[1].PreviousOutPoint
	value := p.Inputs[1].WitnessUtxo.Value
	receiver := p.UnsignedTx.TxOut[0].Value
	hash, err := light.DescriptorDigest(d)
	if err != nil {
		return out, err
	}
	plan := lightRenewalPlan{OperationID: r.OperationID, VaultID: r.VaultID, DescriptorHash: hash, Txid: previous.Hash.String(), Vout: previous.Index, ValueSats: value, ReceiverSats: receiver, FeeSats: value - receiver, FeePolicyDigest: hex.EncodeToString(make([]byte, 32)), RegisterExpireAt: r.ExpiresAt}
	// x-only contracts use the even lift, which must also be the MuSig identity.
	if _, err := verifyLightRegistration(r.Intent.Proof, r.Intent.Message, plan, d, tree, message.ValidAt, r.ExpiresAt, append([]byte{2}, mustDecodeRenewalHex(d.CosignerPub)...)); err != nil {
		return out, err
	}
	if err := verifyDelegatedPartialForfeit(r.ForfeitTxs[0], plan, d, tree, forfeitScript); err != nil {
		return out, err
	}
	if err := verifyLightDelegationDelete(r.DeleteIntent, plan, d, tree); err != nil {
		return out, err
	}
	return lightDelegationPlan{Request: r, Renewal: plan, ValidAt: message.ValidAt}, nil
}
func delegationForfeitScript(network string) ([]byte, error) {
	pins, err := deployment.IdentityFor(network)
	if err != nil {
		return nil, err
	}
	pub := mustDecodeRenewalHex(pins.CheckpointForfeitPubHex)
	return append([]byte{txscript.OP_0, 0x14}, btcutil.Hash160(pub)...), nil
}
func verifyDelegatedPartialForfeit(raw string, p lightRenewalPlan, d light.Descriptor, tree *vtxoPolicyTree, forfeitScript []byte) error {
	tx, err := parseCanonicalVaultBoardPSBT(raw, maxVaultBoardProofBytes)
	if err != nil {
		return err
	}
	if tx.UnsignedTx.Version != 3 || tx.UnsignedTx.LockTime != 0 || len(tx.Inputs) != 1 || len(tx.UnsignedTx.TxIn) != 1 || len(tx.Outputs) != 2 || len(tx.UnsignedTx.TxOut) != 2 || len(tx.Unknowns) != 0 {
		return fmt.Errorf("Light delegated forfeit shape")
	}
	in := tx.UnsignedTx.TxIn[0]
	utxo := tx.Inputs[0].WitnessUtxo
	if in.PreviousOutPoint.Hash.String() != p.Txid || in.PreviousOutPoint.Index != p.Vout || in.Sequence != wire.MaxTxInSequenceNum || utxo == nil || utxo.Value != p.ValueSats || !bytes.Equal(utxo.PkScript, tree.PkScript) {
		return fmt.Errorf("Light delegated forfeit input")
	}
	anchor := txutils.AnchorOutput()
	out := tx.UnsignedTx.TxOut
	// Stock connector is dust=330; its value is committed by the owner before
	// the outpoint exists. Final verification requires that exact connector.
	if out[0].Value != p.ValueSats+330-anchor.Value || !bytes.Equal(out[0].PkScript, forfeitScript) || out[1].Value != anchor.Value || !bytes.Equal(out[1].PkScript, anchor.PkScript) {
		return fmt.Errorf("Light delegated forfeit outputs")
	}
	owner := mustDecodeRenewalHex(d.OwnerPub)
	hash := txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	if err := requireExactLeafWithSighash(tx.Inputs[0], tree.PkScript, tree.SpendLeaf, tree.SpendControl, [][]byte{owner}, hash); err != nil {
		return err
	}
	return requireVerifiedSignersWithSighash(tx, 0, [][]byte{owner}, tree.SpendLeaf, hash)
}

// Delete authorization is BIP-322, with no monetary destination. Zero expiry
// permits queue cleanup after downtime, but only for this exact original input.
func verifyLightDelegationDelete(r lightDelegateIntent, p lightRenewalPlan, d light.Descriptor, tree *vtxoPolicyTree) error {
	var message intent.DeleteMessage
	if err := message.Decode(r.Message); err != nil {
		return err
	}
	canonical, err := message.Encode()
	if err != nil || canonical != r.Message || message.ExpireAt != 0 {
		return fmt.Errorf("Light delegation delete message")
	}
	return verifyLightIntentProof(r.Proof, r.Message, p, d, tree, &wire.TxOut{Value: 0, PkScript: []byte{txscript.OP_RETURN}})
}
