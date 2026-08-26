package application

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type vaultBoardProofFixture struct {
	tree       *vtxoBoardTree
	boarding   *btcec.PrivateKey
	operation  policy.VaultBoardOperation
	expireAt   int64
	receiver   *wire.TxOut
	treePubHex string
}

func newVaultBoardProofFixture(t *testing.T) vaultBoardProofFixture {
	t.Helper()
	master, _ := btcec.NewPrivateKey()
	emulator, _ := btcec.NewPrivateKey()
	operator, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	phone, _ := btcec.NewPrivateKey()
	keys, err := NewFileBackedKeyCapabilities(master, LocalSigner{Priv: emulator})
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		Deployment: deployment.Config{Network: deployment.NetworkMutinynet},
		keys:       keys,
		ArkResolver: stubArkResolver{
			signer: operator.PubKey().SerializeCompressed(),
		},
	}
	tree, err := svc.buildVtxoBoardTree("vault-proof", enrolledSnapshot{PhoneBIP340: phone.PubKey()}, boarding.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	treeSession, _ := btcec.NewPrivateKey()
	txid := bytes.Repeat([]byte{0x42}, chainhash.HashSize)
	operation := policy.VaultBoardOperation{
		VaultID: "vault-proof", Txid: txid, Vout: 7, ValueSats: 50_000,
		BoardingScript:    append([]byte(nil), tree.PkScript...),
		ReceiverScript:    []byte{0x51, 0x20, 0x01},
		SequenceAnchorMTP: time.Now().Add(-time.Hour).Unix(),
	}
	return vaultBoardProofFixture{
		tree: tree, boarding: boarding, operation: operation,
		expireAt:   time.Now().Add(time.Minute).Unix(),
		receiver:   &wire.TxOut{Value: 49_000, PkScript: append([]byte(nil), operation.ReceiverScript...)},
		treePubHex: hex.EncodeToString(treeSession.PubKey().SerializeCompressed()),
	}
}

func (f vaultBoardProofFixture) proof(t *testing.T, message string, outputs []*wire.TxOut) string {
	t.Helper()
	hash := chainhash.Hash(f.operation.Txid)
	proof, err := intent.New(message, []intent.Input{{
		OutPoint: &wire.OutPoint{Hash: hash, Index: f.operation.Vout},
		Sequence: wire.MaxTxInSequenceNum,
		WitnessUtxo: &wire.TxOut{
			Value: f.operation.ValueSats, PkScript: append([]byte(nil), f.tree.PkScript...),
		},
	}}, outputs)
	if err != nil {
		t.Fatal(err)
	}
	for i := range proof.Inputs {
		proof.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: append([]byte(nil), f.tree.ControlBlock...),
			Script:       append([]byte(nil), f.tree.Collaborative...),
			LeafVersion:  txscript.BaseLeafVersion,
		}}
		if err := txutils.SetArkPsbtField(&proof.Packet, i, txutils.VtxoTaprootTreeField, txutils.TapTree(f.tree.RevealedScripts)); err != nil {
			t.Fatal(err)
		}
		sig, err := signTapLeafAtWithSighash(&proof.Packet, i, f.boarding, f.tree.Collaborative, txscript.SigHashAll)
		if err != nil {
			t.Fatal(err)
		}
		proof.Inputs[i].TaprootScriptSpendSig = append(proof.Inputs[i].TaprootScriptSpendSig, sig)
	}
	encoded, err := proof.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (f vaultBoardProofFixture) registerMessage(t *testing.T) string {
	t.Helper()
	message, err := (intent.RegisterMessage{
		BaseMessage:          intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		OnchainOutputIndexes: []int{}, ValidAt: 0, ExpireAt: f.expireAt,
		CosignersPublicKeys: []string{f.treePubHex},
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func TestVerifyVaultBoardRegisterProofBindsExactIntent(t *testing.T) {
	fixture := newVaultBoardProofFixture(t)
	message := fixture.registerMessage(t)
	raw := fixture.proof(t, message, []*wire.TxOut{fixture.receiver})
	verified, err := verifyVaultBoardRegisterProof(raw, message, fixture.operation, fixture.tree, fixture.expireAt)
	if err != nil {
		t.Fatal(err)
	}
	if verified.ReceiverSats != 49_000 || verified.FeeSats != 1_000 || len(verified.TreeSession) != 33 || len(verified.RequestDigest) != 32 {
		t.Fatalf("verified register = %+v", verified)
	}
	packet, err := parsePSBT(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := vaultBoardIntentRequestDigest(policy.VaultBoardPhaseRegister, packet, message, []int{0, 1})
	if err != nil || !bytes.Equal(digest, verified.RequestDigest) {
		t.Fatalf("request digest mismatch: %x %v", digest, err)
	}
	// Randomized Schnorr encodings are not a durable request identity. The
	// exact unsigned proof semantics remain the same across a retry.
	packet.Inputs[0].TaprootScriptSpendSig[0].Signature[0] ^= 0x01
	retryDigest, err := vaultBoardIntentRequestDigest(policy.VaultBoardPhaseRegister, packet, message, []int{0, 1})
	if err != nil || !bytes.Equal(retryDigest, verified.RequestDigest) {
		t.Fatalf("signature-only retry changed digest: %x %v", retryDigest, err)
	}

	wrongReceiver := fixture.proof(t, message, []*wire.TxOut{{Value: 49_000, PkScript: []byte{txscript.OP_TRUE}}})
	if _, err := verifyVaultBoardRegisterProof(wrongReceiver, message, fixture.operation, fixture.tree, fixture.expireAt); err == nil || !strings.Contains(err.Error(), "receiver") {
		t.Fatalf("wrong receiver accepted: %v", err)
	}
	if _, err := verifyVaultBoardRegisterProof(raw, message, fixture.operation, fixture.tree, fixture.expireAt+1); err == nil || !strings.Contains(err.Error(), "message") {
		t.Fatalf("wrong expiry accepted: %v", err)
	}
}

func TestVerifyVaultBoardIntentProofRejectsTreeAndSignatureSubstitution(t *testing.T) {
	fixture := newVaultBoardProofFixture(t)
	message := fixture.registerMessage(t)
	raw := fixture.proof(t, message, []*wire.TxOut{fixture.receiver})
	packet, err := parsePSBT(raw)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[1].TaprootScriptSpendSig = nil
	missing, _ := packet.B64Encode()
	if _, err := verifyVaultBoardRegisterProof(missing, message, fixture.operation, fixture.tree, fixture.expireAt); err == nil || !strings.Contains(err.Error(), "signatures") {
		t.Fatalf("missing boarding signature accepted: %v", err)
	}

	packet, _ = parsePSBT(raw)
	packet.Inputs[1].Unknowns[0].Value = []byte{0x00}
	wrongTree, _ := packet.B64Encode()
	if _, err := verifyVaultBoardRegisterProof(wrongTree, message, fixture.operation, fixture.tree, fixture.expireAt); err == nil || !strings.Contains(err.Error(), "revealed tree") {
		t.Fatalf("substituted tree accepted: %v", err)
	}
}

func TestVerifyVaultBoardDeleteProofIsFiniteAndOutputless(t *testing.T) {
	fixture := newVaultBoardProofFixture(t)
	message, err := (intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete},
		ExpireAt:    fixture.expireAt,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	raw := fixture.proof(t, message, nil)
	verified, err := verifyVaultBoardDeleteProof(raw, message, fixture.operation, fixture.tree, fixture.expireAt)
	if err != nil || verified.ExpireAt != fixture.expireAt || len(verified.RequestDigest) != 32 {
		t.Fatalf("verified delete = %+v, %v", verified, err)
	}
	if _, err := verifyVaultBoardDeleteProof(raw, message, fixture.operation, fixture.tree, 0); err == nil {
		t.Fatal("perpetual delete proof accepted")
	}
	withReceiver := fixture.proof(t, message, []*wire.TxOut{fixture.receiver})
	if _, err := verifyVaultBoardDeleteProof(withReceiver, message, fixture.operation, fixture.tree, fixture.expireAt); err == nil || !strings.Contains(err.Error(), "outputs") {
		t.Fatalf("delete proof with receiver accepted: %v", err)
	}
}

func TestVaultBoardProgramDelayUsesBIP68Seconds(t *testing.T) {
	if program.VaultBoardV1ExitDelay%512 != 0 {
		t.Fatal("vault-board-v1 delay is not exactly BIP68 encodable")
	}
}
