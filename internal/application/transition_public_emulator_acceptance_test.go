package application

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/brg444/arkade-vault-server/internal/vault/savings"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type publicEmulatorVector struct {
	origin        string
	version       string
	pubHex        string
	network       string
	addressPrefix string
}

func TestPublicEmulatorRejectsSavingsTransitionCovenantMutations(t *testing.T) {
	if os.Getenv("ARKADE_LIVE_EMULATOR") != "1" {
		t.Skip("set ARKADE_LIVE_EMULATOR=1 to exercise the release-pinned public Emulator")
	}
	runPublicEmulatorTransitionCovenantVector(t, publicEmulatorVector{
		origin:        deployment.MutinynetArkadeCosignerOrigin,
		version:       deployment.MutinynetArkadeCosignerVersion,
		pubHex:        deployment.MutinynetArkadeCosignerPubHex,
		network:       deployment.NetworkMutinynet,
		addressPrefix: "tb1p",
	})
}

func TestMainnetPublicEmulatorRejectsSavingsTransitionCovenantMutations(t *testing.T) {
	if os.Getenv("ARKADE_LIVE_MAINNET_EMULATOR") != "1" {
		t.Skip("set ARKADE_LIVE_MAINNET_EMULATOR=1 to exercise the public mainnet Emulator")
	}
	runPublicEmulatorTransitionCovenantVector(t, publicEmulatorVector{
		origin:        "https://emulator.arkade.computer",
		version:       "v0.0.7",
		pubHex:        "0239c196415da47b26456a101daaa12ba9e445bfe153197f1e2b750bf40e52092e",
		network:       program.NetworkMainnet,
		addressPrefix: "bc1p",
	})
}

func runPublicEmulatorTransitionCovenantVector(t *testing.T, vector publicEmulatorVector) {
	t.Helper()
	base, remotePub, hardware := publicEmulatorHardwareTransition(t, vector)
	signer, identity, err := DialPublicEmulator(
		context.Background(),
		vector.origin,
		remotePub,
		[]string{vector.version},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Origin != vector.origin || identity.Version != vector.version {
		t.Fatalf("unexpected public Emulator identity: %+v", identity)
	}

	valid, err := clonePacket(base)
	if err != nil {
		t.Fatal(err)
	}
	assertTransitionClaimantSignature(t, valid, hardware)
	assertPublicEmulatorSignsTransition(t, signer, valid, remotePub)

	extra, err := clonePacket(base)
	if err != nil {
		t.Fatal(err)
	}
	extra.UnsignedTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{txscript.OP_TRUE}})
	extra.Outputs = append(extra.Outputs, psbt.POutput{})
	resignTransitionClaimant(t, extra, hardware)
	extra, err = clonePacket(extra)
	if err != nil {
		t.Fatalf("well-formed added-output mutation did not round-trip: %v", err)
	}
	assertTransitionClaimantSignature(t, extra, hardware)
	if _, err := signer.Sign(context.Background(), extra); err == nil {
		t.Fatal("public Emulator accepted an added arbitrary output")
	}

	witnessBytes := savings.InitiateWitnessBytes("hardware", false)
	vbytes := (int64(base.UnsignedTx.SerializeSizeStripped())*4 + witnessBytes + 3) / 4
	feeLimit := program.DefaultSpendingPolicy().FeerateCapSatPerV * vbytes
	if feeLimit > program.DefaultSpendingPolicy().AbsoluteFeeCapSats {
		feeLimit = program.DefaultSpendingPolicy().AbsoluteFeeCapSats
	}
	exact := publicTransitionWithFee(t, base, hardware, feeLimit)
	assertTransitionClaimantSignature(t, exact, hardware)
	assertPublicEmulatorSignsTransition(t, signer, exact, remotePub)
	reduced := publicTransitionWithFee(t, base, hardware, feeLimit+1)
	assertTransitionClaimantSignature(t, reduced, hardware)
	if _, err := signer.Sign(context.Background(), reduced); err == nil {
		t.Fatalf("public Emulator accepted a one-sat destination reduction past fee boundary %d", feeLimit)
	}
}

func assertPublicEmulatorSignsTransition(t *testing.T, signer Signer, submitted *psbt.Packet, base *btcec.PublicKey) {
	t.Helper()
	response, err := signer.Sign(context.Background(), submitted)
	if err != nil {
		t.Fatalf("public Emulator rejected a valid release transition: %v", err)
	}
	packet, err := arkade.FindEmulatorPacket(submitted.UnsignedTx)
	if err != nil || len(packet) != 1 {
		t.Fatalf("release transition packet: entries=%d err=%v", len(packet), err)
	}
	expected := arkade.ComputeArkadeScriptPublicKey(base, arkade.ArkadeScriptHash(packet[0].Script))
	if expected == nil {
		t.Fatal("release transition produced a degenerate public Emulator tweak")
	}
	if _, err := extractVerifiedSignerSig(submitted, response, schnorr.SerializePubKey(expected)); err != nil {
		t.Fatalf("public Emulator response did not contain one valid exact signature delta: %v", err)
	}
}

func assertTransitionClaimantSignature(t *testing.T, packet *psbt.Packet, claimant *btcec.PrivateKey) {
	t.Helper()
	if len(packet.Inputs[0].TaprootScriptSpendSig) != 1 {
		t.Fatalf("claimant signature count = %d, want 1", len(packet.Inputs[0].TaprootScriptSpendSig))
	}
	sig := packet.Inputs[0].TaprootScriptSpendSig[0]
	leaf := packet.Inputs[0].TaprootLeafScript[0].Script
	if err := vault.VerifySchnorrOnSubmittedTx(
		packet, sig.Signature, schnorr.SerializePubKey(claimant.PubKey()), leaf,
	); err != nil {
		t.Fatalf("claimant signature does not commit the current mutation: %v", err)
	}
}

func publicEmulatorHardwareTransition(
	t *testing.T, vector publicEmulatorVector,
) (*psbt.Packet, *btcec.PublicKey, *btcec.PrivateKey) {
	t.Helper()
	remoteRaw, err := hex.DecodeString(vector.pubHex)
	if err != nil {
		t.Fatal(err)
	}
	remotePub, err := btcec.ParsePubKey(remoteRaw)
	if err != nil {
		t.Fatal(err)
	}
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	vaultCosigner, _ := btcec.NewPrivateKey()
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	vaultID := "public-emulator-covenant-vector-" + vector.network
	fam, err := savings.BuildFamily(savings.FamilyInput{
		VaultID:            vaultID,
		Network:            vector.network,
		Phone:              phone.PubKey(),
		Hardware:           hardware.PubKey(),
		PhoneDirectP256:    webauthn.CompressedP256(direct),
		VaultCosignerBase:  vaultCosigner.PubKey(),
		ArkadeCosignerBase: remotePub,
		TemplateVersion:    savings.Template,
		ServerFreeClawback: true,
		ProtectionTier:     program.ProtectionTierStandard,
		SpendingPolicy:     program.DefaultSpendingPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fam.Savings.Address, vector.addressPrefix) ||
		!strings.HasPrefix(fam.Pending[savings.FamilyKey("hardware")].Address, vector.addressPrefix) {
		t.Fatalf("transition family has wrong network addresses: %s %s",
			fam.Savings.Address, fam.Pending[savings.FamilyKey("hardware")].Address)
	}
	pair := fam.Initiate["hardware"]
	leaf, err := savings.Checksig(hardware.PubKey(), pair.Vault, pair.Arkade)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := savings.Checksig(phone.PubKey(), hardware.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	phoneLeaf, err := savings.Checksig(phone.PubKey(), fam.Initiate["phone"].Vault, fam.Initiate["phone"].Arkade)
	if err != nil {
		t.Fatal(err)
	}
	leaves := []txscript.TapLeaf{
		txscript.NewBaseTapLeaf(admin),
		txscript.NewBaseTapLeaf(phoneLeaf),
		txscript.NewBaseTapLeaf(leaf),
	}
	tree := txscript.AssembleTaprootScriptTree(leaves...)
	proofIndex, ok := tree.LeafProofIndex[leaves[2].TapHash()]
	if !ok {
		t.Fatal("hardware initiate proof missing")
	}
	internal, err := savings.ContextInternalKeyTemplate(vaultID, "savings", "", savings.Template)
	if err != nil {
		t.Fatal(err)
	}
	control := tree.LeafMerkleProofs[proofIndex].ToControlBlock(internal)
	controlBytes, err := control.ToBytes()
	if err != nil {
		t.Fatal(err)
	}

	prev := wire.NewMsgTx(2)
	prev.AddTxIn(&wire.TxIn{Sequence: wire.MaxTxInSequenceNum})
	prev.AddTxOut(&wire.TxOut{Value: 100_000, PkScript: fam.Savings.PkScript})
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: prev.TxHash(), Index: 0},
		Sequence:         savings.TransitionSequence,
	})
	tx.AddTxOut(&wire.TxOut{Value: 98_760, PkScript: fam.Pending[savings.FamilyKey("hardware")].PkScript})
	tx.AddTxOut(&wire.TxOut{Value: savings.P2AValueSats, PkScript: mustDecode(t, savings.P2AScriptHex)})
	emulatorPacket, err := arkade.NewPacket(arkade.EmulatorEntry{
		Vin: 0, Script: fam.InitiateAuth["savings-hardware"],
	})
	if err != nil {
		t.Fatal(err)
	}
	packetScript, err := (extension.Extension{emulatorPacket}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	tx.AddTxOut(&wire.TxOut{Value: 0, PkScript: packetScript})
	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].WitnessUtxo = prev.TxOut[0]
	packet.Inputs[0].SighashType = txscript.SigHashDefault
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: controlBytes, Script: leaf, LeafVersion: txscript.BaseLeafVersion,
	}}
	if err := txutils.SetArkPsbtField(packet, 0, arkade.PrevoutTxField, *prev); err != nil {
		t.Fatal(err)
	}
	resignTransitionClaimant(t, packet, hardware)
	return packet, remotePub, hardware
}

func publicTransitionWithFee(t *testing.T, base *psbt.Packet, claimant *btcec.PrivateKey, fee int64) *psbt.Packet {
	t.Helper()
	packet, err := clonePacket(base)
	if err != nil {
		t.Fatal(err)
	}
	inputValue := packet.Inputs[0].WitnessUtxo.Value
	packet.UnsignedTx.TxOut[0].Value = inputValue - packet.UnsignedTx.TxOut[1].Value - fee
	resignTransitionClaimant(t, packet, claimant)
	return packet
}
