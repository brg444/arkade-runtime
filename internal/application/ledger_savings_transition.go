package application

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const ledgerSavingsGuardianDomain = "vaulted/ledger-guardian-savings-v1"
const ledgerSavingsMaxMoney = int64(21_000_000 * 100_000_000)

func ledgerSavingsFields(fields ...[]byte) []byte {
	var encoded []byte
	for _, field := range fields {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		encoded = append(encoded, size[:]...)
		encoded = append(encoded, field...)
	}
	return encoded
}

// deriveLedgerSavingsGuardianRoot is an independent candidate-only HKDF domain.
// IKM is the master scalar, salt is domain + "/guardian-root", and info is
// uint32-BE-length-prefixed network UTF-8, canonical vault ID UTF-8, and one-byte
// counter (0..255). Reject zero/overflow rather than reducing modulo the order.
// The full enrollment context subsequently binds the public HD chain code.
func deriveLedgerSavingsGuardianRoot(master *btcec.PrivateKey, network, vaultID string) (*btcec.PrivateKey, error) {
	if master == nil || master.Key.IsZero() {
		return nil, fmt.Errorf("Ledger Guardian master required")
	}
	if _, err := program.PinsFor(network); err != nil {
		return nil, err
	}
	id, err := hex.DecodeString(vaultID)
	if err != nil || len(id) != 16 || strings.ToLower(vaultID) != vaultID {
		return nil, fmt.Errorf("canonical Ledger vault ID required")
	}
	secret := master.Serialize()
	defer zeroServiceBytes(secret)
	for counter := 0; counter <= 255; counter++ {
		info := ledgerSavingsFields([]byte(network), []byte(vaultID), []byte{byte(counter)})
		raw, err := hkdf.Key(sha256.New, secret, []byte(ledgerSavingsGuardianDomain+"/guardian-root"), string(info), 32)
		if err != nil {
			return nil, err
		}
		var scalar btcec.ModNScalar
		overflow := scalar.SetByteSlice(raw)
		zeroServiceBytes(raw)
		if !overflow && !scalar.IsZero() {
			key := &btcec.PrivateKey{Key: scalar}
			scalar.Zero()
			return key, nil
		}
		scalar.Zero()
	}
	return nil, fmt.Errorf("Ledger Guardian HKDF produced no valid scalar")
}

// This candidate capability is deliberately absent from the live profile's
// KeyCapabilities, enrollment, HTTP handlers, and authenticated database schema.
// A later integration must obtain context and policy from authenticated immutable
// enrollment, and durably reserve the exact candidate before invoking it.
type fileBackedLedgerSavingsAuthorizer struct{ keys *fileBackedVaultKeys }

func (a *fileBackedLedgerSavingsAuthorizer) guardianPublic(network, vaultID string) (*btcec.PublicKey, error) {
	if a == nil || a.keys == nil {
		return nil, fmt.Errorf("Ledger Guardian backend required")
	}
	var public *btcec.PublicKey
	err := a.keys.withMaster(func(master *btcec.PrivateKey) error {
		key, err := deriveLedgerSavingsGuardianRoot(master, network, vaultID)
		if err != nil {
			return err
		}
		defer key.Zero()
		public = key.PubKey()
		return nil
	})
	return public, err
}

type ledgerSavingsTransitionAuthorization struct {
	keyContext                    savings.LedgerSavingsKeyContext
	policy                        program.SpendingPolicy
	kind, claimant, remainingUser string
	change                        uint32
	retainedPSBT                  string
	directProof                   []byte
}

// Context and policy are the trusted enrolled snapshot, never request overrides.
// Retained bytes and every mutable origin/proof field are captured by value.
func newLedgerSavingsTransitionAuthorization(in savings.LedgerSavingsKeyContext, policy program.SpendingPolicy,
	kind, claimant, remainingUser string, change uint32, retainedPSBT string, directProof []byte,
) (ledgerSavingsTransitionAuthorization, error) {
	in.Phone.Path = append([]uint32(nil), in.Phone.Path...)
	in.Hardware.Path = append([]uint32(nil), in.Hardware.Path...)
	if in.Recovery != nil {
		r := *in.Recovery
		r.Path = append([]uint32(nil), r.Path...)
		in.Recovery = &r
	}
	req := ledgerSavingsTransitionAuthorization{in, policy, kind, claimant, remainingUser, change, retainedPSBT, bytes.Clone(directProof)}
	if _, err := validateLedgerSavingsTransition(req); err != nil {
		return ledgerSavingsTransitionAuthorization{}, err
	}
	return req, nil
}

type ledgerSavingsTransitionPlan struct {
	packet              *psbt.Packet
	leaf, guardianXOnly []byte
}

func ledgerSavingsTransitionTrees(req ledgerSavingsTransitionAuthorization) (savings.LedgerRecoveryTree, savings.LedgerRecoveryTree, int, string, *hdkeychain.ExtendedKey, error) {
	family, err := savings.BuildLedgerNativeFamily(req.keyContext, req.policy)
	if err != nil {
		return savings.LedgerRecoveryTree{}, savings.LedgerRecoveryTree{}, 0, "", nil, err
	}
	recovery, ok := family.Recovery[req.claimant]
	if !ok {
		return savings.LedgerRecoveryTree{}, savings.LedgerRecoveryTree{}, 0, "", nil, fmt.Errorf("unenrolled Ledger claimant")
	}
	parent, err := savings.LedgerSavingsGuardianParent(req.keyContext)
	if err != nil {
		return savings.LedgerRecoveryTree{}, savings.LedgerRecoveryTree{}, 0, "", nil, err
	}
	switch req.kind {
	case "initiate":
		if req.remainingUser != "" || req.change > 1 {
			break
		}
		source := family.Receive
		if req.change == 1 {
			source = family.Change
		}
		leafIndex := map[string]int{"phone": 1, "hardware": 2, "recovery": 3}[req.claimant]
		child, err := savings.LedgerGuardianInitiateChild(req.keyContext, parent, req.claimant, req.change)
		return source, recovery.Pending, leafIndex, req.claimant, child, err
	case "clawback":
		if req.change != 0 {
			break
		}
		for i, remaining := range recovery.Guardians {
			if remaining == req.remainingUser {
				child, err := savings.LedgerGuardianClawbackChild(req.keyContext, parent, req.claimant, remaining)
				return recovery.Pending, recovery.Quarantine, i + 1, remaining, child, err
			}
		}
	}
	return savings.LedgerRecoveryTree{}, savings.LedgerRecoveryTree{}, 0, "", nil, fmt.Errorf("unenrolled Ledger transition operation")
}

// LedgerSavingsTransitionDigest is the detached PhoneDirectP256 approval digest.
// It is BIP340 tagged SHA256(domain + "/phone-authorization") over uint32-BE-
// length-prefixed fields: context digest, UTF-8 kind, claimant, remaining user,
// uint32-BE change, canonical unsigned Bitcoin transaction (no witness), and
// canonical Bitcoin TxOut serialization of the verified input. This helper
// computes an approval digest; it neither authorizes nor signs a transaction.
func LedgerSavingsTransitionDigest(in savings.LedgerSavingsKeyContext, kind, claimant, remainingUser string, change uint32,
	tx *wire.MsgTx, prevout *wire.TxOut,
) ([]byte, error) {
	digest, err := savings.LedgerSavingsContextDigest(in)
	if err != nil {
		return nil, err
	}
	if tx == nil || prevout == nil {
		return nil, fmt.Errorf("Ledger transition and prevout required")
	}
	var txBytes, prevBytes bytes.Buffer
	if err := tx.SerializeNoWitness(&txBytes); err != nil {
		return nil, err
	}
	if err := wire.WriteTxOut(&prevBytes, 0, tx.Version, prevout); err != nil {
		return nil, err
	}
	var coordinate [4]byte
	binary.BigEndian.PutUint32(coordinate[:], change)
	preimage := ledgerSavingsFields(digest, []byte(kind), []byte(claimant), []byte(remainingUser), coordinate[:], txBytes.Bytes(), prevBytes.Bytes())
	tag := sha256.Sum256([]byte(ledgerSavingsGuardianDomain + "/phone-authorization"))
	h := sha256.New()
	_, _ = h.Write(tag[:])
	_, _ = h.Write(tag[:])
	_, _ = h.Write(preimage)
	return h.Sum(nil), nil
}

func validateLedgerSavingsTransition(req ledgerSavingsTransitionAuthorization) (ledgerSavingsTransitionPlan, error) {
	reject := func(reason string) (ledgerSavingsTransitionPlan, error) {
		return ledgerSavingsTransitionPlan{}, fmt.Errorf("Ledger transition: %s", reason)
	}
	source, destination, leafIndex, userRole, guardianChild, err := ledgerSavingsTransitionTrees(req)
	if err != nil {
		return ledgerSavingsTransitionPlan{}, err
	}
	packet, err := parsePSBT(req.retainedPSBT)
	if err != nil {
		return ledgerSavingsTransitionPlan{}, err
	}
	tx := packet.UnsignedTx
	if len(tx.TxIn) != 1 || len(packet.Inputs) != 1 || len(tx.TxOut) != 1 || len(packet.Outputs) != 1 {
		return reject("exactly one input and one output required")
	}
	if tx.Version != 2 || tx.LockTime != 0 || tx.TxIn[0].Sequence != savings.TransitionSequence || len(tx.TxIn[0].SignatureScript) != 0 || len(tx.TxIn[0].Witness) != 0 {
		return reject("transaction header or input mismatch")
	}
	input := packet.Inputs[0]
	if input.NonWitnessUtxo == nil || input.WitnessUtxo == nil {
		return reject("full parent and witness prevout required")
	}
	op := tx.TxIn[0].PreviousOutPoint
	parent := input.NonWitnessUtxo
	if parent.TxHash() != op.Hash || uint64(op.Index) >= uint64(len(parent.TxOut)) {
		return reject("parent transaction mismatch")
	}
	prev := parent.TxOut[op.Index]
	if prev == nil || prev.Value <= 0 || prev.Value > ledgerSavingsMaxMoney || prev.Value != input.WitnessUtxo.Value || !bytes.Equal(prev.PkScript, input.WitnessUtxo.PkScript) || !bytes.Equal(prev.PkScript, source.PkScript) {
		return reject("enrolled source prevout mismatch")
	}
	out := tx.TxOut[0]
	// P2TR at Bitcoin Core's default 3000 sat/kvB dust relay fee is 330 sats.
	if out == nil || out.Value < 330 || out.Value > prev.Value || !bytes.Equal(out.PkScript, destination.PkScript) {
		return reject("enrolled destination or amount mismatch")
	}
	if len(input.TaprootLeafScript) != 1 || input.TaprootLeafScript[0] == nil {
		return reject("one exact recovery leaf required")
	}
	leaf := source.Scripts[leafIndex]
	entry := input.TaprootLeafScript[0]
	leaves := make([]txscript.TapLeaf, len(source.Scripts))
	for i, script := range source.Scripts {
		leaves[i] = txscript.NewBaseTapLeaf(script)
	}
	tree := txscript.AssembleTaprootScriptTree(leaves...)
	control := tree.LeafMerkleProofs[tree.LeafProofIndex[leaves[leafIndex].TapHash()]].ToControlBlock(source.Internal)
	controlBytes, err := control.ToBytes()
	if err != nil {
		return ledgerSavingsTransitionPlan{}, err
	}
	if entry.LeafVersion != txscript.BaseLeafVersion || !bytes.Equal(entry.Script, leaf) || !bytes.Equal(entry.ControlBlock, controlBytes) {
		return reject("enrolled leaf or proof mismatch")
	}
	if err := txscript.VerifyTaprootLeafCommitment(&control, prev.PkScript[2:], leaf); err != nil {
		return ledgerSavingsTransitionPlan{}, err
	}
	if input.SighashType != txscript.SigHashDefault || len(input.TaprootScriptSpendSig) != 1 || input.TaprootScriptSpendSig[0] == nil {
		return reject("exactly one DEFAULT user signature required")
	}
	if len(input.FinalScriptSig) != 0 || len(input.FinalScriptWitness) != 0 || len(input.TaprootKeySpendSig) != 0 || len(input.PartialSigs) != 0 || len(input.RedeemScript) != 0 || len(input.WitnessScript) != 0 || len(input.Bip32Derivation) != 0 || len(input.Unknowns) != 0 || len(packet.Unknowns) != 0 {
		return reject("unexpected signing or proprietary fields")
	}
	outputMetadata := packet.Outputs[0]
	if len(outputMetadata.RedeemScript) != 0 || len(outputMetadata.WitnessScript) != 0 || len(outputMetadata.Bip32Derivation) != 0 || len(outputMetadata.TaprootInternalKey) != 0 || len(outputMetadata.TaprootTapTree) != 0 || len(outputMetadata.TaprootBip32Derivation) != 0 || len(outputMetadata.Unknowns) != 0 {
		return reject("unexpected output metadata")
	}
	rootHash := tree.RootNode.TapHash()
	if (len(input.TaprootInternalKey) != 0 && !bytes.Equal(input.TaprootInternalKey, schnorr.SerializePubKey(source.Internal))) || (len(input.TaprootMerkleRoot) != 0 && !bytes.Equal(input.TaprootMerkleRoot, rootHash[:])) {
		return reject("substituted Taproot tree metadata")
	}
	userOrigin := req.keyContext.Phone
	if userRole == "hardware" {
		userOrigin = req.keyContext.Hardware
	} else if userRole == "recovery" {
		userOrigin = *req.keyContext.Recovery
	}
	userParent, err := savings.LedgerAccountKey(userOrigin, req.keyContext.Network)
	if err != nil {
		return ledgerSavingsTransitionPlan{}, err
	}
	var userChild *hdkeychain.ExtendedKey
	if req.kind == "clawback" {
		userChild, err = savings.LedgerRecoveryChild(userParent, "clawback")
	} else {
		branch := 2 + req.change
		if userRole == "recovery" {
			branch = req.change
		}
		userChild, err = savings.LedgerSavingsChild(userParent, branch, 0)
	}
	if err != nil {
		return ledgerSavingsTransitionPlan{}, err
	}
	userPub, err := userChild.ECPubKey()
	if err != nil {
		return ledgerSavingsTransitionPlan{}, err
	}
	guardianPub, err := guardianChild.ECPubKey()
	if err != nil {
		return ledgerSavingsTransitionPlan{}, err
	}
	if len(input.TaprootBip32Derivation) != 0 {
		if len(input.TaprootBip32Derivation) != 2 {
			return reject("exactly two enrolled key derivations required")
		}
		userBranch := uint32(2) + req.change
		if userRole == "recovery" {
			userBranch = req.change
		}
		var guardianBranch uint32
		if req.kind == "clawback" {
			userBranch = 6
			guardianBranch, err = savings.LedgerGuardianClawbackBranch(req.keyContext, req.claimant, req.remainingUser)
		} else {
			guardianBranch, err = savings.LedgerGuardianInitiateBranch(req.keyContext, req.claimant, req.change)
		}
		if err != nil {
			return ledgerSavingsTransitionPlan{}, err
		}
		fingerprint, err := hex.DecodeString(userOrigin.Fingerprint)
		if err != nil {
			return ledgerSavingsTransitionPlan{}, err
		}
		base, err := hex.DecodeString(req.keyContext.VaultCosignerBase)
		if err != nil {
			return ledgerSavingsTransitionPlan{}, err
		}
		userPath := append(append([]uint32(nil), userOrigin.Path...), userBranch, 0)
		expected := map[string]struct {
			fingerprint uint32
			path        []uint32
		}{
			string(schnorr.SerializePubKey(userPub)):     {binary.LittleEndian.Uint32(fingerprint), userPath},
			string(schnorr.SerializePubKey(guardianPub)): {binary.LittleEndian.Uint32(btcutil.Hash160(base)[:4]), []uint32{guardianBranch, 0}},
		}
		leafHash := leaves[leafIndex].TapHash()
		for _, derivation := range input.TaprootBip32Derivation {
			if derivation == nil {
				return reject("nil key derivation")
			}
			want, ok := expected[string(derivation.XOnlyPubKey)]
			if !ok || len(derivation.LeafHashes) != 1 || !bytes.Equal(derivation.LeafHashes[0], leafHash[:]) || derivation.MasterKeyFingerprint != want.fingerprint || !slices.Equal(derivation.Bip32Path, want.path) {
				return reject("unenrolled key derivation")
			}
			delete(expected, string(derivation.XOnlyPubKey))
		}
	}
	if err := requirePresentConnectorSig(packet, 0, schnorr.SerializePubKey(userPub), leaf); err != nil {
		return ledgerSavingsTransitionPlan{}, fmt.Errorf("Ledger user signature: %w", err)
	}
	if userRole == "phone" {
		direct, err := hex.DecodeString(req.keyContext.PhoneDirectP256)
		if err != nil {
			return ledgerSavingsTransitionPlan{}, err
		}
		digest, err := LedgerSavingsTransitionDigest(req.keyContext, req.kind, req.claimant, req.remainingUser, req.change, tx, prev)
		if err != nil {
			return ledgerSavingsTransitionPlan{}, err
		}
		if err := verifyDirectAuth(direct, digest, req.directProof); err != nil {
			return ledgerSavingsTransitionPlan{}, fmt.Errorf("Ledger phone approval: %w", err)
		}
	} else if len(req.directProof) != 0 {
		return reject("inapplicable phone approval")
	}
	// The only final witness is [Guardian64,user64,leaf,control]. Computing its
	// exact serialized weight avoids both old three-signature estimates and caller
	// supplied padding inflating the allowed fee.
	final := tx.Copy()
	final.TxIn[0].Witness = wire.TxWitness{make([]byte, 64), make([]byte, 64), leaf, controlBytes}
	weight := int64(final.SerializeSizeStripped()*3 + final.SerializeSize())
	vsize := (weight + 3) / 4
	fee := prev.Value - out.Value
	if fee <= 0 || fee > req.policy.AbsoluteFeeCapSats || fee > vsize*req.policy.FeerateCapSatPerV {
		return reject("fee exceeds enrolled policy or is not positive")
	}
	return ledgerSavingsTransitionPlan{packet: packet, leaf: bytes.Clone(leaf), guardianXOnly: schnorr.SerializePubKey(guardianPub)}, nil
}

func (a *fileBackedLedgerSavingsAuthorizer) authorizeTransition(ctx context.Context, req ledgerSavingsTransitionAuthorization) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if a == nil || a.keys == nil {
		return "", fmt.Errorf("Ledger Guardian backend required")
	}
	// Rebuild and validate before the key backend is entered, even if a caller
	// bypasses the snapshot constructor or changes package-private fields.
	plan, err := validateLedgerSavingsTransition(req)
	if err != nil {
		return "", err
	}
	var signed string
	err = a.keys.withMaster(func(master *btcec.PrivateKey) error {
		root, err := deriveLedgerSavingsGuardianRoot(master, req.keyContext.Network, req.keyContext.VaultID)
		if err != nil {
			return err
		}
		defer root.Zero()
		if hex.EncodeToString(root.PubKey().SerializeCompressed()) != req.keyContext.VaultCosignerBase {
			return fmt.Errorf("enrolled Ledger Guardian root mismatch")
		}
		public, err := savings.LedgerSavingsGuardianParent(req.keyContext)
		if err != nil {
			return err
		}
		// Neutering in the semantic child helpers checks the complete HD parent,
		// including version, chain code, depth, fingerprint and child index.
		version := chaincfg.TestNet3Params.HDPrivateKeyID[:]
		if req.keyContext.Network == "mainnet" {
			version = chaincfg.MainNetParams.HDPrivateKeyID[:]
		}
		serialized := root.Serialize()
		parent := hdkeychain.NewExtendedKey(version, serialized, public.ChainCode(), make([]byte, 4), 0, 0, true)
		defer parent.Zero()
		defer zeroServiceBytes(serialized)
		var child *hdkeychain.ExtendedKey
		if req.kind == "initiate" {
			child, err = savings.LedgerGuardianInitiateChild(req.keyContext, parent, req.claimant, req.change)
		} else {
			child, err = savings.LedgerGuardianClawbackChild(req.keyContext, parent, req.claimant, req.remainingUser)
		}
		if err != nil {
			return err
		}
		defer child.Zero()
		private, err := child.ECPrivKey()
		if err != nil {
			return err
		}
		defer private.Zero()
		if !bytes.Equal(schnorr.SerializePubKey(private.PubKey()), plan.guardianXOnly) {
			return fmt.Errorf("Ledger Guardian child mismatch")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		signature, err := signTapLeafAtWithSighash(plan.packet, 0, private, plan.leaf, txscript.SigHashDefault)
		if err != nil {
			return err
		}
		if err := verifySchnorrOnInputWithSighash(plan.packet, 0, signature.Signature, plan.guardianXOnly, plan.leaf, txscript.SigHashDefault); err != nil {
			return err
		}
		plan.packet.Inputs[0].TaprootScriptSpendSig = append(plan.packet.Inputs[0].TaprootScriptSpendSig, signature)
		signed, err = plan.packet.B64Encode()
		return err
	})
	return signed, err
}
