package application

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type ledgerTransitionFixture struct {
	auth     *fileBackedLedgerSavingsAuthorizer
	in       savings.LedgerSavingsKeyContext
	policy   program.SpendingPolicy
	direct   *ecdsa.PrivateKey
	accounts map[string]*hdkeychain.ExtendedKey
}

func newLedgerTransitionFixture(t *testing.T, advanced bool) ledgerTransitionFixture {
	t.Helper()
	f := ledgerTransitionFixture{accounts: map[string]*hdkeychain.ExtendedKey{}}
	master, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x31}, 32))
	f.auth = &fileBackedLedgerSavingsAuthorizer{keys: &fileBackedVaultKeys{master: master}}
	t.Cleanup(f.auth.keys.wipe)
	var err error
	f.direct, err = webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	f.policy, err = program.DefaultSpendingPolicyFor("mutinynet")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := program.SpendingPolicyDigestHexFor("mutinynet", f.policy)
	if err != nil {
		t.Fatal(err)
	}
	f.in = savings.LedgerSavingsKeyContext{TemplateVersion: savings.LedgerNativeTemplate, Network: "mutinynet", VaultID: "aabbccddeeff00112233445566778899", PolicyDigest: digest, PhoneDirectP256: hex.EncodeToString(webauthn.CompressedP256(f.direct))}
	root, err := f.auth.guardianPublic(f.in.Network, f.in.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	f.in.VaultCosignerBase = hex.EncodeToString(root.SerializeCompressed())
	roles := []string{"phone", "hardware"}
	if advanced {
		roles = append(roles, "recovery")
	}
	for i, role := range roles {
		master, err := hdkeychain.NewMaster(bytes.Repeat([]byte{byte(51 + i)}, 32), &chaincfg.TestNet3Params)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(master.Zero)
		path := []uint32{hdkeychain.HardenedKeyStart + 86, hdkeychain.HardenedKeyStart + 1, hdkeychain.HardenedKeyStart}
		account := master
		for _, index := range path {
			account, err = account.Derive(index)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(account.Zero)
		}
		public, err := account.Neuter()
		if err != nil {
			t.Fatal(err)
		}
		f.accounts[role] = account
		origin := savings.LedgerAccountOrigin{Xpub: public.String(), Fingerprint: fmt.Sprintf("abcdef%02x", i), Path: path}
		switch role {
		case "phone":
			f.in.Phone = origin
		case "hardware":
			f.in.Hardware = origin
		case "recovery":
			f.in.Recovery = &origin
		}
	}
	return f
}
func (f ledgerTransitionFixture) request(t *testing.T, kind, claimant, remaining string, change uint32) ledgerSavingsTransitionAuthorization {
	t.Helper()
	req := ledgerSavingsTransitionAuthorization{keyContext: f.in, policy: f.policy, kind: kind, claimant: claimant, remainingUser: remaining, change: change}
	source, destination, leafIndex, _, _, err := ledgerSavingsTransitionTrees(req)
	if err != nil {
		t.Fatal(err)
	}
	parent := wire.NewMsgTx(2)
	parent.AddTxIn(&wire.TxIn{Sequence: wire.MaxTxInSequenceNum})
	parent.AddTxOut(&wire.TxOut{Value: 100000, PkScript: source.PkScript})
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: parent.TxHash(), Index: 0}, Sequence: savings.TransitionSequence})
	tx.AddTxOut(&wire.TxOut{Value: 99000, PkScript: destination.PkScript})
	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].NonWitnessUtxo = parent
	packet.Inputs[0].WitnessUtxo = parent.TxOut[0]
	leaves := make([]txscript.TapLeaf, len(source.Scripts))
	for i, script := range source.Scripts {
		leaves[i] = txscript.NewBaseTapLeaf(script)
	}
	tree := txscript.AssembleTaprootScriptTree(leaves...)
	control := tree.LeafMerkleProofs[tree.LeafProofIndex[leaves[leafIndex].TapHash()]].ToControlBlock(source.Internal)
	controlBytes, err := control.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{Script: source.Scripts[leafIndex], ControlBlock: controlBytes, LeafVersion: txscript.BaseLeafVersion}}
	f.approve(t, &req, packet)
	return req
}
func (f ledgerTransitionFixture) approve(t *testing.T, req *ledgerSavingsTransitionAuthorization, packet *psbt.Packet) {
	t.Helper()
	user := req.claimant
	branch := uint32(2) + req.change
	if req.claimant == "recovery" {
		branch = req.change
	}
	if req.kind == "clawback" {
		user, branch = req.remainingUser, 6
	}
	step, err := f.accounts[user].Derive(branch)
	if err != nil {
		t.Fatal(err)
	}
	defer step.Zero()
	child, err := step.Derive(0)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Zero()
	key, err := child.ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()
	if len(packet.Inputs[0].TaprootLeafScript) != 1 {
		t.Fatal("fixture requires one leaf")
	}
	sig, err := signTapLeafAtWithSighash(packet, 0, key, packet.Inputs[0].TaprootLeafScript[0].Script, txscript.SigHashDefault)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
	req.retainedPSBT, err = packet.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	req.directProof = nil
	if user == "phone" {
		digest, err := LedgerSavingsTransitionDigest(req.keyContext, req.kind, req.claimant, req.remainingUser, req.change, packet.UnsignedTx, packet.Inputs[0].WitnessUtxo)
		if err != nil {
			t.Fatal(err)
		}
		req.directProof, err = webauthn.SignDigestLowS(f.direct, digest)
		if err != nil {
			t.Fatal(err)
		}
	}
}
func TestLedgerSavingsNamedGuardianSignsAndExecutes(t *testing.T) {
	for _, advanced := range []bool{false, true} {
		f := newLedgerTransitionFixture(t, advanced)
		roles := []string{"phone", "hardware"}
		if advanced {
			roles = append(roles, "recovery")
		}
		for _, claimant := range roles {
			for _, kind := range []string{"initiate", "clawback"} {
				actors := []string{""}
				if kind == "clawback" {
					actors = nil
					for _, r := range roles {
						if r != claimant {
							actors = append(actors, r)
						}
					}
				}
				for _, remaining := range actors {
					changes := []uint32{0}
					if kind == "initiate" {
						changes = append(changes, 1)
					}
					for _, change := range changes {
						req := f.request(t, kind, claimant, remaining, change)
						sealed, err := newLedgerSavingsTransitionAuthorization(req.keyContext, req.policy, kind, claimant, remaining, change, req.retainedPSBT, req.directProof)
						if err != nil {
							t.Fatal(err)
						}
						signed, err := f.auth.authorizeTransition(t.Context(), sealed)
						if err != nil {
							t.Fatalf("%s/%s/%s/%d: %v", kind, claimant, remaining, change, err)
						}
						packet, err := parsePSBT(signed)
						if err != nil {
							t.Fatal(err)
						}
						if len(packet.Inputs[0].TaprootScriptSpendSig) != 2 {
							t.Fatal("expected exactly two signatures")
						}
						leaf := packet.Inputs[0].TaprootLeafScript[0]
						tx := packet.UnsignedTx.Copy()
						tx.TxIn[0].Witness = wire.TxWitness{packet.Inputs[0].TaprootScriptSpendSig[1].Signature, packet.Inputs[0].TaprootScriptSpendSig[0].Signature, leaf.Script, leaf.ControlBlock}
						prev := packet.Inputs[0].WitnessUtxo
						fetcher := txscript.NewCannedPrevOutputFetcher(prev.PkScript, prev.Value)
						engine, err := txscript.NewEngine(prev.PkScript, tx, 0, txscript.StandardVerifyFlags, nil, txscript.NewTxSigHashes(tx, fetcher), prev.Value, fetcher)
						if err == nil {
							err = engine.Execute()
						}
						if err != nil {
							t.Fatalf("final canonical transition failed: %v", err)
						}
					}
				}
			}
		}
	}
}
func TestLedgerSavingsNamedGuardianRejectsMutations(t *testing.T) {
	f := newLedgerTransitionFixture(t, true)
	mutations := map[string]func(*psbt.Packet){
		"output substitution": func(p *psbt.Packet) {
			p.UnsignedTx.TxOut[0].PkScript = append([]byte(nil), p.Inputs[0].WitnessUtxo.PkScript...)
		},
		"additional output": func(p *psbt.Packet) {
			p.UnsignedTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{txscript.OP_TRUE}})
			p.Outputs = append(p.Outputs, psbt.POutput{})
		},
		"version":        func(p *psbt.Packet) { p.UnsignedTx.Version = 3 },
		"locktime":       func(p *psbt.Packet) { p.UnsignedTx.LockTime = 1 },
		"sequence":       func(p *psbt.Packet) { p.UnsignedTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum },
		"prevout value":  func(p *psbt.Packet) { p.Inputs[0].WitnessUtxo.Value++ },
		"parent":         func(p *psbt.Packet) { p.Inputs[0].NonWitnessUtxo.TxOut[0].Value++ },
		"missing parent": func(p *psbt.Packet) { p.Inputs[0].NonWitnessUtxo = nil },
		"proof":          func(p *psbt.Packet) { p.Inputs[0].TaprootLeafScript[0].ControlBlock[2] ^= 1 },
		"leaf": func(p *psbt.Packet) {
			p.Inputs[0].TaprootLeafScript[0].Script = append(p.Inputs[0].TaprootLeafScript[0].Script, txscript.OP_NOP)
		},
		"fee":         func(p *psbt.Packet) { p.UnsignedTx.TxOut[0].Value = 90000 },
		"dust":        func(p *psbt.Packet) { p.UnsignedTx.TxOut[0].Value = 329 },
		"no fee":      func(p *psbt.Packet) { p.UnsignedTx.TxOut[0].Value = 100000 },
		"keypath":     func(p *psbt.Packet) { p.Inputs[0].TaprootKeySpendSig = make([]byte, 64) },
		"proprietary": func(p *psbt.Packet) { p.Inputs[0].Unknowns = []*psbt.Unknown{{Key: []byte{0xfc, 1}, Value: []byte{1}}} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			req := f.request(t, "initiate", "phone", "", 0)
			packet, err := parsePSBT(req.retainedPSBT)
			if err != nil {
				t.Fatal(err)
			}
			mutate(packet)
			f.approve(t, &req, packet) // Even freshly signed attacker data must fail the named contract.
			if _, err := f.auth.authorizeTransition(t.Context(), req); err == nil {
				t.Fatal("mutated candidate signed")
			}
		})
	}
	for name, mutate := range map[string]func(*ledgerSavingsTransitionAuthorization){
		"unknown operation": func(r *ledgerSavingsTransitionAuthorization) { r.kind = "sweep" },
		"self clawback":     func(r *ledgerSavingsTransitionAuthorization) { r.kind = "clawback"; r.remainingUser = "phone" },
		"coordinate":        func(r *ledgerSavingsTransitionAuthorization) { r.change = 2 },
		"claimant":          func(r *ledgerSavingsTransitionAuthorization) { r.claimant = "arkade" },
		"policy":            func(r *ledgerSavingsTransitionAuthorization) { r.policy.AbsoluteFeeCapSats++ },
		"context": func(r *ledgerSavingsTransitionAuthorization) {
			r.keyContext.VaultID = "00112233445566778899aabbccddeeff"
		},
		"phone proof":         func(r *ledgerSavingsTransitionAuthorization) { r.directProof[0] ^= 1 },
		"missing phone proof": func(r *ledgerSavingsTransitionAuthorization) { r.directProof = nil },
	} {
		t.Run(name, func(t *testing.T) {
			req := f.request(t, "initiate", "phone", "", 0)
			mutate(&req)
			if _, err := f.auth.authorizeTransition(t.Context(), req); err == nil {
				t.Fatal("invalid authorization signed")
			}
		})
	}
	req := f.request(t, "initiate", "hardware", "", 0)
	req.directProof = make([]byte, 64)
	if _, err := f.auth.authorizeTransition(t.Context(), req); err == nil {
		t.Fatal("inapplicable phone proof accepted")
	}
}
func TestLedgerSavingsNamedGuardianDetachedProofAndSnapshot(t *testing.T) {
	f := newLedgerTransitionFixture(t, true)
	req := f.request(t, "clawback", "hardware", "phone", 0)
	snapshot, err := newLedgerSavingsTransitionAuthorization(req.keyContext, req.policy, req.kind, req.claimant, req.remainingUser, req.change, req.retainedPSBT, req.directProof)
	if err != nil {
		t.Fatal(err)
	}
	req.keyContext.Phone.Path[0]++
	req.keyContext.Recovery.Path[0]++
	req.directProof[0] ^= 1
	if _, err := f.auth.authorizeTransition(t.Context(), snapshot); err != nil {
		t.Fatal("snapshot changed through caller slice:", err)
	}
	packet, err := parsePSBT(snapshot.retainedPSBT)
	if err != nil {
		t.Fatal(err)
	}
	packet.UnsignedTx.TxOut[0].Value--
	changed := snapshot
	oldProof := bytes.Clone(snapshot.directProof)
	f.approve(t, &changed, packet)
	changed.directProof = oldProof
	if _, err := f.auth.authorizeTransition(t.Context(), changed); err == nil {
		t.Fatal("detached proof replayed after transaction mutation")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.auth.authorizeTransition(cancelled, snapshot); err == nil {
		t.Fatal("cancelled context signed")
	}
	f.auth.keys.wipe()
	if _, err := f.auth.authorizeTransition(t.Context(), snapshot); err == nil {
		t.Fatal("wiped key backend signed")
	}
}
func TestLedgerSavingsGuardianRootIsolation(t *testing.T) {
	master, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{7}, 32))
	defer master.Zero()
	id := "aabbccddeeff00112233445566778899"
	root, err := deriveLedgerSavingsGuardianRoot(master, "mutinynet", id)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Zero()
	old, err := policy.DeriveVaultCosignerScalar(master, id, policy.CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Zero()
	if bytes.Equal(schnorr.SerializePubKey(root.PubKey()), schnorr.SerializePubKey(old.PubKey())) {
		t.Fatal("legacy root reused")
	}
	for _, fields := range [][2]string{{"mainnet", id}, {"mutinynet", "00112233445566778899aabbccddeeff"}} {
		other, err := deriveLedgerSavingsGuardianRoot(master, fields[0], fields[1])
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(root.Serialize(), other.Serialize()) {
			t.Fatal("network/vault root collision")
		}
		other.Zero()
	}
	for _, fields := range [][2]string{{"unknown", id}, {"mutinynet", "aabb"}, {"mutinynet", "AABBCCDDEEFF00112233445566778899"}} {
		if _, err := deriveLedgerSavingsGuardianRoot(master, fields[0], fields[1]); err == nil {
			t.Fatal("invalid root scope accepted")
		}
	}
}

func TestLedgerSavingsNamedGuardianCanonicalFees(t *testing.T) {
	f := newLedgerTransitionFixture(t, false)
	for _, change := range []uint32{0, 1} {
		req := f.request(t, "initiate", "phone", "", change)
		packet, err := parsePSBT(req.retainedPSBT)
		if err != nil {
			t.Fatal(err)
		}
		leaf := packet.Inputs[0].TaprootLeafScript[0]
		final := packet.UnsignedTx.Copy()
		final.TxIn[0].Witness = wire.TxWitness{make([]byte, 64), make([]byte, 64), leaf.Script, leaf.ControlBlock}
		vsize := int64((final.SerializeSizeStripped()*3 + final.SerializeSize() + 3) / 4)
		packet.UnsignedTx.TxOut[0].Value = packet.Inputs[0].WitnessUtxo.Value - vsize*f.policy.FeerateCapSatPerV
		f.approve(t, &req, packet)
		if _, err := f.auth.authorizeTransition(t.Context(), req); err != nil {
			t.Fatal("canonical feerate boundary failed:", err)
		}
		packet.UnsignedTx.TxOut[0].Value--
		f.approve(t, &req, packet)
		if _, err := f.auth.authorizeTransition(t.Context(), req); err == nil {
			t.Fatal("fee above canonical signed weight accepted")
		}
	}
}

func TestLedgerSavingsNamedGuardianRejectsSignatureAndRootSubstitution(t *testing.T) {
	f := newLedgerTransitionFixture(t, false)
	for name, mutate := range map[string]func(*psbt.Packet){
		"missing signature":    func(p *psbt.Packet) { p.Inputs[0].TaprootScriptSpendSig = nil },
		"bad signature":        func(p *psbt.Packet) { p.Inputs[0].TaprootScriptSpendSig[0].Signature[0] ^= 1 },
		"non-default":          func(p *psbt.Packet) { p.Inputs[0].TaprootScriptSpendSig[0].SigHash = txscript.SigHashAll },
		"input sighash":        func(p *psbt.Packet) { p.Inputs[0].SighashType = txscript.SigHashAll },
		"wrong signer":         func(p *psbt.Packet) { p.Inputs[0].TaprootScriptSpendSig[0].XOnlyPubKey[0] ^= 1 },
		"wrong leaf hash":      func(p *psbt.Packet) { p.Inputs[0].TaprootScriptSpendSig[0].LeafHash[0] ^= 1 },
		"substituted internal": func(p *psbt.Packet) { p.Inputs[0].TaprootInternalKey = bytes.Repeat([]byte{3}, 32) },
	} {
		t.Run(name, func(t *testing.T) {
			req := f.request(t, "initiate", "phone", "", 0)
			packet, err := parsePSBT(req.retainedPSBT)
			if err != nil {
				t.Fatal(err)
			}
			mutate(packet)
			req.retainedPSBT, err = packet.B64Encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.auth.authorizeTransition(t.Context(), req); err == nil {
				t.Fatal("substituted authorization signed")
			}
		})
	}
	fake, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{11}, 32))
	defer fake.Zero()
	f.in.VaultCosignerBase = hex.EncodeToString(fake.PubKey().SerializeCompressed())
	req := f.request(t, "initiate", "phone", "", 0)
	if _, err := validateLedgerSavingsTransition(req); err != nil {
		t.Fatal("fixture must be internally valid:", err)
	}
	if _, err := f.auth.authorizeTransition(t.Context(), req); err == nil {
		t.Fatal("substituted Guardian root signed")
	}
}

func TestLedgerSavingsWalletRecoveryVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/ledger-recovery-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Contract struct {
			Context        savings.LedgerSavingsKeyContext `json:"context"`
			SpendingPolicy program.SpendingPolicy          `json:"spendingPolicy"`
		} `json:"contract"`
		Action struct {
			Kind          string `json:"kind"`
			Claimant      string `json:"claimant"`
			RemainingUser string `json:"remainingUser"`
			Change        uint32 `json:"change"`
		} `json:"action"`
		UserPSBT       string `json:"userPsbt"`
		PhoneDigest    string `json:"phoneDigest"`
		PhoneSignature string `json:"phoneSignature"`
		Vsize          int64  `json:"vsize"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 14 {
		t.Fatalf("expected 14 cross-language phone authorization vectors, got %d", len(vectors))
	}
	for i, vector := range vectors {
		t.Run(fmt.Sprintf("%d/%s/%s/%s", i, vector.Contract.Context.Network, vector.Action.Kind, vector.Action.Claimant), func(t *testing.T) {
			psbtBytes, err := hex.DecodeString(vector.UserPSBT)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := psbt.NewFromRawBytes(bytes.NewReader(psbtBytes), false)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := packet.B64Encode()
			if err != nil {
				t.Fatal(err)
			}
			proof, err := hex.DecodeString(vector.PhoneSignature)
			if err != nil {
				t.Fatal(err)
			}
			action := vector.Action
			req, err := newLedgerSavingsTransitionAuthorization(vector.Contract.Context, vector.Contract.SpendingPolicy, action.Kind, action.Claimant, action.RemainingUser, action.Change, stored, proof)
			if err != nil {
				t.Fatal("wallet recovery authorization rejected:", err)
			}
			digest, err := LedgerSavingsTransitionDigest(req.keyContext, req.kind, req.claimant, req.remainingUser, req.change, packet.UnsignedTx, packet.Inputs[0].WitnessUtxo)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(digest) != vector.PhoneDigest {
				t.Fatal("PhoneDirect digest differs from wallet")
			}
			leaf := packet.Inputs[0].TaprootLeafScript[0]
			final := packet.UnsignedTx.Copy()
			final.TxIn[0].Witness = wire.TxWitness{make([]byte, 64), make([]byte, 64), leaf.Script, leaf.ControlBlock}
			if got := int64((final.SerializeSizeStripped()*3 + final.SerializeSize() + 3) / 4); got != vector.Vsize {
				t.Fatalf("canonical vsize differs: Go%d wallet%d", got, vector.Vsize)
			}
			if len(packet.Inputs[0].TaprootBip32Derivation) != 2 {
				t.Fatal("wallet must supply both enrolled derivations")
			}
			for index := range packet.Inputs[0].TaprootBip32Derivation {
				for _, mutation := range []string{"index", "branch", "fingerprint", "leafhash"} {
					changed, err := clonePacket(packet)
					if err != nil {
						t.Fatal(err)
					}
					d := changed.Inputs[0].TaprootBip32Derivation[index]
					switch mutation {
					case "index":
						d.Bip32Path[len(d.Bip32Path)-1] = 1
					case "branch":
						d.Bip32Path[len(d.Bip32Path)-2]++
					case "fingerprint":
						d.MasterKeyFingerprint ^= 1
					case "leafhash":
						d.LeafHashes[0][0] ^= 1
					}
					changedRequest := req
					changedRequest.retainedPSBT, err = changed.B64Encode()
					if err != nil {
						t.Fatal(err)
					}
					if _, err := validateLedgerSavingsTransition(changedRequest); err == nil {
						t.Fatalf("accepted substituted %s in wallet derivation%d", mutation, index)
					}
				}
			}
		})
	}
}
