package savings

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type ledgerGuardianFixture struct {
	context  LedgerSavingsKeyContext
	policy   program.SpendingPolicy
	family   *LedgerNativeFamily
	accounts map[string]*hdkeychain.ExtendedKey
	guardian *hdkeychain.ExtendedKey
}

func newLedgerGuardianFixture(t *testing.T, advanced bool) ledgerGuardianFixture {
	t.Helper()
	params, err := networkParams("mutinynet")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := program.DefaultSpendingPolicyFor("mutinynet")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := program.SpendingPolicyDigestHexFor("mutinynet", policy)
	if err != nil {
		t.Fatal(err)
	}
	f := ledgerGuardianFixture{policy: policy, accounts: map[string]*hdkeychain.ExtendedKey{}}
	origins := map[string]LedgerAccountOrigin{}
	for i, role := range familyClaimants(advanced) {
		master, err := hdkeychain.NewMaster(bytes.Repeat([]byte{byte(31 + i)}, 32), params)
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
		pub, err := account.Neuter()
		if err != nil {
			t.Fatal(err)
		}
		f.accounts[role] = account
		origins[role] = LedgerAccountOrigin{Xpub: pub.String(), Fingerprint: fmt.Sprintf("aabbcc%02x", i), Path: path}
	}
	scalar := make([]byte, 32)
	scalar[31] = 14
	base, _ := btcec.PrivKeyFromBytes(scalar)
	t.Cleanup(base.Zero)
	f.context = LedgerSavingsKeyContext{TemplateVersion: LedgerNativeTemplate, Network: "mutinynet", VaultID: "aabbccddeeff00112233445566778899", PolicyDigest: digest,
		Phone: origins["phone"], Hardware: origins["hardware"], PhoneDirectP256: "02c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
		VaultCosignerBase: hex.EncodeToString(base.PubKey().SerializeCompressed())}
	if advanced {
		r := origins["recovery"]
		f.context.Recovery = &r
	}
	parent, err := LedgerSavingsGuardianParent(f.context)
	if err != nil {
		t.Fatal(err)
	}
	f.guardian = hdkeychain.NewExtendedKey(params.HDPrivateKeyID[:], base.Serialize(), parent.ChainCode(), make([]byte, 4), 0, 0, true)
	t.Cleanup(f.guardian.Zero)
	f.family, err = BuildLedgerNativeFamily(f.context, policy)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func ledgerPrivate(t *testing.T, key *hdkeychain.ExtendedKey, err error) *btcec.PrivateKey {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	private, err := key.ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(private.Zero)
	return private
}
func ledgerUserPrivate(t *testing.T, f ledgerGuardianFixture, role string, branch uint32) *btcec.PrivateKey {
	t.Helper()
	step, err := f.accounts[role].Derive(branch)
	if err != nil {
		t.Fatal(err)
	}
	child, err := step.Derive(0)
	return ledgerPrivate(t, child, err)
}

// ledgerExecute signs an arbitrary one-output sweep. This checks the Bitcoin
// threshold itself, independently from the named Guardian signing capability.
func ledgerExecute(t *testing.T, tree LedgerRecoveryTree, leafIndex int, sequence uint32, keys ...*btcec.PrivateKey) error {
	t.Helper()
	const amount = 100000
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{Sequence: sequence})
	tx.AddTxOut(&wire.TxOut{Value: amount - 1000, PkScript: []byte{txscript.OP_TRUE}})
	fetcher := txscript.NewCannedPrevOutputFetcher(tree.PkScript, amount)
	hashes := txscript.NewTxSigHashes(tx, fetcher)
	leaves := make([]txscript.TapLeaf, len(tree.Scripts))
	for i, script := range tree.Scripts {
		leaves[i] = txscript.NewBaseTapLeaf(script)
	}
	tapTree := txscript.AssembleTaprootScriptTree(leaves...)
	control := tapTree.LeafMerkleProofs[tapTree.LeafProofIndex[leaves[leafIndex].TapHash()]].ToControlBlock(tree.Internal)
	controlBytes, err := control.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	for i := len(keys) - 1; i >= 0; i-- {
		var signature []byte
		if keys[i] != nil {
			signature, err = txscript.RawTxInTapscriptSignature(tx, hashes, 0, amount, tree.PkScript, leaves[leafIndex], txscript.SigHashDefault, keys[i])
			if err != nil {
				t.Fatal(err)
			}
		}
		tx.TxIn[0].Witness = append(tx.TxIn[0].Witness, signature)
	}
	tx.TxIn[0].Witness = append(tx.TxIn[0].Witness, tree.Scripts[leafIndex], controlBytes)
	engine, err := txscript.NewEngine(tree.PkScript, tx, 0, txscript.StandardVerifyFlags, nil, hashes, amount, fetcher)
	if err != nil {
		return err
	}
	return engine.Execute()
}

func TestLedgerGuardianSavingsThresholds(t *testing.T) {
	for _, advanced := range []bool{false, true} {
		f := newLedgerGuardianFixture(t, advanced)
		for change, tree := range []LedgerRecoveryTree{f.family.Receive, f.family.Change} {
			phone := ledgerUserPrivate(t, f, "phone", uint32(change))
			hardware := ledgerUserPrivate(t, f, "hardware", uint32(change))
			if err := ledgerExecute(t, tree, 0, wire.MaxTxInSequenceNum, phone, hardware); err != nil {
				t.Fatal("phone+hardware failed:", err)
			}
			if err := ledgerExecute(t, tree, 0, wire.MaxTxInSequenceNum, phone, nil); err == nil {
				t.Fatal("phone alone spent normal leaf")
			}
			if err := ledgerExecute(t, tree, 0, wire.MaxTxInSequenceNum, nil, hardware); err == nil {
				t.Fatal("hardware alone spent normal leaf")
			}
			for i, claimant := range familyClaimants(advanced) {
				branch := uint32(2 + change)
				if claimant == "recovery" {
					branch = uint32(change)
				}
				user := ledgerUserPrivate(t, f, claimant, branch)
				child, err := LedgerGuardianInitiateChild(f.context, f.guardian, claimant, uint32(change))
				guardian := ledgerPrivate(t, child, err)
				if err := ledgerExecute(t, tree, i+1, wire.MaxTxInSequenceNum, user, guardian); err != nil {
					t.Fatal("claimant+Guardian failed:", err)
				}
				if err := ledgerExecute(t, tree, i+1, wire.MaxTxInSequenceNum, nil, guardian); err == nil {
					t.Fatal("Guardian alone spent initiation leaf")
				}
				if err := ledgerExecute(t, tree, i+1, wire.MaxTxInSequenceNum, user, nil); err == nil {
					t.Fatal("claimant alone spent initiation leaf")
				}
				// Both private keys can authorize an arbitrary destination immediately.
				// The pending destination is an honest-Guardian policy boundary, not a covenant.
				if claimant == "phone" && ledgerExecute(t, tree, i+1, wire.MaxTxInSequenceNum, user, guardian) != nil {
					t.Fatal("accepted phone+Guardian compromise model changed")
				}
			}
		}
	}
}

func TestLedgerGuardianPendingAndQuarantineThresholds(t *testing.T) {
	for _, advanced := range []bool{false, true} {
		f := newLedgerGuardianFixture(t, advanced)
		for claimant, recovery := range f.family.Recovery {
			claim := ledgerUserPrivate(t, f, claimant, 4)
			if err := ledgerExecute(t, recovery.Pending, 0, recovery.Delay, claim); err != nil {
				t.Fatal("mature claim failed:", err)
			}
			if err := ledgerExecute(t, recovery.Pending, 0, recovery.Delay-1, claim); err == nil {
				t.Fatal("early claim accepted")
			}
			if err := ledgerExecute(t, recovery.Pending, 0, recovery.Delay|wire.SequenceLockTimeDisabled, claim); err == nil {
				t.Fatal("disabled relative lock accepted")
			}
			var cancel, quarantine []*btcec.PrivateKey
			for i, remaining := range recovery.Guardians {
				user := ledgerUserPrivate(t, f, remaining, 6)
				child, err := LedgerGuardianClawbackChild(f.context, f.guardian, claimant, remaining)
				guardian := ledgerPrivate(t, child, err)
				if err := ledgerExecute(t, recovery.Pending, i+1, wire.MaxTxInSequenceNum, user, guardian); err != nil {
					t.Fatal("cooperative cancellation failed:", err)
				}
				if err := ledgerExecute(t, recovery.Pending, i+1, wire.MaxTxInSequenceNum, nil, guardian); err == nil {
					t.Fatal("Guardian alone cancelled pending")
				}
				if err := ledgerExecute(t, recovery.Pending, i+1, wire.MaxTxInSequenceNum, user, nil); err == nil {
					t.Fatal("single user spent cooperative leaf")
				}
				wrong, err := LedgerGuardianInitiateChild(f.context, f.guardian, claimant, 0)
				if err := ledgerExecute(t, recovery.Pending, i+1, wire.MaxTxInSequenceNum, user, ledgerPrivate(t, wrong, err)); err == nil {
					t.Fatal("initiation key reused for cancellation")
				}
				cancel = append(cancel, ledgerUserPrivate(t, f, remaining, 8))
				quarantine = append(quarantine, ledgerUserPrivate(t, f, remaining, 10))
			}
			if err := ledgerExecute(t, recovery.Pending, len(recovery.Pending.Scripts)-1, wire.MaxTxInSequenceNum, cancel...); err != nil {
				t.Fatal("all remaining users could not cancel:", err)
			}
			if err := ledgerExecute(t, recovery.Quarantine, 0, wire.MaxTxInSequenceNum, quarantine...); err != nil {
				t.Fatal("remaining users could not recover quarantine:", err)
			}
			for i := range cancel {
				missing := append([]*btcec.PrivateKey(nil), cancel...)
				missing[i] = nil
				if err := ledgerExecute(t, recovery.Pending, len(recovery.Pending.Scripts)-1, wire.MaxTxInSequenceNum, missing...); err == nil {
					t.Fatal("cancel accepted missing remaining user")
				}
				missing = append([]*btcec.PrivateKey(nil), quarantine...)
				missing[i] = nil
				if err := ledgerExecute(t, recovery.Quarantine, 0, wire.MaxTxInSequenceNum, missing...); err == nil {
					t.Fatal("quarantine accepted missing remaining user")
				}
			}
		}
	}
}

func TestLedgerGuardianContractHasNoEmulatorProgramSurface(t *testing.T) {
	for _, check := range []struct {
		typ   reflect.Type
		names []string
	}{
		{reflect.TypeFor[LedgerSavingsKeyContext](), []string{"ArkadeCosignerBase"}},
		{reflect.TypeFor[LedgerNativeFamily](), []string{"Programs"}},
		{reflect.TypeFor[LedgerRecoveryFamily](), []string{"InitiateProgram", "ClawbackProgram"}},
	} {
		for _, name := range check.names {
			if _, ok := check.typ.FieldByName(name); ok {
				t.Fatalf("candidate retained %s", name)
			}
		}
	}
	f := newLedgerGuardianFixture(t, true)
	if len(f.family.WalletPolicy.KeysInfo) != 5 {
		t.Fatal("Advanced normal policy must have exactly five keys")
	}
	if len(newLedgerGuardianFixture(t, false).family.WalletPolicy.KeysInfo) != 4 {
		t.Fatal("Standard normal policy must have exactly four keys")
	}
}
