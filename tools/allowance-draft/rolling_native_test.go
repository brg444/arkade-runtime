package allowancedraft

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func nativeRollingPayment(t *testing.T) (*nativeFixture, *rolling.Contract, *rolling.Transition, []rolling.Source, HistoryProof) {
	t.Helper()
	// Reuse an actual fixture issuance, then derive the complete rolling tree
	// from its issuance identity, including the owner-only delayed exit.
	n := newNativeFixture(t)
	r := newRollingFixture(t)
	p := r.params
	p.ControllerID = n.p.ControllerID
	p.CheckpointExit = n.exit
	c, err := rolling.BuildContract(p, rolling.ContractKeys{User: testKey(1), Guardian: testKey(2), Emulator: testKey(3), Operator: testKey(4)}, "light", 512)
	check(t, err)
	initial, err := InitialRollingState(p.Budget)
	check(t, err)
	issuerLeaf, err := n.issuer.ForfeitClosures()[0].Script()
	check(t, err)
	boot, cps, err := offchain.BuildTxs([]offchain.VtxoInput{vtxoInput(t, n.genesis.UnsignedTx, 0, n.issuer, issuerLeaf)}, []*wire.TxOut{wire.NewTxOut(ControllerSats, c.PkScript)}, n.exit)
	check(t, err)
	state, err := initial.Packet()
	check(t, err)
	appendRollingPackets(t, boot, n.markerPacket(0), state)
	check(t, txutils.SetArkPsbtField(boot, 0, arkade.PrevArkTxField, *n.genesis.UnsignedTx))
	_, err = rolling.ValidateBootstrap(n.genesis.UnsignedTx, boot, cps[0], rolling.BootstrapExpectation{ControllerID: p.ControllerID, Budget: p.Budget, IssuerScript: n.expect.IssuerScript, ContractScript: c.PkScript, CheckpointTapscript: n.exit})
	check(t, err)
	signPacket(t, boot, privateKey(7), privateKey(4))
	signPacket(t, cps[0], privateKey(7), privateKey(4))
	n.pkScript = c.PkScript
	n.prev[boot.UnsignedTx.TxHash()] = boot.UnsignedTx.Copy()
	ctrl := wire.OutPoint{Hash: boot.UnsignedTx.TxHash()}
	n.assets[ctrl] = []asset.Asset{{AssetId: p.ControllerID.String(), Amount: 1}}
	principal := n.previous(20000, nil, false)
	proof, _, err := BuildHistoryProof(nil, 0)
	check(t, err)
	paid, err := rolling.BuildPayment(c, []rolling.Source{{Previous: boot.UnsignedTx}, {Previous: n.prev[principal.Hash]}}, proof, n.recipientScript, 1000, 0, n.exit)
	check(t, err)
	check(t, n.executePayment(paid.Transaction, paid.Checkpoints))
	emuKey := arkade.ComputeArkadeScriptPrivateKey(privateKey(3), arkade.ArkadeScriptHash(c.Programs.Spend))
	signPacket(t, paid.Transaction, privateKey(1), privateKey(2), emuKey, privateKey(4))
	for _, cp := range paid.Checkpoints {
		signPacket(t, cp, privateKey(1), privateKey(2), emuKey, privateKey(4))
	}
	n.prev[paid.Transaction.UnsignedTx.TxHash()] = paid.Transaction.UnsignedTx.Copy()
	n.assets[wire.OutPoint{Hash: paid.Transaction.UnsignedTx.TxHash()}] = []asset.Asset{{AssetId: p.ControllerID.String(), Amount: 1}}
	return n, c, paid, []rolling.Source{{Previous: boot.UnsignedTx}, {Previous: n.prev[principal.Hash]}}, proof
}

func TestRollingNativeBootstrapPaymentAndCredit(t *testing.T) {
	n, c, paid, _, _ := nativeRollingPayment(t)
	p := c.Parameters
	remove, _, err := BuildHistoryProof([]Debit{*paid.Debit}, paid.Debit.Sequence)
	check(t, err)
	insert, _, err := BuildHistoryProof(nil, paid.After.Sequence)
	check(t, err)
	receipt := signedReceipt(t, p, *paid.Debit, time.Now().Unix()-2*WindowSeconds)
	credit, err := rolling.BuildCredit(c, []rolling.Source{{Previous: paid.Transaction.UnsignedTx}, {Previous: paid.Transaction.UnsignedTx, Index: 2}}, receipt, remove, insert, 0, time.Now().Unix(), n.exit)
	check(t, err)
	check(t, n.executePayment(credit.Transaction, credit.Checkpoints))
	emuKey := arkade.ComputeArkadeScriptPrivateKey(privateKey(3), arkade.ArkadeScriptHash(c.Programs.Credit))
	signPacket(t, credit.Transaction, privateKey(1), privateKey(2), emuKey, privateKey(4))
	for _, cp := range credit.Checkpoints {
		signPacket(t, cp, privateKey(1), privateKey(2), emuKey, privateKey(4))
	}
	if credit.After.Remaining != 10000 || credit.After.Sequence != 1 || credit.Debit != nil {
		t.Fatal("native rolling result mismatch")
	}
	// Every constructor attaches the actual logical state needed behind each checkpoint.
	for _, input := range credit.Transaction.Inputs {
		if len(input.Unknowns) == 0 {
			t.Fatal("missing previous transaction")
		}
	}
	t.Logf("native payment %d stripped bytes; credit %d stripped bytes", paid.Transaction.UnsignedTx.SerializeSizeStripped(), credit.Transaction.UnsignedTx.SerializeSizeStripped())
}

func TestRollingContractPreservesRecoveryRoles(t *testing.T) {
	for _, tier := range []string{"light", "standard", "advanced"} {
		t.Run(tier, func(t *testing.T) {
			r := newRollingFixture(t)
			keys := rolling.ContractKeys{User: testKey(1), Guardian: testKey(2), Emulator: testKey(3), Operator: testKey(4)}
			want := []*btcec.PublicKey{testKey(1)}
			if tier != "light" {
				keys.Hardware = testKey(7)
				want = append(want, testKey(7))
			}
			if tier == "advanced" {
				keys.Recovery = testKey(8)
				want = []*btcec.PublicKey{testKey(7), testKey(8)}
			}
			c, err := rolling.BuildContract(r.params, keys, tier, 512)
			check(t, err)
			closure, err := scriptlib.DecodeClosure(c.Exit.Script)
			check(t, err)
			exit, ok := closure.(*scriptlib.CSVMultisigClosure)
			if !ok || exit.Locktime.Type != arklib.LocktimeTypeSecond || exit.Locktime.Value != 512 || len(exit.PubKeys) != len(want) {
				t.Fatal("recovery policy mismatch")
			}
			for i, key := range want {
				if !bytes.Equal(schnorr.SerializePubKey(key), schnorr.SerializePubKey(exit.PubKeys[i])) {
					t.Fatal("recovery role changed")
				}
			}
			// Program bytes are preserved inside the root's packet serialization.
			packet, err := extension.NewExtensionFromPackets(arkade.EmulatorPacket{{Vin: 0, Script: c.Programs.Spend}})
			check(t, err)
			if _, err := packet.Serialize(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func appendRollingPackets(t *testing.T, p *psbt.Packet, packets ...extension.Packet) {
	t.Helper()
	appendPackets(t, p, packets...)
	last := len(p.UnsignedTx.TxOut) - 1
	p.UnsignedTx.TxOut[last], p.UnsignedTx.TxOut[last-1] = p.UnsignedTx.TxOut[last-1], p.UnsignedTx.TxOut[last]
}

func TestRollingNativeRenewalAndFeeReceipt(t *testing.T) {
	for _, fee := range []int64{0, 100} {
		t.Run(fmt.Sprintf("fee_%d", fee), func(t *testing.T) {
			n, c, paid, _, _ := nativeRollingPayment(t)
			now := time.Now().Unix()
			sources := []rolling.Source{{Previous: paid.Transaction.UnsignedTx}, {Previous: paid.Transaction.UnsignedTx, Index: 2}}
			proof, _, err := BuildHistoryProof([]Debit{*paid.Debit}, paid.After.Sequence)
			check(t, err)
			renew, err := rolling.BuildRenewal(c, sources, proof, fee, now, now+600)
			check(t, err)
			base, err := txutils.GetPrevOutputFetcher(&renew.Proof.Packet)
			check(t, err)
			fetch := nativeFetcher{PrevOutputFetcher: base, logical: map[wire.OutPoint]*wire.MsgTx{}, indexes: map[wire.OutPoint]uint32{}}
			for i, source := range sources {
				op := renew.Proof.UnsignedTx.TxIn[i+1].PreviousOutPoint
				fetch.logical[op] = source.Previous
				fetch.indexes[op] = source.Index
			}
			entries, err := arkade.FindEmulatorPacket(renew.Proof.UnsignedTx)
			check(t, err)
			budget := arkade.NewComputeBudget()
			for _, entry := range entries {
				program, err := arkade.ReadArkadeScript(&renew.Proof.Packet, testKey(3), entry)
				check(t, err)
				check(t, program.Execute(renew.Proof.UnsignedTx, fetch, int(entry.Vin), arkade.WithComputeBudget(budget), arkade.WithIntentMessage(renew.Message), arkade.WithExpiry(now+c.Parameters.RenewalWindow-1)))
			}
			key := arkade.ComputeArkadeScriptPrivateKey(privateKey(3), arkade.ArkadeScriptHash(c.Programs.Renew))
			signPacket(t, &renew.Proof.Packet, privateKey(2), key, privateKey(4))
			raw, err := renew.Proof.B64Encode()
			check(t, err)
			check(t, intent.Verify(raw, renew.Message, nil))
			if renew.After.Remaining != paid.After.Remaining-fee {
				t.Fatal("renewal lost fee")
			}
			reader := &finalizedFixture{controller: c.Parameters.ControllerID, sequence: paid.After.Sequence, record: rolling.FinalizedOperation{Proposal: rolling.Proposal{Kind: rolling.RenewalOperation, Message: renew.Message, Transaction: renew.Proof.UnsignedTx, Sources: sources, Proof: proof, CheckpointExit: n.exit}, AcceptedTxid: renew.Proof.UnsignedTx.TxHash(), ObservedAt: time.Unix(now, 0)}}
			issuer, err := rolling.NewReceiptIssuer(c, privateKey(9), reader, func() time.Time { return time.Unix(now, 0) })
			check(t, err)
			defer issuer.Close()
			receipt, err := issuer.Issue(t.Context(), paid.After.Sequence)
			if fee == 0 {
				if err == nil {
					t.Fatal("zero fee renewal issued credit")
				}
				if renew.After != paid.After {
					t.Fatal("zero fee renewal changed state")
				}
			} else {
				check(t, err)
				if receipt.Debit != *renew.Debit {
					t.Fatal("renewal receipt mismatch")
				}
				check(t, receipt.Verify(c.Parameters, now+WindowSeconds+1))
			}
		})
	}
}

func TestRollingRecoveryEnforcesTierAndDelay(t *testing.T) {
	for _, tier := range []string{"light", "standard", "advanced"} {
		t.Run(tier, func(t *testing.T) {
			r := newRollingFixture(t)
			keys := rolling.ContractKeys{User: testKey(1), Guardian: testKey(2), Emulator: testKey(3), Operator: testKey(4)}
			signing := []*btcec.PrivateKey{privateKey(1)}
			if tier != "light" {
				keys.Hardware = testKey(7)
				signing = append(signing, privateKey(7))
			}
			if tier == "advanced" {
				keys.Recovery = testKey(8)
				signing = []*btcec.PrivateKey{privateKey(7), privateKey(8)}
			}
			c, err := rolling.BuildContract(r.params, keys, tier, 512)
			check(t, err)
			closure, err := scriptlib.DecodeClosure(c.Exit.Script)
			check(t, err)
			for _, tc := range []struct {
				name     string
				sequence uint32
				omit     bool
				want     bool
			}{{"mature", 1<<22 | 1, false, true}, {"early", 1 << 22, false, false}, {"wrong units", 1, false, false}, {"missing owner", 1<<22 | 1, true, false}} {
				t.Run(tc.name, func(t *testing.T) {
					tx := wire.NewMsgTx(2)
					tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{42}}, nil, nil))
					tx.TxIn[0].Sequence = tc.sequence
					tx.AddTxOut(wire.NewTxOut(9900, r.recipientScript))
					fetch := txscript.NewCannedPrevOutputFetcher(c.PkScript, 10000)
					hashes := txscript.NewTxSigHashes(tx, fetch)
					tap := txscript.NewBaseTapLeaf(c.Exit.Script)
					sigs := map[string][]byte{}
					for i, key := range signing {
						sig, err := txscript.RawTxInTapscriptSignature(tx, hashes, 0, 10000, c.PkScript, tap, txscript.SigHashDefault, key)
						check(t, err)
						if tc.omit && i == 0 {
							sig = nil
						}
						sigs[hex.EncodeToString(schnorr.SerializePubKey(key.PubKey()))] = sig
					}
					tx.TxIn[0].Witness, err = closure.Witness(c.Exit.ControlBlock, sigs)
					check(t, err)
					engine, err := txscript.NewEngine(c.PkScript, tx, 0, txscript.StandardVerifyFlags, nil, hashes, 10000, fetch)
					if err == nil {
						err = engine.Execute()
					}
					if (err == nil) != tc.want {
						t.Fatalf("recovery accepted=%v want=%v: %v", err == nil, tc.want, err)
					}
				})
			}
		})
	}
}
