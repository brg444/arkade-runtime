package allowancedraft

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type rollingFixture struct {
	*fixture
	params     RollingParameters
	codes      RollingScripts
	creditLeaf *psbt.TaprootTapLeafScript
	credit     bool
	witness    wire.TxWitness
}

func newRollingFixture(t *testing.T) *rollingFixture {
	f := newFixture(t)
	r := &rollingFixture{fixture: f, params: RollingParameters{Parameters: f.p, NetworkGenesis: chainhash.Hash{0x42}, FeerateCap: 1}}
	copy(r.params.ReceiptKey[:], schnorr.SerializePubKey(testKey(9)))
	checkpoint, err := (&scriptlib.CSVMultisigClosure{MultisigClosure: scriptlib.MultisigClosure{PubKeys: []*btcec.PublicKey{testKey(4)}}, Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512}}).Script()
	check(t, err)
	r.params.CheckpointExit = checkpoint
	r.codes, err = CompileRolling(r.params)
	check(t, err)
	f.scripts = Scripts{Spend: r.codes.Spend, Renew: r.codes.Renew}
	leaves := []txscript.TapLeaf{}
	for i, code := range [][]byte{r.codes.Spend, r.codes.Renew, r.codes.Credit} {
		key := arkade.ComputeArkadeScriptPublicKey(f.emulator, arkade.ArkadeScriptHash(code))
		keys := []*btcec.PublicKey{testKey(1), testKey(2), key, testKey(4)}
		if i == 1 {
			keys = []*btcec.PublicKey{key, testKey(4)}
		}
		s, err := (&scriptlib.MultisigClosure{PubKeys: keys}).Script()
		check(t, err)
		leaves = append(leaves, txscript.NewBaseTapLeaf(s))
	}
	tree := txscript.AssembleTaprootScriptTree(leaves...)
	root := tree.RootNode.TapHash()
	f.pkScript, err = txscript.PayToTaprootScript(txscript.ComputeTaprootOutputKey(scriptlib.UnspendableKey(), root[:]))
	check(t, err)
	for i, proof := range tree.LeafMerkleProofs {
		cb := proof.ToControlBlock(scriptlib.UnspendableKey())
		control, err := cb.ToBytes()
		check(t, err)
		leaf := &psbt.TaprootTapLeafScript{Script: proof.Script, LeafVersion: proof.LeafVersion, ControlBlock: control}
		if i < 2 {
			f.leaves[i] = leaf
		} else {
			r.creditLeaf = leaf
		}
	}
	return r
}

func rollingEncoded(t *testing.T, s RollingState) []byte {
	t.Helper()
	b, e := s.Encode()
	return must(t, b, e)
}

func (r *rollingFixture) spendRolling(old RollingState, history []Debit, pay, fee int64) (RollingState, Debit) {
	r.credit = false
	r.renew = false
	r.spend(State{Remaining: old.Remaining, Sequence: old.Sequence}, []int64{20000}, pay, fee)
	parent := r.previous(ControllerSats, rollingEncoded(r.t, old), true)
	r.tx.TxIn[0].PreviousOutPoint = parent
	d := Debit{Sequence: old.Sequence, Amount: pay + fee, Parent: parent}
	proof, root, err := BuildHistoryProof(history, d.Sequence)
	check(r.t, err)
	if root != old.Root {
		r.t.Fatal("history does not match controller")
	}
	next, err := ApplyDebit(old, r.p.Budget, d, proof)
	check(r.t, err)
	r.state = rollingEncoded(r.t, next)
	r.witness = proof.Witness()
	return next, d
}

func signedReceipt(t *testing.T, p RollingParameters, d Debit, at int64) FinalizationReceipt {
	t.Helper()
	r := FinalizationReceipt{Domain: p.ReceiptDomain(), Debit: d, ObservedAt: at}
	m, err := r.Message()
	check(t, err)
	hash := sha256.Sum256(m)
	sig, err := schnorr.Sign(privateKey(9), hash[:])
	check(t, err)
	copy(r.Signature[:], sig.Serialize())
	return r
}

func (r *rollingFixture) creditRolling(old RollingState, history []Debit, receipt FinalizationReceipt) RollingState {
	r.credit = true
	r.renew = false
	proof, root, err := BuildHistoryProof(history, receipt.Debit.Sequence)
	check(r.t, err)
	if root != old.Root {
		r.t.Fatal("history does not match controller")
	}
	next, err := ApplyCredit(old, r.p.Budget, receipt.Debit, proof)
	check(r.t, err)
	r.tx = wire.NewMsgTx(3)
	parent := r.previous(ControllerSats, rollingEncoded(r.t, old), true)
	r.tx.AddTxIn(wire.NewTxIn(&parent, nil, nil))
	r.tx.AddTxOut(wire.NewTxOut(ControllerSats, bytes.Clone(r.pkScript)))
	r.tx.AddTxOut(txutils.AnchorOutput())
	r.tx.AddTxOut(wire.NewTxOut(0, nil))
	r.packet = r.markerPacket(0)
	r.state = rollingEncoded(r.t, next)
	message, err := receipt.Message()
	check(r.t, err)
	r.witness = append(proof.Witness(), bytes.Clone(receipt.Signature[:]), message)
	return next
}

func (r *rollingFixture) evaluateRolling() error {
	code, leaf, first := r.codes.Spend, r.leaves[0], 0
	if r.credit {
		code, leaf = r.codes.Credit, r.creditLeaf
	}
	if r.renew {
		code, leaf, first = r.codes.Renew, r.leaves[1], 1
	}
	entries := arkade.EmulatorPacket{}
	for i := first; i < len(r.tx.TxIn); i++ {
		entries = append(entries, arkade.EmulatorEntry{Vin: uint16(i), Script: code, Witness: r.witness})
	}
	ext, err := extension.NewExtensionFromPackets(r.packet, entries, extension.UnknownPacket{PacketType: StatePacketType, Data: r.state})
	if err != nil {
		return err
	}
	raw, err := ext.Serialize()
	if err != nil {
		return err
	}
	r.tx.TxOut[len(r.tx.TxOut)-1].PkScript = raw
	if !r.renew {
		last := len(r.tx.TxOut) - 1
		r.tx.TxOut[last], r.tx.TxOut[last-1] = r.tx.TxOut[last-1], r.tx.TxOut[last]
		defer func() { r.tx.TxOut[last], r.tx.TxOut[last-1] = r.tx.TxOut[last-1], r.tx.TxOut[last] }()
	}
	if err := r.validateAssets(); err != nil {
		return err
	}
	p, err := psbt.NewFromUnsignedTx(r.tx)
	if err != nil {
		return err
	}
	for i := range p.Inputs {
		p.Inputs[i].WitnessUtxo = r.FetchPrevOutput(r.tx.TxIn[i].PreviousOutPoint)
		p.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{leaf}
	}
	budget := arkade.NewComputeBudget()
	for _, entry := range entries {
		if err := arkade.VerifyTaprootLeafCommitment(p.Inputs[entry.Vin].WitnessUtxo.PkScript, leaf); err != nil {
			return err
		}
		script, err := arkade.ReadArkadeScript(p, r.emulator, entry)
		if err != nil {
			return err
		}
		opts := []arkade.ExecuteOption{arkade.WithComputeBudget(budget)}
		if r.renew {
			opts = append(opts, arkade.WithIntentMessage(r.intent), arkade.WithExpiry(r.expiries[int(entry.Vin)]))
		}
		if err := script.Execute(r.tx, r.fixture, int(entry.Vin), opts...); err != nil {
			return fmt.Errorf("input %d: %w", entry.Vin, err)
		}
	}
	return nil
}

func TestRollingSpendAndMatureCredit(t *testing.T) {
	r := newRollingFixture(t)
	initial, err := InitialRollingState(r.p.Budget)
	check(t, err)
	spent, debit := r.spendRolling(initial, nil, 1000, 100)
	check(t, r.evaluateRolling())
	receipt := signedReceipt(t, r.params, debit, time.Now().Unix()-2*WindowSeconds)
	check(t, receipt.Verify(r.params, time.Now().Unix()))
	restored := r.creditRolling(spent, []Debit{debit}, receipt)
	check(t, r.evaluateRolling())
	if restored.Remaining != initial.Remaining || restored.Root != initial.Root || restored.Sequence != 1 {
		t.Fatal("credit failed to restore exactly one debit")
	}
	proof, _, err := BuildHistoryProof(nil, debit.Sequence)
	check(t, err)
	if _, err := ApplyCredit(restored, r.p.Budget, debit, proof); err == nil {
		t.Fatal("duplicate credit accepted")
	}
	t.Logf("spend=%d credit=%d renew=%d bytes", len(r.codes.Spend), len(r.codes.Credit), len(r.codes.Renew))
}

func TestRollingCreditRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*rollingFixture)
	}{
		{"recent receipt", func(r *rollingFixture) {
			d, err := DecodeDebit(r.witness[3][32:84])
			check(r.t, err)
			receipt := signedReceipt(r.t, r.params, d, time.Now().Unix()-60)
			msg, err := receipt.Message()
			check(r.t, err)
			r.witness[2] = receipt.Signature[:]
			r.witness[3] = msg
		}},
		{"forged timestamp", func(r *rollingFixture) { r.witness[3][84] ^= 1 }},
		{"signature substitution", func(r *rollingFixture) { r.witness[2][0] ^= 1 }},
		{"different controller domain", func(r *rollingFixture) { r.witness[3][0] ^= 1 }},
		{"wrong debit", func(r *rollingFixture) { r.witness[3][40] ^= 1 }},
		{"wrong history sibling", func(r *rollingFixture) { r.witness[0][0] ^= 1 }},
		{"oversized sibling", func(r *rollingFixture) { r.witness[0] = append(r.witness[0], 0) }},
		{"missing witness", func(r *rollingFixture) { r.witness = nil }},
		{"extra witness", func(r *rollingFixture) { r.witness = append(r.witness, []byte{1}) }},
		{"unchanged charged root", func(r *rollingFixture) {
			old := r.FetchPrevOutArkTx(r.tx.TxIn[0].PreviousOutPoint)
			ext, err := extension.NewExtensionFromTx(old)
			check(r.t, err)
			b, err := ext.GetPacketByType(StatePacketType).Serialize()
			check(r.t, err)
			copy(r.state[20:], b[20:])
		}},
		{"extra restored allowance", func(r *rollingFixture) { r.state[4]++ }},
		{"sequence rollback", func(r *rollingFixture) { r.state[12] = 0 }},
		{"principal escape", func(r *rollingFixture) { r.tx.TxOut[0].PkScript = r.recipientScript }},
		{"controller value loss", func(r *rollingFixture) { r.tx.TxOut[0].Value-- }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRollingFixture(t)
			initial, err := InitialRollingState(r.p.Budget)
			check(t, err)
			spent, d := r.spendRolling(initial, nil, 1000, 100)
			r.creditRolling(spent, []Debit{d}, signedReceipt(t, r.params, d, time.Now().Unix()-2*WindowSeconds))
			tc.mutate(r)
			if err := r.evaluateRolling(); err == nil {
				t.Fatal("invalid credit accepted")
			}
		})
	}
}

func TestRollingHistoryRandomized(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	state, err := InitialRollingState(MaxBudget)
	check(t, err)
	history := []Debit{}
	var charged int64
	for i := 0; i < 500; i++ {
		if len(history) > 0 && rng.IntN(3) == 0 {
			idx := rng.IntN(len(history))
			d := history[idx]
			proof, root, err := BuildHistoryProof(history, d.Sequence)
			check(t, err)
			if root != state.Root {
				t.Fatal("root mismatch")
			}
			state, err = ApplyCredit(state, MaxBudget, d, proof)
			check(t, err)
			history = append(history[:idx], history[idx+1:]...)
			charged -= d.Amount
			if _, err := ApplyCredit(state, MaxBudget, d, proof); err == nil {
				t.Fatal("stale removal proof accepted")
			}
		} else {
			d := Debit{Sequence: state.Sequence, Amount: int64(rng.IntN(5000) + 1), Parent: wire.OutPoint{Hash: chainhash.Hash{byte(i), byte(i >> 8), 1}}}
			proof, root, err := BuildHistoryProof(history, d.Sequence)
			check(t, err)
			if root != state.Root {
				t.Fatal("root mismatch")
			}
			state, err = ApplyDebit(state, MaxBudget, d, proof)
			check(t, err)
			history = append(history, d)
			charged += d.Amount
		}
		if state.Remaining != MaxBudget-charged {
			t.Fatal("reference accounting mismatch")
		}
	}
}

func (r *rollingFixture) addCreditFee(credited RollingState, remainingHistory []Debit, fee int64) (RollingState, Debit) {
	principal := r.previous(20000, nil, false)
	r.tx.AddTxIn(wire.NewTxIn(&principal, nil, nil))
	r.tx.TxOut = append(r.tx.TxOut[:1], wire.NewTxOut(20000-fee, bytes.Clone(r.pkScript)), txutils.AnchorOutput(), wire.NewTxOut(0, nil))
	d := Debit{Sequence: credited.Sequence, Amount: fee, Parent: r.tx.TxIn[0].PreviousOutPoint}
	proof, root, err := BuildHistoryProof(remainingHistory, d.Sequence)
	check(r.t, err)
	if root != credited.Root {
		r.t.Fatal("intermediate history mismatch")
	}
	next, err := ApplyDebit(credited, r.p.Budget, d, proof)
	check(r.t, err)
	r.state = rollingEncoded(r.t, next)
	r.witness = append(proof.Witness(), r.witness...)
	return next, d
}

func TestRollingCreditChargesItsOwnFee(t *testing.T) {
	r := newRollingFixture(t)
	initial, err := InitialRollingState(r.p.Budget)
	check(t, err)
	spent, d := r.spendRolling(initial, nil, 1000, 100)
	check(t, r.evaluateRolling())
	credited := r.creditRolling(spent, []Debit{d}, signedReceipt(t, r.params, d, time.Now().Unix()-2*WindowSeconds))
	next, fee := r.addCreditFee(credited, nil, 100)
	check(t, r.evaluateRolling())
	if next.Remaining != 9900 || fee.Amount != 100 || next.Sequence != 2 {
		t.Fatal("credit fee not charged")
	}
	// Replenishing the payment cannot silently discard the credit's own fee.
	r.state = rollingEncoded(t, credited)
	if err := r.evaluateRolling(); err == nil {
		t.Fatal("unrecorded credit fee accepted")
	}
}

func (r *rollingFixture) renewRolling(old RollingState, history []Debit, fee int64) (RollingState, *Debit) {
	r.credit = false
	r.renewal(State{Remaining: old.Remaining, Sequence: old.Sequence}, []int64{20000})
	parent := r.previous(ControllerSats, rollingEncoded(r.t, old), true)
	r.tx.TxIn[1].PreviousOutPoint = parent
	r.tx.TxOut[1].Value -= fee
	r.witness = nil
	r.state = rollingEncoded(r.t, old)
	if fee == 0 {
		return old, nil
	}
	d := Debit{Sequence: old.Sequence, Amount: fee, Parent: parent}
	proof, root, err := BuildHistoryProof(history, d.Sequence)
	check(r.t, err)
	if root != old.Root {
		r.t.Fatal("history mismatch")
	}
	next, err := ApplyDebit(old, r.p.Budget, d, proof)
	check(r.t, err)
	r.witness = proof.Witness()
	r.state = rollingEncoded(r.t, next)
	return next, &d
}

func TestRollingRenewalPreservesHistoryAndChargesFees(t *testing.T) {
	r := newRollingFixture(t)
	initial, err := InitialRollingState(r.p.Budget)
	check(t, err)
	spent, d := r.spendRolling(initial, nil, 1000, 100)
	check(t, r.evaluateRolling())
	r.renewRolling(spent, []Debit{d}, 0)
	check(t, r.evaluateRolling())
	renewed, fee := r.renewRolling(spent, []Debit{d}, 100)
	check(t, r.evaluateRolling())
	if renewed.Remaining != 8800 || renewed.Sequence != 2 || fee.Amount != 100 {
		t.Fatal("renewal fee not charged")
	}
	r.state = rollingEncoded(t, spent)
	if err := r.evaluateRolling(); err == nil {
		t.Fatal("renewal fee omitted from state")
	}
}

func TestRollingMultipleDebitCredits(t *testing.T) {
	r := newRollingFixture(t)
	state, err := InitialRollingState(r.p.Budget)
	check(t, err)
	history := []Debit{}
	for i := 0; i < 12; i++ {
		var d Debit
		state, d = r.spendRolling(state, history, 330, 1)
		check(t, r.evaluateRolling())
		history = append(history, d)
	}
	for len(history) > 0 {
		// Removal order exercises both left and right Merkle branches.
		index := len(history) / 2
		d := history[index]
		state = r.creditRolling(state, history, signedReceipt(t, r.params, d, time.Now().Unix()-2*WindowSeconds))
		check(t, r.evaluateRolling())
		history = append(history[:index], history[index+1:]...)
	}
	if state.Remaining != r.p.Budget || state.Sequence != 12 || state.Root != emptyRoots()[HistoryDepth] {
		t.Fatal("rolling window did not restore")
	}
}
