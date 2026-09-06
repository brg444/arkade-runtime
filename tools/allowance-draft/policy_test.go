package allowancedraft

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func TestSpendValid(t *testing.T) {
	for _, tc := range []struct {
		name     string
		old      State
		values   []int64
		pay, fee int64
	}{
		{"payment with change", State{10000, 5}, []int64{20000}, 1000, 100},
		{"four principal inputs", State{10000, 5}, []int64{5000, 5000, 5000, 5000}, 1000, 100},
		{"zero remaining budget", State{5100, 5}, []int64{10000}, 5000, 100},
		{"exact balance without change", State{10000, 5}, []int64{5100}, 5000, 100},
		{"zero fee", State{10000, 5}, []int64{10000}, 5000, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.spend(tc.old, tc.values, tc.pay, tc.fee)
			check(t, f.evaluate(true, nil))
		})
	}
}

func TestRenewValid(t *testing.T) {
	for _, tc := range []struct {
		name      string
		values    []int64
		remaining int64
	}{
		{"controller only", nil, 10000},
		{"controller and four principal inputs", []int64{5000, 5000, 5000, 5000}, 8900},
		{"exhausted allowance", []int64{5000}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.renewal(State{tc.remaining, 5}, tc.values)
			check(t, f.evaluate(true, nil))
		})
	}
}

func TestRenewSharedComputeBudget(t *testing.T) {
	f := newFixture(t)
	f.renewal(State{8900, 5}, []int64{5000, 5000, 5000, 5000})
	// Each of five real inputs evaluates four message fields. The stock request
	// limit is 64; a request limit of 19 must fail on the fifth input.
	budget := arkade.NewComputeBudgetWithLimits(arkade.ComputeLimits{arkade.OP_INSPECTINTENTMESSAGE: 19})
	if err := f.evaluate(true, budget); err == nil || !strings.Contains(err.Error(), "request execution limit of 19") {
		t.Fatalf("expected shared request budget rejection, got %v", err)
	}
}

func TestSpendRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"recipient over cap", func(f *fixture) {
			f.tx.TxOut[1].Value = 5001
			f.tx.TxOut[2].Value = 14899
			f.state = encoded(t, State{4899, 6})
		}},
		{"fee over cap", func(f *fixture) { f.tx.TxOut[2].Value = 18799; f.state = encoded(t, State{8799, 6}) }},
		{"negative fee", func(f *fixture) { f.tx.TxOut[2].Value = 19100; f.state = encoded(t, State{9100, 6}) }},
		{"fee omitted from debit", func(f *fixture) { f.state = encoded(t, State{9000, 6}) }},
		{"spent budget restored", func(f *fixture) { f.state = encoded(t, State{10000, 6}) }},
		{"budget insufficient", func(f *fixture) { f.replaceController(State{1000, 5}); f.state = encoded(t, State{0, 6}) }},
		{"sequence skipped", func(f *fixture) { f.state = encoded(t, State{8900, 7}) }},
		{"sequence unchanged", func(f *fixture) { f.state = encoded(t, State{8900, 5}) }},
		{"sequence rolled back", func(f *fixture) { f.state = encoded(t, State{8900, 4}) }},
		{"sequence exhausted", func(f *fixture) { f.replaceController(State{10000, MaxSequence}); f.state = encoded(t, State{8900, 0}) }},
		{"missing state", func(f *fixture) { f.state = nil }},
		{"truncated state", func(f *fixture) { f.state = f.state[:19] }},
		{"extended state", func(f *fixture) { f.state = append(f.state, 0) }},
		{"oversize packet", func(f *fixture) { f.state = make([]byte, 521) }},
		{"wrong program magic", func(f *fixture) { f.state[0] = 'X' }},
		{"negative state budget", func(f *fixture) { f.state[11] |= 0x80 }},
		{"state above compile cap", func(f *fixture) { binary.LittleEndian.PutUint64(f.state[4:12], 10001) }},
		{"state sequence sign bit", func(f *fixture) { f.state[19] |= 0x80 }},
		{"protected change escaped", func(f *fixture) { f.tx.TxOut[2].PkScript = f.recipientScript }},
		{"successor controller escaped", func(f *fixture) { f.tx.TxOut[0].PkScript = f.recipientScript }},
		{"controller principal removed", func(f *fixture) { f.tx.TxOut[0].Value = 0 }},
		{"extra destination", func(f *fixture) {
			f.tx.TxOut = append(f.tx.TxOut[:3], append([]*wire.TxOut{wire.NewTxOut(330, f.recipientScript)}, f.tx.TxOut[3:]...)...)
		}},
		{"anchor pays value", func(f *fixture) { f.tx.TxOut[3].Value = 1 }},
		{"anchor substituted", func(f *fixture) { f.tx.TxOut[3].PkScript = f.recipientScript }},
		{"extension burns value", func(f *fixture) { f.tx.TxOut[4].Value = 1 }},
		{"non taproot recipient", func(f *fixture) { f.tx.TxOut[1].PkScript = []byte{0x51} }},
		{"dust recipient", func(f *fixture) { f.tx.TxOut[1].Value = 329 }},
		{"dust change", func(f *fixture) { f.tx.TxOut[2].Value = 329 }},
		{"wrong version", func(f *fixture) { f.tx.Version = 2 }},
		{"caller locktime", func(f *fixture) { f.tx.LockTime = 1 }},
		{"wrong marker id", func(f *fixture) { id := f.p.ControllerID; id.Txid[0]++; f.packet[0].AssetId = &id }},
		{"wrong controller input", func(f *fixture) { f.packet[0].Inputs[0].Vin = 1 }},
		{"marker sent to recipient", func(f *fixture) { f.packet[0].Outputs[0].Vout = 1 }},
		{"two successor controllers", func(f *fixture) {
			f.packet[0].Outputs = append(f.packet[0].Outputs, asset.AssetOutput{Type: asset.AssetOutputTypeLocal, Vout: 2, Amount: 1})
		}},
		{"two controller inputs", func(f *fixture) {
			f.packet[0].Inputs = append(f.packet[0].Inputs, asset.AssetInput{Type: asset.AssetInputTypeLocal, Vin: 1, Amount: 1})
		}},
		{"foreign asset group", func(f *fixture) {
			other := f.markerPacket(1)[0]
			id := f.p.ControllerID
			id.Txid[0]++
			other.AssetId = &id
			f.packet = append(f.packet, other)
		}},
		{"foreign principal tree", func(f *fixture) {
			op := f.tx.TxIn[1].PreviousOutPoint
			f.prev[op.Hash].TxOut[0].PkScript = f.recipientScript
		}},
		{"missing controller packet", func(f *fixture) { op := f.previous(ControllerSats, nil, true); f.tx.TxIn[0].PreviousOutPoint = op }},
		{"fifth principal input", func(f *fixture) {
			for i := 0; i < 4; i++ {
				op := f.previous(1000, nil, false)
				f.tx.AddTxIn(wire.NewTxIn(&op, nil, nil))
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.spend(State{10000, 5}, []int64{20000}, 1000, 100)
			tc.mutate(f)
			if err := f.evaluate(false, nil); err == nil {
				t.Fatal("invalid spend passed emulator checks")
			}
		})
	}
}

func (f *fixture) replaceController(s State) {
	i := 0
	if f.renew {
		i = 1
	}
	op := f.previous(ControllerSats, encoded(f.t, s), true)
	f.tx.TxIn[i].PreviousOutPoint = op
}

func TestNegativeZeroRejected(t *testing.T) {
	for _, renew := range []bool{false, true} {
		t.Run(fmt.Sprintf("renew=%t", renew), func(t *testing.T) {
			f := newFixture(t)
			if renew {
				f.renewal(State{0, 5}, nil)
			} else {
				f.spend(State{1100, 5}, []int64{20000}, 1000, 100)
			}
			f.state[11] = 0x80
			if renew {
				op := f.previous(ControllerSats, bytes.Clone(f.state), true)
				f.tx.TxIn[1].PreviousOutPoint = op
			}
			if err := f.evaluate(false, nil); err == nil {
				t.Fatal("negative zero accepted")
			}
		})
	}
}

func TestMarkerProvenanceRequiresOperator(t *testing.T) {
	f := newFixture(t)
	f.spend(State{10000, 5}, []int64{20000}, 1000, 100)
	delete(f.assets, f.tx.TxIn[0].PreviousOutPoint)
	// The VM sees a matching declaration; authoritative asset ownership is a
	// separate mandatory validation step. This is an explicit trust boundary.
	check(t, f.evaluate(false, nil))
	if err := f.evaluate(true, nil); err == nil || !strings.Contains(err.Error(), "asset provenance") {
		t.Fatalf("forged ownership accepted: %v", err)
	}
}

func TestDepositCannotResetBudget(t *testing.T) {
	f := newFixture(t)
	f.spend(State{2000, 8}, []int64{20000}, 1000, 100)
	// Anyone can deposit to this tree and attach invented state. Only the
	// authenticated controller input supplies the spend's previous allowance.
	deposit := f.previous(20000, encoded(t, State{10000, 0}), false)
	f.tx.TxIn[1].PreviousOutPoint = deposit
	check(t, f.evaluate(true, nil))
	f.state = encoded(t, State{8900, 9})
	if err := f.evaluate(true, nil); err == nil {
		t.Fatal("deposit reset the budget")
	}
}

func TestSpendSuccessorChain(t *testing.T) {
	f := newFixture(t)
	f.spend(State{10000, 0}, []int64{20000}, 1000, 100)
	for n := uint64(1); n <= 3; n++ {
		check(t, f.evaluate(true, nil))
		prior := f.tx.Copy()
		f.prev[prior.TxHash()] = prior
		ctrl := wire.OutPoint{Hash: prior.TxHash(), Index: 0}
		change := wire.OutPoint{Hash: prior.TxHash(), Index: 2}
		f.assets[ctrl] = []asset.Asset{{AssetId: f.p.ControllerID.String(), Amount: 1}}
		if n == 3 {
			break
		}
		remaining := int64(10000) - int64(n)*1100
		f.spend(State{remaining, n}, []int64{prior.TxOut[2].Value}, 1000, 100)
		f.tx.TxIn[0].PreviousOutPoint = ctrl
		f.tx.TxIn[1].PreviousOutPoint = change
	}
	f.state = encoded(t, State{8900, 3})
	if err := f.evaluate(true, nil); err == nil {
		t.Fatal("successor chain restored earlier remaining allowance")
	}
}

func TestConflictingSpendsNeedSingleSpendAdmission(t *testing.T) {
	f := newFixture(t)
	f.spend(State{2000, 5}, []int64{20000}, 1000, 100)
	check(t, f.evaluate(true, nil))
	first := f.tx.Copy()
	// A second principal input can be disjoint, while both spends must consume
	// the same controller. The VM alone can approve both conflicting proposals.
	op := f.previous(20000, nil, false)
	f.tx.TxIn[1].PreviousOutPoint = op
	check(t, f.evaluate(true, nil))
	if first.TxHash() == f.tx.TxHash() || first.TxIn[0].PreviousOutPoint != f.tx.TxIn[0].PreviousOutPoint {
		t.Fatal("fixture did not construct conflicting proposals")
	}
}

func TestRenewRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"premature controller", func(f *fixture) { f.expiries[1] = time.Now().Unix() + f.p.RenewalWindow + 3600 }},
		{"premature money input", func(f *fixture) { f.expiries[2] = time.Now().Unix() + f.p.RenewalWindow + 3600 }},
		{"missing expiry", func(f *fixture) { delete(f.expiries, 1) }},
		{"missing intent", func(f *fixture) { f.intent = "" }},
		{"wrong intent", func(f *fixture) { f.intent = strings.Replace(f.intent, "register", "delete", 1) }},
		{"onchain output", func(f *fixture) {
			f.intent = strings.Replace(f.intent, `"onchain_output_indexes":[]`, `"onchain_output_indexes":[0]`, 1)
		}},
		{"wrong delegate", func(f *fixture) {
			f.intent = strings.Replace(f.intent, fmt.Sprintf("%x", f.p.DelegatePubkey), fmt.Sprintf("%x", testKey(8).SerializeCompressed()), 1)
		}},
		{"additional delegate", func(f *fixture) {
			f.intent = strings.Replace(f.intent, fmt.Sprintf(`"%x"`, f.p.DelegatePubkey), fmt.Sprintf(`"%x","%x"`, f.p.DelegatePubkey, testKey(8).SerializeCompressed()), 1)
		}},
		{"refilled budget", func(f *fixture) { f.state = encoded(t, State{10000, 5}) }},
		{"decreased budget", func(f *fixture) { f.state = encoded(t, State{8800, 5}) }},
		{"sequence advanced", func(f *fixture) { f.state = encoded(t, State{8900, 6}) }},
		{"sequence reset", func(f *fixture) { f.state = encoded(t, State{8900, 0}) }},
		{"missing state", func(f *fixture) { f.state = nil }},
		{"principal escaped", func(f *fixture) { f.tx.TxOut[1].PkScript = f.recipientScript }},
		{"principal debited", func(f *fixture) { f.tx.TxOut[1].Value-- }},
		{"principal increased", func(f *fixture) { f.tx.TxOut[1].Value++ }},
		{"controller escaped", func(f *fixture) { f.tx.TxOut[0].PkScript = f.recipientScript }},
		{"marker moved", func(f *fixture) { f.packet[0].Outputs[0].Vout = 1 }},
		{"marker duplicated", func(f *fixture) { f.packet[0].Outputs[0].Amount = 2 }},
		{"extra output", func(f *fixture) {
			f.tx.TxOut = append(f.tx.TxOut[:2], append([]*wire.TxOut{wire.NewTxOut(0, f.pkScript)}, f.tx.TxOut[2:]...)...)
		}},
		{"spend version via renewal leaf", func(f *fixture) { f.tx.Version = 3 }},
		{"locktime set", func(f *fixture) { f.tx.LockTime = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.renewal(State{8900, 5}, []int64{5000})
			tc.mutate(f)
			if err := f.evaluate(false, nil); err == nil {
				t.Fatal("invalid renewal passed emulator checks")
			}
		})
	}
}

func TestScriptBinding(t *testing.T) {
	f := newFixture(t)
	f.spend(State{10000, 5}, []int64{20000}, 1000, 100)
	ptx, err := psbt.NewFromUnsignedTx(f.tx)
	check(t, err)
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{f.leaves[0]}
	if _, err := arkade.ReadArkadeScript(ptx, f.emulator, arkade.EmulatorEntry{Vin: 0, Script: f.scripts.Renew}); err == nil {
		t.Fatal("renewal program accepted under spend key")
	}
	if _, err := arkade.ReadArkadeScript(ptx, f.emulator, arkade.EmulatorEntry{Vin: 0, Script: []byte{0x51}}); err == nil {
		t.Fatal("arbitrary program accepted under spend key")
	}
	leaf := *f.leaves[0]
	leaf.ControlBlock = bytes.Clone(leaf.ControlBlock)
	leaf.ControlBlock[len(leaf.ControlBlock)-1] ^= 1
	if err := arkade.VerifyTaprootLeafCommitment(f.pkScript, &leaf); err == nil {
		t.Fatal("modified control block accepted")
	}
}

func TestPrincipalRenewalIndependentOfController(t *testing.T) {
	f := newFixture(t)
	f.renewal(State{8900, 5}, []int64{5000, 5000, 5000, 5000})
	controller := f.tx.TxIn[1].PreviousOutPoint
	// A recently renewed controller can be outside its window while older
	// deposits need renewal. Only the four principal inputs participate here.
	f.tx.TxIn = append(f.tx.TxIn[:1], f.tx.TxIn[2:]...)
	f.tx.TxOut = f.tx.TxOut[1:]
	f.packet = nil
	f.state = nil
	check(t, f.evaluate(true, nil))
	for _, in := range f.tx.TxIn {
		if in.PreviousOutPoint == controller {
			t.Fatal("principal renewal consumed controller")
		}
	}
	for _, state := range [][]byte{encoded(t, State{10000, 0}), encoded(t, State{8900, 5})} {
		f.state = state
		if err := f.evaluate(true, nil); err == nil {
			t.Fatal("principal-only renewal created allowance state")
		}
	}
}

func TestRenewMarkerOmissionRequiresOperator(t *testing.T) {
	f := newFixture(t)
	f.renewal(State{8900, 5}, nil)
	f.packet = nil
	f.state = nil
	// Hiding the controller declaration is invisible to the VM's asset packet
	// introspection. The resolved input-asset check rejects this attempted burn.
	check(t, f.evaluate(false, nil))
	if err := f.evaluate(true, nil); err == nil || !strings.Contains(err.Error(), "asset provenance") {
		t.Fatalf("controller stripped through principal renewal: %v", err)
	}
}

func TestDraftMetrics(t *testing.T) {
	f := newFixture(t)
	f.spend(State{10000, 5}, []int64{5000, 5000, 5000, 5000}, 1000, 100)
	t.Logf("spend_script_bytes=%d renewal_script_bytes=%d max_spend_unsigned_bytes=%d max_spend_extension_bytes=%d", len(f.scripts.Spend), len(f.scripts.Renew), f.tx.SerializeSizeStripped(), len(f.tx.TxOut[len(f.tx.TxOut)-1].PkScript))
	f.renewal(State{8900, 5}, []int64{5000, 5000, 5000, 5000})
	t.Logf("max_renewal_unsigned_bytes=%d max_renewal_extension_bytes=%d", f.tx.SerializeSizeStripped(), len(f.tx.TxOut[len(f.tx.TxOut)-1].PkScript))
}
