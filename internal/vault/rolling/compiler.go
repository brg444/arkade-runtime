// Package rolling compiles the named rolling allowance contract and verifies
// its authenticated debit history. Enrollment and service admission remain
// separate responsibilities; this package exposes no signing service.
package rolling

import (
	"fmt"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
)

const (
	StatePacketType        = 2
	MaxBudget       int64  = 1_000_000_000
	MaxSequence     uint64 = 2_147_483_647
	ControllerSats  int64  = 330
	MaxMoneyInputs         = 4
	maxMoney        int64  = 2_100_000_000_000_000
)

type Parameters struct {
	ControllerID   asset.AssetId
	Budget         int64
	RecipientCap   int64
	FeeCap         int64
	DelegatePubkey []byte // compressed tree-cosigner key
	RenewalWindow  int64
}

func (p Parameters) Validate() error {
	if p.ControllerID.Txid == ([32]byte{}) || p.Budget < ControllerSats || p.Budget > MaxBudget ||
		p.RecipientCap < ControllerSats || p.RecipientCap > p.Budget || p.FeeCap < 0 || p.FeeCap > 100_000 ||
		p.RenewalWindow <= 0 || p.RenewalWindow > 30*86400 || len(p.DelegatePubkey) != 33 {
		return fmt.Errorf("invalid rolling parameters")
	}
	_, err := btcec.ParsePubKey(p.DelegatePubkey)
	return err
}

type builder struct{ *txscript.ScriptBuilder }

func newBuilder() builder    { return builder{txscript.NewScriptBuilder()} }
func (b builder) eq(n int64) { b.AddInt64(n).AddOp(OP_EQUALVERIFY) }
func (b builder) bounded(lo, hi int64) {
	b.AddOp(OP_DUP).AddInt64(lo).AddOp(OP_GREATERTHANOREQUAL).AddOp(OP_VERIFY).
		AddOp(OP_DUP).AddInt64(hi).AddOp(OP_LESSTHANOREQUAL).AddOp(OP_VERIFY)
}
func (b builder) inputValue(i int)  { b.AddInt64(int64(i)).AddOp(OP_INSPECTINPUTVALUE) }
func (b builder) outputValue(i int) { b.AddInt64(int64(i)).AddOp(OP_INSPECTOUTPUTVALUE) }
func (b builder) inputScript(i int) {
	b.AddInt64(int64(i)).AddOp(OP_INSPECTINPUTSCRIPTPUBKEY)
	b.eq(1)
	b.AddOp(OP_DUP).AddOp(OP_SIZE)
	b.eq(32)
	b.AddOp(OP_DROP)
}
func (b builder) outputScript(i int) {
	b.AddInt64(int64(i)).AddOp(OP_INSPECTOUTPUTSCRIPTPUBKEY)
	b.eq(1)
	b.AddOp(OP_DUP).AddOp(OP_SIZE)
	b.eq(32)
	b.AddOp(OP_DROP)
}
func (b builder) outputMatchesInput(out, in int) {
	b.outputScript(out)
	b.inputScript(in)
	b.AddOp(OP_EQUALVERIFY)
}
func (b builder) header(version int64, minInputs, maxInputs int64) {
	b.AddOp(OP_INSPECTVERSION)
	b.eq(version)
	b.AddOp(OP_INSPECTLOCKTIME)
	b.eq(0)
	b.AddOp(OP_INSPECTNUMINPUTS)
	b.bounded(minInputs, maxInputs)
	b.AddOp(OP_DROP)
}

// Require one declared, existing asset input at controller and one output at 0.
// Operator asset validation must authenticate these declarations against the
// resolved input assets; the VM alone is not an issuance/provenance verifier.
func (b builder) marker(id asset.AssetId, controller int) {
	b.AddOp(OP_INSPECTNUMASSETGROUPS)
	b.eq(1)
	b.AddInt64(0).AddOp(OP_INSPECTASSETGROUPASSETID)
	b.eq(int64(id.Index))
	b.AddData(id.Txid[:]).AddOp(OP_EQUALVERIFY)
	for source := int64(0); source < 2; source++ {
		b.AddInt64(0).AddInt64(source).AddOp(OP_INSPECTASSETGROUPNUM)
		b.eq(1)
		b.AddInt64(0).AddInt64(0).AddInt64(source).AddOp(OP_INSPECTASSETGROUP)
		b.eq(1) // amount
		if source == 0 {
			b.eq(int64(controller))
		} else {
			b.eq(0)
		}
		b.eq(1) // LOCAL input or output
	}
}

func compileSpendWithState(p Parameters, state func(builder)) ([]byte, error) {
	b := newBuilder()
	b.header(3, 2, MaxMoneyInputs+1)
	b.AddOp(OP_INSPECTNUMOUTPUTS)
	b.bounded(4, 5)
	b.AddOp(OP_DROP)
	b.marker(p.ControllerID, 0)
	b.inputValue(0)
	b.eq(ControllerSats)
	b.outputValue(0)
	b.eq(ControllerSats)
	b.outputMatchesInput(0, 0)
	// Every selected principal input belongs to the same enrolled tree.
	for i := 1; i <= MaxMoneyInputs; i++ {
		b.AddOp(OP_INSPECTNUMINPUTS).AddInt64(int64(i)).AddOp(OP_GREATERTHAN).AddOp(OP_IF)
		b.inputScript(i)
		b.inputScript(0)
		b.AddOp(OP_EQUALVERIFY)
		b.inputValue(i)
		b.bounded(ControllerSats, maxMoney)
		b.AddOp(OP_DROP).AddOp(OP_ENDIF)
	}
	b.outputScript(1)
	b.AddOp(OP_DROP)
	b.outputValue(1)
	b.bounded(ControllerSats, p.RecipientCap)
	b.AddOp(OP_DROP)
	// The last two outputs are the zero-value P2A and extension outputs.
	b.AddOp(OP_INSPECTNUMOUTPUTS).AddOp(OP_1SUB).AddOp(OP_INSPECTOUTPUTVALUE)
	b.eq(0)
	b.AddOp(OP_INSPECTNUMOUTPUTS).AddOp(OP_1SUB).AddOp(OP_INSPECTOUTPUTSCRIPTPUBKEY)
	b.eq(1)
	b.AddData([]byte{0x4e, 0x73}).AddOp(OP_EQUALVERIFY)
	b.AddOp(OP_INSPECTNUMOUTPUTS).AddInt64(2).AddOp(OP_SUB).AddOp(OP_INSPECTOUTPUTVALUE)
	b.eq(0)
	b.AddOp(OP_INSPECTNUMOUTPUTS).AddInt64(2).AddOp(OP_SUB).AddOp(OP_INSPECTOUTPUTSCRIPTPUBKEY)
	b.eq(-1)
	b.AddOp(OP_DROP)
	// Sum the actual principal inputs. The controller contributes zero outflow.
	b.AddInt64(0)
	for i := 1; i <= MaxMoneyInputs; i++ {
		b.AddOp(OP_INSPECTNUMINPUTS).AddInt64(int64(i)).AddOp(OP_GREATERTHAN).AddOp(OP_IF)
		b.inputValue(i)
		b.AddOp(OP_ADD).AddOp(OP_ENDIF)
	}
	b.bounded(ControllerSats, maxMoney)
	b.AddOp(OP_INSPECTNUMOUTPUTS).AddInt64(5).AddOp(OP_EQUAL).AddOp(OP_IF)
	b.outputMatchesInput(2, 0)
	b.outputValue(2)
	b.bounded(ControllerSats, maxMoney)
	b.AddOp(OP_SUB).AddOp(OP_ENDIF)
	// stack: debit = principal in - protected principal out = recipient + fee.
	b.AddOp(OP_DUP)
	b.outputValue(1)
	b.AddOp(OP_SUB)
	b.bounded(0, p.FeeCap)
	b.AddOp(OP_DROP)
	state(b)
	b.AddOp(OP_TRUE)
	return b.Script()
}

// OP_TXWEIGHT reports stripped transaction weight. Using it is conservative
// relative to the signed transaction's virtual size and cannot weaken the cap.
func (b builder) feeRate(cap int64) {
	b.AddOp(OP_DUP).AddOp(OP_TXWEIGHT).AddInt64(4).AddOp(OP_DIV).
		AddInt64(cap).AddOp(OP_MUL).AddOp(OP_LESSTHANOREQUAL).AddOp(OP_VERIFY)
}
