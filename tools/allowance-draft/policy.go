package allowancedraft

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
)

const maxMoney int64 = 2_100_000_000_000_000

// Parameters are compile-time research inputs, never an HTTP policy surface.
type Parameters struct {
	ControllerID   asset.AssetId
	Budget         int64
	RecipientCap   int64
	FeeCap         int64
	DelegatePubkey []byte // compressed tree-cosigner key
	RenewalWindow  int64
}

type Scripts struct{ Spend, Renew []byte }

func Compile(p Parameters) (Scripts, error) {
	if p.ControllerID.Txid == ([32]byte{}) || p.Budget < ControllerSats || p.Budget > MaxBudget ||
		p.RecipientCap < ControllerSats || p.RecipientCap > p.Budget || p.FeeCap < 0 || p.FeeCap > 100_000 ||
		p.RenewalWindow <= 0 || p.RenewalWindow > 30*86400 || len(p.DelegatePubkey) != 33 {
		return Scripts{}, fmt.Errorf("invalid draft parameters")
	}
	if _, err := btcec.ParsePubKey(p.DelegatePubkey); err != nil {
		return Scripts{}, err
	}
	s, err := compileSpend(p)
	if err != nil {
		return Scripts{}, err
	}
	r, err := compileRenew(p)
	return Scripts{Spend: s, Renew: r}, err
}

type builder struct{ *txscript.ScriptBuilder }

func newBuilder() builder    { return builder{txscript.NewScriptBuilder()} }
func (b builder) eq(n int64) { b.AddInt64(n).AddOp(arkade.OP_EQUALVERIFY) }
func (b builder) bounded(lo, hi int64) {
	b.AddOp(arkade.OP_DUP).AddInt64(lo).AddOp(arkade.OP_GREATERTHANOREQUAL).AddOp(arkade.OP_VERIFY).
		AddOp(arkade.OP_DUP).AddInt64(hi).AddOp(arkade.OP_LESSTHANOREQUAL).AddOp(arkade.OP_VERIFY)
}
func (b builder) inputValue(i int)  { b.AddInt64(int64(i)).AddOp(arkade.OP_INSPECTINPUTVALUE) }
func (b builder) outputValue(i int) { b.AddInt64(int64(i)).AddOp(arkade.OP_INSPECTOUTPUTVALUE) }
func (b builder) inputScript(i int) {
	b.AddInt64(int64(i)).AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY)
	b.eq(1)
	b.AddOp(arkade.OP_DUP).AddOp(arkade.OP_SIZE)
	b.eq(32)
	b.AddOp(arkade.OP_DROP)
}
func (b builder) outputScript(i int) {
	b.AddInt64(int64(i)).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY)
	b.eq(1)
	b.AddOp(arkade.OP_DUP).AddOp(arkade.OP_SIZE)
	b.eq(32)
	b.AddOp(arkade.OP_DROP)
}
func (b builder) outputMatchesInput(out, in int) {
	b.outputScript(out)
	b.inputScript(in)
	b.AddOp(arkade.OP_EQUALVERIFY)
}
func (b builder) header(version int64, minInputs, maxInputs int64) {
	b.AddOp(arkade.OP_INSPECTVERSION)
	b.eq(version)
	b.AddOp(arkade.OP_INSPECTLOCKTIME)
	b.eq(0)
	b.AddOp(arkade.OP_INSPECTNUMINPUTS)
	b.bounded(minInputs, maxInputs)
	b.AddOp(arkade.OP_DROP)
}

// Require one declared, existing asset input at controller and one output at 0.
// Operator asset validation must authenticate these declarations against the
// resolved input assets; the VM alone is not an issuance/provenance verifier.
func (b builder) marker(id asset.AssetId, controller int) {
	b.AddOp(arkade.OP_INSPECTNUMASSETGROUPS)
	b.eq(1)
	b.AddInt64(0).AddOp(arkade.OP_INSPECTASSETGROUPASSETID)
	b.eq(int64(id.Index))
	b.AddData(id.Txid[:]).AddOp(arkade.OP_EQUALVERIFY)
	for source := int64(0); source < 2; source++ {
		b.AddInt64(0).AddInt64(source).AddOp(arkade.OP_INSPECTASSETGROUPNUM)
		b.eq(1)
		b.AddInt64(0).AddInt64(0).AddInt64(source).AddOp(arkade.OP_INSPECTASSETGROUP)
		b.eq(1) // amount
		if source == 0 {
			b.eq(int64(controller))
		} else {
			b.eq(0)
		}
		b.eq(1) // LOCAL input or output
	}
}

// A read yields the actual transaction packet. The fixed width and numeric
// bounds make signed BIN2NUM interpretation unambiguous for this draft.
func (b builder) statePacket(input int) {
	b.AddInt64(StatePacketType)
	if input < 0 {
		b.AddOp(arkade.OP_INSPECTPACKET)
	} else {
		b.AddInt64(int64(input)).AddOp(arkade.OP_INSPECTINPUTPACKET)
	}
	b.AddOp(arkade.OP_VERIFY).AddOp(arkade.OP_SIZE)
	b.eq(StateSize)
	b.AddOp(arkade.OP_DUP).AddInt64(4).AddOp(arkade.OP_LEFT).AddData(stateMagic).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(16).AddOp(arkade.OP_RIGHT)
}
func (b builder) stateField(input int, sequence bool, budget int64) {
	b.statePacket(input)
	b.AddInt64(8)
	if sequence {
		b.AddOp(arkade.OP_RIGHT)
	} else {
		b.AddOp(arkade.OP_LEFT)
	}
	// Round-trip the padded representation to reject negative zero as well.
	b.AddOp(arkade.OP_DUP).AddOp(arkade.OP_BIN2NUM).AddOp(arkade.OP_DUP).
		AddInt64(8).AddOp(arkade.OP_NUM2BIN).AddOp(arkade.OP_ROT).AddOp(arkade.OP_EQUALVERIFY)
	if sequence {
		b.bounded(0, int64(MaxSequence))
	} else {
		b.bounded(0, budget)
	}
}

func compileSpend(p Parameters) ([]byte, error) {
	b := newBuilder()
	b.header(3, 2, MaxMoneyInputs+1)
	b.AddOp(arkade.OP_INSPECTNUMOUTPUTS)
	b.bounded(4, 5)
	b.AddOp(arkade.OP_DROP)
	b.marker(p.ControllerID, 0)
	b.inputValue(0)
	b.eq(ControllerSats)
	b.outputValue(0)
	b.eq(ControllerSats)
	b.outputMatchesInput(0, 0)
	// Every selected principal input belongs to the same enrolled tree.
	for i := 1; i <= MaxMoneyInputs; i++ {
		b.AddOp(arkade.OP_INSPECTNUMINPUTS).AddInt64(int64(i)).AddOp(arkade.OP_GREATERTHAN).AddOp(arkade.OP_IF)
		b.inputScript(i)
		b.inputScript(0)
		b.AddOp(arkade.OP_EQUALVERIFY)
		b.inputValue(i)
		b.bounded(ControllerSats, maxMoney)
		b.AddOp(arkade.OP_DROP).AddOp(arkade.OP_ENDIF)
	}
	b.outputScript(1)
	b.AddOp(arkade.OP_DROP)
	b.outputValue(1)
	b.bounded(ControllerSats, p.RecipientCap)
	b.AddOp(arkade.OP_DROP)
	// The last two outputs are the zero-value P2A and extension outputs.
	b.AddOp(arkade.OP_INSPECTNUMOUTPUTS).AddInt64(2).AddOp(arkade.OP_SUB).AddOp(arkade.OP_INSPECTOUTPUTVALUE)
	b.eq(0)
	b.AddOp(arkade.OP_INSPECTNUMOUTPUTS).AddInt64(2).AddOp(arkade.OP_SUB).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY)
	b.eq(1)
	b.AddData([]byte{0x4e, 0x73}).AddOp(arkade.OP_EQUALVERIFY)
	b.AddOp(arkade.OP_INSPECTNUMOUTPUTS).AddOp(arkade.OP_1SUB).AddOp(arkade.OP_INSPECTOUTPUTVALUE)
	b.eq(0)
	b.AddOp(arkade.OP_INSPECTNUMOUTPUTS).AddOp(arkade.OP_1SUB).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY)
	b.eq(-1)
	b.AddOp(arkade.OP_DROP)
	// Sum the actual principal inputs. The controller contributes zero outflow.
	b.AddInt64(0)
	for i := 1; i <= MaxMoneyInputs; i++ {
		b.AddOp(arkade.OP_INSPECTNUMINPUTS).AddInt64(int64(i)).AddOp(arkade.OP_GREATERTHAN).AddOp(arkade.OP_IF)
		b.inputValue(i)
		b.AddOp(arkade.OP_ADD).AddOp(arkade.OP_ENDIF)
	}
	b.bounded(ControllerSats, maxMoney)
	b.AddOp(arkade.OP_INSPECTNUMOUTPUTS).AddInt64(5).AddOp(arkade.OP_EQUAL).AddOp(arkade.OP_IF)
	b.outputMatchesInput(2, 0)
	b.outputValue(2)
	b.bounded(ControllerSats, maxMoney)
	b.AddOp(arkade.OP_SUB).AddOp(arkade.OP_ENDIF)
	// stack: debit = principal in - protected principal out = recipient + fee.
	b.AddOp(arkade.OP_DUP)
	b.outputValue(1)
	b.AddOp(arkade.OP_SUB)
	b.bounded(0, p.FeeCap)
	b.AddOp(arkade.OP_DROP)
	b.stateField(0, false, p.Budget)
	b.AddOp(arkade.OP_SWAP).AddOp(arkade.OP_SUB)
	b.bounded(0, p.Budget)
	b.stateField(-1, false, p.Budget)
	b.AddOp(arkade.OP_EQUALVERIFY)
	b.stateField(0, true, p.Budget)
	b.AddOp(arkade.OP_1ADD)
	b.stateField(-1, true, p.Budget)
	b.AddOp(arkade.OP_EQUALVERIFY).AddOp(arkade.OP_TRUE)
	return b.Script()
}

func compileRenew(p Parameters) ([]byte, error) {
	b := newBuilder()
	b.header(2, 2, MaxMoneyInputs+2)
	// Output count includes the extension; input zero is the intent message.
	b.AddOp(arkade.OP_INSPECTNUMOUTPUTS).AddOp(arkade.OP_INSPECTNUMINPUTS).AddOp(arkade.OP_EQUALVERIFY)
	b.inputValue(0)
	b.eq(0)
	b.AddOp(arkade.OP_PUSHEXPIRY).AddInt64(p.RenewalWindow).AddOp(arkade.OP_SUB).AddOp(arkade.OP_CHECKTIMEVERIFY)
	for _, pair := range [][2]string{{"type", "register"}, {"onchain_output_indexes", "[]"}, {"cosigners_public_keys.0", fmt.Sprintf("%x", p.DelegatePubkey)}} {
		b.AddData([]byte(pair[0])).AddOp(arkade.OP_INSPECTINTENTMESSAGE).AddOp(arkade.OP_VERIFY).
			AddData([]byte(pair[1])).AddOp(arkade.OP_EQUALVERIFY)
	}
	b.AddData([]byte("cosigners_public_keys.1")).AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(arkade.OP_NOT).AddOp(arkade.OP_VERIFY).AddOp(arkade.OP_DROP)
	// Principal can renew independently when its expiry differs from the
	// controller's. Operator asset validation must reject a controller passed
	// off as asset-free principal. This branch carries no allowance authority.
	// Asset introspection errors when no asset packet exists, so test packet
	// presence first. Type zero is the stock asset packet.
	b.AddInt64(0).AddOp(arkade.OP_INSPECTPACKET).AddOp(arkade.OP_SWAP).
		AddOp(arkade.OP_DROP).AddOp(arkade.OP_NOT).AddOp(arkade.OP_IF)
	b.AddOp(arkade.OP_INSPECTNUMINPUTS)
	b.bounded(2, MaxMoneyInputs+1)
	b.AddOp(arkade.OP_DROP).AddInt64(StatePacketType).AddOp(arkade.OP_INSPECTPACKET).
		AddOp(arkade.OP_NOT).AddOp(arkade.OP_VERIFY).AddOp(arkade.OP_DROP).AddOp(arkade.OP_ELSE)
	b.marker(p.ControllerID, 1)
	b.inputValue(1)
	b.eq(ControllerSats)
	// Explicit controller-state preservation is independent of TUNNEL assets.
	b.stateField(1, false, p.Budget)
	b.AddOp(arkade.OP_DROP)
	b.stateField(1, true, p.Budget)
	b.AddOp(arkade.OP_DROP)
	b.statePacket(1)
	b.statePacket(-1)
	b.AddOp(arkade.OP_EQUALVERIFY).AddOp(arkade.OP_ENDIF)
	for i := 1; i <= MaxMoneyInputs+1; i++ {
		b.AddOp(arkade.OP_INSPECTNUMINPUTS).AddInt64(int64(i)).AddOp(arkade.OP_GREATERTHAN).AddOp(arkade.OP_IF)
		b.inputScript(i)
		b.inputScript(1)
		b.AddOp(arkade.OP_EQUALVERIFY)
		b.outputMatchesInput(i-1, i)
		b.inputValue(i)
		b.bounded(ControllerSats, maxMoney)
		b.outputValue(i - 1)
		b.AddOp(arkade.OP_EQUALVERIFY).AddOp(arkade.OP_ENDIF)
	}
	b.AddOp(arkade.OP_INSPECTNUMOUTPUTS).AddOp(arkade.OP_1SUB).AddOp(arkade.OP_INSPECTOUTPUTVALUE)
	b.eq(0)
	b.AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddOp(arkade.OP_1SUB).
		AddInt64(7).AddInt64(0).AddOp(arkade.OP_TUNNEL).AddOp(arkade.OP_VERIFY).AddOp(arkade.OP_TRUE)
	return b.Script()
}
