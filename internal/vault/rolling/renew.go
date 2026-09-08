package rolling

import (
	"fmt"
)

func compileRollingRenew(p RollingParameters) ([]byte, error) {
	b := newBuilder()
	b.header(2, 2, MaxMoneyInputs+2)
	b.AddOp(OP_INSPECTNUMOUTPUTS).AddOp(OP_INSPECTNUMINPUTS).AddOp(OP_EQUALVERIFY)
	b.inputValue(0)
	b.eq(0)
	b.AddOp(OP_PUSHEXPIRY).AddInt64(p.RenewalWindow).AddOp(OP_SUB).AddOp(OP_CHECKTIMEVERIFY)
	for _, pair := range [][2]string{{"type", "register"}, {"onchain_output_indexes", "[]"}, {"cosigners_public_keys.0", fmt.Sprintf("%x", p.DelegatePubkey)}} {
		b.AddData([]byte(pair[0])).AddOp(OP_INSPECTINTENTMESSAGE).AddOp(OP_VERIFY).AddData([]byte(pair[1])).AddOp(OP_EQUALVERIFY)
	}
	b.AddData([]byte("cosigners_public_keys.1")).AddOp(OP_INSPECTINTENTMESSAGE).AddOp(OP_NOT).AddOp(OP_VERIFY).AddOp(OP_DROP)
	// Compute fee over preserved protected destinations, including the controller.
	b.AddInt64(0)
	for i := 1; i <= MaxMoneyInputs+1; i++ {
		b.AddOp(OP_INSPECTNUMINPUTS).AddInt64(int64(i)).AddOp(OP_GREATERTHAN).AddOp(OP_IF)
		b.inputScript(i)
		b.inputScript(1)
		b.AddOp(OP_EQUALVERIFY)
		b.outputMatchesInput(i-1, i)
		b.inputValue(i)
		b.bounded(ControllerSats, maxMoney)
		b.outputValue(i - 1)
		b.bounded(ControllerSats, maxMoney)
		b.AddOp(OP_SUB)
		b.bounded(0, p.FeeCap)
		b.AddOp(OP_ADD).AddOp(OP_ENDIF)
	}
	b.bounded(0, p.FeeCap)
	b.feeRate(p.FeerateCap)
	// No controller means there is no authority to charge a renewal fee.
	b.AddInt64(0).AddOp(OP_INSPECTPACKET).AddOp(OP_SWAP).AddOp(OP_DROP).AddOp(OP_NOT).AddOp(OP_IF)
	b.eq(0)
	b.AddOp(OP_INSPECTNUMINPUTS)
	b.bounded(2, MaxMoneyInputs+1)
	b.AddOp(OP_DROP)
	b.AddInt64(StatePacketType).AddOp(OP_INSPECTPACKET).AddOp(OP_NOT).AddOp(OP_VERIFY).AddOp(OP_DROP)
	b.AddOp(OP_DEPTH)
	b.eq(0)
	b.AddOp(OP_ELSE)
	b.marker(p.ControllerID, 1)
	b.inputValue(1)
	b.eq(ControllerSats)
	b.outputValue(0)
	b.eq(ControllerSats)
	b.AddOp(OP_DUP).AddOp(OP_0NOTEQUAL).AddOp(OP_IF)
	rollingDebitState(b, p, 1)
	b.AddOp(OP_ELSE).AddOp(OP_DROP)
	b.rollingNumber(1, 4, p.Budget)
	b.AddOp(OP_DROP)
	b.rollingNumber(1, 12, int64(MaxSequence))
	b.AddOp(OP_DROP)
	b.rollingPacket(1)
	b.rollingPacket(-1)
	b.AddOp(OP_EQUALVERIFY)
	b.AddOp(OP_DEPTH)
	b.eq(0)
	b.AddOp(OP_ENDIF).AddOp(OP_ENDIF)
	b.AddOp(OP_INSPECTNUMOUTPUTS).AddOp(OP_1SUB).AddOp(OP_INSPECTOUTPUTVALUE)
	b.eq(0)
	// Script and assets remain unchanged; explicit arithmetic above allows only
	// a bounded fee charged to the controller. Value preservation is checked there.
	b.AddOp(OP_PUSHCURRENTINPUTINDEX).AddOp(OP_1SUB).AddInt64(5).AddInt64(0).AddOp(OP_TUNNEL).AddOp(OP_VERIFY).AddOp(OP_TRUE)
	return b.Script()
}
