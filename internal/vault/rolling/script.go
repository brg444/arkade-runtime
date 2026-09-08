package rolling

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type RollingParameters struct {
	Parameters
	NetworkGenesis [32]byte
	ReceiptKey     [32]byte
	FeerateCap     int64
	CheckpointExit []byte
}

type RollingScripts struct {
	Spend, Credit, Renew, Cleanup []byte
	ReceiptDomain                 [32]byte
}

// ReceiptDomain commits the network and complete compile-time policy, including
// the controller's immutable issuance ID and separate receipt verification key.
func (p RollingParameters) ReceiptDomain() [32]byte {
	b := append([]byte(RollingProgram+"\x00finalization\x00"), p.NetworkGenesis[:]...)
	b = append(b, p.ControllerID.Txid[:]...)
	b = binary.LittleEndian.AppendUint16(b, p.ControllerID.Index)
	for _, n := range []int64{p.Budget, p.RecipientCap, p.FeeCap, p.RenewalWindow, WindowSeconds, p.FeerateCap} {
		b = binary.LittleEndian.AppendUint64(b, uint64(n))
	}
	b = append(b, p.DelegatePubkey...)
	b = append(b, p.ReceiptKey[:]...)
	checkpointHash := sha256.Sum256(p.CheckpointExit)
	b = append(b, checkpointHash[:]...)
	return sha256.Sum256(b)
}

func Compile(p RollingParameters) (RollingScripts, error) {
	if err := p.Parameters.Validate(); err != nil {
		return RollingScripts{}, err
	}
	exit := &script.CSVMultisigClosure{}
	ok, err := exit.Decode(p.CheckpointExit)
	if err != nil || !ok || len(exit.PubKeys) != 1 {
		return RollingScripts{}, fmt.Errorf("checkpoint exit pin required")
	}
	canonical, err := exit.Script()
	if err != nil || !bytes.Equal(canonical, p.CheckpointExit) {
		return RollingScripts{}, fmt.Errorf("noncanonical checkpoint exit")
	}
	if p.FeerateCap < 1 || p.FeerateCap > 100 {
		return RollingScripts{}, fmt.Errorf("invalid feerate cap")
	}
	if p.NetworkGenesis == ([32]byte{}) {
		return RollingScripts{}, fmt.Errorf("network identity required")
	}
	if _, err := schnorr.ParsePubKey(p.ReceiptKey[:]); err != nil {
		return RollingScripts{}, err
	}
	s, err := compileSpendWithState(p.Parameters, func(b builder) {
		b.AddOp(OP_DUP)
		b.outputValue(1)
		b.AddOp(OP_SUB)
		b.feeRate(p.FeerateCap)
		b.AddOp(OP_DROP)
		rollingDebitState(b, p, 0)
	})
	if err != nil {
		return RollingScripts{}, err
	}
	c, err := compileRollingCredit(p)
	if err != nil {
		return RollingScripts{}, err
	}
	r, err := compileRollingRenew(p)
	if err != nil {
		return RollingScripts{}, err
	}
	cleanup, err := compileRollingCleanup()
	return RollingScripts{Spend: s, Credit: c, Renew: r, Cleanup: cleanup, ReceiptDomain: p.ReceiptDomain()}, err
}

func (b builder) rollingPacket(input int) {
	b.AddInt64(StatePacketType)
	if input < 0 {
		b.AddOp(OP_INSPECTPACKET)
	} else {
		b.AddInt64(int64(input)).AddOp(OP_INSPECTINPUTPACKET)
	}
	b.AddOp(OP_VERIFY).AddOp(OP_SIZE)
	b.eq(RollingStateSize)
	b.AddOp(OP_DUP).AddInt64(4).AddOp(OP_LEFT).AddData(rollingMagic).AddOp(OP_EQUALVERIFY)
}

func (b builder) slice(offset, size int64) {
	b.AddInt64(offset + size).AddOp(OP_LEFT).AddInt64(size).AddOp(OP_RIGHT)
}

func (b builder) unsigned(width int64, max int64) {
	b.AddOp(OP_DUP).AddOp(OP_BIN2NUM).AddOp(OP_DUP).
		AddInt64(width).AddOp(OP_NUM2BIN).AddOp(OP_ROT).AddOp(OP_EQUALVERIFY)
	b.bounded(0, max)
}

func (b builder) rollingNumber(input int, offset, max int64) {
	b.rollingPacket(input)
	b.slice(offset, 8)
	b.unsigned(8, max)
}

func (b builder) rollingRoot(input int) { b.rollingPacket(input); b.slice(20, 32) }

// historyRoot leaves the proof untouched and replaces leaf,index with the root.
// The index is already bound into the debit and checked against the sequence.
// Sorted branch hashing permits compact native proof verification; uniqueness
// follows from monotonic debit sequences, irrespective of tree position.
func (b builder) historyRoot() {
	b.AddOp(OP_DROP)
	for i, size := range []int64{512, 480} {
		b.AddOp(OP_TOALTSTACK).AddInt64(0).AddData([]byte(HistoryBranchTag)).
			AddInt64(int64(2 + i)).AddOp(OP_PICK).AddOp(OP_SIZE)
		b.eq(size)
		b.AddOp(OP_FROMALTSTACK).AddOp(OP_MERKLEBRANCHVERIFY)
	}
}

func (b builder) dropHistoryProof() { b.AddOp(OP_DROP).AddOp(OP_DROP) }

func rollingDebitState(b builder, p RollingParameters, input int) {
	// debit is above the proof. Preserve it until its canonical leaf is built.
	b.AddOp(OP_DEPTH)
	b.eq(HistoryWitnessItems + 1)
	b.AddOp(OP_DUP).AddOp(OP_TOALTSTACK)
	b.rollingNumber(input, 4, p.Budget)
	b.AddOp(OP_SWAP).AddOp(OP_SUB)
	b.bounded(0, p.Budget)
	b.rollingNumber(-1, 4, p.Budget)
	b.AddOp(OP_EQUALVERIFY)
	b.rollingNumber(input, 12, int64(MaxSequence))
	b.AddOp(OP_1ADD)
	b.rollingNumber(-1, 12, int64(MaxSequence))
	b.AddOp(OP_EQUALVERIFY)
	empty := EmptyRoots()[0]
	b.AddData(empty[:])
	b.rollingNumber(input, 12, int64(MaxSequence-1))
	b.historyRoot()
	b.rollingRoot(input)
	b.AddOp(OP_EQUALVERIFY)
	b.AddData([]byte{1})
	b.rollingNumber(input, 12, int64(MaxSequence-1))
	b.AddInt64(8).AddOp(OP_NUM2BIN).AddOp(OP_CAT).
		AddOp(OP_FROMALTSTACK).AddInt64(8).AddOp(OP_NUM2BIN).AddOp(OP_CAT).
		AddInt64(int64(input)).AddOp(OP_INSPECTINPUTOUTPOINT)
	b.eq(0)
	b.AddData([]byte{0, 0, 0, 0}).AddOp(OP_CAT).AddOp(OP_CAT).AddOp(OP_SHA256)
	b.rollingNumber(input, 12, int64(MaxSequence-1))
	b.historyRoot()
	b.rollingRoot(-1)
	b.AddOp(OP_EQUALVERIFY)
	b.dropHistoryProof()
	b.AddOp(OP_DEPTH)
	b.eq(0)
}

func (b builder) receiptField(offset, size int64) {
	b.AddOp(OP_FROMALTSTACK).AddOp(OP_DUP).AddOp(OP_TOALTSTACK)
	b.slice(offset, size)
}
