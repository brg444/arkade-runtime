package allowancedraft

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// This is a primitive-composition probe, separate from the fixed-budget
// contract. It verifies an expected receipt identity and its signed maturity.
// It neither verifies finalization nor updates a controller or expiring queue.
func TestSignedReceiptMaturityProbe(t *testing.T) {
	prefix := append([]byte("vault-allowance-finalization-probe-v0\x00"), bytes.Repeat([]byte{0x21}, 34)...)
	prefix = append(prefix, bytes.Repeat([]byte{0x43}, 32)...) // expected debit txid
	prefix = binary.LittleEndian.AppendUint64(prefix, 7)       // expected unique debit sequence
	prefix = binary.LittleEndian.AppendUint64(prefix, 1100)    // payment plus fee
	b := newBuilder()
	b.AddOp(arkade.OP_SIZE)
	b.eq(int64(len(prefix) + 8))
	b.AddOp(arkade.OP_DUP).AddInt64(int64(len(prefix))).AddOp(arkade.OP_LEFT).AddData(prefix).AddOp(arkade.OP_EQUALVERIFY)
	b.AddOp(arkade.OP_DUP).AddOp(arkade.OP_TOALTSTACK).AddOp(arkade.OP_SHA256).
		AddData(schnorr.SerializePubKey(testKey(9))).AddOp(arkade.OP_CHECKSIGFROMSTACK).AddOp(arkade.OP_VERIFY).
		AddOp(arkade.OP_FROMALTSTACK).AddInt64(8).AddOp(arkade.OP_RIGHT).
		AddOp(arkade.OP_DUP).AddOp(arkade.OP_BIN2NUM).AddOp(arkade.OP_DUP).
		AddInt64(8).AddOp(arkade.OP_NUM2BIN).AddOp(arkade.OP_ROT).AddOp(arkade.OP_EQUALVERIFY)
	b.bounded(0, 100_000_000_000)
	// Guardian keeps second-resolution completed debits charged at exactly
	// observedAt+24h and releases strictly after that boundary.
	b.AddInt64(86401).AddOp(arkade.OP_ADD).AddOp(arkade.OP_CHECKTIMEVERIFY).AddOp(arkade.OP_TRUE)
	code, err := b.Script()
	check(t, err)
	now := time.Now().Unix()
	for _, tc := range []struct {
		name                    string
		at                      int64
		key                     byte
		changePrefix, forgeTime bool
		valid                   bool
	}{
		{"mature authenticated receipt", now - 2*86400, 9, false, false, true},
		{"recent finalization", now - 3600, 9, false, false, false},
		{"timestamp changed after signature", now - 3600, 9, false, true, false},
		{"different debit signed by trusted key", now - 2*86400, 9, true, false, false},
		{"untrusted signer", now - 2*86400, 8, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt := binary.LittleEndian.AppendUint64(bytes.Clone(prefix), uint64(tc.at))
			if tc.changePrefix {
				receipt[len(prefix)-1] ^= 1
			}
			hash := sha256.Sum256(receipt)
			sig, err := schnorr.Sign(privateKey(tc.key), hash[:])
			check(t, err)
			if tc.forgeTime {
				binary.LittleEndian.PutUint64(receipt[len(prefix):], uint64(now-2*86400))
			}
			f := newFixture(t)
			f.spend(State{10000, 0}, []int64{20000}, 1000, 100)
			vm, err := arkade.NewEngine(code, f.tx, 0, nil, txscript.NewTxSigHashes(f.tx, f), ControllerSats, f)
			check(t, err)
			vm.SetStack(wire.TxWitness{sig.Serialize(), receipt})
			err = vm.Execute()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
