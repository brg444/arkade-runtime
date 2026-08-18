package vault

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestAdminSpendUsesOwnerLeafAndReturnsCanonicalChange(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	packet, err := AdminSpend(
		f.operational, f.prevTx, f.prevOutPoint, f.recipientPK,
		securityRecipientSats, securityFeeSats, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.UnsignedTx.TxOut) != 2 {
		t.Fatalf("owner output count = %d, want recipient + change", len(packet.UnsignedTx.TxOut))
	}
	change := packet.UnsignedTx.TxOut[1]
	if !bytes.Equal(change.PkScript, f.operational.PkScript) {
		t.Fatal("owner change does not return to canonical Operational vault")
	}
	wantChange := securityPrevoutValue - securityRecipientSats - securityFeeSats
	if change.Value != wantChange {
		t.Fatalf("change = %d, want %d", change.Value, wantChange)
	}
	assertSecurityBuilderLeaf(t, packet, f.operational.Leaves.Admin)
	assertSecurityNoEmulatorPacket(t, packet)
}

func TestOwnerFullSweepCanTargetCanonicalVaultWithoutPhantomChange(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	destinationAmount := securityPrevoutValue - securityFeeSats
	packet, err := AdminSpend(
		f.operational, f.prevTx, f.prevOutPoint, f.operational.PkScript,
		destinationAmount, securityFeeSats, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.UnsignedTx.TxOut) != 1 || packet.UnsignedTx.TxOut[0].Value != destinationAmount {
		t.Fatalf("full sweep outputs = %#v", packet.UnsignedTx.TxOut)
	}
}

func TestAdminSpendRejectsUnsafeBoundaries(t *testing.T) {
	f := newSecurityVaultFixture(t)

	tests := []struct {
		name string
		call func() (*psbt.Packet, error)
	}{
		{name: "outputs exceed input", call: func() (*psbt.Packet, error) {
			return AdminSpend(f.operational, f.prevTx, f.prevOutPoint, f.recipientPK, securityPrevoutValue, 1, 0)
		}},
		{name: "negative fee", call: func() (*psbt.Packet, error) {
			return AdminSpend(f.operational, f.prevTx, f.prevOutPoint, f.recipientPK, securityRecipientSats, -1, 0)
		}},
		{name: "dust destination", call: func() (*psbt.Packet, error) {
			return AdminSpend(f.operational, f.prevTx, f.prevOutPoint, f.recipientPK, fixture.DustSats-1, securityFeeSats, 0)
		}},
		{name: "dust change", call: func() (*psbt.Packet, error) {
			amount := securityPrevoutValue - securityFeeSats - (fixture.DustSats - 1)
			return AdminSpend(f.operational, f.prevTx, f.prevOutPoint, f.recipientPK, amount, securityFeeSats, 0)
		}},
		{name: "outpoint txid mismatch", call: func() (*psbt.Packet, error) {
			op := f.prevOutPoint
			op.Hash = chainhash.Hash{1}
			return AdminSpend(f.operational, f.prevTx, op, f.recipientPK, securityRecipientSats, securityFeeSats, 0)
		}},
		{name: "outpoint index", call: func() (*psbt.Packet, error) {
			op := f.prevOutPoint
			op.Index = 9
			return callOwnerWithoutPanic(f.operational, f.prevTx, op, f.recipientPK, securityRecipientSats, securityFeeSats)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.call(); err == nil {
				t.Fatal("owner builder accepted unsafe boundary")
			} else if strings.Contains(err.Error(), "panicked on untrusted outpoint") {
				t.Fatalf("owner builder must return an error rather than panic: %v", err)
			}
		})
	}
}

func TestRecoverySpendUsesOfflineCSVLeaf(t *testing.T) {
	t.Parallel()

	f := newSecurityVaultFixture(t)
	destinationAmount := securityPrevoutValue - securityFeeSats
	packet, err := RecoverySpend(
		f.operational, f.prevTx, f.prevOutPoint, f.recipientPK,
		destinationAmount, securityFeeSats,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantSequence, err := arklib.BIP68Sequence(f.operational.Record.HardwareCSV)
	if err != nil {
		t.Fatal(err)
	}
	if packet.UnsignedTx.TxIn[0].Sequence != wantSequence {
		t.Fatalf("recovery sequence = %d, want %d", packet.UnsignedTx.TxIn[0].Sequence, wantSequence)
	}
	assertSecurityBuilderLeaf(t, packet, f.operational.Leaves.HardwareCSV)
	assertSecurityNoEmulatorPacket(t, packet)
}

func TestRecoverySpendRejectsUnsafeBoundaries(t *testing.T) {
	f := newSecurityVaultFixture(t)

	tests := []struct {
		name string
		call func() (*psbt.Packet, error)
	}{
		{name: "does not consume input", call: func() (*psbt.Packet, error) {
			return RecoverySpend(f.operational, f.prevTx, f.prevOutPoint, f.recipientPK, securityRecipientSats, securityFeeSats)
		}},
		{name: "dust destination", call: func() (*psbt.Packet, error) {
			return RecoverySpend(f.operational, f.prevTx, f.prevOutPoint, f.recipientPK, fixture.DustSats-1, securityPrevoutValue-(fixture.DustSats-1))
		}},
		{name: "negative fee", call: func() (*psbt.Packet, error) {
			return RecoverySpend(f.operational, f.prevTx, f.prevOutPoint, f.recipientPK, securityPrevoutValue+1, -1)
		}},
		{name: "outpoint txid mismatch", call: func() (*psbt.Packet, error) {
			op := f.prevOutPoint
			op.Hash = chainhash.Hash{1}
			return RecoverySpend(f.operational, f.prevTx, op, f.recipientPK, securityPrevoutValue-securityFeeSats, securityFeeSats)
		}},
		{name: "outpoint index", call: func() (*psbt.Packet, error) {
			op := f.prevOutPoint
			op.Index = 9
			return callRecoveryWithoutPanic(f.operational, f.prevTx, op, f.recipientPK, securityPrevoutValue-securityFeeSats, securityFeeSats)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.call(); err == nil {
				t.Fatal("recovery builder accepted unsafe boundary")
			} else if strings.Contains(err.Error(), "panicked on untrusted outpoint") {
				t.Fatalf("recovery builder must return an error rather than panic: %v", err)
			}
		})
	}
}

func TestVaultSpendBuildersRejectInt64OverflowAndNonBitcoinValues(t *testing.T) {
	f := newSecurityVaultFixture(t)

	t.Run("routine recipient is not native segwit", func(t *testing.T) {
		params := f.routineParams()
		params.RecipientScript = []byte{txscript.OP_TRUE}
		if _, err := BuildRoutineSpend(params); err == nil {
			t.Fatal("routine builder accepted a non-segwit recipient")
		}
	})

	t.Run("routine amount plus fee overflow", func(t *testing.T) {
		params := f.routineParams()
		params.RecipientAmount = math.MaxInt64
		params.Fee = math.MaxInt64
		if _, err := BuildRoutineSpend(params); err == nil {
			t.Fatal("routine builder accepted amounts whose subtraction wraps int64")
		}
	})

	t.Run("owner amount plus fee overflow", func(t *testing.T) {
		if _, err := AdminSpend(
			f.operational, f.prevTx, f.prevOutPoint, f.recipientPK,
			math.MaxInt64, math.MaxInt64, 0,
		); err == nil {
			t.Fatal("owner builder accepted amounts whose subtraction wraps int64")
		}
	})

	for _, tc := range []struct {
		name string
		call func(prev *wire.MsgTx, op wire.OutPoint) error
	}{
		{
			name: "routine prevout exceeds MAX_MONEY",
			call: func(prev *wire.MsgTx, op wire.OutPoint) error {
				params := f.routineParams()
				params.PrevTx, params.PrevOutPoint = prev, op
				_, err := BuildRoutineSpend(params)
				return err
			},
		},
		{
			name: "owner prevout exceeds MAX_MONEY",
			call: func(prev *wire.MsgTx, op wire.OutPoint) error {
				_, err := AdminSpend(
					f.operational, prev, op, f.recipientPK,
					securityRecipientSats, securityFeeSats, 0,
				)
				return err
			},
		},
		{
			name: "recovery prevout exceeds MAX_MONEY",
			call: func(prev *wire.MsgTx, op wire.OutPoint) error {
				_, err := RecoverySpend(
					f.operational, prev, op, f.recipientPK,
					btcutil.MaxSatoshi, 1,
				)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := cloneSecurityTx(f.prevTx)
			prev.TxOut[0].Value = btcutil.MaxSatoshi + 1
			op := wire.OutPoint{Hash: prev.TxHash(), Index: 0}
			if err := tc.call(prev, op); err == nil {
				t.Fatal("builder accepted a prevout outside Bitcoin's money range")
			}
		})
	}
}

func assertSecurityBuilderLeaf(t *testing.T, packet *psbt.Packet, leaf *Leaf) {
	t.Helper()
	if len(packet.Inputs) != 1 || len(packet.Inputs[0].TaprootLeafScript) != 1 {
		t.Fatalf("builder did not select exactly one tapscript leaf")
	}
	got := packet.Inputs[0].TaprootLeafScript[0]
	if !bytes.Equal(got.Script, leaf.Script) || !bytes.Equal(got.ControlBlock, leaf.ControlBlock) {
		t.Fatalf("builder selected the wrong leaf")
	}
}

func assertSecurityNoEmulatorPacket(t *testing.T, packet *psbt.Packet) {
	t.Helper()
	got, err := arkade.FindEmulatorPacket(packet.UnsignedTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("owner-controlled spend unexpectedly contains an Emulator packet")
	}
}

func callOwnerWithoutPanic(v *Built, prev *wire.MsgTx, op wire.OutPoint, dest []byte, amount, fee int64) (packet *psbt.Packet, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("AdminSpend panicked on untrusted outpoint: %v", recovered)
		}
	}()
	return AdminSpend(v, prev, op, dest, amount, fee, 0)
}

func callRecoveryWithoutPanic(v *Built, prev *wire.MsgTx, op wire.OutPoint, dest []byte, amount, fee int64) (packet *psbt.Packet, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("RecoverySpend panicked on untrusted outpoint: %v", recovered)
		}
	}()
	return RecoverySpend(v, prev, op, dest, amount, fee)
}
