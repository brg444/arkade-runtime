package application

import (
	"context"
	"testing"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func TestSavingsTransitionCovenantRejectsAddedArbitraryOutput(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	packet := mustHardwareTransitionPacket(t, e)
	packet.UnsignedTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
	resignTransitionClaimant(t, packet, e.externalOwner)

	if _, err := (LocalSigner{Priv: e.operator}).Sign(context.Background(), packet); err == nil {
		t.Fatal("Savings transition covenant accepted an added arbitrary output")
	}
}

func TestSavingsTransitionCovenantRejectsReducedDestinationPastFeeBoundary(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	base := mustHardwareTransitionPacket(t, e)

	accepted := func(fee int64) bool {
		candidate := transitionWithFee(t, base, e.externalOwner, fee)
		_, err := (LocalSigner{Priv: e.operator}).Sign(context.Background(), candidate)
		return err == nil
	}

	// The compiled covenant permits a fee only up to the tighter of its
	// absolute and feerate limits. Find that exact edge without duplicating the
	// transaction-weight implementation in the test.
	low, high := int64(0), int64(5_001)
	if !accepted(low) {
		t.Fatal("Savings transition covenant rejected its zero-fee boundary fixture")
	}
	if accepted(high) {
		t.Fatal("Savings transition covenant accepted a fee above its absolute cap")
	}
	for high-low > 1 {
		mid := low + (high-low)/2
		if accepted(mid) {
			low = mid
		} else {
			high = mid
		}
	}
	if !accepted(low) {
		t.Fatalf("Savings transition covenant rejected its discovered fee boundary %d", low)
	}
	if accepted(low + 1) {
		t.Fatalf("Savings transition covenant accepted a one-sat destination reduction past fee boundary %d", low)
	}
}

func TestSignTransitionRejectsReducedDestinationAfterClaimantAuthorization(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	packet := mustHardwareTransitionPacket(t, e)
	packet.UnsignedTx.TxOut[0].Value--
	encoded, err := packet.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SignTransition(context.Background(), TransitionRequest{
		VaultID: fixture.VaultID,
		Purpose: "initiate",
		PSBT:    encoded,
	}); err == nil {
		t.Fatal("server accepted a destination value reduced after claimant authorization")
	}
}

func mustHardwareTransitionPacket(t *testing.T, e *env) *psbt.Packet {
	t.Helper()
	encoded := hardwareInitiatePSBT(t, e.svc, e.externalOwner)
	packet, err := parsePSBT(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func transitionWithFee(t *testing.T, base *psbt.Packet, claimant *btcec.PrivateKey, fee int64) *psbt.Packet {
	t.Helper()
	packet, err := clonePacket(base)
	if err != nil {
		t.Fatal(err)
	}
	inputValue := packet.Inputs[0].WitnessUtxo.Value
	p2aValue := packet.UnsignedTx.TxOut[1].Value
	packet.UnsignedTx.TxOut[0].Value = inputValue - p2aValue - fee
	resignTransitionClaimant(t, packet, claimant)
	return packet
}

func resignTransitionClaimant(t *testing.T, packet *psbt.Packet, claimant *btcec.PrivateKey) {
	t.Helper()
	packet.Inputs[0].TaprootScriptSpendSig = nil
	leaf := packet.Inputs[0].TaprootLeafScript[0].Script
	sig, err := signTapLeafAt(packet, 0, claimant, leaf)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
}
