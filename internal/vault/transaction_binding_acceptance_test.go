package vault

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// TestDirectP256AuthorizationIsTransactionBoundAndKeepsWebAuthnOffChain is a
// release acceptance test for the PRF-derived direct-signer design.
//
// WebAuthn remains the ceremony that releases PRF material to the browser, but
// its clientDataJSON/authenticatorData are provider-side evidence only. The
// Arkade packet must contain exactly one compact P-256 signature made directly
// over the current transaction's Arkade sighash. Therefore a signature copied
// from spend A must fail in spend B without relying on ordinary provider Go.
func TestDirectP256AuthorizationIsTransactionBoundAndKeepsWebAuthnOffChain(t *testing.T) {
	directKey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	webauthnKey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	directPub := webauthn.CompressedP256(directKey)
	if bytes.Equal(directPub, webauthn.CompressedP256(webauthnKey)) {
		t.Fatal("test setup failed: WebAuthn and DirectP256 keys are not distinct")
	}

	f := newSecurityVaultFixture(t)
	op, err := NewOperational(OperationalKeys{
		PhoneRoutineBIP340:  f.phoneRoutine.PubKey(),
		ExternalOwnerWallet: f.externalOwner.PubKey(),
		VaultCosignerBase:   f.vaultCosigner.PubKey(),
		ArkadeCosignerBase:  f.arkadeCosigner.PubKey(),
		PhoneDirectP256:     directPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	prevTx := f.prevTx.Copy()
	prevTx.TxOut[0].PkScript = append([]byte(nil), op.PkScript...)

	paramsA := f.routineParams()
	paramsA.Vault = op
	paramsA.PrevTx = prevTx
	paramsA.PrevOutPoint = wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}
	spendA, err := BuildRoutineSpend(paramsA)
	if err != nil {
		t.Fatal(err)
	}
	paramsB := paramsA
	paramsB.RecipientAmount++
	spendB, err := BuildRoutineSpend(paramsB)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(spendA.Challenge, spendB.Challenge) {
		t.Fatal("test setup failed: changed spend has the same Arkade challenge")
	}

	directSigA := signDirectP256LowS(t, directKey, spendA.Challenge)
	if err := SetPacketWitness(spendA.Packet.UnsignedTx, wire.TxWitness{directSigA}); err != nil {
		t.Fatal(err)
	}
	if err := executeRawPacketAuthorization(spendA.Packet, f.vaultCosigner.PubKey()); err != nil {
		t.Fatalf("raw Arkade signer rejected a direct signature for spend A: %v", err)
	}

	packetA, err := arkade.FindEmulatorPacket(spendA.Packet.UnsignedTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(packetA) != 1 || len(packetA[0].Witness) != 1 || len(packetA[0].Witness[0]) != 64 {
		t.Fatalf("serialized direct-authorization packet witness: entries=%d items=%d, want 1 entry with one 64-byte signature", len(packetA), packetWitnessItems(packetA))
	}
	if !bytes.Equal(packetA[0].Witness[0], directSigA) {
		t.Fatal("serialized packet witness is not the verified direct signature")
	}

	if err := SetPacketWitness(spendB.Packet.UnsignedTx, wire.TxWitness{directSigA}); err != nil {
		t.Fatal(err)
	}
	if err := executeRawPacketAuthorization(spendB.Packet, f.vaultCosigner.PubKey()); err == nil {
		t.Fatal("raw Arkade signer accepted spend A's direct P-256 signature on changed spend B")
	}
}

func signDirectP256LowS(t *testing.T, priv *ecdsa.PrivateKey, digest []byte) []byte {
	t.Helper()
	if len(digest) != 32 {
		t.Fatalf("direct P-256 digest length = %d, want 32", len(digest))
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		s.Sub(n, s)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

func packetWitnessItems(packet []arkade.EmulatorEntry) int {
	if len(packet) != 1 {
		return -1
	}
	return len(packet[0].Witness)
}

func executeRawPacketAuthorization(ptx *psbt.Packet, providerPub *btcec.PublicKey) error {
	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return err
	}
	if len(packet) != 1 {
		return fmt.Errorf("expected exactly one emulator entry")
	}
	script, err := arkade.ReadArkadeScript(ptx, providerPub, packet[0])
	if err != nil {
		return err
	}
	prevTx, err := RequireVerifiedPrevout(ptx)
	if err != nil {
		return err
	}
	prev := ptx.Inputs[0].WitnessUtxo
	fetcher := NewPrevFetcher(
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint, prev,
	).WithPrevTx(prevTx)
	return script.Execute(ptx.UnsignedTx, fetcher, 0)
}
