package vault

import (
	"crypto/ecdsa"
	"math"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	securityPrevoutValue  = int64(200_000)
	securityRecipientSats = int64(40_000)
	securityFeeSats       = int64(1_000)
)

type securityVaultFixture struct {
	phoneRoutine   *btcec.PrivateKey
	externalOwner  *btcec.PrivateKey
	recovery       *btcec.PrivateKey
	vaultCosigner  *btcec.PrivateKey
	arkadeCosigner *btcec.PrivateKey
	phoneDirect    *ecdsa.PrivateKey
	recipient      *btcec.PrivateKey
	operational    *Built
	savings        *Built
	prevTx         *wire.MsgTx
	prevOutPoint   wire.OutPoint
	recipientPK    []byte
}

func newSecurityVaultFixture(t *testing.T) *securityVaultFixture {
	t.Helper()

	phoneRoutine := mustSecurityK1Key(t)
	externalOwner := mustSecurityK1Key(t)
	recovery := mustSecurityK1Key(t)
	vaultCosigner := mustSecurityK1Key(t)
	arkadeCosigner := mustSecurityK1Key(t)
	recipient := mustSecurityK1Key(t)
	p256, err := webauthn.NewP256()
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	operational, err := NewOperational(OperationalKeys{
		PhoneRoutineBIP340:  phoneRoutine.PubKey(),
		PhoneDirectP256:     webauthn.CompressedP256(p256),
		ExternalOwnerWallet: externalOwner.PubKey(),
		VaultCosignerBase:   vaultCosigner.PubKey(),
		ArkadeCosignerBase:  arkadeCosigner.PubKey(),
	})
	if err != nil {
		t.Fatalf("build Operational vault: %v", err)
	}
	savings, err := NewSavings(
		phoneRoutine.PubKey(), externalOwner.PubKey(),
		vaultCosigner.PubKey(), operational.TweakedVaultCosigner,
		arkadeCosigner.PubKey(), operational.TweakedArkadeCosigner,
	)
	if err != nil {
		t.Fatalf("build Savings vault: %v", err)
	}
	recipientPK, err := txscript.PayToTaprootScript(recipient.PubKey())
	if err != nil {
		t.Fatalf("recipient P2TR script: %v", err)
	}

	prevTx := wire.NewMsgTx(2)
	prevTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: math.MaxUint32},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	prevTx.AddTxOut(&wire.TxOut{Value: securityPrevoutValue, PkScript: operational.PkScript})

	return &securityVaultFixture{
		phoneRoutine:   phoneRoutine,
		externalOwner:  externalOwner,
		recovery:       recovery,
		vaultCosigner:  vaultCosigner,
		arkadeCosigner: arkadeCosigner,
		phoneDirect:    p256,
		recipient:      recipient,
		operational:    operational,
		savings:        savings,
		prevTx:         prevTx,
		prevOutPoint:   wire.OutPoint{Hash: prevTx.TxHash(), Index: 0},
		recipientPK:    recipientPK,
	}
}

func (f *securityVaultFixture) routineParams() SpendParams {
	return SpendParams{
		Vault:           f.operational,
		PrevTx:          f.prevTx,
		PrevOutPoint:    f.prevOutPoint,
		RecipientScript: append([]byte(nil), f.recipientPK...),
		RecipientAmount: securityRecipientSats,
		Fee:             securityFeeSats,
	}
}

func mustSecurityK1Key(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: %v", err)
	}
	return key
}

func cloneSecurityTx(tx *wire.MsgTx) *wire.MsgTx {
	return tx.Copy()
}
