package provider

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type env struct {
	svc    *Service
	hot    *btcec.PrivateKey
	p256   *ecdsa.PrivateKey
	direct *ecdsa.PrivateKey
	credID []byte
}

func newEnv(t *testing.T) *env {
	t.Helper()
	hot, _ := btcec.NewPrivateKey()
	externalOwner, _ := btcec.NewPrivateKey()
	offline, _ := btcec.NewPrivateKey()
	_ = offline
	prov, _ := btcec.NewPrivateKey()
	arkadeKey, _ := btcec.NewPrivateKey()
	p256, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	led, err := policy.OpenLedger(filepath.Join(t.TempDir(), "p.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	svc := &Service{
		Ledger:              led,
		PhoneRoutineBIP340:  hot.PubKey(),
		ExternalOwnerWallet: externalOwner.PubKey(),
		VaultCosignerPub:    prov.PubKey(),
		ArkadeCosignerPub:   arkadeKey.PubKey(),
		VaultSigner:         LocalSigner{Priv: prov},
		ArkadeCosignerSigner: LocalSigner{
			Priv: arkadeKey,
		},
	}
	credID := []byte{0x11}
	if err := svc.Register(RegisterRequest{
		CredentialID:    hex.EncodeToString(credID),
		WebAuthnP256:    hex.EncodeToString(webauthn.CompressedP256(p256)),
		PhoneDirectP256: hex.EncodeToString(webauthn.CompressedP256(direct)),
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Register(RegisterRequest{
		CredentialID:    "00",
		WebAuthnP256:    hex.EncodeToString(webauthn.CompressedP256(p256)),
		PhoneDirectP256: hex.EncodeToString(webauthn.CompressedP256(direct)),
	}); err == nil {
		t.Fatal("second enroll must lock")
	}
	return &env{svc: svc, hot: hot, p256: p256, direct: direct, credID: credID}
}

func fundOp(t *testing.T, e *env, value int64) (*wire.MsgTx, wire.OutPoint) {
	t.Helper()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{}})
	tx.AddTxOut(&wire.TxOut{Value: value, PkScript: e.svc.Operational.PkScript})
	return tx, wire.OutPoint{Hash: tx.TxHash(), Index: 0}
}

func destScript(t *testing.T) []byte {
	t.Helper()
	k, _ := btcec.NewPrivateKey()
	pk, err := txscript.PayToTaprootScript(k.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func TestAuthorizeHappyAndMutations(t *testing.T) {
	e := newEnv(t)
	prevTx, op := fundOp(t, e, 80_000)
	dest := destScript(t)
	built, err := vault.BuildRoutineSpend(vault.SpendParams{
		Vault: e.svc.Operational, PrevTx: prevTx, PrevOutPoint: op,
		RecipientScript: dest, RecipientAmount: 40_000, Fee: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := webauthn.Synth(e.p256, e.credID, built.Challenge, fixture.Origin, fixture.RPID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	directSig, err := webauthn.SignDigestLowS(e.direct, built.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.SetPacketWitness(built.Packet.UnsignedTx, [][]byte{directSig}); err != nil {
		t.Fatal(err)
	}
	hotSig, err := vault.SignLeaf(built.Packet.UnsignedTx, built.Prevout, e.svc.Operational.Leaves.Routine.Script, e.hot)
	if err != nil {
		t.Fatal(err)
	}
	vault.AddPartialSig(built.Packet, e.hot.PubKey(), e.svc.Operational.Leaves.Routine.Hash, hotSig)
	enc, err := built.Packet.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	req := AuthorizeRequest{
		PSBT:              enc,
		CredentialID:      hex.EncodeToString(e.credID),
		ClientDataJSON:    hex.EncodeToString(a.ClientDataJSON),
		AuthenticatorData: hex.EncodeToString(a.AuthenticatorData),
		Signature:         hex.EncodeToString(a.DERSignature),
	}
	signed, replay, err := e.svc.Authorize(context.Background(), req)
	if err != nil || replay || signed == "" {
		t.Fatalf("authorize: %v replay=%v", err, replay)
	}
	signed2, replay, err := e.svc.Authorize(context.Background(), req)
	if err != nil || !replay || signed2 != signed {
		t.Fatalf("retry: %v replay=%v", err, replay)
	}

	built2, err := vault.BuildRoutineSpend(vault.SpendParams{
		Vault: e.svc.Operational, PrevTx: prevTx, PrevOutPoint: op,
		RecipientScript: dest, RecipientAmount: 41_000, Fee: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	enc2, _ := built2.Packet.B64Encode()
	req.PSBT = enc2
	if _, _, err := e.svc.Authorize(context.Background(), req); err == nil {
		t.Fatal("reused assertion on mutated tx accepted")
	}

	prevBig, opBig := fundOp(t, e, 200_000)
	over, err := vault.BuildRoutineSpend(vault.SpendParams{
		Vault: e.svc.Operational, PrevTx: prevBig, PrevOutPoint: opBig,
		RecipientScript: dest, RecipientAmount: fixture.TxRecipientCapSats + 1, Fee: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	encOver, _ := over.Packet.B64Encode()
	a2, _ := webauthn.Synth(e.p256, e.credID, over.Challenge, fixture.Origin, fixture.RPID, true, true)
	if _, _, err := e.svc.Authorize(context.Background(), AuthorizeRequest{
		PSBT: encOver, CredentialID: hex.EncodeToString(e.credID),
		ClientDataJSON:    hex.EncodeToString(a2.ClientDataJSON),
		AuthenticatorData: hex.EncodeToString(a2.AuthenticatorData),
		Signature:         hex.EncodeToString(a2.DERSignature),
	}); err == nil {
		t.Fatal("over-cap accepted")
	}

	built.Packet.Inputs[0].SighashType = txscript.SigHashAll
	encAll, _ := built.Packet.B64Encode()
	req.PSBT = encAll
	if _, _, err := e.svc.Authorize(context.Background(), req); err == nil {
		t.Fatal("SIGHASH_ALL accepted")
	}

	if _, _, err := e.svc.Authorize(context.Background(), AuthorizeRequest{
		PSBT: `{"prf":true}`, CredentialID: "00", ClientDataJSON: "00",
		AuthenticatorData: "00", Signature: "00",
	}); err == nil {
		t.Fatal("prf payload accepted")
	}

	if err := e.svc.Savings.AssertNoRoutineCosigners(
		e.svc.VaultCosignerPub, e.svc.Operational.TweakedVaultCosigner,
		e.svc.ArkadeCosignerPub, e.svc.Operational.TweakedArkadeCosigner,
	); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterRejectsReusedWebAuthnKeyAsDirectAuth(t *testing.T) {
	externalOwner, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	offline, err := btcec.NewPrivateKey()
	_ = offline
	if err != nil {
		t.Fatal(err)
	}
	prov, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	arkadeKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	p256, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	led, err := policy.OpenLedger(filepath.Join(t.TempDir(), "reuse-p256.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	svc := &Service{
		Ledger:              led,
		ExternalOwnerWallet: externalOwner.PubKey(),
		VaultCosignerPub:    prov.PubKey(),
		ArkadeCosignerPub:   arkadeKey.PubKey(),
		VaultSigner:         LocalSigner{Priv: prov},
		ArkadeCosignerSigner: LocalSigner{
			Priv: arkadeKey,
		},
	}
	same := hex.EncodeToString(webauthn.CompressedP256(p256))
	if err := svc.Register(RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte{0x33}),
		WebAuthnP256:          same,
		PhoneDirectP256:       same,
		PhoneRoutineBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}); err == nil {
		t.Fatal("register accepted the WebAuthn credential P-256 as the direct-auth key")
	}
}

func TestRegisterUsesBrowserHotWhenServiceHotIsNil(t *testing.T) {
	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	externalOwner, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	offline, err := btcec.NewPrivateKey()
	_ = offline
	if err != nil {
		t.Fatal(err)
	}
	prov, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	arkadeKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	p256, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	led, err := policy.OpenLedger(filepath.Join(t.TempDir(), "nil-hot.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	svc := &Service{
		Ledger:              led,
		ExternalOwnerWallet: externalOwner.PubKey(),
		VaultCosignerPub:    prov.PubKey(),
		ArkadeCosignerPub:   arkadeKey.PubKey(),
		VaultSigner:         LocalSigner{Priv: prov},
		ArkadeCosignerSigner: LocalSigner{
			Priv: arkadeKey,
		},
	}
	if err := svc.Register(RegisterRequest{
		CredentialID:    hex.EncodeToString([]byte{0x22}),
		WebAuthnP256:    hex.EncodeToString(webauthn.CompressedP256(p256)),
		PhoneDirectP256: hex.EncodeToString(webauthn.CompressedP256(direct)),
	}); err == nil {
		t.Fatal("registration without a browser hot pubkey must fail when Service.PhoneRoutineBIP340 is nil")
	}
	browserHot := hex.EncodeToString(hot.PubKey().SerializeCompressed())
	if err := svc.Register(RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte{0x22}),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(p256)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub: browserHot,
	}); err != nil {
		t.Fatalf("browser-supplied hot pubkey: %v", err)
	}
	if svc.PhoneRoutineBIP340 == nil || hex.EncodeToString(svc.PhoneRoutineBIP340.SerializeCompressed()) != browserHot {
		t.Fatal("enrolled hot pubkey is not the browser-supplied key")
	}
	st, err := svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantDirect := hex.EncodeToString(webauthn.CompressedP256(direct))
	if st.PhoneDirectP256 != wantDirect {
		t.Fatalf("status phoneDirectP256 = %q, want persisted %q", st.PhoneDirectP256, wantDirect)
	}
	wantProvider := hex.EncodeToString(schnorr.SerializePubKey(svc.Operational.TweakedVaultCosigner))
	if st.TweakedVaultCosignerXOnly != wantProvider {
		t.Fatalf("status tweakedProviderXOnly = %q, want persisted %q", st.TweakedVaultCosignerXOnly, wantProvider)
	}
}
