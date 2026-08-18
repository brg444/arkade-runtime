package application

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestTwoTenantsHaveIsolatedDescriptorsCapsAndLoaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tenants.sqlite")
	led, err := policy.OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })

	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	ownerA, _ := btcec.NewPrivateKey()
	recA, _ := btcec.NewPrivateKey()
	_ = recA
	hotA, _ := btcec.NewPrivateKey()
	passA, _ := webauthn.NewP256()
	dirA, _ := webauthn.NewP256()
	svc := &Service{
		Ledger:               led,
		ExternalOwnerWallet:  ownerA.PubKey(),
		VaultCosignerPub:     master.PubKey(),
		ArkadeCosignerPub:    arkade.PubKey(),
		VaultSigner:          LocalSigner{Priv: master},
		ArkadeCosignerSigner: LocalSigner{Priv: arkade},
	}
	if err := svc.Register(RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("cred-a")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passA)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(dirA)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hotA.PubKey().SerializeCompressed()),
	}); err != nil {
		t.Fatal(err)
	}
	key, err := svc.credentialIntegrityKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}

	token := bytes.Repeat([]byte{0x5a}, 32)
	now := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := led.PutInvite(token, now, now); err != nil {
		t.Fatal(err)
	}

	ownerB, _ := btcec.NewPrivateKey()
	recB, _ := btcec.NewPrivateKey()
	hotB, _ := btcec.NewPrivateKey()
	passB, _ := webauthn.NewP256()
	dirB, _ := webauthn.NewP256()
	const tenantB = "tenant-b"
	if err := svc.CreateTenantVault(tenantB, token, proposedPoP(t, svc, tenantB, ownerB, recB, RegisterRequest{
		CredentialID:             hex.EncodeToString([]byte("cred-b")),
		WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(passB)),
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(dirB)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hotB.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(ownerB.PubKey())),
	})); err != nil {
		t.Fatal(err)
	}

	snapA := svc.snapshot(fixture.VaultID)
	snapB := svc.snapshot(tenantB)
	if snapA.Operational == nil || snapB.Operational == nil {
		t.Fatal("both tenants must be published")
	}
	if snapA.Operational.Address == snapB.Operational.Address {
		t.Fatal("tenants share an operational address")
	}
	if bytes.Equal(snapA.VaultCosignerBase.SerializeCompressed(), snapB.VaultCosignerBase.SerializeCompressed()) {
		t.Fatal("tenants share a VaultCosigner pubkey")
	}
	if bytes.Equal(snapA.CredentialID, snapB.CredentialID) {
		t.Fatal("tenants share a credential id")
	}
	if err := policy.VerifyVaultCosignerPub(master, policy.VaultRecord{
		VaultID: tenantB, CosignerMode: policy.CosignerModeHKDFSHA256V1,
		VaultCosignerBase: snapB.VaultCosignerBase.SerializeCompressed(),
	}); err != nil {
		t.Fatal(err)
	}

	digest := bytes.Repeat([]byte{0x11}, 32)
	if _, _, err := led.IssueForTest(context.Background(), fixture.VaultID, digest, 1_000, 100, fixture.PeriodAllowanceSats, func(context.Context) (string, error) {
		return "signed-a", nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := led.IssueForTest(context.Background(), tenantB, digest, 1_000, 100, fixture.PeriodAllowanceSats, func(context.Context) (string, error) {
		return "signed-b", nil
	}); err != nil {
		t.Fatal(err)
	}
	spentA, err := led.SpentInPeriod(context.Background(), fixture.VaultID, led.PeriodStart())
	if err != nil {
		t.Fatal(err)
	}
	spentB, err := led.SpentInPeriod(context.Background(), tenantB, led.PeriodStart())
	if err != nil {
		t.Fatal(err)
	}
	if spentA != 1_100 || spentB != 1_100 {
		t.Fatalf("isolated spend A=%d B=%d", spentA, spentB)
	}

	if err := led.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := policy.OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := reopened.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	restarted := &Service{
		Ledger:               reopened,
		ExternalOwnerWallet:  ownerA.PubKey(),
		VaultCosignerPub:     master.PubKey(),
		ArkadeCosignerPub:    arkade.PubKey(),
		VaultSigner:          LocalSigner{Priv: master},
		ArkadeCosignerSigner: LocalSigner{Priv: arkade},
	}
	if err := restarted.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	if restarted.snapshot(fixture.VaultID).Operational == nil || restarted.snapshot(tenantB).Operational == nil {
		t.Fatal("restart lost a tenant")
	}
	if restarted.snapshot(fixture.VaultID).Operational.Address != snapA.Operational.Address {
		t.Fatal("first vault address changed across restart")
	}
	if restarted.snapshot(tenantB).Operational.Address != snapB.Operational.Address {
		t.Fatal("tenant B address changed across restart")
	}
	if restarted.enrolled().Operational.Address != snapA.Operational.Address {
		t.Fatal("legacy enrolled() wrapper does not default to operational-vault-v1")
	}
}

func TestRemoteSignerExpectedKeyIsPerCallNotSharedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "remote-tenants.sqlite")
	led, err := policy.OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	ownerA, _ := btcec.NewPrivateKey()
	recA, _ := btcec.NewPrivateKey()
	_ = recA
	hotA, _ := btcec.NewPrivateKey()
	passA, _ := webauthn.NewP256()
	dirA, _ := webauthn.NewP256()
	svc := &Service{
		Ledger:               led,
		ExternalOwnerWallet:  ownerA.PubKey(),
		VaultCosignerPub:     master.PubKey(),
		ArkadeCosignerPub:    arkade.PubKey(),
		VaultSigner:          LocalSigner{Priv: master},
		ArkadeCosignerSigner: LocalSigner{Priv: arkade},
	}
	if err := svc.Register(RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("cred-a")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passA)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(dirA)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hotA.PubKey().SerializeCompressed()),
	}); err != nil {
		t.Fatal(err)
	}
	key, err := svc.credentialIntegrityKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{0x6b}, 32)
	now := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := led.PutInvite(token, now, now); err != nil {
		t.Fatal(err)
	}
	ownerB, _ := btcec.NewPrivateKey()
	recB, _ := btcec.NewPrivateKey()
	hotB, _ := btcec.NewPrivateKey()
	passB, _ := webauthn.NewP256()
	dirB, _ := webauthn.NewP256()
	const tenantB = "tenant-remote-b"
	if err := svc.CreateTenantVault(tenantB, token, proposedPoP(t, svc, tenantB, ownerB, recB, RegisterRequest{
		CredentialID:             hex.EncodeToString([]byte("cred-b")),
		WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(passB)),
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(dirB)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hotB.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(ownerB.PubKey())),
	})); err != nil {
		t.Fatal(err)
	}
	child, err := policy.DeriveVaultCosignerScalar(master, tenantB, policy.CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}
	transport := &dualBaseRemoteTransport{bases: []*btcec.PrivateKey{master, child}}
	remote := &RemoteSigner{Client: transport}
	expA := schnorr.SerializePubKey(svc.snapshot(fixture.VaultID).Operational.TweakedVaultCosigner)
	expB := schnorr.SerializePubKey(svc.snapshot(tenantB).Operational.TweakedVaultCosigner)
	if bytes.Equal(expA, expB) {
		t.Fatal("tenants share a tweaked VaultCosigner")
	}

	// Reuse the first vault's operational packet shape via LocalSigner once so
	// we have a well-formed PSBT, then ask the shared RemoteSigner for both
	// expected keys. A process-wide bind would make one of these fail.
	ptx := mustSignablePacket(t, svc.snapshot(fixture.VaultID).Operational, hotA, dirA)
	gotA, err := remote.SignExpected(context.Background(), ptx, expA)
	if err != nil {
		t.Fatalf("tenant A remote sign: %v", err)
	}
	ptxB := mustSignablePacket(t, svc.snapshot(tenantB).Operational, hotB, dirB)
	gotB, err := remote.SignExpected(context.Background(), ptxB, expB)
	if err != nil {
		t.Fatalf("tenant B remote sign: %v", err)
	}
	if _, err := extractVerifiedSignerSig(ptx, gotA, expA); err != nil {
		t.Fatalf("tenant A signature: %v", err)
	}
	if _, err := extractVerifiedSignerSig(ptxB, gotB, expB); err != nil {
		t.Fatalf("tenant B signature: %v", err)
	}
	if remote.SuccessfulCalls() != 2 {
		t.Fatalf("successful remote calls = %d", remote.SuccessfulCalls())
	}
}

func TestMultiTenantAuthorizeRequiresVaultID(t *testing.T) {
	svc := &Service{MultiTenantEnrollment: true}
	if _, err := svc.routeVaultID(""); err == nil || !strings.Contains(err.Error(), "vault id required") {
		t.Fatalf("empty vault id on a tenant process: %v", err)
	}
	if _, _, _, err := svc.resolveSpendVaultRecord(""); err == nil || !strings.Contains(err.Error(), "vault id required") {
		t.Fatalf("empty spend resolve: %v", err)
	}
	legacy := &Service{}
	id, err := legacy.routeVaultID("")
	if err != nil || id != fixture.VaultID {
		t.Fatalf("leftover singleton default: %q %v", id, err)
	}
}

type dualBaseRemoteTransport struct {
	bases []*btcec.PrivateKey
}

func (d *dualBaseRemoteTransport) SubmitOnchainTx(ctx context.Context, encoded string) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
	if err != nil {
		return "", err
	}
	var lastErr error
	for _, priv := range d.bases {
		clone, err := clonePacket(ptx)
		if err != nil {
			return "", err
		}
		signed, err := (LocalSigner{Priv: priv}).Sign(ctx, clone)
		if err != nil {
			lastErr = err
			continue
		}
		return signed.B64Encode()
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no tenant cosigner could sign")
}

func mustSignablePacket(t *testing.T, built *vault.Built, hot *btcec.PrivateKey, direct *ecdsa.PrivateKey) *psbt.Packet {
	t.Helper()
	if built == nil || built.Leaves.Routine == nil {
		t.Fatal("missing vault")
	}
	prevTx := wire.NewMsgTx(2)
	prevTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{}})
	prevTx.AddTxOut(&wire.TxOut{Value: 80_000, PkScript: built.PkScript})
	dest, err := txscript.PayToTaprootScript(hot.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	spend, err := vault.BuildRoutineSpend(vault.SpendParams{
		Vault: built, PrevTx: prevTx, PrevOutPoint: wire.OutPoint{Hash: prevTx.TxHash(), Index: 0},
		RecipientScript: dest, RecipientAmount: 40_000, Fee: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	directSig, err := webauthn.SignDigestLowS(direct, spend.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.SetPacketWitness(spend.Packet.UnsignedTx, [][]byte{directSig}); err != nil {
		t.Fatal(err)
	}
	hotSig, err := vault.SignLeaf(spend.Packet.UnsignedTx, spend.Prevout, built.Leaves.Routine.Script, hot)
	if err != nil {
		t.Fatal(err)
	}
	vault.AddPartialSig(spend.Packet, hot.PubKey(), built.Leaves.Routine.Hash, hotSig)
	return spend.Packet
}
