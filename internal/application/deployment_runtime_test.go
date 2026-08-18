package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestQuarantineIsExactLeftoverTemplateOnly(t *testing.T) {
	mt := &Service{MultiTenantEnrollment: true}
	if quarantineLegacyVault(&Service{}, "tenant-a", fixture.LeftoverV3TemplateVersion) {
		t.Fatal("singleton authorizer must fail closed on a leftover template")
	}
	if !quarantineLegacyVault(mt, "tenant-a", fixture.LeftoverV3TemplateVersion) {
		t.Fatal("multi-tenant boot should quarantine the exact leftover v3 template")
	}
	if quarantineLegacyVault(mt, "tenant-a", fixture.TemplateVersion) {
		t.Fatal("current template must not be quarantined")
	}
	if quarantineLegacyVault(mt, "tenant-a", "phone-direct-p256-routine-3of3-admin-phone-hww-v4-forged") {
		t.Fatal("unknown template must fail closed, not quarantine")
	}
}

func TestMutinynetDeploymentIdentityAndDelaysPersistAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mutinynet.sqlite")
	cfg := deployment.Config{
		ClientOrigin: "https://vault.example.com", RPID: "vault.example.com",
		Network: deployment.NetworkMutinynet, OperationalCSVBlocks: 4032, SavingsCSVBlocks: 288,
	}
	providerKey, _ := btcec.NewPrivateKey()
	arkadeKey, _ := btcec.NewPrivateKey()
	externalOwner, _ := btcec.NewPrivateKey()
	offline, _ := btcec.NewPrivateKey()
	_ = offline
	hot, _ := btcec.NewPrivateKey()
	passkey, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5c}, 32))
	bootstrap, err := HashEnrollmentToken(token)
	if err != nil {
		t.Fatal(err)
	}
	integrityKey := bytes.Repeat([]byte{0x5a}, sha256.Size)

	ledger, err := policy.OpenLedger(dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		Ledger: ledger, Deployment: cfg, CredentialIntegrityKey: integrityKey,
		ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerPub: providerKey.PubKey(),
		ArkadeCosignerPub: arkadeKey.PubKey(), ArkadeCosignerOrigin: deployment.MutinynetArkadeCosignerOrigin,
		ArkadeCosignerVersion: deployment.MutinynetArkadeCosignerVersion,
		VaultSigner:           LocalSigner{Priv: providerKey}, ArkadeCosignerSigner: LocalSigner{Priv: arkadeKey},
		EnrollmentTokenHash: bootstrap,
		EnrollmentDeadline:  time.Now().Add(time.Hour),
	}
	if err := svc.RegisterWithBootstrap(RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("mutinynet-credential")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passkey)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}, token); err != nil {
		t.Fatal(err)
	}
	status, err := svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Network != deployment.NetworkMutinynet || status.ClientOrigin != cfg.ClientOrigin || status.RPID != cfg.RPID || !strings.HasPrefix(status.OperationalAddr, "tb1p") {
		t.Fatalf("mutinynet status: %+v", status)
	}
	if status.RecoveryKeyPub != "" {
		t.Fatalf("v4 status leaked recoveryKeyPub: %+v", status)
	}
	if status.ExternalOwnerWalletPub != hex.EncodeToString(externalOwner.PubKey().SerializeCompressed()) ||
		status.VaultCosignerBasePub != hex.EncodeToString(providerKey.PubKey().SerializeCompressed()) ||
		status.ArkadeCosignerBasePub != hex.EncodeToString(arkadeKey.PubKey().SerializeCompressed()) ||
		status.OperationalCSVBlocks != cfg.OperationalCSVBlocks ||
		status.SavingsCSVBlocks != cfg.SavingsCSVBlocks ||
		status.TemplateVersion != fixture.TemplateVersion ||
		status.PolicyVersion != fixture.PolicyVersion ||
		status.AbsoluteFeeCap != fixture.AbsoluteFeeCeiling ||
		status.FeerateCapSatPerV != fixture.FeerateCeilingSatPerV {
		t.Fatalf("mutinynet public descriptor inputs: %+v", status)
	}
	cred, err := ledger.GetCredential()
	if err != nil {
		t.Fatal(err)
	}
	if cred.Network != cfg.Network || cred.Origin != cfg.ClientOrigin || cred.RPID != cfg.RPID || cred.OperationalCSVValue != cfg.OperationalCSVBlocks || cred.SavingsCSVValue != cfg.SavingsCSVBlocks {
		t.Fatalf("persisted deployment identity: %+v", cred)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := policy.OpenLedger(dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restart := &Service{
		Ledger: reopened, Deployment: cfg, CredentialIntegrityKey: integrityKey,
		ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerPub: providerKey.PubKey(), ArkadeCosignerPub: arkadeKey.PubKey(),
		ArkadeCosignerOrigin: deployment.MutinynetArkadeCosignerOrigin,
		// The outbound transport separately accepted this exact release version.
		// A reviewed server version change must not strand an unchanged or
		// actively-deprecated enrolled key.
		ArkadeCosignerVersion: "v-reviewed-next",
		VaultSigner:           LocalSigner{Priv: providerKey}, ArkadeCosignerSigner: LocalSigner{Priv: arkadeKey},
	}
	if err := restart.LoadVaults(); err != nil {
		t.Fatalf("same deployment restart: %v", err)
	}
	restartedStatus, err := restart.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if restartedStatus.ArkadeCosignerVersion != deployment.MutinynetArkadeCosignerVersion {
		t.Fatalf("restart rewrote enrolled Arkade version to runtime %q", restartedStatus.ArkadeCosignerVersion)
	}
	changed := cfg
	changed.SavingsCSVBlocks++
	wrong := &Service{
		Ledger: reopened, Deployment: changed, CredentialIntegrityKey: integrityKey,
		ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerPub: providerKey.PubKey(), ArkadeCosignerPub: arkadeKey.PubKey(),
		ArkadeCosignerOrigin:  deployment.MutinynetArkadeCosignerOrigin,
		ArkadeCosignerVersion: deployment.MutinynetArkadeCosignerVersion,
	}
	if err := wrong.LoadVaults(); err == nil || !strings.Contains(err.Error(), "Savings CSV") && !strings.Contains(err.Error(), "savings CSV") {
		t.Fatalf("changed recovery delay accepted: %v", err)
	}
}
