package application

import (
	"bytes"
	"errors"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/apperr"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestNewDoesNotInstallMasterAsSigner(t *testing.T) {
	master, _ := btcec.NewPrivateKey()
	svc := New(Deps{MasterIKM: master, MultiTenantEnrollment: true})
	if !isNilInterface(svc.VaultSigner) {
		t.Fatal("constructor installed the master scalar as VaultSigner")
	}
	got, err := svc.vaultCosignerMaster()
	if err != nil || got != master {
		t.Fatalf("IKM: %v %v", got, err)
	}
}

func TestVaultCosignerSignerRefusesLegacyDirect(t *testing.T) {
	svc := New(Deps{MultiTenantEnrollment: true})
	_, err := svc.vaultCosignerSigner(&policy.VaultRecord{
		VaultID:      policy.LegacyFirstVaultID,
		CosignerMode: policy.CosignerModeLegacyDirectV0,
	})
	if !errors.Is(err, apperr.ErrLegacyMasterSign) {
		t.Fatalf("legacy signer: %v", err)
	}
}

func TestRoutineSignersDerivesProtectedVaultSigner(t *testing.T) {
	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	vaultTweak, _ := btcec.NewPrivateKey()
	arkadeTweak, _ := btcec.NewPrivateKey()
	const vaultID = "protected-runtime-vault"
	derived, err := policy.DeriveVaultCosignerScalar(master, vaultID, policy.CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}
	rec := &policy.VaultRecord{
		VaultID:           vaultID,
		CosignerMode:      policy.CosignerModeHKDFSHA256V1,
		VaultCosignerBase: derived.PubKey().SerializeCompressed(),
	}
	svc := New(Deps{
		MasterIKM:             master,
		ArkadeSigner:          LocalSigner{Priv: arkade},
		MultiTenantEnrollment: true,
	})
	if !isNilInterface(svc.VaultSigner) {
		t.Fatal("protected runtime unexpectedly has a global VaultSigner")
	}

	vaultSigner, arkadeSigner, err := svc.routineSigners(rec, &vault.Built{
		TweakedVaultCosigner:  vaultTweak.PubKey(),
		TweakedArkadeCosigner: arkadeTweak.PubKey(),
	})
	if err != nil {
		t.Fatalf("routine signers: %v", err)
	}
	local, ok := vaultSigner.(LocalSigner)
	if !ok || local.Priv == nil {
		t.Fatalf("derived signer = %T", vaultSigner)
	}
	if !bytes.Equal(local.Priv.PubKey().SerializeCompressed(), derived.PubKey().SerializeCompressed()) {
		t.Fatal("derived signer does not match the enrolled vault")
	}
	if isNilInterface(arkadeSigner) {
		t.Fatal("ArkadeCosigner signer missing")
	}
}
