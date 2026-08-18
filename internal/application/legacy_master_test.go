package application

import (
	"errors"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/apperr"
	"github.com/brg444/arkade-vault-server/internal/policy"
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
