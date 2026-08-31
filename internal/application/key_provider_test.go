package application

import (
	"reflect"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestScopedKeyCapabilitiesPreserveExistingDerivations(t *testing.T) {
	master, _ := btcec.NewPrivateKey()
	emulator, _ := btcec.NewPrivateKey()
	keys, err := NewFileBackedKeyCapabilities(master, LocalSigner{Priv: emulator})
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Validate(); err != nil {
		t.Fatal(err)
	}

	vaultID := "vault-key-provider-compatibility"
	gotVault, err := keys.enrollment.vaultCosignerPublic(vaultID)
	if err != nil {
		t.Fatal(err)
	}
	wantVault, err := policy.DeriveVaultCosignerScalar(master, vaultID, policy.CosignerModeHKDFSHA256V1)
	if err != nil {
		t.Fatal(err)
	}
	if !gotVault.IsEqual(wantVault.PubKey()) {
		t.Fatal("enrollment derivation changed behind the scoped capability")
	}

	operator, _ := btcec.NewPrivateKey()
	keyContext, err := newVtxoKeyContext(vaultID, program.NetworkMainnet, operator.PubKey().SerializeCompressed())
	if err != nil {
		t.Fatal(err)
	}
	gotVtxo, err := keys.vtxoTransaction.vtxoVaultCosignerPublic(keyContext)
	if err != nil {
		t.Fatal(err)
	}
	wantVtxo, err := policy.DeriveVtxoVaultCosignerScalar(
		master, vaultID, program.VaultPolicyV1, program.NetworkMainnet, operator.PubKey().SerializeCompressed(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !gotVtxo.IsEqual(wantVtxo.PubKey()) {
		t.Fatal("vault-policy-v1 derivation changed behind the scoped capability")
	}
}

func TestVaultBoardCapabilityIsAlwaysAvailable(t *testing.T) {
	master, _ := btcec.NewPrivateKey()
	emulator, _ := btcec.NewPrivateKey()
	keys, err := NewFileBackedKeyCapabilities(master, LocalSigner{Priv: emulator})
	if err != nil {
		t.Fatal(err)
	}
	if isNilInterface(keys.vaultBoard) {
		t.Fatal("runtime lacks mandatory vault-board-v1 authorization")
	}
}

func TestKeyCapabilitySurfaceIsSealedAndSemantic(t *testing.T) {
	typ := reflect.TypeOf(KeyCapabilities{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).PkgPath == "" {
			t.Fatalf("key capability field %q is exported", typ.Field(i).Name)
		}
	}
	for _, forbidden := range []string{"Sign", "SignPSBT", "SignDigest", "RawKey", "MasterKey"} {
		if _, ok := typ.MethodByName(forbidden); ok {
			t.Fatalf("generic or raw-key method %q is exposed", forbidden)
		}
	}
	privateKeyType := reflect.TypeOf((*btcec.PrivateKey)(nil))
	genericSignerType := reflect.TypeOf((*Signer)(nil)).Elem()
	for _, surface := range []reflect.Type{reflect.TypeOf(Service{}), reflect.TypeOf(Deps{})} {
		for i := 0; i < surface.NumField(); i++ {
			field := surface.Field(i)
			if field.Type == privateKeyType || field.Type == genericSignerType {
				t.Fatalf("%s still receives raw or generic signing field %q", surface.Name(), field.Name)
			}
		}
	}
	if _, err := newSavingsRecoveryAuthorization(nil, "", nil, nil); err == nil {
		t.Fatal("unvalidated Savings authorization accepted")
	}
	if _, err := newVtxoTransactionAuthorization(vtxoKeyContext{}, "", "", nil, nil); err == nil {
		t.Fatal("unvalidated VTXO transaction authorization accepted")
	}
	if _, err := newVtxoCheckpointAuthorization(vtxoKeyContext{}, nil, nil, nil); err == nil {
		t.Fatal("unvalidated VTXO checkpoint authorization accepted")
	}
}

func TestKeyCapabilitiesWipeBackendAndHandles(t *testing.T) {
	master, _ := btcec.NewPrivateKey()
	emulator, _ := btcec.NewPrivateKey()
	keys, err := NewFileBackedKeyCapabilities(master, LocalSigner{Priv: emulator})
	if err != nil {
		t.Fatal(err)
	}
	keys.Wipe()
	if err := keys.Validate(); err == nil {
		t.Fatal("wiped capabilities remained usable")
	}
}
