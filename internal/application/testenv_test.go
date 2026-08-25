package application

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/policy"
	arkadevaultv1 "github.com/brg444/arkade-vault-server/internal/profile/arkadevaultv1"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type env struct {
	svc           *Service
	ledger        *policy.Ledger
	savings       *savingsSnapshot
	hot           *btcec.PrivateKey
	externalOwner *btcec.PrivateKey
	master        *btcec.PrivateKey
	operator      *btcec.PrivateKey
	p256          *ecdsa.PrivateKey
	direct        *ecdsa.PrivateKey
	credID        []byte
	dbPath        string
}

const (
	testArkadeCosignerOrigin  = "https://operator.test"
	testArkadeCosignerVersion = "savings-v1-test"
)

var testCredentialIntegrityKey = bytes.Repeat([]byte{0x5a}, 32)

func newEnv(t *testing.T) *env {
	t.Helper()
	hot, _ := btcec.NewPrivateKey()
	externalOwner, _ := btcec.NewPrivateKey()
	master, _ := btcec.NewPrivateKey()
	operator, _ := btcec.NewPrivateKey()
	passkey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "policy.sqlite")
	ledger, err := policy.OpenMainnetLedger(dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	integrityKey := append([]byte(nil), testCredentialIntegrityKey...)
	stores, err := arkadevaultv1.StoresFromLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	service := New(Deps{
		Stores: stores, Deployment: deployment.Config{
			ClientOrigin: fixture.Origin, RPID: fixture.RPID, Network: deployment.NetworkMutinynet,
		}, IntegrityKey: integrityKey,
		MasterIKM: master, VaultCosignerPub: master.PubKey(), ArkadeCosignerPub: operator.PubKey(),
		ArkadeCosignerOrigin: testArkadeCosignerOrigin, ArkadeCosignerVersion: testArkadeCosignerVersion,
		ArkadeSigner: LocalSigner{Priv: operator},
	})
	if err := ledger.SetIntegrityKey(integrityKey); err != nil {
		t.Fatal(err)
	}
	credentialID := []byte{0x11}
	tokenHash := bytes.Repeat([]byte{0x42}, 32)
	now := time.Now().UTC()
	if err := ledger.PutInvite(tokenHash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	request := RegisterRequest{
		CredentialID:             hex.EncodeToString(credentialID),
		WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(passkey)),
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(externalOwner.PubKey())),
	}
	preview, err := service.previewTenantDescriptor(fixture.VaultID, request)
	if err != nil {
		t.Fatal(err)
	}
	request.DescriptorHash = preview.DescriptorHash
	if err := service.CreateTenantVault(fixture.VaultID, tokenHash, request); err != nil {
		t.Fatal(err)
	}
	snapshot := service.snapshot(fixture.VaultID)
	if snapshot.Savings == nil {
		t.Fatal("current Vault enrollment was not published")
	}
	return &env{
		svc: service, ledger: ledger, savings: snapshot.Savings,
		hot: hot, externalOwner: externalOwner, master: master, operator: operator,
		p256: passkey, direct: direct, credID: credentialID, dbPath: dbPath,
	}
}

func testStores(t *testing.T, ledger *policy.Ledger) arkadevaultv1.Stores {
	t.Helper()
	stores, err := arkadevaultv1.StoresFromLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	return stores
}
