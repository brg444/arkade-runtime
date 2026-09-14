package application

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	arkadevaultv1 "github.com/brg444/arkade-runtime/internal/profile/arkadevaultv1"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type env struct {
	svc      *Service
	ledger   *policy.Ledger
	hot      *btcec.PrivateKey
	master   *btcec.PrivateKey
	operator *btcec.PrivateKey
	boarding *btcec.PrivateKey
	p256     *ecdsa.PrivateKey
	direct   *ecdsa.PrivateKey
	credID   []byte
	dbPath   string
}

const (
	testArkadeCosignerOrigin  = "https://operator.test"
	testArkadeCosignerVersion = "savings-v1-test"
)

var testCredentialIntegrityKey = bytes.Repeat([]byte{0x5a}, 32)

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvForNetwork(t, deployment.NetworkMutinynet)
}

func newEnvForNetwork(t *testing.T, network string) *env {
	t.Helper()
	e := newUnenrolledEnvForNetwork(t, network)
	service, ledger := e.svc, e.ledger
	credentialID, passkey, direct := e.credID, e.p256, e.direct
	hot, boarding := e.hot, e.boarding
	service.LightEnabled = true
	var err error
	tokenHash := bytes.Repeat([]byte{0x42}, 32)
	now := time.Now().UTC()
	if err := ledger.PutInvite(tokenHash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	request := RegisterRequest{
		CredentialID:           hex.EncodeToString(credentialID),
		WebAuthnP256:           hex.EncodeToString(webauthn.CompressedP256(passkey)),
		PhoneDirectP256:        hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:         hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		VtxoBoardingProgram:    program.VaultBoardV1,
		VaultBoardingBIP340Pub: hex.EncodeToString(schnorr.SerializePubKey(boarding.PubKey())),
		ProtectionTier:         program.ProtectionTierLight,
	}
	request.SpendingPolicy, err = program.DefaultSpendingPolicyFor(network)
	if err != nil {
		t.Fatal(err)
	}
	request.SpendingPolicyDigest, err = program.SpendingPolicyDigestHexFor(network, request.SpendingPolicy)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := service.previewVaultBoardEnrollmentDescriptor(fixture.VaultID, request)
	if err != nil {
		t.Fatal(err)
	}
	request.DescriptorHash = preview.DescriptorHash
	if err := service.CreateTenantVault(fixture.VaultID, tokenHash, request); err != nil {
		t.Fatal(err)
	}
	snapshot := service.snapshot(fixture.VaultID)
	if snapshot.Savings != nil || snapshot.Board == nil || snapshot.PhoneBIP340 == nil {
		t.Fatal("current Vault enrollment was not published")
	}
	return e
}

func newUnenrolledEnvForNetwork(t *testing.T, network string) *env {
	t.Helper()
	identity, err := deployment.IdentityFor(network)
	if err != nil {
		t.Fatal(err)
	}
	origin, rpID := fixture.Origin, fixture.RPID
	if network == deployment.NetworkMainnet {
		origin, rpID = deployment.MainnetRCOrigin, deployment.MainnetRCRPID
	}
	hot, _ := btcec.NewPrivateKey()
	master, _ := btcec.NewPrivateKey()
	operator, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	passkey, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "policy.sqlite")
	ledger, err := policy.OpenLedgerForNetwork(dbPath, nil, network)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	integrityKey := append([]byte(nil), testCredentialIntegrityKey...)
	stores, err := arkadevaultv1.StoresFromLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	operatorSigner, err := hex.DecodeString(identity.OperatorSignerPubHex)
	if err != nil {
		t.Fatal(err)
	}
	resolver := stubArkResolver{signer: operatorSigner, network: network}
	service := New(Deps{
		Stores: stores, Deployment: deployment.Config{
			ClientOrigin: origin, RPID: rpID, Network: network,
		}, IntegrityKey: integrityKey,
		Keys: testKeys(t, master), VaultCosignerPub: master.PubKey(), ArkadeCosignerPub: operator.PubKey(),
		ArkadeCosignerOrigin: testArkadeCosignerOrigin, ArkadeCosignerVersion: testArkadeCosignerVersion,
		ArkResolver: resolver,
	})
	if err := ledger.SetIntegrityKey(integrityKey); err != nil {
		t.Fatal(err)
	}
	return &env{
		svc: service, ledger: ledger,
		hot: hot, master: master, operator: operator, boarding: boarding,
		p256: passkey, direct: direct, credID: []byte{0x11}, dbPath: dbPath,
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

func testKeys(t *testing.T, master *btcec.PrivateKey) KeyCapabilities {
	t.Helper()
	keys, err := NewFileBackedKeyCapabilities(master)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}
