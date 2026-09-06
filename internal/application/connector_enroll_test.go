package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func newConnectorEnrollService(t *testing.T) (*Service, *policy.Ledger) {
	t.Helper()
	f := newConnectorFixture(t, deployment.NetworkMutinynet)
	return f.svc, f.led
}

// connectorFixture retains everything needed to reopen the same database
// with identical keys and deployment after a restart.
type connectorFixture struct {
	svc          *Service
	led          *policy.Ledger
	dbPath       string
	master       *btcec.PrivateKey
	operator     *btcec.PrivateKey
	network      string
	origin       string
	rpid         string
	integrityKey []byte
	resolver     stubArkResolver
}

func newConnectorFixture(t *testing.T, network string) *connectorFixture {
	t.Helper()
	identity, err := deployment.IdentityFor(network)
	if err != nil {
		t.Fatal(err)
	}
	origin, rpid := fixture.Origin, fixture.RPID
	if network == deployment.NetworkMainnet {
		origin, rpid = deployment.MainnetRCOrigin, deployment.MainnetRCRPID
	}
	dbPath := filepath.Join(t.TempDir(), "connector-enroll.sqlite")
	led, err := policy.OpenLedgerForNetwork(dbPath, nil, network)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	integrityKey := append([]byte(nil), testCredentialIntegrityKey...)
	if err := led.SetIntegrityKey(integrityKey); err != nil {
		t.Fatal(err)
	}
	master, _ := btcec.NewPrivateKey()
	operator, _ := btcec.NewPrivateKey()
	operatorSigner, err := hex.DecodeString(identity.OperatorSignerPubHex)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := hex.DecodeString(identity.CheckpointTapscriptHex)
	if err != nil {
		t.Fatal(err)
	}
	resolver := stubArkResolver{signer: operatorSigner, network: network, checkpoint: checkpoint}
	// Like newEnv, the operator doubles as the ArkadeCosigner so recovery
	// cosigning works end to end in tests.
	svc := New(Deps{
		Stores: testStores(t, led), Deployment: deployment.Config{
			ClientOrigin: origin, RPID: rpid, Network: network,
		}, IntegrityKey: append([]byte(nil), integrityKey...),
		Keys: testKeys(t, master, LocalSigner{Priv: operator}), VaultCosignerPub: master.PubKey(), ArkadeCosignerPub: operator.PubKey(),
		ArkadeCosignerOrigin: testArkadeCosignerOrigin, ArkadeCosignerVersion: testArkadeCosignerVersion,
		ArkResolver: resolver,
	})
	return &connectorFixture{
		svc: svc, led: led, dbPath: dbPath, master: master, operator: operator,
		network: network, origin: origin, rpid: rpid,
		integrityKey: integrityKey, resolver: resolver,
	}
}

// reopen closes the ledger and reopens the same database with identical keys,
// then reloads every vault through the production LoadVaults path.
func (f *connectorFixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.led.Close(); err != nil {
		t.Fatal(err)
	}
	led, err := policy.OpenLedgerForNetwork(f.dbPath, nil, f.network)
	if err != nil {
		t.Fatal(err)
	}
	f.led = led
	t.Cleanup(func() { _ = led.Close() })
	if err := led.SetIntegrityKey(f.integrityKey); err != nil {
		t.Fatal(err)
	}
	f.svc = New(Deps{
		Stores: testStores(t, led), Deployment: deployment.Config{
			ClientOrigin: f.origin, RPID: f.rpid, Network: f.network,
		}, IntegrityKey: append([]byte(nil), f.integrityKey...),
		Keys: testKeys(t, f.master, LocalSigner{Priv: f.operator}), VaultCosignerPub: f.master.PubKey(), ArkadeCosignerPub: f.operator.PubKey(),
		ArkadeCosignerOrigin: testArkadeCosignerOrigin, ArkadeCosignerVersion: testArkadeCosignerVersion,
		ArkResolver: f.resolver,
	})
	if err := f.svc.LoadVaults(); err != nil {
		t.Fatal(err)
	}
}

func connectorEnrollRequest(t *testing.T, phone, hardware, boarding *btcec.PrivateKey, tier string, recovery *btcec.PrivateKey, kind connector.Kind) RegisterRequest {
	t.Helper()
	return connectorEnrollRequestForNetwork(t, deployment.NetworkMutinynet, phone, hardware, boarding, tier, recovery, kind, false)
}

// connectorEnrollRequestForNetwork builds an enrollment request for the named
// network. On mainnet the BIP84/86 coin segment is 0'/0; electrum selects a
// native m/0'/change/index origin instead of a purpose-prefixed path.
func connectorEnrollRequestForNetwork(t *testing.T, network string, phone, hardware, boarding *btcec.PrivateKey, tier string, recovery *btcec.PrivateKey, kind connector.Kind, electrum bool) RegisterRequest {
	t.Helper()
	pass, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	coin := uint32(0x80000000)
	if network == deployment.NetworkMutinynet {
		coin++
	}
	req := RegisterRequest{
		CredentialID:             mustRandomHex(t, 16),
		WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(pass)),
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(phone.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(hardware.PubKey())),
		VtxoBoardingProgram:      program.VaultBoardV1,
		VaultBoardingBIP340Pub:   hex.EncodeToString(schnorr.SerializePubKey(boarding.PubKey())),
		ProtectionTier:           tier,
		ConnectorType:            string(kind),
		ConnectorPub:             hex.EncodeToString(hardware.PubKey().SerializeCompressed()),
		ConnectorFingerprint:     0x12345678,
	}
	switch {
	case electrum:
		req.ConnectorPath = []uint32{0x80000000, 0, 7}
	case kind == connector.Taproot:
		req.ConnectorPath = []uint32{0x80000056, coin, 0x80000000, 0, 0}
	default:
		req.ConnectorPath = []uint32{0x80000054, coin, 0x80000000, 0, 0}
	}
	if recovery != nil {
		req.RecoveryXOnly = hex.EncodeToString(schnorr.SerializePubKey(recovery.PubKey()))
	}
	selected, err := program.DefaultSpendingPolicyFor(network)
	if err != nil {
		t.Fatal(err)
	}
	req.SpendingPolicy = selected
	req.SpendingPolicyDigest, err = program.SpendingPolicyDigestHexFor(network, selected)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func putConnectorInvite(t *testing.T, led *policy.Ledger, tokenHash []byte) {
	t.Helper()
	now := time.Now().UTC()
	if err := led.PutInvite(tokenHash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

func enrollConnectorVault(t *testing.T, svc *Service, vaultID string, tokenHash []byte, req RegisterRequest) RegisterRequest {
	t.Helper()
	preview, err := svc.previewConnectorEnrollmentDescriptor(vaultID, req)
	if err != nil {
		t.Fatal(err)
	}
	req.DescriptorHash = preview.DescriptorHash
	if err := svc.CreateTenantVault(vaultID, tokenHash, req); err != nil {
		t.Fatal(err)
	}
	return req
}

func oddHardwareKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	for i := 0; i < 256; i++ {
		k, _ := btcec.NewPrivateKey()
		compressed := k.PubKey().SerializeCompressed()
		if compressed[0] != 0x03 {
			continue
		}
		if knownFixtureXOnly(schnorr.SerializePubKey(k.PubKey())) {
			continue
		}
		return k
	}
	t.Fatal("no odd test key found")
	return nil
}

func TestConnectorEnrollmentBindsFullDescriptor(t *testing.T) {
	svc, _ := newConnectorEnrollService(t)
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	vaultID, err := newOpaqueVaultID()
	if err != nil {
		t.Fatal(err)
	}
	base := connectorEnrollRequest(t, phone, hardware, boarding, program.ProtectionTierStandard, nil, connector.Taproot)
	first, err := svc.previewConnectorEnrollmentDescriptor(vaultID, base)
	if err != nil {
		t.Fatal(err)
	}
	if first.DescriptorHash == "" {
		t.Fatal("connector descriptor hash required")
	}
	// Boarding binding: a different boarding key must change the hash.
	otherBoarding, _ := btcec.NewPrivateKey()
	changedBoard := base
	changedBoard.VaultBoardingBIP340Pub = hex.EncodeToString(schnorr.SerializePubKey(otherBoarding.PubKey()))
	second, err := svc.previewConnectorEnrollmentDescriptor(vaultID, changedBoard)
	if err != nil {
		t.Fatal(err)
	}
	if second.DescriptorHash == first.DescriptorHash {
		t.Fatal("boarding change did not change connector enrollment hash")
	}
	// Connector binding: a different origin path must change the hash.
	changedOrigin := base
	changedOrigin.ConnectorPath = []uint32{0x80000056, 0x80000001, 0x80000000, 0, 1}
	third, err := svc.previewConnectorEnrollmentDescriptor(vaultID, changedOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if third.DescriptorHash == first.DescriptorHash {
		t.Fatal("connector origin change did not change enrollment hash")
	}
	// Legacy preview must never equal the connector commitment.
	legacyReq := base
	legacyReq.ConnectorType, legacyReq.ConnectorPub, legacyReq.ConnectorFingerprint, legacyReq.ConnectorPath = "", "", 0, nil
	legacy, err := svc.previewVaultBoardEnrollmentDescriptor(vaultID, legacyReq)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.DescriptorHash == first.DescriptorHash {
		t.Fatal("legacy descriptor hash collided with connector commitment")
	}
	// Partial origins are rejected, never treated as legacy.
	partial := base
	partial.ConnectorPub = ""
	if _, err := svc.previewConnectorEnrollmentDescriptor(vaultID, partial); err == nil {
		t.Fatal("partial connector origin accepted")
	}
}

func TestConnectorEnrollmentAtomicParityAndDuplicate(t *testing.T) {
	svc, led := newConnectorEnrollService(t)
	phone, _ := btcec.NewPrivateKey()
	hardware := oddHardwareKey(t)
	if hardware.PubKey().SerializeCompressed()[0] != 0x03 {
		t.Fatal("odd fixture is not odd")
	}
	boarding, _ := btcec.NewPrivateKey()
	vaultID, err := newOpaqueVaultID()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := bytes.Repeat([]byte{0x77}, 32)
	putConnectorInvite(t, led, tokenHash)
	req := connectorEnrollRequest(t, phone, hardware, boarding, program.ProtectionTierStandard, nil, connector.NativeSegwit)
	// Override with the odd key's exact compressed bytes (parity preserved).
	req.ExternalOwnerWalletXOnly = hex.EncodeToString(schnorr.SerializePubKey(hardware.PubKey()))
	req.ConnectorPub = hex.EncodeToString(hardware.PubKey().SerializeCompressed())
	req.ConnectorPath = []uint32{0x80000054, 0x80000001, 0x80000000, 0, 0}
	req = enrollConnectorVault(t, svc, vaultID, tokenHash, req)

	cred, err := svc.loadVerifiedCredentialFor(vaultID)
	if err != nil || cred == nil {
		t.Fatalf("connector credential: %v %v", cred, err)
	}
	if cred.TemplateVersion != connector.Template {
		t.Fatalf("template %q, want %q", cred.TemplateVersion, connector.Template)
	}
	if !bytes.Equal(cred.ExternalOwnerWallet, hardware.PubKey().SerializeCompressed()) {
		t.Fatal("enrolled hardware key parity was not preserved")
	}
	stored, err := svc.Stores.Connector.GetConnectorEnrollment(vaultID)
	if err != nil || stored == nil {
		t.Fatalf("connector origin row: %v %v", stored, err)
	}
	if !bytes.Equal(stored.Pub, hardware.PubKey().SerializeCompressed()) || stored.Pub[0] != 0x03 {
		t.Fatal("origin row did not preserve odd parity")
	}
	board, err := svc.Stores.VaultBoard.GetVaultBoardEnrollment(vaultID)
	if err != nil || board == nil {
		t.Fatalf("boarding row missing: %v %v", board, err)
	}
	snap := svc.snapshot(vaultID)
	if snap.Savings == nil || snap.Savings.Address != cred.SavingsAddress {
		t.Fatal("connector snapshot was not published")
	}
	// Exact duplicate finish replays.
	st, ok := svc.acceptDuplicateFinish(vaultID, req)
	if !ok || st == nil || st.VaultID != vaultID {
		t.Fatal("exact connector duplicate finish rejected")
	}
	// Changed origin is refused, not resigned.
	forged := req
	other, _ := btcec.NewPrivateKey()
	forged.ConnectorPub = hex.EncodeToString(other.PubKey().SerializeCompressed())
	forged.ExternalOwnerWalletXOnly = hex.EncodeToString(schnorr.SerializePubKey(other.PubKey()))
	if _, ok := svc.acceptDuplicateFinish(vaultID, forged); ok {
		t.Fatal("duplicate finish accepted a different connector origin")
	}
	// Legacy replay against a connector vault is refused.
	legacy := req
	legacy.ConnectorType, legacy.ConnectorPub, legacy.ConnectorFingerprint, legacy.ConnectorPath = "", "", 0, nil
	if _, ok := svc.acceptDuplicateFinish(vaultID, legacy); ok {
		t.Fatal("legacy duplicate matched a connector vault")
	}
	// Failed enrollment with a wrong hash writes nothing.
	badVault, err := newOpaqueVaultID()
	if err != nil {
		t.Fatal(err)
	}
	badToken := bytes.Repeat([]byte{0x78}, 32)
	putConnectorInvite(t, led, badToken)
	bad := req
	bad.DescriptorHash = hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	if err := svc.CreateTenantVault(badVault, badToken, bad); err == nil {
		t.Fatal("connector create accepted a forged descriptor hash")
	}
	if cred, _ := svc.loadVerifiedCredentialFor(badVault); cred != nil {
		t.Fatal("failed connector enrollment left a credential")
	} else if got, _ := svc.Stores.Connector.GetConnectorEnrollment(badVault); got != nil {
		t.Fatal("failed connector enrollment left an origin row")
	}
}

func TestConnectorEnrollmentTiersAndLegacy(t *testing.T) {
	svc, led := newConnectorEnrollService(t)
	// Standard without recovery succeeds.
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	vaultID, _ := newOpaqueVaultID()
	tokenHash := bytes.Repeat([]byte{0x71}, 32)
	putConnectorInvite(t, led, tokenHash)
	req := connectorEnrollRequest(t, phone, hardware, boarding, program.ProtectionTierStandard, nil, connector.Taproot)
	enrollConnectorVault(t, svc, vaultID, tokenHash, req)

	// Advanced with recovery succeeds.
	phone2, _ := btcec.NewPrivateKey()
	hardware2, _ := btcec.NewPrivateKey()
	boarding2, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	vault2, _ := newOpaqueVaultID()
	token2 := bytes.Repeat([]byte{0x72}, 32)
	putConnectorInvite(t, led, token2)
	req2 := connectorEnrollRequest(t, phone2, hardware2, boarding2, program.ProtectionTierAdvanced, recovery, connector.Taproot)
	enrollConnectorVault(t, svc, vault2, token2, req2)
	cred2, err := svc.loadVerifiedCredentialFor(vault2)
	if err != nil || cred2 == nil || len(cred2.RecoveryKey) == 0 {
		t.Fatalf("advanced connector recovery: %v %v", cred2, err)
	}

	// Mismatched origin (connector key != enrolled hardware) is rejected.
	phone3, _ := btcec.NewPrivateKey()
	hardware3, _ := btcec.NewPrivateKey()
	other, _ := btcec.NewPrivateKey()
	boarding3, _ := btcec.NewPrivateKey()
	vault3, _ := newOpaqueVaultID()
	token3 := bytes.Repeat([]byte{0x73}, 32)
	putConnectorInvite(t, led, token3)
	bad := connectorEnrollRequest(t, phone3, hardware3, boarding3, program.ProtectionTierStandard, nil, connector.Taproot)
	bad.ConnectorPub = hex.EncodeToString(other.PubKey().SerializeCompressed())
	if _, err := svc.previewConnectorEnrollmentDescriptor(vault3, bad); err == nil {
		t.Fatal("mismatched connector origin accepted")
	}

	// Legacy enrollment without connector fields still works.
	legacyPhone, _ := btcec.NewPrivateKey()
	legacyOwner, _ := btcec.NewPrivateKey()
	legacyBoarding, _ := btcec.NewPrivateKey()
	legacyVault, _ := newOpaqueVaultID()
	legacyToken := bytes.Repeat([]byte{0x74}, 32)
	putConnectorInvite(t, led, legacyToken)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	legacyReq := RegisterRequest{
		CredentialID:             hex.EncodeToString([]byte{0x41}),
		WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(pass)),
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(legacyPhone.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(legacyOwner.PubKey())),
		VtxoBoardingProgram:      program.VaultBoardV1,
		VaultBoardingBIP340Pub:   hex.EncodeToString(schnorr.SerializePubKey(legacyBoarding.PubKey())),
		ProtectionTier:           program.ProtectionTierStandard,
	}
	selected, _ := program.DefaultSpendingPolicyFor(deployment.NetworkMutinynet)
	legacyReq.SpendingPolicy = selected
	legacyReq.SpendingPolicyDigest, _ = program.SpendingPolicyDigestHexFor(deployment.NetworkMutinynet, selected)
	preview, err := svc.previewVaultBoardEnrollmentDescriptor(legacyVault, legacyReq)
	if err != nil {
		t.Fatal(err)
	}
	legacyReq.DescriptorHash = preview.DescriptorHash
	if err := svc.CreateTenantVault(legacyVault, legacyToken, legacyReq); err != nil {
		t.Fatal(err)
	}
	legacyCred, err := svc.loadVerifiedCredentialFor(legacyVault)
	if err != nil || legacyCred.TemplateVersion != savings.Template {
		t.Fatalf("legacy template changed: %v %v", legacyCred, err)
	}
	if got, _ := svc.Stores.Connector.GetConnectorEnrollment(legacyVault); got != nil {
		t.Fatal("legacy vault gained a connector row")
	}
}

func TestConnectorRecoveryDispatchesToConnectorFamily(t *testing.T) {
	svc, led := newConnectorEnrollService(t)
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	vaultID, _ := newOpaqueVaultID()
	tokenHash := bytes.Repeat([]byte{0x75}, 32)
	putConnectorInvite(t, led, tokenHash)
	req := connectorEnrollRequest(t, phone, hardware, boarding, program.ProtectionTierStandard, nil, connector.Taproot)
	enrollConnectorVault(t, svc, vaultID, tokenHash, req)

	cred, err := svc.loadVerifiedCredentialFor(vaultID)
	if err != nil || cred == nil {
		t.Fatal(err)
	}
	fam, err := svc.transitionFamily(cred)
	if err != nil {
		t.Fatal(err)
	}
	if fam.Savings.Address != cred.SavingsAddress {
		t.Fatal("transition family did not use the connector Savings tree")
	}
	rebuilt, err := svc.rebuildConnectorFamily(cred)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Recovery == nil || rebuilt.Recovery.Savings.Address != cred.SavingsAddress {
		t.Fatal("connector rebuild did not match the stored descriptor")
	}
	if fam.Savings.Address != rebuilt.Recovery.Savings.Address {
		t.Fatal("transition family diverged from the connector recovery family")
	}
	// A legacy rebuild of the same keys must not match: the connector tree
	// replaced the admin leaf.
	childPub, err := svc.keys.enrollmentPublic(vaultID)
	if err != nil {
		t.Fatal(err)
	}
	legacyIn, err := svc.savingsFamilyInput(vaultID, parsedRegisterRequest{
		phone: phone.PubKey(), externalOwner: hardware.PubKey(),
		protectionTier: program.ProtectionTierStandard, spendingPolicy: req.SpendingPolicy,
		phoneDirectP256: mustDecodeHex(t, req.PhoneDirectP256),
	}, childPub, svc.ArkadeCosignerPub)
	if err == nil {
		applySavingsProgram(&legacyIn, savings.Template)
		if _, legacyFam, err := savings.BuildPublicDescriptor(legacyIn, cred.ArkadeCosignerOrigin, cred.ArkadeCosignerVersion); err == nil {
			if legacyFam.Savings.Address == cred.SavingsAddress {
				t.Fatal("legacy tree collided with the connector Savings address")
			}
		}
	}
	// A credential whose stored Savings was swapped fails closed on rebuild.
	tampered := *cred
	tampered.SavingsAddress = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	if _, err := svc.rebuildConnectorFamily(&tampered); err == nil {
		t.Fatal("tampered connector Savings still rebuilt")
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustRandomHex(t *testing.T, n int) string {
	t.Helper()
	s, err := randomHex(n)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestIndependentEnrolledConnectorServesActualStatusDescriptor is the
// independently reproduced enrollment regression: a newly enrolled connector
// vault must serve its ACTUAL connector Savings tree through the status
// descriptor path, not a phantom legacy tree.
func TestIndependentEnrolledConnectorServesActualStatusDescriptor(t *testing.T) {
	svc, led := newConnectorEnrollService(t)
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	vaultID, err := newOpaqueVaultID()
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{0x79}, 32)
	putConnectorInvite(t, led, token)
	req := connectorEnrollRequest(t, phone, hardware, boarding, program.ProtectionTierStandard, nil, connector.Taproot)
	enrollConnectorVault(t, svc, vaultID, token, req)
	cred, err := svc.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, _, err := svc.statusVaultBoardDescriptor(cred, svc.snapshot(vaultID))
	if err != nil {
		t.Fatalf("GET /v1/status cannot serve the newly enrolled connector: %v", err)
	}
	if descriptor.Savings.Savings.Address != cred.SavingsAddress {
		t.Fatal("status reconstructed wrong Savings contract")
	}
}

// TestConnectorEnrolledVaultServesStatusOverHTTP drives the actual GET
// /v1/status handler for a connector vault and checks the served Savings
// contract matches the enrolled credential.
func TestConnectorEnrolledVaultServesStatusOverHTTP(t *testing.T) {
	svc, led := newConnectorEnrollService(t)
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	vaultID, err := newOpaqueVaultID()
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{0x7a}, 32)
	putConnectorInvite(t, led, token)
	req := connectorEnrollRequest(t, phone, hardware, boarding, program.ProtectionTierStandard, nil, connector.Taproot)
	enrollConnectorVault(t, svc, vaultID, token, req)
	cred, err := svc.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		t.Fatal(err)
	}
	response := boundaryHTTPCall(t, testAuthorizer(svc), http.MethodGet, "/v1/status?vault="+vaultID, "", fixture.Origin, "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET /v1/status = %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Status
		VtxoBoardingDescriptorHash string `json:"vtxoBoardingDescriptorHash"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.SavingsAddr != cred.SavingsAddress {
		t.Fatalf("HTTP status Savings %q, want enrolled %q", body.SavingsAddr, cred.SavingsAddress)
	}
	if body.VtxoBoardingDescriptorHash == "" {
		t.Fatal("HTTP status missing boarding descriptor hash")
	}
	if _, err := svc.StatusFor(context.Background(), vaultID); err != nil {
		t.Fatalf("StatusFor connector vault: %v", err)
	}
}

// TestConnectorEnrollmentMainnetMatrix enrolls Standard and Advanced connector
// vaults on mainnet across P2TR, P2WPKH, and native Electrum origins. Mainnet
// is an RC target: coin segments, address encoding, and the full
// preview/status/duplicate contract must hold there, not just on mutinynet.
func TestConnectorEnrollmentMainnetMatrix(t *testing.T) {
	tests := []struct {
		name     string
		tier     string
		kind     connector.Kind
		electrum bool
	}{
		{name: "standard/p2tr/bip86", tier: program.ProtectionTierStandard, kind: connector.Taproot},
		{name: "advanced/p2tr/bip86", tier: program.ProtectionTierAdvanced, kind: connector.Taproot},
		{name: "standard/p2wpkh/bip84", tier: program.ProtectionTierStandard, kind: connector.NativeSegwit},
		{name: "advanced/p2wpkh/bip84", tier: program.ProtectionTierAdvanced, kind: connector.NativeSegwit},
		{name: "standard/p2wpkh/electrum", tier: program.ProtectionTierStandard, kind: connector.NativeSegwit, electrum: true},
		{name: "advanced/p2wpkh/electrum", tier: program.ProtectionTierAdvanced, kind: connector.NativeSegwit, electrum: true},
	}
	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newConnectorFixture(t, deployment.NetworkMainnet)
			phone, _ := btcec.NewPrivateKey()
			hardware, _ := btcec.NewPrivateKey()
			if knownFixtureXOnly(schnorr.SerializePubKey(hardware.PubKey())) {
				t.Skip("fixture key collision, retry")
			}
			boarding, _ := btcec.NewPrivateKey()
			var recovery *btcec.PrivateKey
			if test.tier == program.ProtectionTierAdvanced {
				recovery, _ = btcec.NewPrivateKey()
			}
			vaultID, err := newOpaqueVaultID()
			if err != nil {
				t.Fatal(err)
			}
			token := bytes.Repeat([]byte{byte(0x80 + i)}, 32)
			putConnectorInvite(t, f.led, token)
			req := connectorEnrollRequestForNetwork(t, deployment.NetworkMainnet, phone, hardware, boarding, test.tier, recovery, test.kind, test.electrum)
			req = enrollConnectorVault(t, f.svc, vaultID, token, req)
			cred, err := f.svc.loadVerifiedCredentialFor(vaultID)
			if err != nil || cred == nil {
				t.Fatal(err)
			}
			if cred.TemplateVersion != connector.Template || cred.Network != deployment.NetworkMainnet {
				t.Fatalf("enrolled %+v", cred.TemplateVersion+" / "+cred.Network)
			}
			stored, err := f.svc.Stores.Connector.GetConnectorEnrollment(vaultID)
			if err != nil || stored == nil {
				t.Fatal(err)
			}
			if stored.Type != string(test.kind) || !bytes.Equal(stored.Pub, hardware.PubKey().SerializeCompressed()) {
				t.Fatalf("origin row %+v", stored)
			}
			if test.electrum && (len(stored.Path) != 3 || stored.Path[0] != 0x80000000) {
				t.Fatalf("electrum path %+v", stored.Path)
			}
			if _, _, err := f.svc.statusVaultBoardDescriptor(cred, f.svc.snapshot(vaultID)); err != nil {
				t.Fatalf("mainnet status: %v", err)
			}
			st, ok := f.svc.acceptDuplicateFinish(vaultID, req)
			if !ok || st.VaultID != vaultID {
				t.Fatal("mainnet exact duplicate finish rejected")
			}
		})
	}
}

// TestConnectorEnrollmentSurvivesReopen enrolls legacy and connector vaults,
// reopens the database through LoadVaults, and requires status, duplicate
// finish, and recovery dispatch to keep working on the restarted service.
func TestConnectorEnrollmentSurvivesReopen(t *testing.T) {
	f := newConnectorFixture(t, deployment.NetworkMutinynet)
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	vaultID, err := newOpaqueVaultID()
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{0x81}, 32)
	putConnectorInvite(t, f.led, token)
	req := connectorEnrollRequest(t, phone, hardware, boarding, program.ProtectionTierStandard, nil, connector.Taproot)
	req = enrollConnectorVault(t, f.svc, vaultID, token, req)
	before, _, err := f.svc.statusVaultBoardDescriptor(mustConnectorCred(t, f.svc, vaultID), f.svc.snapshot(vaultID))
	if err != nil {
		t.Fatal(err)
	}

	f.reopen(t)

	st, err := f.svc.StatusFor(context.Background(), vaultID)
	if err != nil || st.SavingsAddr == "" {
		t.Fatalf("status after reopen: %+v %v", st, err)
	}
	cred, err := f.svc.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		t.Fatal(err)
	}
	after, _, err := f.svc.statusVaultBoardDescriptor(cred, f.svc.snapshot(vaultID))
	if err != nil {
		t.Fatalf("descriptor after reopen: %v", err)
	}
	if after.Savings.Savings.Address != before.Savings.Savings.Address || after.Savings.Savings.Address != cred.SavingsAddress {
		t.Fatal("descriptor changed across reopen")
	}
	if dup, ok := f.svc.acceptDuplicateFinish(vaultID, req); !ok || dup.VaultID != vaultID {
		t.Fatal("duplicate finish rejected after reopen")
	}
	fam, err := f.svc.transitionFamily(cred)
	if err != nil || fam.Savings.Address != cred.SavingsAddress {
		t.Fatalf("recovery dispatch after reopen: %v %v", fam, err)
	}
}

func mustConnectorCred(t *testing.T, svc *Service, vaultID string) *policy.Credential {
	t.Helper()
	cred, err := svc.loadVerifiedCredentialFor(vaultID)
	if err != nil || cred == nil {
		t.Fatal(err)
	}
	return cred
}

// TestConnectorDescriptorReconstruction ties the three representations
// together from independent inputs: the library enrollment digest recomputed
// from test-held keys must match the preview descriptor object, and the
// preview hash must equal the combined hash over that digest and the status
// boarding hash.
func TestConnectorDescriptorReconstruction(t *testing.T) {
	svc, led := newConnectorEnrollService(t)
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	vaultID, err := newOpaqueVaultID()
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{0x82}, 32)
	putConnectorInvite(t, led, token)
	req := connectorEnrollRequest(t, phone, hardware, boarding, program.ProtectionTierStandard, nil, connector.Taproot)
	preview, err := svc.previewConnectorEnrollmentDescriptor(vaultID, req)
	if err != nil {
		t.Fatal(err)
	}
	desc, ok := preview.Descriptor.(connectorBoardCompositeDescriptor)
	if !ok {
		t.Fatalf("descriptor type %T", preview.Descriptor)
	}
	childPub, err := svc.keys.enrollmentPublic(vaultID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := svc.parseRegisterRequestIndependent(req)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = svc.applyVaultBoardEnrollmentRequest(parsed, req)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = applyConnectorEnrollmentRequest(parsed, req, svc.runtimeConfig().Network)
	if err != nil {
		t.Fatal(err)
	}
	in, origin, err := svc.connectorFamilyInput(vaultID, parsed, childPub, svc.ArkadeCosignerPub)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := connector.EnrollmentDigest(in, *origin)
	if err != nil {
		t.Fatal(err)
	}
	if digest != desc.Connector.EnrollmentDigest {
		t.Fatal("preview digest does not match independent enrollment digest")
	}
	if desc.Connector.HardwarePub != req.ConnectorPub || desc.Connector.ConnectorType != string(connector.Taproot) {
		t.Fatalf("descriptor origin %+v", desc.Connector)
	}
	kind, err := origin.Kind()
	if err != nil {
		t.Fatal(err)
	}
	wantScript, err := kind.Script(hardware.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	if desc.Connector.ConnectorScript != hex.EncodeToString(wantScript) {
		t.Fatal("descriptor connector script does not match independent derivation")
	}
	req.DescriptorHash = preview.DescriptorHash
	if err := svc.CreateTenantVault(vaultID, token, req); err != nil {
		t.Fatal(err)
	}
	cred := mustConnectorCred(t, svc, vaultID)
	if desc.Connector.SavingsScript != hex.EncodeToString(cred.SavingsScript) || desc.Connector.SavingsAddress != cred.SavingsAddress {
		t.Fatal("descriptor Savings does not match the enrolled credential")
	}
	_, statusHash, err := svc.statusVaultBoardDescriptor(cred, svc.snapshot(vaultID))
	if err != nil {
		t.Fatal(err)
	}
	want, err := hashConnectorBoardComposite(digest, statusHash)
	if err != nil || want != preview.DescriptorHash {
		t.Fatalf("combined hash = %q, want preview %q (%v)", want, preview.DescriptorHash, err)
	}
}

// connectorHardwareInitiatePSBT builds a hardware-claimant initiate transition
// for a connector vault: the Savings input is the enrolled connector tree and
// the destination is its pending tree. The Merkle proof is reassembled from
// the transition family's initiate pairs plus the connector normal leaf using
// public savings helpers.
func connectorHardwareInitiatePSBT(t *testing.T, svc *Service, vaultID string, owner *btcec.PrivateKey) string {
	t.Helper()
	cred, err := svc.loadVerifiedCredentialFor(vaultID)
	if err != nil || cred == nil {
		t.Fatal(err)
	}
	fam, err := svc.transitionFamily(cred)
	if err != nil {
		t.Fatal(err)
	}
	connectorFam, err := svc.rebuildConnectorFamily(cred)
	if err != nil {
		t.Fatal(err)
	}
	roles := []string{"phone", "hardware"}
	var recoveryPub *btcec.PublicKey
	if len(cred.RecoveryKey) > 0 {
		var err error
		recoveryPub, err = btcec.ParsePubKey(cred.RecoveryKey)
		if err != nil {
			t.Fatal(err)
		}
		roles = append(roles, "recovery")
	}
	rolePubs := map[string]*btcec.PublicKey{}
	for _, role := range roles {
		switch role {
		case "phone":
			rolePubs[role], err = btcec.ParsePubKey(cred.PhoneBIP340)
		case "hardware":
			rolePubs[role] = owner.PubKey()
		case "recovery":
			rolePubs[role] = recoveryPub
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	leaves := []txscript.TapLeaf{txscript.NewBaseTapLeaf(connectorFam.Leaf)}
	leafScripts := map[string][]byte{}
	for _, role := range roles {
		pair := fam.Initiate[role]
		script, err := savings.Checksig(rolePubs[role], pair.Vault, pair.Arkade)
		if err != nil {
			t.Fatal(err)
		}
		leafScripts[role] = script
		leaves = append(leaves, txscript.NewBaseTapLeaf(script))
	}
	tree := txscript.AssembleTaprootScriptTree(leaves...)
	target := txscript.NewBaseTapLeaf(leafScripts["hardware"]).TapHash()
	proofIndex, ok := tree.LeafProofIndex[target]
	if !ok {
		t.Fatal("connector initiate proof missing")
	}
	internal, err := savings.ContextInternalKeyTemplate(vaultID, "savings", "", connector.Template)
	if err != nil {
		t.Fatal(err)
	}
	control := tree.LeafMerkleProofs[proofIndex].ToControlBlock(internal)
	controlBytes, err := control.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	prev := wire.NewMsgTx(2)
	prev.AddTxIn(&wire.TxIn{Sequence: wire.MaxTxInSequenceNum})
	prev.AddTxOut(&wire.TxOut{Value: 100_000, PkScript: fam.Savings.PkScript})
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: prev.TxHash(), Index: 0}, Sequence: savings.TransitionSequence})
	tx.AddTxOut(&wire.TxOut{Value: 98_760, PkScript: fam.Pending[savings.FamilyKey("hardware")].PkScript})
	tx.AddTxOut(&wire.TxOut{Value: savings.P2AValueSats, PkScript: mustDecodeHex(t, savings.P2AScriptHex)})
	emulatorPacket, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: fam.InitiateAuth["savings-hardware"]})
	if err != nil {
		t.Fatal(err)
	}
	packetScript, err := (extension.Extension{emulatorPacket}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	tx.AddTxOut(&wire.TxOut{Value: 0, PkScript: packetScript})
	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].WitnessUtxo = prev.TxOut[0]
	packet.Inputs[0].SighashType = txscript.SigHashDefault
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: controlBytes, Script: leafScripts["hardware"], LeafVersion: txscript.BaseLeafVersion,
	}}
	if err := txutils.SetArkPsbtField(packet, 0, arkade.PrevoutTxField, *prev); err != nil {
		t.Fatal(err)
	}
	claimantSig, err := signTapLeafAt(packet, 0, owner, leafScripts["hardware"])
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].TaprootScriptSpendSig = append(packet.Inputs[0].TaprootScriptSpendSig, claimantSig)
	encoded, err := packet.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestConnectorRecoveryTransitionSignsThroughConnectorFamily performs actual
// recovery initiation signing for a connector vault with a hardware-claimant
// packet built against the enrolled connector tree, plus replay and
// wrong-purpose rejection.
func TestConnectorRecoveryTransitionSignsThroughConnectorFamily(t *testing.T) {
	svc, led := newConnectorEnrollService(t)
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	vaultID, err := newOpaqueVaultID()
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{0x83}, 32)
	putConnectorInvite(t, led, token)
	req := connectorEnrollRequest(t, phone, hardware, boarding, program.ProtectionTierStandard, nil, connector.Taproot)
	enrollConnectorVault(t, svc, vaultID, token, req)
	encoded := connectorHardwareInitiatePSBT(t, svc, vaultID, hardware)
	response, err := svc.SignTransition(context.Background(), TransitionRequest{VaultID: vaultID, Purpose: "initiate", PSBT: encoded})
	if err != nil {
		t.Fatalf("connector initiate: %v", err)
	}
	if response.SignedPSBT == "" || response.Replay {
		t.Fatalf("unexpected initiate response: %+v", response)
	}
	signed, err := parsePSBT(response.SignedPSBT)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed.Inputs[0].TaprootScriptSpendSig) != 3 {
		t.Fatalf("initiate signatures = %d, want claimant plus two cosigners", len(signed.Inputs[0].TaprootScriptSpendSig))
	}
	replay, err := svc.SignTransition(context.Background(), TransitionRequest{VaultID: vaultID, Purpose: "initiate", PSBT: encoded})
	if err != nil || !replay.Replay || replay.SignedPSBT != response.SignedPSBT {
		t.Fatalf("initiate replay: %+v %v", replay, err)
	}
	if _, err := svc.SignTransition(context.Background(), TransitionRequest{VaultID: vaultID, Purpose: "clawback", PSBT: encoded}); err == nil {
		t.Fatal("clawback accepted an initiate packet")
	}
}
