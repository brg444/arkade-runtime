package authorizer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/application"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

type stubPublisher struct{}

func (stubPublisher) Broadcast(context.Context, []byte) (string, error) {
	return "", nil
}

func (stubPublisher) Lookup(context.Context, string) (int64, bool, error) {
	return 0, false, nil
}

type stubEmulatorSigner struct{}

func (stubEmulatorSigner) Sign(context.Context, *psbt.Packet) (*psbt.Packet, error) {
	return nil, errors.New("stub public signer must not be called")
}

func TestLoadVaultCosignerKeyRejectsNormalizedAndOutOfRangeScalars(t *testing.T) {
	order := btcec.S256().N
	orderMinusOne := new(big.Int).Sub(new(big.Int).Set(order), big.NewInt(1))
	orderPlusOne := new(big.Int).Add(new(big.Int).Set(order), big.NewInt(1))
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "zero", raw: make([]byte, 32)},
		{name: "curve order", raw: order.FillBytes(make([]byte, 32))},
		{name: "curve order plus one", raw: orderPlusOne.FillBytes(make([]byte, 32))},
		{name: "known generator fixture", raw: append(make([]byte, 31), 1)},
		{name: "negated generator fixture", raw: orderMinusOne.FillBytes(make([]byte, 32))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vault-cosigner-key")
			if err := os.WriteFile(path, []byte(hex.EncodeToString(test.raw)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadVaultCosignerKey(path); err == nil {
				t.Fatal("unsafe VaultCosigner scalar accepted")
			}
		})
	}

	valid, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vault-cosigner-key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(valid.Serialize())), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadVaultCosignerKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.PubKey().IsEqual(valid.PubKey()) {
		t.Fatal("loaded VaultCosigner key changed")
	}
	overlong := filepath.Join(t.TempDir(), "vault-cosigner-key")
	if err := os.WriteFile(overlong, []byte(hex.EncodeToString(valid.Serialize())+"  ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVaultCosignerKey(overlong); err == nil {
		t.Fatal("overlong file with a valid key prefix was accepted")
	}
}

func TestCredentialIntegrityKeyUsesDomainSeparatedHKDF(t *testing.T) {
	first, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	a, err := deriveCredentialIntegrityKey(first)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(a)
	b, err := deriveCredentialIntegrityKey(first)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(b)
	c, err := deriveCredentialIntegrityKey(second)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(c)
	if len(a) != 32 || !bytes.Equal(a, b) {
		t.Fatal("credential integrity derivation is not deterministic")
	}
	if bytes.Equal(a, first.Serialize()) {
		t.Fatal("provider scalar was used directly as the MAC key")
	}
	if bytes.Equal(a, c) {
		t.Fatal("distinct provider scalars derived the same MAC key")
	}
}

func TestDeploymentKeyRejectsFixtureEncodings(t *testing.T) {
	fixtureRaw, err := hex.DecodeString(fixture.RecoveryKeyPubHex)
	if err != nil {
		t.Fatal(err)
	}
	fixturePub, err := btcec.ParsePubKey(fixtureRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoded := range []string{
		fixture.RecoveryKeyPubHex,
		strings.ToUpper(fixture.RecoveryKeyPubHex),
		hex.EncodeToString(negatePub(t, fixturePub).SerializeCompressed()),
		hex.EncodeToString(fixturePub.SerializeUncompressed()),
	} {
		if _, err := parseDeploymentPub("RecoveryKey", encoded); err == nil {
			t.Fatalf("unsafe RecoveryKey accepted: %s", encoded)
		}
	}
}

func negatePub(t *testing.T, pub *btcec.PublicKey) *btcec.PublicKey {
	t.Helper()
	raw := append([]byte(nil), pub.SerializeCompressed()...)
	raw[0] ^= 1
	negated, err := btcec.ParsePubKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return negated
}

func TestRuntimeOwnsKeyAndLedgerAndDropsEnrollmentSecret(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "test-gateway-secret")
	dir := t.TempDir()
	vaultCosignerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	externalOwnerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recoveryKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	_ = recoveryKey
	vaultCosignerPath := filepath.Join(dir, "vault-cosigner-key")
	if err := os.WriteFile(vaultCosignerPath, []byte(hex.EncodeToString(vaultCosignerKey.Serialize())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6d}, 32))
	tokenPath := filepath.Join(dir, "enrollment-token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Deployment: deployment.Config{
			ClientOrigin: "https://vault.example.com", RPID: "vault.example.com",
			Network: deployment.NetworkMutinynet, OperationalCSVBlocks: 4032, SavingsCSVBlocks: 288,
		},
		DatabasePath:              filepath.Join(dir, "vault.sqlite"),
		VaultCosignerKeyFile:      vaultCosignerPath,
		ExternalOwnerWalletPubHex: hex.EncodeToString(externalOwnerKey.PubKey().SerializeCompressed()),
		EsploraURL:                "https://mempool.mutinynet.arkade.sh/api",
	}
	dials := 0
	dial := func(_ context.Context, baseURL, network string) (application.Broadcaster, error) {
		dials++
		if baseURL != cfg.EsploraURL || network != deployment.NetworkMutinynet {
			t.Fatalf("publisher identity = %q, %q", baseURL, network)
		}
		return stubPublisher{}, nil
	}
	emulatorDials := 0
	emulatorDial := func(_ context.Context, origin string, expected *btcec.PublicKey, versions []string, allowDeprecated bool) (application.Signer, application.PublicEmulatorIdentity, error) {
		emulatorDials++
		if origin != deployment.MutinynetArkadeCosignerOrigin ||
			expected == nil || hex.EncodeToString(expected.SerializeCompressed()) != deployment.MutinynetArkadeCosignerPubHex ||
			len(versions) != 1 || versions[0] != deployment.MutinynetArkadeCosignerVersion {
			t.Fatalf("public emulator pin = %q %x %v", origin, expected.SerializeCompressed(), versions)
		}
		if allowDeprecated != (emulatorDials > 1) {
			t.Fatalf("public emulator deprecated-key allowance on dial %d = %v", emulatorDials, allowDeprecated)
		}
		return stubEmulatorSigner{}, application.PublicEmulatorIdentity{
			Origin: origin, Version: versions[0], BasePub: expected,
		}, nil
	}

	if _, err := openWithDialers(context.Background(), cfg, dial, emulatorDial); err == nil || !strings.Contains(err.Error(), "enrollment token file") {
		t.Fatalf("fresh ledger without enrollment secret: %v", err)
	}
	if dials != 0 || emulatorDials != 0 {
		t.Fatal("external service contacted before fresh-ledger bootstrap validation")
	}

	cfg.EnrollmentTokenFile = tokenPath
	runtime, err := openWithDialers(context.Background(), cfg, dial, emulatorDial)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.service.HasVaultSigner() {
		t.Fatal("protected runtime installed the master scalar as VaultSigner")
	}
	if runtime.service.EnrollmentTokenLen() != 32 {
		t.Fatal("fresh runtime did not load the enrollment authorization hash")
	}
	if len(runtime.service.IntegrityKeyCopy()) != 32 {
		t.Fatal("fresh runtime did not derive a credential integrity key")
	}
	passkey, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	err = runtime.service.RegisterWithBootstrap(application.RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("mutinynet-credential")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passkey)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.service.EnrollmentTokenLen() != 0 {
		t.Fatal("successful enrollment retained the one-time authorization hash")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if len(runtime.service.IntegrityKeyCopy()) != 0 {
		t.Fatal("runtime close did not release credential integrity key")
	}

	// Empty boot seals issuance and now lands on schema 5 with no .pre-v5.
	// Restarting a singleton credential without that snapshot must fail closed.
	// Fresh-tenant reopen is TestFreshOnlyReopenAfterEmptyBootAndTenantEnroll.
	cfg.EnrollmentTokenFile = filepath.Join(dir, "already-removed-token")
	if _, err := openWithDialers(context.Background(), cfg, dial, emulatorDial); err == nil ||
		!strings.Contains(err.Error(), "already advanced") {
		t.Fatalf("singleton restart without pre-v5: %v", err)
	}
}

func TestRuntimeRequiresGatewaySecret(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "")
	dir := t.TempDir()
	vaultCosignerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	vaultCosignerPath := filepath.Join(dir, "vault-cosigner-key")
	if err := os.WriteFile(vaultCosignerPath, []byte(hex.EncodeToString(vaultCosignerKey.Serialize())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Deployment: deployment.Config{
			ClientOrigin: "https://vault.example.com", RPID: "vault.example.com",
			Network: deployment.NetworkMutinynet, OperationalCSVBlocks: 4032, SavingsCSVBlocks: 288,
		},
		DatabasePath:         filepath.Join(dir, "vault.sqlite"),
		VaultCosignerKeyFile: vaultCosignerPath,
		EnrollmentTokenFile:  filepath.Join(dir, "enrollment-token"),
		EsploraURL:           "https://mempool.mutinynet.arkade.sh/api",
	}
	_, err = openWithDialers(context.Background(), cfg,
		func(context.Context, string, string) (application.Broadcaster, error) { return stubPublisher{}, nil },
		func(_ context.Context, origin string, expected *btcec.PublicKey, versions []string, _ bool) (application.Signer, application.PublicEmulatorIdentity, error) {
			return stubEmulatorSigner{}, application.PublicEmulatorIdentity{Origin: origin, Version: versions[0], BasePub: expected}, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "VAULT_GATEWAY_SECRET") {
		t.Fatalf("missing gateway secret: %v", err)
	}
}

func TestMutinynetRejectsOpenEnrollment(t *testing.T) {
	dir := t.TempDir()
	vaultCosignerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	vaultCosignerPath := filepath.Join(dir, "vault-cosigner-key")
	if err := os.WriteFile(vaultCosignerPath, []byte(hex.EncodeToString(vaultCosignerKey.Serialize())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Deployment: deployment.Config{
			ClientOrigin: "https://portable.example.com", RPID: "portable.example.com",
			Network: deployment.NetworkMutinynet, OperationalCSVBlocks: 4032, SavingsCSVBlocks: 288,
		},
		DatabasePath:         filepath.Join(dir, "vault.sqlite"),
		VaultCosignerKeyFile: vaultCosignerPath,
		OpenEnrollment:       true,
		EsploraURL:           "https://mempool.mutinynet.arkade.sh/api",
	}
	_, err = openWithDialers(context.Background(), cfg,
		func(context.Context, string, string) (application.Broadcaster, error) { return stubPublisher{}, nil },
		func(_ context.Context, origin string, expected *btcec.PublicKey, versions []string, _ bool) (application.Signer, application.PublicEmulatorIdentity, error) {
			return stubEmulatorSigner{}, application.PublicEmulatorIdentity{Origin: origin, Version: versions[0], BasePub: expected}, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "invite-only") {
		t.Fatalf("open enrollment: %v", err)
	}
}
