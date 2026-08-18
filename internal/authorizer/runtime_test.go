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
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/provider"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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
	dial := func(_ context.Context, baseURL, network string) (provider.Broadcaster, error) {
		dials++
		if baseURL != cfg.EsploraURL || network != deployment.NetworkMutinynet {
			t.Fatalf("publisher identity = %q, %q", baseURL, network)
		}
		return stubPublisher{}, nil
	}
	emulatorDials := 0
	emulatorDial := func(_ context.Context, origin string, expected *btcec.PublicKey, versions []string, allowDeprecated bool) (provider.Signer, provider.PublicEmulatorIdentity, error) {
		emulatorDials++
		if origin != deployment.MutinynetArkadeCosignerOrigin ||
			expected == nil || hex.EncodeToString(expected.SerializeCompressed()) != deployment.MutinynetArkadeCosignerPubHex ||
			len(versions) != 1 || versions[0] != deployment.MutinynetArkadeCosignerVersion {
			t.Fatalf("public emulator pin = %q %x %v", origin, expected.SerializeCompressed(), versions)
		}
		if allowDeprecated != (emulatorDials > 1) {
			t.Fatalf("public emulator deprecated-key allowance on dial %d = %v", emulatorDials, allowDeprecated)
		}
		return stubEmulatorSigner{}, provider.PublicEmulatorIdentity{
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
	if _, ok := runtime.service.VaultSigner.(provider.LocalSigner); !ok {
		t.Fatalf("protected runtime signer = %T, want local policy-final signer", runtime.service.VaultSigner)
	}
	if len(runtime.service.EnrollmentTokenHash) != 32 {
		t.Fatal("fresh runtime did not load the enrollment authorization hash")
	}
	if len(runtime.service.CredentialIntegrityKey) != 32 {
		t.Fatal("fresh runtime did not derive a credential integrity key")
	}
	passkey, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	err = runtime.service.RegisterWithBootstrap(provider.RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("mutinynet-credential")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passkey)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.service.EnrollmentTokenHash) != 0 {
		t.Fatal("successful enrollment retained the one-time authorization hash")
	}
	integrityAlias := runtime.service.CredentialIntegrityKey
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if len(runtime.service.CredentialIntegrityKey) != 0 || !bytes.Equal(integrityAlias, make([]byte, 32)) {
		t.Fatal("runtime close did not zero and release credential integrity key")
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

func TestPortableOpenEnrollmentLetsFirstClaimantChooseImmutablePublicRoles(t *testing.T) {
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
	dial := func(context.Context, string, string) (provider.Broadcaster, error) {
		return stubPublisher{}, nil
	}
	emulatorDial := func(_ context.Context, origin string, expected *btcec.PublicKey, versions []string, _ bool) (provider.Signer, provider.PublicEmulatorIdentity, error) {
		return stubEmulatorSigner{}, provider.PublicEmulatorIdentity{Origin: origin, Version: versions[0], BasePub: expected}, nil
	}
	runtime, err := openWithDialers(context.Background(), cfg, dial, emulatorDial)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.service.ExternalOwnerWallet != nil || runtime.service.RecoveryKey != nil {
		t.Fatal("fresh portable runtime preselected claimant public keys")
	}
	initial, err := runtime.service.Status(context.Background())
	if err != nil || initial.EnrollmentMode != "open" || initial.EnrollmentExpiresAt == "" {
		t.Fatalf("open enrollment status = %+v, %v", initial, err)
	}
	runtime.service.EnrollmentNow = func() time.Time { return runtime.service.EnrollmentDeadline }
	expired, err := runtime.service.Status(context.Background())
	if err != nil || expired.EnrollmentMode != "expired" {
		t.Fatalf("expired enrollment status = %+v, %v", expired, err)
	}
	runtime.service.EnrollmentNow = nil
	owner, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	_ = recovery
	phone, _ := btcec.NewPrivateKey()
	passkey, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	req := provider.RegisterRequest{
		CredentialID:             hex.EncodeToString([]byte("portable-credential")),
		WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(passkey)),
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(phone.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	}
	if err := runtime.service.RegisterWithBootstrap(req, ""); err != nil {
		t.Fatal(err)
	}
	status, err := runtime.service.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Enrolled || status.EnrollmentMode != "closed" || status.PasskeyLoginAvailable ||
		status.ExternalOwnerWalletPub[2:] != req.ExternalOwnerWalletXOnly {
		t.Fatalf("portable enrollment status = %+v", status)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}

	// Persisted public roles were committed in-process above. Restarting this
	// sealed v5 singleton without a historical .pre-v5 must fail closed.
	if _, err := openWithDialers(context.Background(), cfg, dial, emulatorDial); err == nil ||
		!strings.Contains(err.Error(), "already advanced") {
		t.Fatalf("singleton restart without pre-v5: %v", err)
	}
}
