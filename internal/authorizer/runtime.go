// Package authorizer assembles the Mutinynet software signing boundary.
// This process is the sole owner of both the VaultCosigner private key and the
// authoritative issuance ledger. It exposes Service policy operations, never
// the policy-agnostic LocalSigner primitive.
package authorizer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/brg444/arkade-vault-server/internal/provider"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Config contains only deployment inputs for the protected authorizer. The
// The VaultCosigner key is a file-backed secret and cannot be supplied through
// environment text or a network signer. Optional token-gated enrollment uses
// a second file-backed secret; explicitly armed open enrollment uses none.
type Config struct {
	Deployment                deployment.Config
	DatabasePath              string
	VaultCosignerKeyFile      string
	ExternalOwnerWalletPubHex string
	EnrollmentTokenFile       string
	EnrollmentWindow          time.Duration
	OpenEnrollment            bool
	MultiTenantEnrollment     bool
	FreshOnly                 bool
	EsploraURL                string
}

// Runtime owns the Service and its SQLite connection for one process lifetime.
type Runtime struct {
	handler http.Handler
	service *provider.Service
	ledger  *policy.Ledger
}

// Handler returns the constrained HTTP API. The underlying Service and its
// policy-agnostic final signer stay private to this package.
func (r *Runtime) Handler() http.Handler {
	if r == nil {
		return http.NotFoundHandler()
	}
	return r.handler
}

// Close releases the authoritative ledger.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	if r.service != nil {
		r.service.WipeSecrets()
	}
	if r.ledger == nil {
		return nil
	}
	return r.ledger.Close()
}

type publisherDialer func(context.Context, string, string) (provider.Broadcaster, error)
type arkadeSignerDialer func(context.Context, string, *btcec.PublicKey, []string, bool) (provider.Signer, provider.PublicEmulatorIdentity, error)

// Open constructs the Mutinynet authorizer and checkpoint-pins its publisher.
func Open(ctx context.Context, cfg Config) (*Runtime, error) {
	return openWithDialers(ctx, cfg, func(ctx context.Context, baseURL, network string) (provider.Broadcaster, error) {
		return provider.DialEsplora(ctx, baseURL, network)
	}, provider.DialPublicEmulator)
}

func openWithDialers(ctx context.Context, cfg Config, dial publisherDialer, dialArkade arkadeSignerDialer) (*Runtime, error) {
	if err := cfg.Deployment.Validate(); err != nil {
		return nil, fmt.Errorf("deployment: %w", err)
	}
	if cfg.Deployment.Network != deployment.NetworkMutinynet {
		return nil, fmt.Errorf("protected authorizer is mutinynet-only")
	}
	if cfg.OpenEnrollment {
		return nil, fmt.Errorf("mutinynet enroll is invite-only")
	}
	cfg.MultiTenantEnrollment = true
	if !filepath.IsAbs(cfg.DatabasePath) || cfg.DatabasePath == "/" || strings.Contains(strings.ToLower(cfg.DatabasePath), "mode=memory") {
		return nil, fmt.Errorf("authoritative database must be an absolute on-disk file path")
	}
	if cfg.EsploraURL == "" {
		return nil, fmt.Errorf("mutinynet esplora url required")
	}
	if dial == nil {
		return nil, fmt.Errorf("publisher dialer required")
	}
	if dialArkade == nil {
		return nil, fmt.Errorf("public arkade emulator dialer required")
	}

	if cfg.FreshOnly {
		if err := policy.RefuseLegacyDatabase(cfg.DatabasePath); err != nil {
			return nil, fmt.Errorf("fresh-only: %w", err)
		}
	}
	vaultCosignerKey, err := LoadVaultCosignerKey(cfg.VaultCosignerKeyFile)
	if err != nil {
		return nil, err
	}
	arkadeBase, err := parseCanonicalCompressedPub("ArkadeCosigner", deployment.MutinynetArkadeCosignerPubHex)
	if err != nil {
		return nil, err
	}
	ledger, err := policy.OpenLedger(cfg.DatabasePath, nil)
	if err != nil {
		return nil, fmt.Errorf("authoritative ledger: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = ledger.Close()
		}
	}()
	credentialIntegrityKey, err := deriveCredentialIntegrityKey(vaultCosignerKey)
	if err != nil {
		return nil, err
	}
	if err := ledger.SetIntegrityKey(credentialIntegrityKey); err != nil {
		zero(credentialIntegrityKey)
		return nil, err
	}
	if err := ledger.BackupSQLiteIfAbsent(cfg.DatabasePath + ".pre-v4"); err != nil {
		zero(credentialIntegrityKey)
		return nil, fmt.Errorf("pre-v4 backup: %w", err)
	}
	if err := ledger.MigrateLegacySingleton(credentialIntegrityKey); err != nil {
		zero(credentialIntegrityKey)
		return nil, fmt.Errorf("multi-tenant migration: %w", err)
	}
	if err := ledger.BackupGenerationIfAbsent(cfg.DatabasePath+".pre-v5", policy.BackupGenerationPreV5); err != nil {
		zero(credentialIntegrityKey)
		return nil, fmt.Errorf("pre-v5 backup: %w", err)
	}
	if err := ledger.MigrateIssuanceIntegrity(credentialIntegrityKey); err != nil {
		zero(credentialIntegrityKey)
		return nil, fmt.Errorf("issuance integrity migration: %w", err)
	}
	if err := ledger.MigrateRecoverySessions(); err != nil {
		zero(credentialIntegrityKey)
		return nil, fmt.Errorf("recovery session migration: %w", err)
	}

	persisted, err := ledger.GetCredential()
	if err != nil {
		zero(credentialIntegrityKey)
		return nil, err
	}
	if persisted != nil {
		rec, cred, err := ledger.LoadVerifiedVault(persisted.VaultID, credentialIntegrityKey)
		if err != nil {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("stored v4 vault: %w", err)
		}
		if rec == nil || cred == nil {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("v4 vault row missing after migration; restore %s.pre-v4 or a verified backup", cfg.DatabasePath)
		}
		if rec.OperationalAddress != persisted.OperationalAddress ||
			!bytes.Equal(rec.OperationalScript, persisted.OperationalScript) ||
			!bytes.Equal(rec.SavingsScript, persisted.SavingsScript) ||
			!bytes.Equal(rec.VaultCosignerBase, persisted.VaultCosignerBase) ||
			rec.CosignerMode != policy.CosignerModeLegacyDirectV0 {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("v4 migration changed the first vault descriptor")
		}
		if !bytes.Equal(cred.CredentialID, persisted.ID) {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("v4 migration changed the first vault credential id")
		}
		if err := policy.VerifyVaultCosignerPub(vaultCosignerKey, *rec); err != nil {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("stored vault cosigner: %w", err)
		}
	}
	allowActiveDeprecated := false
	var externalOwner, recovery *btcec.PublicKey
	if persisted != nil {
		if err := policy.VerifyCredentialIntegrity(persisted, credentialIntegrityKey); err != nil {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("stored credential integrity: %w; restore a trusted backup or perform an explicit migration; do not delete the authoritative database", err)
		}
		arkadeBase, err = btcec.ParsePubKey(persisted.ArkadeCosignerBase)
		if err != nil || !bytes.Equal(arkadeBase.SerializeCompressed(), persisted.ArkadeCosignerBase) {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("stored public arkade emulator base key is invalid")
		}
		externalOwner, err = btcec.ParsePubKey(persisted.ExternalOwnerWallet)
		if err != nil || !bytes.Equal(externalOwner.SerializeCompressed(), persisted.ExternalOwnerWallet) {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("stored ExternalOwnerWallet is invalid")
		}
		if len(persisted.RecoveryKey) > 0 {
			recovery, err = btcec.ParsePubKey(persisted.RecoveryKey)
			if err != nil || !bytes.Equal(recovery.SerializeCompressed(), persisted.RecoveryKey) {
				zero(credentialIntegrityKey)
				return nil, fmt.Errorf("stored RecoveryKey is invalid")
			}
		}
		if cfg.ExternalOwnerWalletPubHex != "" {
			configured, parseErr := parseDeploymentPub("ExternalOwnerWallet", cfg.ExternalOwnerWalletPubHex)
			if parseErr != nil || !sameXOnly(configured, externalOwner) {
				zero(credentialIntegrityKey)
				return nil, fmt.Errorf("configured ExternalOwnerWallet does not match the persisted vault")
			}
		}
		allowActiveDeprecated = true
	} else if cfg.ExternalOwnerWalletPubHex != "" {
		externalOwner, err = parseDeploymentPub("ExternalOwnerWallet", cfg.ExternalOwnerWalletPubHex)
		if err != nil {
			zero(credentialIntegrityKey)
			return nil, err
		}
	}
	roles := map[string]*btcec.PublicKey{
		"VaultCosigner":  vaultCosignerKey.PubKey(),
		"ArkadeCosigner": arkadeBase,
	}
	if externalOwner != nil {
		roles["ExternalOwnerWallet"] = externalOwner
	}
	if err := requirePairwiseIndependent(roles); err != nil {
		zero(credentialIntegrityKey)
		return nil, err
	}

	var enrollmentTokenHash []byte
	if persisted == nil {
		if cfg.OpenEnrollment && cfg.EnrollmentTokenFile != "" {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("open enrollment and enrollment token are mutually exclusive")
		}
		if !cfg.OpenEnrollment && cfg.EnrollmentTokenFile == "" {
			zero(credentialIntegrityKey)
			return nil, fmt.Errorf("unenrolled authorizer requires explicit open enrollment or an enrollment token file")
		}
		if !cfg.OpenEnrollment {
			token, err := readBoundedSecret(cfg.EnrollmentTokenFile, "enrollment token", 43, 43)
			if err != nil {
				zero(credentialIntegrityKey)
				return nil, err
			}
			enrollmentTokenHash, err = provider.HashEnrollmentToken(string(token))
			zero(token)
			if err != nil {
				zero(credentialIntegrityKey)
				return nil, fmt.Errorf("enrollment token: %w", err)
			}
		}
	}

	arkadeSigner, arkadeIdentity, err := dialArkade(
		ctx,
		deployment.MutinynetArkadeCosignerOrigin,
		arkadeBase,
		[]string{deployment.MutinynetArkadeCosignerVersion},
		allowActiveDeprecated,
	)
	if err != nil {
		zero(enrollmentTokenHash)
		zero(credentialIntegrityKey)
		return nil, err
	}
	svc := provider.New(provider.Deps{
		Ledger:                ledger,
		Deployment:            cfg.Deployment,
		IntegrityKey:          credentialIntegrityKey,
		MasterIKM:             vaultCosignerKey,
		ExternalOwner:         externalOwner,
		VaultCosignerPub:      vaultCosignerKey.PubKey(),
		ArkadeCosignerPub:     arkadeIdentity.BasePub,
		ArkadeCosignerOrigin:  arkadeIdentity.Origin,
		ArkadeCosignerVersion: arkadeIdentity.Version,
		ArkadeSigner:          arkadeSigner,
		EnrollmentTokenHash:   enrollmentTokenHash,
		OpenEnrollment:        cfg.OpenEnrollment,
		MultiTenantEnrollment: cfg.MultiTenantEnrollment,
	})
	if persisted == nil {
		window := cfg.EnrollmentWindow
		if window == 0 {
			window = 30 * time.Minute
		}
		if window < time.Minute || window > 24*time.Hour {
			zero(svc.EnrollmentTokenHash)
			zero(svc.CredentialIntegrityKey)
			return nil, fmt.Errorf("enrollment window must be between 1 minute and 24 hours")
		}
		svc.EnrollmentDeadline = time.Now().Add(window)
	}
	defer func() {
		if closeOnError {
			zero(svc.EnrollmentTokenHash)
			zero(svc.CredentialIntegrityKey)
		}
	}()
	// Authenticate and rebuild persisted state before contacting the external
	// publisher. The public cosigner was contacted only after the bootstrap
	// secret or persisted credential MAC was validated above.
	if err := svc.LoadVaults(); err != nil {
		return nil, err
	}

	publisher, err := dial(ctx, cfg.EsploraURL, cfg.Deployment.Network)
	if err != nil {
		return nil, fmt.Errorf("publisher: %w", err)
	}
	if publisher == nil {
		return nil, fmt.Errorf("publisher not configured")
	}
	svc.Broadcaster = publisher

	closeOnError = false
	return &Runtime{handler: provider.AuthorizerHandler(svc), service: svc, ledger: ledger}, nil
}

func parseCanonicalCompressedPub(role, encoded string) (*btcec.PublicKey, error) {
	if len(encoded) != 66 || encoded != strings.ToLower(encoded) {
		return nil, fmt.Errorf("%s pubkey must be canonical 33-byte compressed lowercase hex", role)
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 33 || (raw[0] != 0x02 && raw[0] != 0x03) {
		return nil, fmt.Errorf("%s pubkey must be canonical 33-byte compressed lowercase hex", role)
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil || !bytes.Equal(pub.SerializeCompressed(), raw) {
		return nil, fmt.Errorf("%s pubkey is invalid", role)
	}
	return pub, nil
}

const (
	credentialIntegrityHKDFSalt = "arkade-2fa-vault/vault-cosigner-scalar-hkdf-salt/v3"
	credentialIntegrityHKDFInfo = "arkade-2fa-vault/credential-integrity-key/v3"
)

// deriveCredentialIntegrityKey implements the one-block RFC 5869
// HKDF-SHA256 extract+expand needed for the 32-byte record MAC key. The
// VaultCosigner scalar is input keying material, never the HMAC key directly.
func deriveCredentialIntegrityKey(vaultCosignerKey *btcec.PrivateKey) ([]byte, error) {
	if vaultCosignerKey == nil {
		return nil, fmt.Errorf("VaultCosigner key required for credential integrity")
	}
	ikm := vaultCosignerKey.Serialize()
	defer zero(ikm)
	extract := hmac.New(sha256.New, []byte(credentialIntegrityHKDFSalt))
	_, _ = extract.Write(ikm)
	prk := extract.Sum(nil)
	defer zero(prk)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write([]byte(credentialIntegrityHKDFInfo))
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil), nil
}

// LoadVaultCosignerKey reads exactly one strict secp256k1 scalar from a bounded
// hex file. btcec.PrivKeyFromBytes is called only after rejecting zero and
// every value greater than or equal to the curve order.
func LoadVaultCosignerKey(path string) (*btcec.PrivateKey, error) {
	encoded, err := readBoundedSecret(path, "VaultCosigner key", 64, 64)
	if err != nil {
		return nil, err
	}
	defer zero(encoded)
	raw := make([]byte, 32)
	if _, err := hex.Decode(raw, encoded); err != nil {
		zero(raw)
		return nil, fmt.Errorf("VaultCosigner key must be exactly 32-byte hex")
	}
	defer zero(raw)
	scalar := new(big.Int).SetBytes(raw)
	if scalar.Sign() <= 0 || scalar.Cmp(btcec.S256().N) >= 0 {
		return nil, fmt.Errorf("VaultCosigner key scalar must be in [1, secp256k1.N-1]")
	}
	priv, _ := btcec.PrivKeyFromBytes(raw)
	if role, known := knownPublicFixtureRole(priv.PubKey()); known {
		return nil, fmt.Errorf("public %s fixture VaultCosigner key is forbidden", role)
	}
	return priv, nil
}

func parseDeploymentPub(role, encoded string) (*btcec.PublicKey, error) {
	pub, err := parseCanonicalCompressedPub(role, encoded)
	if err != nil {
		return nil, err
	}
	if fixtureRole, known := knownPublicFixtureRole(pub); known {
		return nil, fmt.Errorf("public %s fixture is forbidden for %s", fixtureRole, role)
	}
	return pub, nil
}

func knownPublicFixtureRole(pub *btcec.PublicKey) (string, bool) {
	for role, encoded := range map[string]string{
		"RecoveryKey":         program.UnsafeGeneratorG,
		"ExternalOwnerWallet": program.UnsafeGenerator2G,
	} {
		fixturePub, err := parseCanonicalCompressedPub(role+" fixture", encoded)
		if err != nil {
			continue
		}
		if sameXOnly(pub, fixturePub) {
			return role, true
		}
	}
	return "", false
}

func requirePairwiseIndependent(keys map[string]*btcec.PublicKey) error {
	for leftName, left := range keys {
		if left == nil {
			return fmt.Errorf("%s key is required", leftName)
		}
		for rightName, right := range keys {
			if leftName >= rightName {
				continue
			}
			if sameXOnly(left, right) {
				return fmt.Errorf("%s and %s keys must be x-only independent", leftName, rightName)
			}
		}
	}
	return nil
}

func sameXOnly(a, b *btcec.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(schnorr.SerializePubKey(a), schnorr.SerializePubKey(b))
}

func readBoundedSecret(path, name string, min, max int64) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%s file required", name)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s file: %w", name, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s file: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", name)
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+2))
	if err != nil {
		return nil, fmt.Errorf("%s file: %w", name, err)
	}
	if int64(len(raw)) > max+1 {
		zero(raw)
		return nil, fmt.Errorf("%s file is too large", name)
	}
	secret := raw
	if len(secret) > 0 && secret[len(secret)-1] == '\n' {
		secret = secret[:len(secret)-1]
	}
	if int64(len(secret)) < min || int64(len(secret)) > max {
		zero(raw)
		return nil, fmt.Errorf("%s must contain %d..%d bytes", name, min, max)
	}
	out := append([]byte(nil), secret...)
	zero(raw)
	return out, nil
}

func zero(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}
