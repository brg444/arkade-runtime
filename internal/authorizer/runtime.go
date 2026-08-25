// Package authorizer assembles the protected software signing boundary.
// This process is the sole owner of both the VaultCosigner private key and the
// authoritative policy ledger. It exposes Service policy operations, never
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
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/brg444/arkade-vault-server/internal/application"
	"github.com/brg444/arkade-vault-server/internal/contractpack"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	httpapi "github.com/brg444/arkade-vault-server/internal/iface/http"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/profile/arkadevaultv1"
	"github.com/brg444/arkade-vault-server/internal/profile/arkadevaultv2"
	"github.com/brg444/arkade-vault-server/internal/program"
	arkaderuntime "github.com/brg444/arkade-vault-server/internal/runtime"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Config contains only deployment inputs for the protected authorizer. The
// VaultCosigner key and each operator-provisioned enrollment token are file-backed secrets; they
// cannot be supplied through environment text or a network signer.
type Config struct {
	Deployment           deployment.Config
	DatabasePath         string
	PolicySequencePath   string
	VaultCosignerKeyFile string
	EnrollmentTokenFile  string
	EnrollmentWindow     time.Duration
}

// Runtime owns the Service and its SQLite connection for one process lifetime.
type Runtime struct {
	host    *arkaderuntime.Host
	service *application.Service
	ledger  *policy.Ledger
}

// Handler returns the constrained HTTP API. The underlying Service and its
// policy-agnostic final signer stay private to this package.
func (r *Runtime) Handler() http.Handler {
	if r == nil || r.host == nil {
		return http.NotFoundHandler()
	}
	return r.host.Handler()
}

// Close releases the authoritative ledger.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	if r.host != nil {
		return r.host.Close()
	}
	if r.service != nil {
		r.service.WipeSecrets()
	}
	if r.ledger == nil {
		return nil
	}
	return r.ledger.Close()
}

type arkadeSignerDialer func(context.Context, string, *btcec.PublicKey, []string, bool) (application.Signer, application.PublicEmulatorIdentity, error)

// Open constructs the Mutinynet authorizer and pins its external signing
// identities before it serves traffic.
func Open(ctx context.Context, cfg Config) (*Runtime, error) {
	return open(ctx, cfg, false)
}

// OpenVaultBoardV2 is the explicit fresh Mutinynet v2 release gate. Existing
// Open callers remain on the byte-compatible v1 schema and profile.
func OpenVaultBoardV2(ctx context.Context, cfg Config) (*Runtime, error) {
	return open(ctx, cfg, true)
}

func open(ctx context.Context, cfg Config, boardV2 bool) (*Runtime, error) {
	rt, err := openWithArkadeDialerMode(ctx, cfg, application.DialPublicEmulator, boardV2)
	if err != nil {
		return nil, err
	}
	resolver, err := application.DialArkResolver(ctx, cfg.Deployment.Network)
	if err != nil {
		_ = rt.Close()
		return nil, fmt.Errorf("required Arkade resolver: %w", err)
	}
	rt.service.ArkResolver = resolver
	if err := rt.host.Ready(ctx); err != nil {
		_ = rt.Close()
		return nil, fmt.Errorf("authorizer readiness: %w", err)
	}
	return rt, nil
}

func openWithArkadeDialer(ctx context.Context, cfg Config, dialArkade arkadeSignerDialer) (*Runtime, error) {
	return openWithArkadeDialerMode(ctx, cfg, dialArkade, false)
}

func openWithArkadeDialerMode(ctx context.Context, cfg Config, dialArkade arkadeSignerDialer, boardV2 bool) (*Runtime, error) {
	if err := cfg.Deployment.Validate(); err != nil {
		return nil, fmt.Errorf("deployment: %w", err)
	}
	if cfg.Deployment.Network != deployment.NetworkMutinynet {
		return nil, fmt.Errorf("protected authorizer is mutinynet-only")
	}
	if strings.TrimSpace(os.Getenv("VAULT_GATEWAY_SECRET")) == "" {
		return nil, fmt.Errorf("VAULT_GATEWAY_SECRET is required")
	}
	if !filepath.IsAbs(cfg.DatabasePath) || cfg.DatabasePath == "/" || strings.Contains(strings.ToLower(cfg.DatabasePath), "mode=memory") {
		return nil, fmt.Errorf("authoritative database must be an absolute on-disk file path")
	}
	if !filepath.IsAbs(cfg.PolicySequencePath) || cfg.PolicySequencePath == "/" || cfg.PolicySequencePath == cfg.DatabasePath {
		return nil, fmt.Errorf("policy sequence must be a distinct absolute on-disk file path")
	}
	if dialArkade == nil {
		return nil, fmt.Errorf("public arkade emulator dialer required")
	}
	if err := contractpack.Validate(); err != nil {
		return nil, fmt.Errorf("release Contract Pack: %w", err)
	}

	vaultCosignerKey, err := LoadVaultCosignerKey(cfg.VaultCosignerKeyFile)
	if err != nil {
		return nil, err
	}
	keyOwnedByService := false
	defer func() {
		if !keyOwnedByService {
			wipePrivateKey(vaultCosignerKey)
		}
	}()
	arkadeBase, err := parseCanonicalCompressedPub("ArkadeCosigner", deployment.MutinynetArkadeCosignerPubHex)
	if err != nil {
		return nil, err
	}
	var ledger *policy.Ledger
	if boardV2 {
		ledger, err = policy.OpenMutinynetVaultBoardV2Ledger(cfg.DatabasePath, nil)
	} else {
		ledger, err = policy.OpenMainnetLedger(cfg.DatabasePath, nil)
	}
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
	mono, err := policy.OpenMonotonic(cfg.PolicySequencePath, credentialIntegrityKey)
	if err != nil {
		zero(credentialIntegrityKey)
		return nil, fmt.Errorf("monotonic counter: %w", err)
	}
	if err := ledger.AttachMonotonic(mono); err != nil {
		zero(credentialIntegrityKey)
		return nil, fmt.Errorf("policy sequence: %w", err)
	}

	vaultIDs, err := ledger.ListVaultIDs()
	if err != nil {
		zero(credentialIntegrityKey)
		return nil, err
	}
	roles := map[string]*btcec.PublicKey{
		"VaultCosigner":  vaultCosignerKey.PubKey(),
		"ArkadeCosigner": arkadeBase,
	}
	if err := requirePairwiseIndependent(roles); err != nil {
		zero(credentialIntegrityKey)
		return nil, err
	}

	if err := provisionEnrollmentInvite(ledger, cfg, len(vaultIDs) > 0, time.Now().UTC()); err != nil {
		zero(credentialIntegrityKey)
		return nil, err
	}

	arkadeSigner, arkadeIdentity, err := dialArkade(
		ctx,
		deployment.MutinynetArkadeCosignerOrigin,
		arkadeBase,
		[]string{deployment.MutinynetArkadeCosignerVersion},
		false,
	)
	if err != nil {
		zero(credentialIntegrityKey)
		return nil, err
	}
	if err := validateArkadeDialResult(arkadeSigner, arkadeIdentity, arkadeBase); err != nil {
		zero(credentialIntegrityKey)
		return nil, err
	}
	stores, err := arkadevaultv1.StoresFromLedger(ledger)
	if err != nil {
		zero(credentialIntegrityKey)
		return nil, err
	}
	var keys application.KeyCapabilities
	if boardV2 {
		keys, err = application.NewFileBackedVaultBoardV2KeyCapabilities(vaultCosignerKey, arkadeSigner)
	} else {
		keys, err = application.NewFileBackedKeyCapabilities(vaultCosignerKey, arkadeSigner)
	}
	if err != nil {
		zero(credentialIntegrityKey)
		return nil, err
	}
	deps := application.Deps{
		Stores:                stores,
		Deployment:            cfg.Deployment,
		IntegrityKey:          credentialIntegrityKey,
		Keys:                  keys,
		VaultCosignerPub:      vaultCosignerKey.PubKey(),
		ArkadeCosignerPub:     arkadeIdentity.BasePub,
		ArkadeCosignerOrigin:  arkadeIdentity.Origin,
		ArkadeCosignerVersion: arkadeIdentity.Version,
	}
	if boardV2 {
		deps.VaultBoardV2Store = ledger
	}
	svc := application.New(deps)
	keyOwnedByService = true
	defer func() {
		if closeOnError {
			svc.WipeSecrets()
		}
	}()
	// Authenticate and rebuild persisted state before contacting the external
	// publisher. The public cosigner was contacted only after the bootstrap
	// secret or persisted credential MAC was validated above.
	if err := svc.LoadVaults(); err != nil {
		return nil, err
	}

	registry, profileID, err := compiledRegistryFor(boardV2)
	if err != nil {
		return nil, err
	}
	host, err := arkaderuntime.Open(registry, profileID, arkaderuntime.Mount{
		Handler: httpapi.Authorizer(svc),
		Readiness: func(ctx context.Context) error {
			ready := svc.Ready(ctx)
			if !ready.Ok {
				return fmt.Errorf("%s", ready.Error)
			}
			return nil
		},
		Shutdown: func() error {
			svc.WipeSecrets()
			return ledger.Close()
		},
	})
	if err != nil {
		return nil, err
	}

	closeOnError = false
	return &Runtime{host: host, service: svc, ledger: ledger}, nil
}

func validateArkadeDialResult(signer application.Signer, identity application.PublicEmulatorIdentity, expected *btcec.PublicKey) error {
	if signerUnavailable(signer) {
		return fmt.Errorf("public arkade emulator signer capability required")
	}
	if identity.Origin != deployment.MutinynetArkadeCosignerOrigin ||
		identity.Version != deployment.MutinynetArkadeCosignerVersion ||
		identity.BasePub == nil || expected == nil ||
		!bytes.Equal(identity.BasePub.SerializeCompressed(), expected.SerializeCompressed()) {
		return fmt.Errorf("public arkade emulator identity does not match the release pin")
	}
	return nil
}

func signerUnavailable(signer application.Signer) bool {
	if signer == nil {
		return true
	}
	value := reflect.ValueOf(signer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// compiledRegistry is the single production composition point. Profiles are
// linked here at build time; there is no configuration or discovery path that
// can add another profile at runtime.
func compiledRegistry() (*arkaderuntime.Registry, error) {
	return arkaderuntime.Compile(arkadevaultv1.Definition())
}

func compiledRegistryFor(boardV2 bool) (*arkaderuntime.Registry, string, error) {
	if !boardV2 {
		registry, err := compiledRegistry()
		return registry, arkadevaultv1.ProfileID, err
	}
	registry, err := arkaderuntime.Compile(arkadevaultv2.Definition())
	return registry, arkadevaultv2.ProfileID, err
}

// provisionEnrollmentInvite turns one operator-supplied secret file into one
// durable invitation. Re-presenting the exact file is idempotent, including
// after the invitation is consumed; rotating the file provisions a distinct
// invitation without exposing an administrative route on the signing API.
func provisionEnrollmentInvite(ledger *policy.Ledger, cfg Config, hasVaults bool, now time.Time) error {
	if ledger == nil {
		return fmt.Errorf("enrollment ledger required")
	}
	if cfg.EnrollmentTokenFile == "" {
		if hasVaults {
			return nil
		}
		return fmt.Errorf("fresh authorizer requires an enrollment token file")
	}
	window := cfg.EnrollmentWindow
	if window == 0 {
		window = 30 * time.Minute
	}
	if window < time.Minute || window > 24*time.Hour {
		return fmt.Errorf("enrollment window must be between 1 minute and 24 hours")
	}
	token, err := readBoundedSecret(cfg.EnrollmentTokenFile, "enrollment token", 43, 43)
	if err != nil {
		return err
	}
	tokenHash, err := application.HashEnrollmentToken(string(token))
	zero(token)
	if err != nil {
		return fmt.Errorf("enrollment token: %w", err)
	}
	defer zero(tokenHash)
	invite, err := ledger.GetInvite(tokenHash)
	if err != nil {
		return fmt.Errorf("enrollment invite: %w", err)
	}
	if invite != nil {
		return nil
	}
	if err := ledger.PutInvite(tokenHash, now.Add(window).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		return fmt.Errorf("enrollment invite: %w", err)
	}
	return nil
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
	var scalar btcec.ModNScalar
	overflow := scalar.SetByteSlice(raw)
	defer scalar.Zero()
	if overflow || scalar.IsZero() {
		return nil, fmt.Errorf("VaultCosigner key scalar must be in [1, secp256k1.N-1]")
	}
	priv, _ := btcec.PrivKeyFromBytes(raw)
	if role, known := knownPublicFixtureRole(priv.PubKey()); known {
		wipePrivateKey(priv)
		return nil, fmt.Errorf("public %s fixture VaultCosigner key is forbidden", role)
	}
	return priv, nil
}

func wipePrivateKey(priv *btcec.PrivateKey) {
	if priv == nil {
		return
	}
	priv.Key.Zero()
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
