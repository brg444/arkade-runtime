package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/apperr"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/ports"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/brg444/arkade-vault-server/internal/vault"
	v5 "github.com/brg444/arkade-vault-server/internal/vault/v5"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// Service is the trusted VaultCosigner authorization boundary.
type Service struct {
	Ledger     *policy.Ledger
	Deployment deployment.Config
	// CredentialIntegrityKey authenticates the immutable descriptor stored in
	// the authoritative ledger. Production obtains this key from the VaultCosigner
	// scalar through a domain-separated KDF; regtest uses a public deterministic
	// test key so existing demo deployments retain corruption detection.
	CredentialIntegrityKey []byte
	// EnrollmentTokenHash gates the first and only enrollment. Once a
	// credential exists, the token is never consulted again; only the exact
	// persisted tuple remains idempotent.
	EnrollmentTokenHash []byte
	// EnrollmentDeadline bounds how long a fresh deployment can be claimed.
	// An enrolled deployment never consults it. Production sets this at
	// process start; tests may inject EnrollmentNow.
	EnrollmentDeadline time.Time
	EnrollmentNow      func() time.Time
	// OpenEnrollment explicitly arms a first-come claim without an invite.
	// Production still sets a short EnrollmentDeadline. The singleton insert
	// permanently closes this mode after the first successful claimant.
	OpenEnrollment bool
	// MultiTenantEnrollment arms invite-scoped /v1/enroll/* and /v1/invite.
	// Default false: those routes stay 404 until an explicit cutover.
	MultiTenantEnrollment     bool
	PhoneRoutineBIP340        *btcec.PublicKey
	ExternalOwnerWallet       *btcec.PublicKey
	RecoveryKey               *btcec.PublicKey
	VaultCosignerPub          *btcec.PublicKey
	DeprecatedVaultCosigners  []*btcec.PublicKey
	ArkadeCosignerPub         *btcec.PublicKey
	DeprecatedArkadeCosigners []*btcec.PublicKey
	ArkadeCosignerOrigin      string
	ArkadeCosignerVersion     string
	Operational               *vault.Built
	Savings                   *vault.Built
	// VaultSigner is the private VaultCosigner-key stage. ArkadeCosignerSigner
	// is the independent public stage and must never hold the VaultCosigner key.
	VaultSigner          Signer
	ArkadeCosignerSigner Signer
	SignTimeout          time.Duration
	// MaxConcurrentVerifications bounds the CPU-heavy WebAuthn, P-256 and
	// Schnorr verification stage. Zero uses the conservative default.
	MaxConcurrentVerifications int
	Broadcaster                Broadcaster
	ArkResolver                ports.ArkResolver
	contractPackJSON           []byte
	vaultPolicyHasExit         *bool
	fulmineHTTP                *http.Client
	fulmineInfoFn              func(context.Context) (fulmineInfo, error)
	fulmineForwardFn           func(context.Context, IntentWire, []string) error
	mu                         sync.Mutex
	published                  atomic.Pointer[publishedIndex]
	verificationOnce           sync.Once
	verificationSlots          chan struct{}
	sessionMu                  sync.Mutex
	sessionChallenges          map[string]passkeyChallenge
	SessionNow                 func() time.Time
	afterLoadPending           func()
	// vaultIKM is the long-lived master scalar. It is never a Taproot signer.
	// Per-vault keys are HKDF children. Leftover-direct-v0 signing is refused.
	vaultIKM *btcec.PrivateKey
}

// Deps is the constructor input. The master scalar is IKM only.
type Deps struct {
	Ledger                *policy.Ledger
	Deployment            deployment.Config
	IntegrityKey          []byte
	MasterIKM             *btcec.PrivateKey
	ExternalOwner         *btcec.PublicKey
	VaultCosignerPub      *btcec.PublicKey
	ArkadeCosignerPub     *btcec.PublicKey
	ArkadeCosignerOrigin  string
	ArkadeCosignerVersion string
	ArkadeSigner          Signer
	EnrollmentTokenHash   []byte
	OpenEnrollment        bool
	MultiTenantEnrollment bool
	EnrollmentDeadline    time.Time
	Broadcaster           Broadcaster
	ArkResolver           ports.ArkResolver
}

// New builds the application service. VaultSigner is not the master scalar.
func New(d Deps) *Service {
	return &Service{
		Ledger:                 d.Ledger,
		Deployment:             d.Deployment,
		CredentialIntegrityKey: d.IntegrityKey,
		ExternalOwnerWallet:    d.ExternalOwner,
		VaultCosignerPub:       d.VaultCosignerPub,
		ArkadeCosignerPub:      d.ArkadeCosignerPub,
		ArkadeCosignerOrigin:   d.ArkadeCosignerOrigin,
		ArkadeCosignerVersion:  d.ArkadeCosignerVersion,
		ArkadeCosignerSigner:   d.ArkadeSigner,
		EnrollmentTokenHash:    d.EnrollmentTokenHash,
		OpenEnrollment:         d.OpenEnrollment,
		MultiTenantEnrollment:  d.MultiTenantEnrollment,
		EnrollmentDeadline:     d.EnrollmentDeadline,
		Broadcaster:            d.Broadcaster,
		ArkResolver:            d.ArkResolver,
		vaultIKM:               d.MasterIKM,
	}
}

// ClientOrigin is the pinned signing origin.
func (s *Service) ClientOrigin() string {
	if s == nil {
		return ""
	}
	return s.runtimeConfig().ClientOrigin
}

// ArmEnrollmentDeadline sets the first-claim window on a fresh process.
func (s *Service) ArmEnrollmentDeadline(deadline time.Time) {
	if s != nil {
		s.EnrollmentDeadline = deadline
	}
}

// AttachBroadcaster sets the post-verify publisher.
func (s *Service) AttachBroadcaster(b Broadcaster) {
	if s != nil {
		s.Broadcaster = b
	}
}

// HasVaultSigner reports whether a leftover in-process signer is attached.
func (s *Service) HasVaultSigner() bool {
	return s != nil && !isNilInterface(s.VaultSigner)
}

// EnrollmentTokenLen is the loaded invite hash length. Tests use this instead
// of reading the field.
func (s *Service) EnrollmentTokenLen() int {
	if s == nil {
		return 0
	}
	return len(s.EnrollmentTokenHash)
}

// IntegrityKeyCopy returns a copy of the MAC key for shutdown tests.
func (s *Service) IntegrityKeyCopy() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.CredentialIntegrityKey...)
}

// WipeSecrets zeros the IKM and integrity key. Called on process shutdown.
func (s *Service) WipeSecrets() {
	if s == nil {
		return
	}
	zeroServiceBytes(s.CredentialIntegrityKey)
	s.CredentialIntegrityKey = nil
	zeroServiceBytes(s.EnrollmentTokenHash)
	s.EnrollmentTokenHash = nil
	if s.vaultIKM != nil {
		raw := s.vaultIKM.Serialize()
		zeroServiceBytes(raw)
		s.vaultIKM.Key = btcec.ModNScalar{}
		s.vaultIKM = nil
	}
	s.VaultSigner = nil
}

const defaultConcurrentVerifications = 4

const regtestCredentialIntegrityDomain = "arkade-2fa-vault/regtest-public-credential-integrity-key/v1"

var ErrVerificationBusy = errors.New("crypto verification capacity exhausted")

// enrolledSnapshot is one immutable published enrollment for a single vault.
type enrolledSnapshot struct {
	VaultID             string
	CredentialID        []byte
	PhoneRoutineBIP340  *btcec.PublicKey
	ExternalOwnerWallet *btcec.PublicKey
	RecoveryKey         *btcec.PublicKey
	VaultCosignerBase   *btcec.PublicKey
	ArkadeCosignerBase  *btcec.PublicKey
	Operational         *vault.Built
	Savings             *vault.Built
}

// publishedIndex is a swapped immutable map of vaults and credential IDs.
type publishedIndex struct {
	byVault map[string]*enrolledSnapshot
	byCred  map[string]string
}

// RegisterRequest is the enrollment payload. All byte fields are hex.
// A second call is accepted only when it matches the already-enrolled
// credential ID, WebAuthn P-256, PhoneDirectP256, and PhoneRoutineBIP340,
// and this process's pinned deployment keys/policy still rebuild the stored
// descriptor.
type RegisterRequest struct {
	CredentialID          string `json:"credentialId"`
	WebAuthnP256          string `json:"webauthnP256"`
	PhoneDirectP256       string `json:"phoneDirectP256"`
	PhoneRoutineBIP340Pub string `json:"phoneRoutineBip340Pub"`
	// These BIP340 x-only keys are chosen exactly once for a fresh portable
	// deployment. A configured deployment may precommit the same identities.
	ExternalOwnerWalletXOnly string `json:"externalOwnerWalletXOnly,omitempty"`
	RecoveryXOnly            string `json:"recoveryXOnly,omitempty"`
	RecoveryKeyXOnly         string `json:"recoveryKeyXOnly,omitempty"`
	// Optional tenant identity. Extra fields must not 400 under
	// DisallowUnknownFields; new enrollments should send them.
	VaultID            string `json:"vaultId,omitempty"`
	ExternalOwnerProof string `json:"externalOwnerProof,omitempty"`
	RecoveryPoP        string `json:"recoveryPoP,omitempty"`
	RecoveryProof      string `json:"recoveryProof,omitempty"`
	DescriptorHash     string `json:"descriptorHash,omitempty"`
}

type parsedRegisterRequest struct {
	id, webauthnP256, phoneDirectP256 []byte
	phoneRoutine                      *btcec.PublicKey
	externalOwner                     *btcec.PublicKey
	recovery                          *btcec.PublicKey
	vaultID                           string
}

func (s *Service) Register(req RegisterRequest) error {
	return s.RegisterWithBootstrap(req, "")
}

// RegisterWithBootstrap applies the configured first-enrollment mode only
// while the ledger is unenrolled. Open mode requires an empty bootstrap;
// optional token mode validates it without ever reflecting token material.
func (s *Service) attachLedgerIntegrity() error {
	if s == nil || s.Ledger == nil {
		return fmt.Errorf("ledger required")
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	return s.Ledger.SetIntegrityKey(key)
}

func (s *Service) RegisterWithBootstrap(req RegisterRequest, bootstrap string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.attachLedgerIntegrity(); err != nil {
		return err
	}
	if err := s.runtimeConfig().Validate(); err != nil {
		return fmt.Errorf("deployment: %w", err)
	}

	existing, err := s.loadVerifiedCredential()
	if err != nil {
		return err
	}
	if existing != nil {
		parsed, err := s.parseRegisterRequest(req, existing)
		if err != nil {
			return err
		}
		if err := s.acceptPersistedEnrollment(existing, parsed); err != nil {
			return err
		}
		s.clearEnrollmentTokenHash()
		return nil
	}
	// Validate the explicitly armed claim mode and deadline before parsing
	// attacker-controlled public keys or deriving any descriptor. Open mode is
	// intentionally first-come; token mode authenticates one intended claimant.
	if err := s.validateEnrollmentBootstrap(bootstrap); err != nil {
		return err
	}
	parsed, err := s.parseRegisterRequest(req, nil)
	if err != nil {
		return err
	}
	if recoveryField(req) != "" || recoveryProofField(req) != "" || parsed.recovery != nil {
		return fmt.Errorf("recoveryKeyXOnly is retired")
	}
	op, sv, err := s.makeTrees(parsed.phoneRoutine, parsed.phoneDirectP256, parsed.externalOwner)
	if err != nil {
		return err
	}
	descriptor := descriptorFromTrees(
		s.runtimeConfig(), parsed.id, parsed.webauthnP256, parsed.phoneDirectP256,
		parsed.phoneRoutine, parsed.externalOwner,
		s.VaultCosignerPub, s.ArkadeCosignerPub,
		s.ArkadeCosignerOrigin, s.ArkadeCosignerVersion, op, sv,
	)
	if err := s.sealCredential(&descriptor); err != nil {
		return err
	}
	if err := s.Ledger.Enroll(descriptor); err != nil {
		existing, getErr := s.loadVerifiedCredential()
		if getErr != nil {
			return err
		}
		if existing == nil {
			return err
		}
		if err := s.acceptPersistedEnrollment(existing, parsed); err != nil {
			return err
		}
		s.clearEnrollmentTokenHash()
		return nil
	}
	s.publishEnrollmentAt(program.LeftoverVaultID, parsed.id, parsed.phoneRoutine, op, sv)
	s.clearEnrollmentTokenHash()
	return nil
}

// CreateTenantVault atomically persists a new HKDF-derived vault and consumes
// the invite. HTTP enrollment remains gated; this is the PR1 service primitive.
func (s *Service) CreateTenantVault(vaultID string, tokenHash []byte, req RegisterRequest) error {
	return s.createTenantVault(vaultID, tokenHash, req, nil)
}

func (s *Service) createTenantVault(vaultID string, tokenHash []byte, req RegisterRequest, pending *policy.PendingEnrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.runtimeConfig().Validate(); err != nil {
		return fmt.Errorf("deployment: %w", err)
	}
	if vaultID == "" || vaultID == program.LeftoverVaultID {
		return fmt.Errorf("tenant vault id required")
	}
	if req.ExternalOwnerWalletXOnly == "" {
		return fmt.Errorf("tenant owner pub required")
	}
	master, err := s.vaultCosignerMaster()
	if err != nil {
		return err
	}
	child, err := policy.DeriveVaultCosignerScalar(master, vaultID, policy.CosignerModeHKDFSHA256V1)
	if err != nil {
		return err
	}
	parsed, err := s.parseRegisterRequestIndependent(req)
	if err != nil {
		return err
	}
	proposed, err := s.previewTenantDescriptor(vaultID, req)
	if err != nil {
		return err
	}
	if req.DescriptorHash == "" || req.DescriptorHash != proposed.DescriptorHash {
		return fmt.Errorf("enrollment descriptor hash does not match the proposed vault")
	}
	if err := verifyEnrollmentPoP(vaultID, parsed.externalOwner, req); err != nil {
		return err
	}
	if parsed.recovery != nil {
		handle := ""
		if pending != nil {
			handle = pending.Handle
		}
		if err := v5.VerifyRecoveryPoP(parsed.recovery, vaultID, handle, proposed.DescriptorHash, recoveryProofField(req)); err != nil {
			return err
		}
	}
	descriptor, op, sv, err := s.mintV5Credential(vaultID, parsed, child.PubKey())
	if err != nil {
		return err
	}
	if err := s.sealCredential(&descriptor); err != nil {
		return err
	}
	rec := policy.VaultRecord{}
	rec = vaultRecordFromDescriptor(descriptor)
	if err := sealVaultRecordForService(&rec, s); err != nil {
		return err
	}
	vcred := policy.VaultCredential{
		CredentialID: append([]byte(nil), descriptor.ID...),
		VaultID:      vaultID,
		WebAuthnP256: append([]byte(nil), descriptor.WebAuthnP256...),
		UserHandle:   []byte(vaultID),
		Resident:     true,
	}
	if err := sealVaultCredentialForService(&vcred, s); err != nil {
		return err
	}
	if err := s.Ledger.CreateVault(policy.CreateVaultInput{
		Record: rec, Credential: vcred, TokenHash: tokenHash, Pending: pending,
	}); err != nil {
		return err
	}
	s.publishEnrollmentAt(vaultID, descriptor.ID, parsed.phoneRoutine, op, sv)
	return nil
}

func (s *Service) vaultCosignerMaster() (*btcec.PrivateKey, error) {
	if s.vaultIKM != nil {
		return s.vaultIKM, nil
	}
	ls, ok := s.VaultSigner.(LocalSigner)
	if !ok || ls.Priv == nil {
		return nil, fmt.Errorf("vault cosigner IKM required")
	}
	return ls.Priv, nil
}

func vaultRecordFromDescriptor(c policy.Credential) policy.VaultRecord {
	return policy.VaultRecordFromCredential(c)
}

func sealVaultRecordForService(rec *policy.VaultRecord, s *Service) error {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	return policy.SealVaultRecord(rec, key)
}

func sealVaultCredentialForService(cred *policy.VaultCredential, s *Service) error {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	return policy.SealVaultCredential(cred, key)
}

func (s *Service) validateEnrollmentBootstrap(bootstrap string) error {
	if !s.EnrollmentDeadline.IsZero() && !s.currentEnrollmentTime().Before(s.EnrollmentDeadline) {
		return fmt.Errorf("enrollment window is closed")
	}
	if s.runtimeConfig().Network == deployment.NetworkRegtest && len(s.EnrollmentTokenHash) == 0 {
		return nil
	}
	if s.OpenEnrollment {
		if bootstrap != "" {
			return fmt.Errorf("open enrollment does not accept an invitation token")
		}
		return nil
	}
	if len(s.EnrollmentTokenHash) != sha256.Size {
		return fmt.Errorf("enrollment bootstrap authorization is not configured")
	}
	raw, err := decodeEnrollmentToken(bootstrap)
	if err != nil {
		return fmt.Errorf("enrollment bootstrap authorization failed")
	}
	defer zeroServiceBytes(raw)
	got := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(got[:], s.EnrollmentTokenHash) != 1 {
		return fmt.Errorf("enrollment bootstrap authorization failed")
	}
	return nil
}

func (s *Service) currentEnrollmentTime() time.Time {
	if s.EnrollmentNow != nil {
		return s.EnrollmentNow()
	}
	return time.Now()
}

// HashEnrollmentToken validates the one supported token encoding and returns
// the SHA-256 digest held by the authorizer process.
func HashEnrollmentToken(token string) ([]byte, error) {
	raw, err := decodeEnrollmentToken(token)
	if err != nil {
		return nil, err
	}
	defer zeroServiceBytes(raw)
	digest := sha256.Sum256(raw)
	return append([]byte(nil), digest[:]...), nil
}

func decodeEnrollmentToken(token string) ([]byte, error) {
	if len(token) != 43 || strings.TrimSpace(token) != token {
		return nil, fmt.Errorf("enrollment token must be 32-byte base64url without padding")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		zeroServiceBytes(raw)
		return nil, fmt.Errorf("enrollment token must be 32-byte base64url without padding")
	}
	return raw, nil
}

func (s *Service) clearEnrollmentTokenHash() {
	for i := range s.EnrollmentTokenHash {
		s.EnrollmentTokenHash[i] = 0
	}
	s.EnrollmentTokenHash = nil
}

// acceptPersistedEnrollment succeeds only for the exact user tuple when
// runtime config matches the stored descriptor and trees rebuilt from that
// record equal the persisted addresses/scripts/tweaked provider. It never
// publishes trees derived from this process's speculative RecoveryKey/Provider.
func (s *Service) acceptPersistedEnrollment(existing *policy.Credential, parsed parsedRegisterRequest) error {
	if !sameEnrollmentTuple(existing, parsed) {
		return fmt.Errorf("enrollment locked")
	}
	return s.publishStoredEnrollment(existing, false)
}

func (s *Service) parseRegisterRequest(req RegisterRequest, existing *policy.Credential) (parsedRegisterRequest, error) {
	return s.parseRegisterRequestWithKeys(req, existing, s.PhoneRoutineBIP340, s.ExternalOwnerWallet, s.RecoveryKey)
}

func (s *Service) parseRegisterRequestIndependent(req RegisterRequest) (parsedRegisterRequest, error) {
	return s.parseRegisterRequestWithKeys(req, nil, nil, nil, nil)
}

func (s *Service) parseRegisterRequestWithKeys(
	req RegisterRequest,
	existing *policy.Credential,
	phoneFallback, ownerFallback, recoveryFallback *btcec.PublicKey,
) (parsed parsedRegisterRequest, err error) {
	parsed.id, err = decodeHex(req.CredentialID)
	if err != nil {
		return parsed, fmt.Errorf("credentialId: %w", err)
	}
	if len(parsed.id) > 1024 {
		return parsed, fmt.Errorf("credentialId too large")
	}
	parsed.webauthnP256, err = decodeHex(req.WebAuthnP256)
	if err != nil {
		return parsed, fmt.Errorf("webauthnP256: %w", err)
	}
	if _, err = webauthn.ParseCompressedP256(parsed.webauthnP256); err != nil {
		return parsed, fmt.Errorf("webauthnP256: %w", err)
	}
	parsed.phoneDirectP256, err = decodeHex(req.PhoneDirectP256)
	if err != nil {
		return parsed, fmt.Errorf("phoneDirectP256: %w", err)
	}
	if _, err = webauthn.ParseCompressedP256(parsed.phoneDirectP256); err != nil {
		return parsed, fmt.Errorf("phoneDirectP256: %w", err)
	}
	if bytes.Equal(parsed.webauthnP256, parsed.phoneDirectP256) {
		return parsed, fmt.Errorf("direct-auth p256 must be distinct from the webauthn credential p256")
	}
	parsed.phoneRoutine, err = parsePhoneRoutineBIP340Pub(req.PhoneRoutineBIP340Pub, phoneFallback)
	if err != nil {
		return parsed, err
	}
	var existingOwner *btcec.PublicKey
	if existing != nil {
		existingOwner, err = btcec.ParsePubKey(existing.ExternalOwnerWallet)
		if err != nil {
			return parsed, fmt.Errorf("stored ExternalOwnerWallet: %w", err)
		}
	}
	parsed.externalOwner, err = s.parseOnboardingKey("externalOwnerWalletXOnly", req.ExternalOwnerWalletXOnly, ownerFallback, existingOwner)
	if err != nil {
		return parsed, err
	}
	var existingRecovery *btcec.PublicKey
	if existing != nil && len(existing.RecoveryKey) > 0 {
		if pub, err := btcec.ParsePubKey(existing.RecoveryKey); err == nil && !knownFixtureXOnly(schnorr.SerializePubKey(pub)) {
			existingRecovery = pub
		}
	}
	if rec := recoveryField(req); rec != "" {
		parsed.recovery, err = s.parseOnboardingKey("recoveryXOnly", rec, recoveryFallback, existingRecovery)
		if err != nil {
			return parsed, err
		}
	} else if existingRecovery != nil {
		parsed.recovery = existingRecovery
	}
	parsed.vaultID = req.VaultID
	return parsed, nil
}

func sameEnrollmentTuple(c *policy.Credential, parsed parsedRegisterRequest) bool {
	return c != nil && parsed.phoneRoutine != nil && parsed.externalOwner != nil &&
		bytes.Equal(c.ID, parsed.id) &&
		bytes.Equal(c.WebAuthnP256, parsed.webauthnP256) &&
		bytes.Equal(c.PhoneDirectP256, parsed.phoneDirectP256) &&
		bytes.Equal(c.PhoneRoutineBIP340, parsed.phoneRoutine.SerializeCompressed()) &&
		bytes.Equal(c.ExternalOwnerWallet, parsed.externalOwner.SerializeCompressed()) &&
		(parsed.vaultID == "" || parsed.vaultID == c.VaultID)
}

// LoadVaults rebuilds trees from the persisted enrollment descriptor.
// Runtime config must be compatible; trees are never derived from a
// rotated GetInfo key or a changed CSV/network/template.
func (s *Service) LoadVaults() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.attachLedgerIntegrity(); err != nil {
		return err
	}
	if err := s.runtimeConfig().Validate(); err != nil {
		return fmt.Errorf("deployment: %w", err)
	}
	ids, err := s.Ledger.ListVaultIDs()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		cred, err := s.loadVerifiedCredential()
		if err != nil {
			return err
		}
		if cred == nil {
			return nil
		}
		if quarantineLegacyVault(s, cred.VaultID, cred.TemplateVersion) {
			return nil
		}
		return s.publishStoredEnrollment(cred, true)
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	for _, id := range ids {
		rec, vcred, err := s.Ledger.LoadVerifiedVault(id, key)
		if err != nil {
			return err
		}
		if rec == nil || vcred == nil {
			return fmt.Errorf("vault %s missing credential", id)
		}
		cred := rec.ToCredential(*vcred)
		if quarantineLegacyVault(s, id, cred.TemplateVersion) {
			continue
		}
		if err := s.publishStoredEnrollment(&cred, true && id == program.LeftoverVaultID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) publishStoredEnrollment(cred *policy.Credential, startup bool) error {
	phoneRoutine, externalOwner, recovery, vaultBase, arkadeBase, op, sv, err := s.rebuildFromCredential(cred)
	if err != nil {
		return err
	}
	runtimeVaultCosigner := s.VaultCosignerPub
	// Startup may replace a deprecated/current RemoteSigner identity with the
	// persisted vault identity after compatibility is checked. An idempotent
	// /register never rewrites fields read by concurrent requests.
	if startup {
		s.ExternalOwnerWallet = externalOwner
		s.RecoveryKey = recovery
		s.VaultCosignerPub = vaultBase
		s.ArkadeCosignerPub = arkadeBase
	}
	s.publishEnrollmentAt(cred.VaultID, cred.ID, phoneRoutine, op, sv)
	if runtimeVaultCosigner != nil && !sameCompressed(runtimeVaultCosigner, cred.VaultCosignerBase) {
		log.Printf("rebuilt vault from enrolled VaultCosigner base %x; current runtime signer %x must remain deprecated",
			cred.VaultCosignerBase, runtimeVaultCosigner.SerializeCompressed())
	}
	return nil
}

func (s *Service) rebuildFromCredential(cred *policy.Credential) (
	phoneRoutine, externalOwner, recovery, vaultBase, arkadeBase *btcec.PublicKey,
	op, sv *vault.Built, err error,
) {
	if err = s.requireCompatible(cred); err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	if isV5Template(cred.TemplateVersion) {
		return s.rebuildV5(cred)
	}
	phoneRoutine, err = btcec.ParsePubKey(cred.PhoneRoutineBIP340)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("stored PhoneRoutineBIP340: %w", err)
	}
	externalOwner, err = btcec.ParsePubKey(cred.ExternalOwnerWallet)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("stored ExternalOwnerWallet: %w", err)
	}
	if len(cred.RecoveryKey) > 0 {
		recovery, err = btcec.ParsePubKey(cred.RecoveryKey)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("stored RecoveryKey: %w", err)
		}
	}
	vaultBase, err = btcec.ParsePubKey(cred.VaultCosignerBase)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("stored VaultCosigner: %w", err)
	}
	arkadeBase, err = btcec.ParsePubKey(cred.ArkadeCosignerBase)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("stored ArkadeCosigner: %w", err)
	}
	opCSV := arklib.RelativeLocktime{Type: arklib.RelativeLocktimeType(cred.OperationalCSVType), Value: cred.OperationalCSVValue}
	svCSV := arklib.RelativeLocktime{Type: arklib.RelativeLocktimeType(cred.SavingsCSVType), Value: cred.SavingsCSVValue}
	op, err = vault.NewFromRecord(vault.Record{
		Kind:                vault.Operational,
		PhoneRoutineBIP340:  phoneRoutine,
		PhoneDirectP256:     cred.PhoneDirectP256,
		ExternalOwnerWallet: externalOwner,
		VaultCosignerBase:   vaultBase,
		ArkadeCosignerBase:  arkadeBase,
		CSV:                 opCSV,
		HardwareCSV:         svCSV,
		AuthorizationPolicy: authorizationPolicyFromCredential(cred),
		Network:             cred.Network,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	sv, err = vault.NewFromRecord(vault.Record{
		Kind:                vault.Savings,
		PhoneRoutineBIP340:  phoneRoutine,
		ExternalOwnerWallet: externalOwner,
		CSV:                 opCSV,
		HardwareCSV:         svCSV,
		Network:             cred.Network,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	if err = sv.AssertNoRoutineCosigners(vaultBase, op.TweakedVaultCosigner, arkadeBase, op.TweakedArkadeCosigner); err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	if op.Address != cred.OperationalAddress || !bytes.Equal(op.PkScript, cred.OperationalScript) {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt operational vault does not match stored descriptor")
	}
	if sv.Address != cred.SavingsAddress || !bytes.Equal(sv.PkScript, cred.SavingsScript) {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt savings vault does not match stored descriptor")
	}
	if op.TweakedVaultCosigner == nil || !bytes.Equal(op.TweakedVaultCosigner.SerializeCompressed(), cred.TweakedVaultCosigner) {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt tweaked VaultCosigner does not match stored descriptor")
	}
	if op.TweakedArkadeCosigner == nil || !bytes.Equal(op.TweakedArkadeCosigner.SerializeCompressed(), cred.TweakedArkadeCosigner) {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("rebuilt tweaked ArkadeCosigner does not match stored descriptor")
	}
	return phoneRoutine, externalOwner, recovery, vaultBase, arkadeBase, op, sv, nil
}

func (s *Service) makeTrees(phoneRoutine *btcec.PublicKey, phoneDirectP256 []byte, externalOwner *btcec.PublicKey) (*vault.Built, *vault.Built, error) {
	return s.makeTreesWithCosigner(phoneRoutine, phoneDirectP256, externalOwner, s.VaultCosignerPub)
}

func (s *Service) makeTreesWithCosigner(phoneRoutine *btcec.PublicKey, phoneDirectP256 []byte, externalOwner, vaultCosigner *btcec.PublicKey) (*vault.Built, *vault.Built, error) {
	if phoneRoutine == nil || externalOwner == nil || vaultCosigner == nil || s.ArkadeCosignerPub == nil {
		return nil, nil, fmt.Errorf("vault keys not configured")
	}
	cfg := s.runtimeConfig()
	opCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.OperationalCSVBlocks}
	svCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.SavingsCSVBlocks}
	op, err := vault.NewOperationalWithPolicy(vault.OperationalKeys{
		PhoneRoutineBIP340:  phoneRoutine,
		PhoneDirectP256:     phoneDirectP256,
		ExternalOwnerWallet: externalOwner,
		VaultCosignerBase:   vaultCosigner,
		ArkadeCosignerBase:  s.ArkadeCosignerPub,
	}, cfg.Network, opCSV, svCSV, configuredAuthorizationPolicy())
	if err != nil {
		return nil, nil, err
	}
	sv, err := vault.NewSavingsWithPolicy(
		phoneRoutine, externalOwner, cfg.Network, opCSV, svCSV,
		vaultCosigner, op.TweakedVaultCosigner, s.ArkadeCosignerPub, op.TweakedArkadeCosigner,
	)
	if err != nil {
		return nil, nil, err
	}
	return op, sv, nil
}

func descriptorFromTrees(
	cfg deployment.Config, id, webauthnP256, phoneDirectP256 []byte,
	phoneRoutine, externalOwner, vaultBase, arkadeBase *btcec.PublicKey,
	arkadeOrigin, arkadeVersion string, op, sv *vault.Built,
) policy.Credential {
	opCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.OperationalCSVBlocks}
	svCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.SavingsCSVBlocks}
	return policy.Credential{
		ID:                    id,
		WebAuthnP256:          append([]byte(nil), webauthnP256...),
		PhoneDirectP256:       append([]byte(nil), phoneDirectP256...),
		PhoneRoutineBIP340:    phoneRoutine.SerializeCompressed(),
		ExternalOwnerWallet:   externalOwner.SerializeCompressed(),
		RecoveryKey:           retiredRecoveryPlaceholder(),
		RPID:                  cfg.RPID,
		Origin:                cfg.ClientOrigin,
		VaultCosignerBase:     vaultBase.SerializeCompressed(),
		TweakedVaultCosigner:  op.TweakedVaultCosigner.SerializeCompressed(),
		ArkadeCosignerBase:    arkadeBase.SerializeCompressed(),
		TweakedArkadeCosigner: op.TweakedArkadeCosigner.SerializeCompressed(),
		ArkadeCosignerOrigin:  arkadeOrigin,
		ArkadeCosignerVersion: arkadeVersion,
		TemplateVersion:       program.LeftoverV4Template,
		PolicyVersion:         program.PolicyVersion,
		Network:               cfg.Network,
		VaultID:               program.LeftoverVaultID,
		OperationalCSVType:    int64(opCSV.Type),
		OperationalCSVValue:   opCSV.Value,
		SavingsCSVType:        int64(svCSV.Type),
		SavingsCSVValue:       svCSV.Value,
		OperationalAddress:    op.Address,
		OperationalScript:     append([]byte(nil), op.PkScript...),
		SavingsAddress:        sv.Address,
		SavingsScript:         append([]byte(nil), sv.PkScript...),
		RecipientDustSats:     program.DustSats,
		TxRecipientCapSats:    program.TxRecipientCapSats,
		PeriodAllowanceSats:   program.PeriodAllowanceSats,
		AbsoluteFeeCapSats:    program.AbsoluteFeeCeiling,
		FeerateCapSatPerV:     program.FeerateCeilingSatPerV,
	}
}

func retiredRecoveryPlaceholder() []byte {
	raw, err := hex.DecodeString(program.UnsafeGeneratorG)
	if err != nil {
		return []byte{0}
	}
	return raw
}

func configuredAuthorizationPolicy() vault.AuthorizationPolicy {
	return vault.AuthorizationPolicy{
		RecipientDustSats:      program.DustSats,
		RecipientCapSats:       program.TxRecipientCapSats,
		AbsoluteFeeCeilingSats: program.AbsoluteFeeCeiling,
		FeerateCeilingSatPerV:  program.FeerateCeilingSatPerV,
	}
}

func authorizationPolicyFromCredential(cred *policy.Credential) vault.AuthorizationPolicy {
	return vault.AuthorizationPolicy{
		RecipientDustSats:      cred.RecipientDustSats,
		RecipientCapSats:       cred.TxRecipientCapSats,
		AbsoluteFeeCeilingSats: cred.AbsoluteFeeCapSats,
		FeerateCeilingSatPerV:  cred.FeerateCapSatPerV,
	}
}

func (s *Service) requireCompatible(cred *policy.Credential) error {
	cfg := s.runtimeConfig()
	if !knownTemplate(cred.TemplateVersion) {
		return fmt.Errorf("stored template %q incompatible with runtime", cred.TemplateVersion)
	}
	if cred.PolicyVersion != program.PolicyVersion {
		return fmt.Errorf("stored policy %q incompatible with runtime %q", cred.PolicyVersion, program.PolicyVersion)
	}
	if cred.Network != cfg.Network {
		return fmt.Errorf("stored network %q incompatible with runtime %q", cred.Network, cfg.Network)
	}
	if cred.VaultID == "" {
		return fmt.Errorf("stored vault id required")
	}
	opCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.OperationalCSVBlocks}
	svCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: cfg.SavingsCSVBlocks}
	if cred.OperationalCSVType != int64(opCSV.Type) || cred.OperationalCSVValue != opCSV.Value {
		return fmt.Errorf("stored operational CSV incompatible with runtime")
	}
	if cred.SavingsCSVType != int64(svCSV.Type) || cred.SavingsCSVValue != svCSV.Value {
		return fmt.Errorf("stored savings CSV incompatible with runtime")
	}
	if cred.Origin != cfg.ClientOrigin {
		return fmt.Errorf("stored origin %q incompatible with runtime %q", cred.Origin, cfg.ClientOrigin)
	}
	if cred.RPID != cfg.RPID {
		return fmt.Errorf("stored rp id %q incompatible with runtime %q", cred.RPID, cfg.RPID)
	}
	if cred.RecipientDustSats != program.DustSats ||
		cred.TxRecipientCapSats != program.TxRecipientCapSats ||
		cred.PeriodAllowanceSats != program.PeriodAllowanceSats ||
		cred.AbsoluteFeeCapSats != program.AbsoluteFeeCeiling ||
		cred.FeerateCapSatPerV != program.FeerateCeilingSatPerV {
		return fmt.Errorf("stored economic policy incompatible with runtime")
	}
	wantOrigin, wantVersion := s.arkadeIdentity()
	if isV5Template(cred.TemplateVersion) {
		if cred.ArkadeCosignerOrigin != wantOrigin {
			return fmt.Errorf("stored ArkadeCosigner origin %q incompatible with runtime %q", cred.ArkadeCosignerOrigin, wantOrigin)
		}
		if cred.ArkadeCosignerVersion != wantVersion {
			return fmt.Errorf("stored ArkadeCosigner version %q incompatible with runtime %q", cred.ArkadeCosignerVersion, wantVersion)
		}
	} else if cred.ArkadeCosignerOrigin != s.ArkadeCosignerOrigin {
		return fmt.Errorf("stored ArkadeCosigner origin %q incompatible with runtime %q", cred.ArkadeCosignerOrigin, s.ArkadeCosignerOrigin)
	}
	if cfg.Network != deployment.NetworkRegtest && (cred.ArkadeCosignerVersion == "" || s.ArkadeCosignerVersion == "") {
		return fmt.Errorf("stored and runtime ArkadeCosigner versions are required")
	}
	// The persisted value records the exact reviewed version at enrollment.
	// Runtime separately accepts only its release allowlist. They need not be
	// equal after a reviewed key/version rotation: an existing descriptor stays
	// live only when its exact MAC-authenticated key is still advertised as an
	// active deprecated signer.
	if cred.VaultID == program.LeftoverVaultID {
		if s.ExternalOwnerWallet != nil && !sameCompressed(s.ExternalOwnerWallet, cred.ExternalOwnerWallet) {
			return fmt.Errorf("runtime ExternalOwnerWallet does not match enrolled vault")
		}
		// v4 does not commit RecoveryKey. Ignore leftover column bytes.
		if err := requireSignerCompatible("VaultCosigner", s.VaultCosignerPub, s.DeprecatedVaultCosigners, cred.VaultCosignerBase); err != nil {
			return err
		}
	}
	if err := requireSignerCompatible("ArkadeCosigner", s.ArkadeCosignerPub, s.DeprecatedArkadeCosigners, cred.ArkadeCosignerBase); err != nil {
		return err
	}
	return nil
}

func requireSignerCompatible(name string, current *btcec.PublicKey, deprecated []*btcec.PublicKey, stored []byte) error {
	if current == nil && len(deprecated) == 0 {
		return nil
	}
	if current != nil && sameCompressed(current, stored) {
		return nil
	}
	for _, pub := range deprecated {
		if sameCompressed(pub, stored) {
			return nil
		}
	}
	return fmt.Errorf("enrolled %s key does not match the configured runtime signer or an allowed deprecated key", name)
}

func sameCompressed(pub *btcec.PublicKey, raw []byte) bool {
	return pub != nil && bytes.Equal(pub.SerializeCompressed(), raw)
}

func parsePhoneRoutineBIP340Pub(hexPub string, fallback *btcec.PublicKey) (*btcec.PublicKey, error) {
	if hexPub == "" {
		if fallback == nil {
			return nil, fmt.Errorf("phoneRoutineBip340Pub required")
		}
		return fallback, nil
	}
	raw, err := decodeHex(hexPub)
	if err != nil {
		return nil, fmt.Errorf("phoneRoutineBip340Pub: %w", err)
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("phoneRoutineBip340Pub: %w", err)
	}
	return pub, nil
}

func (s *Service) parseOnboardingKey(name, encoded string, configured, persisted *btcec.PublicKey) (*btcec.PublicKey, error) {
	if encoded == "" {
		if persisted != nil {
			return persisted, nil
		}
		if configured != nil {
			return configured, nil
		}
		return nil, fmt.Errorf("%s required", name)
	}
	if len(encoded) != 64 || encoded != strings.ToLower(encoded) {
		return nil, fmt.Errorf("%s must be canonical 32-byte BIP340 x-only lowercase hex", name)
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("%s must be canonical 32-byte BIP340 x-only lowercase hex", name)
	}
	pub, err := schnorr.ParsePubKey(raw)
	if err != nil || !bytes.Equal(schnorr.SerializePubKey(pub), raw) {
		return nil, fmt.Errorf("%s is invalid", name)
	}
	if configured != nil && !bytes.Equal(schnorr.SerializePubKey(configured), raw) {
		return nil, fmt.Errorf("%s does not match deployment precommit", name)
	}
	if persisted != nil && !bytes.Equal(schnorr.SerializePubKey(persisted), raw) {
		return nil, fmt.Errorf("enrollment locked")
	}
	if s.runtimeConfig().Network != deployment.NetworkRegtest && knownFixtureXOnly(raw) {
		return nil, fmt.Errorf("public test fixture is forbidden for %s", name)
	}
	return pub, nil
}

func knownFixtureXOnly(xonly []byte) bool {
	for _, encoded := range []string{program.UnsafeGenerator2G, program.UnsafeGeneratorG} {
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			continue
		}
		pub, err := btcec.ParsePubKey(raw)
		if err == nil && bytes.Equal(schnorr.SerializePubKey(pub), xonly) {
			return true
		}
	}
	return false
}

// PublicStatus is the unauthenticated authorizer identity. It is not a
// tenant descriptor and must not be treated as enrolled.
type PublicStatus struct {
	Network              string `json:"network"`
	ClientOrigin         string `json:"clientOrigin"`
	RPID                 string `json:"rpId"`
	TemplateVersion      string `json:"templateVersion"`
	PolicyVersion        string `json:"policyVersion"`
	OperationalCSVBlocks uint32 `json:"operationalCsvBlocks"`
	SavingsCSVBlocks     uint32 `json:"savingsCsvBlocks"`
	EnrollmentMode       string `json:"enrollmentMode"`
	EnrollmentExpiresAt  string `json:"enrollmentExpiresAt,omitempty"`
}

// Status is the UI snapshot.
type Status struct {
	Enrolled                        bool     `json:"enrolled"`
	Network                         string   `json:"network"`
	ClientOrigin                    string   `json:"clientOrigin"`
	RPID                            string   `json:"rpId"`
	VaultID                         string   `json:"vaultId"`
	TemplateVersion                 string   `json:"templateVersion"`
	PolicyVersion                   string   `json:"policyVersion"`
	OperationalCSVBlocks            uint32   `json:"operationalCsvBlocks"`
	SavingsCSVBlocks                uint32   `json:"savingsCsvBlocks"`
	ExternalOwnerWalletPub          string   `json:"externalOwnerWalletPub,omitempty"`
	RecoveryKeyPub                  string   `json:"recoveryKeyPub,omitempty"`
	VaultCosignerBasePub            string   `json:"vaultCosignerBasePub,omitempty"`
	ArkadeCosignerBasePub           string   `json:"arkadeCosignerBasePub,omitempty"`
	ArkadeCosignerOrigin            string   `json:"arkadeCosignerOrigin"`
	ArkadeCosignerVersion           string   `json:"arkadeCosignerVersion"`
	OperationalAddr                 string   `json:"operationalAddress"`
	OperationalScript               string   `json:"operationalScript,omitempty"`
	SavingsAddr                     string   `json:"savingsAddress"`
	SavingsScript                   string   `json:"savingsScript,omitempty"`
	SavingsExcludesRoutineCosigners bool     `json:"savingsExcludesRoutineCosigners"`
	PasskeyLoginAvailable           bool     `json:"passkeyLoginAvailable"`
	EnrollmentMode                  string   `json:"enrollmentMode"`
	EnrollmentExpiresAt             string   `json:"enrollmentExpiresAt,omitempty"`
	PeriodAllowance                 int64    `json:"periodAllowance"`
	PeriodSpent                     int64    `json:"periodSpent"`
	PeriodRemaining                 int64    `json:"periodRemaining"`
	TxCap                           int64    `json:"txCap"`
	AbsoluteFeeCap                  int64    `json:"absoluteFeeCap"`
	FeerateCapSatPerV               int64    `json:"feerateCapSatVb"`
	PhoneRoutineBIP340Pub           string   `json:"phoneRoutineBip340Pub,omitempty"`
	PhoneDirectP256                 string   `json:"phoneDirectP256,omitempty"`
	TweakedVaultCosignerXOnly       string   `json:"tweakedVaultCosignerXOnly,omitempty"`
	TweakedArkadeCosignerXOnly      string   `json:"tweakedArkadeCosignerXOnly,omitempty"`
	Warnings                        []string `json:"warnings,omitempty"`
	VtxoVaultCosignerPub     string `json:"vtxoVaultCosignerPub"`
	VtxoExitDelay            uint32 `json:"vtxoExitDelay"`
	VtxoExitDelayUnit        string `json:"vtxoExitDelayUnit"`
	SpendingArkAddress       string `json:"spendingArkAddress"`
	SpendingArkScript        string `json:"spendingArkScript"`
	SpendingOnchainAddress   string `json:"spendingOnchainAddress"`
	SpendingOnchainScript    string `json:"spendingOnchainScript"`
	VtxoTweakedEmulatorPub   string `json:"vtxoTweakedEmulatorPub"`
	VtxoDelegatePub          string `json:"vtxoDelegatePub"`
}

func statusWarnings(cred *policy.Credential) []string {
	if cred == nil {
		return nil
	}
	var out []string
	if isStagedTemplate(cred.TemplateVersion) {
		out = append(out, "A recovery already in flight cannot be cancelled if both cosigners are gone.")
		if cred.TemplateVersion != v5.Template {
			out = append(out, "This vault still needs both cosigners to cancel a pending recovery.")
		}
	}
	if cred.Network == deployment.NetworkMutinynet {
		out = append(out, "Mutinynet blocks are much faster than mainnet. Delays are block counts, not days.")
	}
	return out
}

func (s *Service) publishEnrollmentAt(vaultID string, credID []byte, phoneRoutine *btcec.PublicKey, op, sv *vault.Built) {
	snap := &enrolledSnapshot{
		VaultID:            vaultID,
		CredentialID:       append([]byte(nil), credID...),
		PhoneRoutineBIP340: phoneRoutine, Operational: op, Savings: sv,
	}
	if op != nil {
		snap.ExternalOwnerWallet = op.Record.ExternalOwnerWallet
		snap.RecoveryKey = op.Record.RecoveryKey
		snap.VaultCosignerBase = op.Record.VaultCosignerBase
		snap.ArkadeCosignerBase = op.Record.ArkadeCosignerBase
	}
	prev := s.published.Load()
	next := &publishedIndex{
		byVault: make(map[string]*enrolledSnapshot, 4),
		byCred:  make(map[string]string, 4),
	}
	if prev != nil {
		for k, v := range prev.byVault {
			next.byVault[k] = v
		}
		for k, v := range prev.byCred {
			next.byCred[k] = v
		}
	}
	next.byVault[vaultID] = snap
	if len(credID) > 0 {
		next.byCred[hex.EncodeToString(credID)] = vaultID
	}
	s.published.Store(next)
	// Keep exported legacy/test fields stable after their first publication.
	if vaultID == program.LeftoverVaultID {
		if s.PhoneRoutineBIP340 == nil {
			s.PhoneRoutineBIP340 = phoneRoutine
		}
		if s.Operational == nil {
			s.Operational = op
		}
		if s.Savings == nil {
			s.Savings = sv
		}
	}
}

func (s *Service) enrolled() enrolledSnapshot {
	return s.snapshot(program.LeftoverVaultID)
}

func (s *Service) snapshot(vaultID string) enrolledSnapshot {
	idx := s.published.Load()
	if idx == nil {
		return enrolledSnapshot{}
	}
	if snap := idx.byVault[vaultID]; snap != nil {
		return *snap
	}
	return enrolledSnapshot{}
}

func periodAllowanceSats(rec *policy.VaultRecord, cred *policy.Credential) int64 {
	if rec != nil && rec.PeriodAllowanceSats > 0 {
		return rec.PeriodAllowanceSats
	}
	if cred != nil && cred.PeriodAllowanceSats > 0 {
		return cred.PeriodAllowanceSats
	}
	return program.PeriodAllowanceSats
}

func (s *Service) routeVaultID(vaultID string) (string, error) {
	id := strings.TrimSpace(vaultID)
	if id != "" {
		return id, nil
	}
	if s != nil && s.MultiTenantEnrollment {
		return "", apperr.ErrVaultIDRequired
	}
	return program.LeftoverVaultID, nil
}

func (s *Service) resolveSpendVault(vaultID string) (string, enrolledSnapshot, error) {
	id, snap, _, err := s.resolveSpendVaultRecord(vaultID)
	return id, snap, err
}

func (s *Service) resolveSpendVaultRecord(vaultID string) (string, enrolledSnapshot, *policy.VaultRecord, error) {
	id, err := s.routeVaultID(vaultID)
	if err != nil {
		return "", enrolledSnapshot{}, nil, err
	}
	snap := s.snapshot(id)
	if snap.Operational == nil {
		return "", enrolledSnapshot{}, nil, fmt.Errorf("not enrolled")
	}
	if s.Ledger == nil || !s.Ledger.MultiTenantReady() {
		if id != program.LeftoverVaultID {
			return "", enrolledSnapshot{}, nil, fmt.Errorf("not enrolled")
		}
		return id, snap, nil, nil
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return "", enrolledSnapshot{}, nil, err
	}
	defer zeroServiceBytes(key)
	rec, _, err := s.Ledger.LoadVerifiedVault(id, key)
	if err != nil {
		return "", enrolledSnapshot{}, nil, err
	}
	if rec == nil && id != program.LeftoverVaultID {
		return "", enrolledSnapshot{}, nil, fmt.Errorf("not enrolled")
	}
	return id, snap, rec, nil
}

func (s *Service) vaultCosignerSigner(rec *policy.VaultRecord) (Signer, error) {
	if rec != nil && rec.CosignerMode == policy.CosignerModeLegacyDirectV0 {
		return nil, apperr.ErrLegacyMasterSign
	}
	if rec == nil || rec.CosignerMode == "" {
		if isNilInterface(s.VaultSigner) {
			return nil, apperr.ErrLegacyMasterSign
		}
		return s.VaultSigner, nil
	}
	master, err := s.vaultCosignerMaster()
	if err != nil {
		return nil, err
	}
	if err := policy.VerifyVaultCosignerPub(master, *rec); err != nil {
		return nil, err
	}
	child, err := policy.DeriveVaultCosignerScalar(master, rec.VaultID, rec.CosignerMode)
	if err != nil {
		return nil, err
	}
	return LocalSigner{Priv: child}, nil
}

func (s *Service) rejectCrossVaultCredential(vaultID string, credID []byte) error {
	idx := s.published.Load()
	if idx == nil || len(credID) == 0 {
		return nil
	}
	mapped, ok := idx.byCred[hex.EncodeToString(credID)]
	if ok && mapped != vaultID {
		return fmt.Errorf("credential does not belong to this vault")
	}
	return nil
}

// Status is the first-vault snapshot used by in-process tests. HTTP never
// calls this for an unauthenticated dump; see PublicStatus and StatusFor.
func (s *Service) Status(ctx context.Context) (Status, error) {
	return s.statusFor(ctx, program.LeftoverVaultID)
}

// StatusFor returns one tenant the caller already named. An empty id is
// rejected so spend/status cannot fall through to the first vault.
func (s *Service) StatusFor(ctx context.Context, vaultID string) (Status, error) {
	if strings.TrimSpace(vaultID) == "" {
		return Status{}, fmt.Errorf("vault id required")
	}
	return s.statusFor(ctx, vaultID)
}

// PublicStatus is the unauthenticated GET /v1/status body. It never includes
// a vault id, addresses, pubs, or remaining allowance.
func (s *Service) PublicStatus() (PublicStatus, error) {
	cfg := s.runtimeConfig()
	if err := cfg.Validate(); err != nil {
		return PublicStatus{}, fmt.Errorf("deployment: %w", err)
	}
	st := PublicStatus{
		Network:              cfg.Network,
		ClientOrigin:         cfg.ClientOrigin,
		RPID:                 cfg.RPID,
		TemplateVersion:      publicEnrollTemplate(s),
		PolicyVersion:        program.PolicyVersion,
		OperationalCSVBlocks: cfg.OperationalCSVBlocks,
		SavingsCSVBlocks:     cfg.SavingsCSVBlocks,
	}
	st.EnrollmentMode, st.EnrollmentExpiresAt = s.publicEnrollmentMode()
	return st, nil
}

// publicEnrollmentMode is the unauthenticated setup state. Invite-gated
// multi-tenant does not inherit the singleton 30-minute first-claim window;
// each invite has its own expires_at.
func (s *Service) publicEnrollmentMode() (mode, expires string) {
	cfg := s.runtimeConfig()
	if cfg.Network == deployment.NetworkRegtest {
		return "open", ""
	}
	if s.MultiTenantEnrollment {
		return "token", ""
	}
	deadline := ""
	if !s.EnrollmentDeadline.IsZero() {
		deadline = s.EnrollmentDeadline.UTC().Format(time.RFC3339)
	}
	if s.EnrollmentDeadline.IsZero() || !s.currentEnrollmentTime().Before(s.EnrollmentDeadline) {
		return "expired", deadline
	}
	if s.OpenEnrollment {
		return "open", deadline
	}
	if len(s.EnrollmentTokenHash) == sha256.Size {
		return "token", deadline
	}
	return "unavailable", deadline
}

func (s *Service) statusFor(ctx context.Context, vaultID string) (Status, error) {
	if vaultID == "" {
		return Status{}, fmt.Errorf("vault id required")
	}
	if err := s.attachLedgerIntegrity(); err != nil {
		return Status{}, err
	}
	cfg := s.runtimeConfig()
	if err := cfg.Validate(); err != nil {
		return Status{}, fmt.Errorf("deployment: %w", err)
	}
	cred, err := s.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		return Status{}, err
	}
	if cred == nil && vaultID != program.LeftoverVaultID {
		return Status{}, fmt.Errorf("not enrolled")
	}
	spent, err := s.Ledger.SpentInPeriod(ctx, vaultID, s.Ledger.PeriodStart())
	if err != nil {
		return Status{}, err
	}
	allowance := periodAllowanceSats(nil, cred)
	txCap := program.TxRecipientCapSats
	feeCap := program.AbsoluteFeeCeiling
	feerate := program.FeerateCeilingSatPerV
	policyVersion := program.PolicyVersion
	if cred != nil {
		if cred.TxRecipientCapSats > 0 {
			txCap = cred.TxRecipientCapSats
		}
		if cred.AbsoluteFeeCapSats >= 0 {
			feeCap = cred.AbsoluteFeeCapSats
		}
		if cred.FeerateCapSatPerV > 0 {
			feerate = cred.FeerateCapSatPerV
		}
		if cred.PolicyVersion != "" {
			policyVersion = cred.PolicyVersion
		}
	}
	rem := allowance - spent
	if rem < 0 {
		rem = 0
	}
	st := Status{
		Enrolled:             cred != nil,
		Network:              cfg.Network,
		ClientOrigin:         cfg.ClientOrigin,
		RPID:                 cfg.RPID,
		VaultID:              vaultID,
		TemplateVersion:      publicEnrollTemplate(s),
		PolicyVersion:        policyVersion,
		OperationalCSVBlocks: cfg.OperationalCSVBlocks,
		SavingsCSVBlocks:     cfg.SavingsCSVBlocks,
		PeriodAllowance:      allowance,
		PeriodSpent:          spent,
		PeriodRemaining:      rem,
		TxCap:                txCap,
		AbsoluteFeeCap:       feeCap,
		FeerateCapSatPerV:    feerate,
	}
	if cred != nil {
		st.EnrollmentMode = "closed"
	} else {
		st.EnrollmentMode, st.EnrollmentExpiresAt = s.publicEnrollmentMode()
	}
	snap := s.snapshot(vaultID)
	if cred == nil {
		if s.ExternalOwnerWallet != nil {
			st.ExternalOwnerWalletPub = hex.EncodeToString(s.ExternalOwnerWallet.SerializeCompressed())
		}
		if s.VaultCosignerPub != nil {
			st.VaultCosignerBasePub = hex.EncodeToString(s.VaultCosignerPub.SerializeCompressed())
		}
		if s.ArkadeCosignerPub != nil {
			st.ArkadeCosignerBasePub = hex.EncodeToString(s.ArkadeCosignerPub.SerializeCompressed())
		}
	}
	if cred != nil {
		// Report the persisted descriptor inputs, not merely mutable runtime
		// fields. LoadVaults/Register already require these to match runtime.
		st.TemplateVersion = cred.TemplateVersion
		if isV5Template(cred.TemplateVersion) && len(cred.RecoveryKey) > 0 {
			if pub, err := btcec.ParsePubKey(cred.RecoveryKey); err == nil && !knownFixtureXOnly(schnorr.SerializePubKey(pub)) {
				st.RecoveryKeyPub = hex.EncodeToString(cred.RecoveryKey)
			}
		}
		st.ExternalOwnerWalletPub = hex.EncodeToString(cred.ExternalOwnerWallet)
		st.VaultCosignerBasePub = hex.EncodeToString(cred.VaultCosignerBase)
		st.ArkadeCosignerBasePub = hex.EncodeToString(cred.ArkadeCosignerBase)
		st.ArkadeCosignerOrigin = cred.ArkadeCosignerOrigin
		st.ArkadeCosignerVersion = cred.ArkadeCosignerVersion
		envelope, envelopeErr := s.loadVerifiedEnvelopeFor(vaultID, cred.ID)
		if envelopeErr != nil {
			return Status{}, envelopeErr
		}
		st.PasskeyLoginAvailable = envelope != nil
		st.Warnings = statusWarnings(cred)
	}
	if snap.Operational != nil {
		st.OperationalAddr = snap.Operational.Address
		st.OperationalScript = hex.EncodeToString(snap.Operational.PkScript)
		if snap.Operational.TweakedVaultCosigner != nil {
			st.TweakedVaultCosignerXOnly = hex.EncodeToString(schnorr.SerializePubKey(snap.Operational.TweakedVaultCosigner))
		}
		if snap.Operational.TweakedArkadeCosigner != nil {
			st.TweakedArkadeCosignerXOnly = hex.EncodeToString(schnorr.SerializePubKey(snap.Operational.TweakedArkadeCosigner))
		}
	}
	if snap.Savings != nil {
		st.SavingsAddr = snap.Savings.Address
		st.SavingsScript = hex.EncodeToString(snap.Savings.PkScript)
		var forbidden []*btcec.PublicKey
		if snap.VaultCosignerBase != nil {
			forbidden = append(forbidden, snap.VaultCosignerBase)
		}
		if snap.Operational != nil && snap.Operational.TweakedVaultCosigner != nil {
			forbidden = append(forbidden, snap.Operational.TweakedVaultCosigner)
		}
		if snap.ArkadeCosignerBase != nil {
			forbidden = append(forbidden, snap.ArkadeCosignerBase)
		}
		if snap.Operational != nil && snap.Operational.TweakedArkadeCosigner != nil {
			forbidden = append(forbidden, snap.Operational.TweakedArkadeCosigner)
		}
		st.SavingsExcludesRoutineCosigners = snap.Savings.AssertNoRoutineCosigners(forbidden...) == nil
	}
	if snap.PhoneRoutineBIP340 != nil {
		st.PhoneRoutineBIP340Pub = hex.EncodeToString(snap.PhoneRoutineBIP340.SerializeCompressed())
	}
	if cred != nil && len(cred.PhoneDirectP256) > 0 {
		st.PhoneDirectP256 = hex.EncodeToString(cred.PhoneDirectP256)
	}
	s.fillVtxoStatus(&st, vaultID, snap)
	return st, nil
}

func (s *Service) fillVtxoStatus(st *Status, vaultID string, snap enrolledSnapshot) {
	if st == nil {
		return
	}
	st.VtxoExitDelay = program.VaultPolicyV1ExitDelay
	st.VtxoExitDelayUnit = program.VaultPolicyV1ExitDelayUnit
	if vaultID == "" || snap.PhoneRoutineBIP340 == nil {
		return
	}
	priv, err := s.deriveVtxoVaultCosigner(vaultID)
	if err == nil && priv != nil {
		st.VtxoVaultCosignerPub = hex.EncodeToString(priv.PubKey().SerializeCompressed())
	}
	tree, err := s.buildVtxoPolicyTree(vaultID, snap)
	if err != nil || tree == nil {
		// Fail-closed: empty address fields stay present. Reserve still
		// requires policy dest from the vault-policy-v1 tree.
		return
	}
	st.SpendingArkAddress = tree.ArkAddress
	st.SpendingArkScript = hex.EncodeToString(tree.PkScript)
	st.SpendingOnchainAddress = tree.OnchainAddress
	st.SpendingOnchainScript = hex.EncodeToString(tree.PkScript)
	if tree.TweakedEmulator != nil {
		st.VtxoTweakedEmulatorPub = hex.EncodeToString(tree.TweakedEmulator.SerializeCompressed())
	}
	if tree.DelegatePub != nil {
		st.VtxoDelegatePub = hex.EncodeToString(tree.DelegatePub.SerializeCompressed())
	}
}

// DraftRequest builds an empty-witness routine PSBT the browser can bind.
type DraftRequest struct {
	VaultID         string `json:"vaultId,omitempty"`
	PrevTxHex       string `json:"prevTxHex"`
	Vout            uint32 `json:"vout"`
	RecipientScript string `json:"recipientScript"`
	RecipientAmount int64  `json:"recipientAmount"`
	Fee             int64  `json:"fee"`
}

func (s *Service) Draft(req DraftRequest) (string, error) {
	return s.DraftContext(context.Background(), req)
}

// DraftContext bounds transaction parsing, hashing, classification and tree
// work under the same non-queueing verification budget as signing routes.
func (s *Service) DraftContext(ctx context.Context, req DraftRequest) (string, error) {
	_, snap, err := s.resolveSpendVault(req.VaultID)
	if err != nil {
		return "", err
	}
	op := snap.Operational
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	raw, err := decodeHex(req.PrevTxHex)
	if err != nil {
		return "", err
	}
	prev := wire.NewMsgTx(2)
	if err := prev.Deserialize(bytes.NewReader(raw)); err != nil {
		return "", fmt.Errorf("prev tx: %w", err)
	}
	dest, err := decodeHex(req.RecipientScript)
	if err != nil {
		return "", err
	}
	if req.RecipientAmount <= 0 || req.Fee < 0 {
		return "", fmt.Errorf("invalid amount")
	}
	built, err := vault.BuildRoutineSpend(vault.SpendParams{
		Vault:           op,
		PrevTx:          prev,
		PrevOutPoint:    wire.OutPoint{Hash: prev.TxHash(), Index: req.Vout},
		RecipientScript: dest,
		RecipientAmount: req.RecipientAmount,
		Fee:             req.Fee,
	})
	if err != nil {
		return "", err
	}
	if _, err := classifySpend(built.Packet, op); err != nil {
		return "", err
	}
	return built.Packet.B64Encode()
}

// BindRequest carries the off-chain WebAuthn assertion plus the compact
// direct-auth signature. Only directSig is written into the packet witness.
type BindRequest struct {
	VaultID           string `json:"vaultId,omitempty"`
	PSBT              string `json:"psbt"`
	CredentialID      string `json:"credentialId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	DirectSig         string `json:"directSig"`
}

func (s *Service) Bind(req BindRequest) (string, error) {
	return s.BindContext(context.Background(), req)
}

// BindContext verifies and binds a direct-auth witness under the shared
// bounded crypto-verification budget.
func (s *Service) BindContext(ctx context.Context, req BindRequest) (string, error) {
	vaultID, snap, err := s.resolveSpendVault(req.VaultID)
	if err != nil {
		return "", err
	}
	op := snap.Operational
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	ptx, _, err := parseAndVerifyPrevout(req.PSBT)
	if err != nil {
		return "", err
	}
	if _, err := classifySpend(ptx, op); err != nil {
		return "", err
	}
	assertion, err := decodeAssertion(AuthorizeRequest{
		CredentialID: req.CredentialID, ClientDataJSON: req.ClientDataJSON,
		AuthenticatorData: req.AuthenticatorData, Signature: req.Signature,
	})
	if err != nil {
		return "", err
	}
	if err := rejectPRF(assertion.ClientDataJSON); err != nil {
		return "", err
	}
	ch, err := vault.Challenge(ptx, op)
	if err != nil {
		return "", err
	}
	cred, err := s.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		return "", err
	}
	if cred == nil {
		return "", fmt.Errorf("not enrolled")
	}
	verified, err := webauthn.Validate(assertion, webauthn.Expected{
		CredentialID: cred.ID, WebAuthnP256: cred.WebAuthnP256, Challenge: ch,
		Origin: cred.Origin, RPID: cred.RPID,
	})
	if err != nil {
		return "", err
	}
	if err := s.advanceSignCount(vaultID, cred.ID, verified.SignCount); err != nil {
		return "", err
	}
	directSig, err := decodeHex(req.DirectSig)
	if err != nil {
		return "", fmt.Errorf("directSig: %w", err)
	}
	if err := verifyDirectAuth(cred.PhoneDirectP256, ch, directSig); err != nil {
		return "", err
	}
	if err := vault.SetPacketWitness(ptx.UnsignedTx, wire.TxWitness{directSig}); err != nil {
		return "", err
	}
	return ptx.B64Encode()
}

// PreflightRequest is a non-signing challenge request.
type PreflightRequest struct {
	VaultID string `json:"vaultId,omitempty"`
	PSBT    string `json:"psbt"`
}

type PreflightResponse struct {
	Challenge string `json:"challenge"`
}

func (s *Service) Preflight(rawPSBT string) (*PreflightResponse, error) {
	return s.PreflightRequestContext(context.Background(), PreflightRequest{PSBT: rawPSBT})
}

func (s *Service) PreflightContext(ctx context.Context, rawPSBT string) (*PreflightResponse, error) {
	return s.PreflightRequestContext(ctx, PreflightRequest{PSBT: rawPSBT})
}

// PreflightRequestContext admits PSBT parsing and sighash computation only while a
// bounded verification slot is available.
func (s *Service) PreflightRequestContext(ctx context.Context, req PreflightRequest) (*PreflightResponse, error) {
	_, snap, err := s.resolveSpendVault(req.VaultID)
	if err != nil {
		return nil, err
	}
	op := snap.Operational
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ptx, _, err := parseAndVerifyPrevout(req.PSBT)
	if err != nil {
		return nil, err
	}
	if _, err := classifySpend(ptx, op); err != nil {
		return nil, err
	}
	ch, err := vault.Challenge(ptx, op)
	if err != nil {
		return nil, err
	}
	return &PreflightResponse{Challenge: hex.EncodeToString(ch)}, nil
}

// AuthorizeRequest is the field-by-field signing request. No PRF fields.
type AuthorizeRequest struct {
	VaultID           string `json:"vaultId,omitempty"`
	PSBT              string `json:"psbt"`
	CredentialID      string `json:"credentialId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
}

func (s *Service) Authorize(ctx context.Context, req AuthorizeRequest) (signedPSBT string, replay bool, err error) {
	if err := s.attachLedgerIntegrity(); err != nil {
		return "", false, err
	}
	vaultID, snap, rec, err := s.resolveSpendVaultRecord(req.VaultID)
	if err != nil {
		return "", false, err
	}
	op := snap.Operational
	ptx, cl, challenge, err := s.verifyAuthorizeRequest(ctx, req, op, vaultID)
	if err != nil {
		return "", false, err
	}

	requestPSBT, err := ptx.B64Encode()
	if err != nil {
		return "", false, err
	}
	if s.VaultSigner == nil || s.ArkadeCosignerSigner == nil || op.TweakedVaultCosigner == nil || op.TweakedArkadeCosigner == nil {
		return "", false, fmt.Errorf("both VaultCosigner and ArkadeCosigner signers are required")
	}

	timeout := s.SignTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	vaultSigner, err := s.vaultCosignerSigner(rec)
	if err != nil {
		return "", false, err
	}
	allowance := periodAllowanceSats(rec, nil)
	signed, replay, err := s.Ledger.IssueSequential(
		ctx, vaultID, challenge, requestPSBT,
		cl.Recipient.Value, cl.Fee, allowance,
		func(issueCtx context.Context, storedRequest string) (string, error) {
			if err := issueCtx.Err(); err != nil {
				return "", err
			}
			// Start the signing window only after Issue has serialized this
			// caller and committed its reservation. Creating it earlier lets a
			// queued request expire while waiting, then reserve budget and
			// call Sign with a dead context.
			signCtx, cancel := context.WithTimeout(issueCtx, timeout)
			defer cancel()
			return signExactStage(
				signCtx, storedRequest, vaultSigner,
				schnorr.SerializePubKey(op.TweakedVaultCosigner), "VaultCosigner",
			)
		},
		func(issueCtx context.Context, storedVaultPSBT string) (string, error) {
			if err := issueCtx.Err(); err != nil {
				return "", err
			}
			vaultStage, _, err := parseAndVerifyPrevout(storedVaultPSBT)
			if err != nil {
				return "", fmt.Errorf("stored VaultCosigner stage: %w", err)
			}
			if err := verifyExactRoutineSignatures(
				vaultStage, op, op.Record.PhoneRoutineBIP340, op.TweakedVaultCosigner,
			); err != nil {
				return "", fmt.Errorf("stored VaultCosigner stage: %w", err)
			}
			signCtx, cancel := context.WithTimeout(issueCtx, timeout)
			defer cancel()
			completed, err := signExactStage(
				signCtx, storedVaultPSBT, s.ArkadeCosignerSigner,
				schnorr.SerializePubKey(op.TweakedArkadeCosigner), "ArkadeCosigner",
			)
			if err != nil {
				return "", err
			}
			completedPacket, _, err := parseAndVerifyPrevout(completed)
			if err != nil {
				return "", err
			}
			if err := verifyExactRoutineSignatures(
				completedPacket, op, op.Record.PhoneRoutineBIP340, op.TweakedVaultCosigner, op.TweakedArkadeCosigner,
			); err != nil {
				return "", err
			}
			return completed, nil
		},
	)
	if err != nil {
		return "", false, mapLedgerBusy(err)
	}
	return signed, replay, nil
}

func mapLedgerBusy(err error) error {
	if errors.Is(err, policy.ErrIssuanceBusy) || errors.Is(err, policy.ErrRecoveryBusy) {
		return apperr.ErrBusy
	}
	return err
}

func (s *Service) verifyAuthorizeRequest(ctx context.Context, req AuthorizeRequest, op *vault.Built, vaultID string) (*psbt.Packet, *Classified, []byte, error) {
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer release()
	ptx, _, err := parseAndVerifyPrevout(req.PSBT)
	if err != nil {
		return nil, nil, nil, err
	}
	cl, err := classifySpend(ptx, op)
	if err != nil {
		return nil, nil, nil, err
	}
	challenge, err := s.verifyAuthorization(req, ptx, op, vaultID)
	if err != nil {
		return nil, nil, nil, err
	}
	return ptx, cl, challenge, nil
}

func (s *Service) verifyAuthorization(req AuthorizeRequest, ptx *psbt.Packet, op *vault.Built, vaultID string) ([]byte, error) {

	assertion, err := decodeAssertion(req)
	if err != nil {
		return nil, err
	}
	if err := rejectPRF(assertion.ClientDataJSON); err != nil {
		return nil, err
	}
	cred, err := s.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("not enrolled")
	}
	if err := s.rejectCrossVaultCredential(vaultID, cred.ID); err != nil {
		return nil, err
	}

	challenge, err := vault.Challenge(ptx, op)
	if err != nil {
		return nil, err
	}
	verified, err := webauthn.Validate(assertion, webauthn.Expected{
		CredentialID: cred.ID,
		WebAuthnP256: cred.WebAuthnP256,
		Challenge:    challenge,
		Origin:       cred.Origin,
		RPID:         cred.RPID,
	})
	if err != nil {
		return nil, err
	}
	if err := s.advanceSignCount(vaultID, cred.ID, verified.SignCount); err != nil {
		return nil, err
	}

	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return nil, err
	}
	if len(packet) != 1 {
		return nil, fmt.Errorf("emulator packet")
	}
	if len(packet[0].Witness) != 1 || len(packet[0].Witness[0]) != 64 {
		return nil, fmt.Errorf("packet witness must be the one-item 64-byte direct signature")
	}
	if err := verifyDirectAuth(cred.PhoneDirectP256, challenge, packet[0].Witness[0]); err != nil {
		return nil, err
	}
	if err := verifyPhoneRoutineSignature(ptx, op); err != nil {
		return nil, err
	}
	return challenge, nil
}

func (s *Service) acquireVerification(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.verificationOnce.Do(func() {
		limit := s.MaxConcurrentVerifications
		if limit <= 0 {
			limit = defaultConcurrentVerifications
		}
		s.verificationSlots = make(chan struct{}, limit)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.verificationSlots <- struct{}{}:
		return func() { <-s.verificationSlots }, nil
	default:
		return nil, ErrVerificationBusy
	}
}

func (s *Service) runtimeConfig() deployment.Config {
	if s == nil {
		return deployment.Default()
	}
	return s.Deployment.WithDefaults()
}

func (s *Service) credentialIntegrityKey() ([]byte, error) {
	if len(s.CredentialIntegrityKey) == sha256.Size {
		return append([]byte(nil), s.CredentialIntegrityKey...), nil
	}
	if len(s.CredentialIntegrityKey) != 0 {
		return nil, fmt.Errorf("credential integrity key must be 32 bytes")
	}
	if s.runtimeConfig().Network != deployment.NetworkRegtest {
		return nil, fmt.Errorf("credential integrity key is required outside regtest")
	}
	// This is intentionally public and provides corruption detection only for
	// the disposable regtest demo. Production authorizer construction never
	// accepts this fallback.
	digest := sha256.Sum256([]byte(regtestCredentialIntegrityDomain))
	return append([]byte(nil), digest[:]...), nil
}

func (s *Service) sealCredential(cred *policy.Credential) error {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	if err := policy.SealCredential(cred, key); err != nil {
		return fmt.Errorf("seal credential record: %w", err)
	}
	return nil
}

func (s *Service) sealCredentialEnvelope(envelope *policy.CredentialEnvelope, credentialID []byte) error {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	if err := policy.SealCredentialEnvelope(envelope, credentialID, key); err != nil {
		return fmt.Errorf("seal credential envelope: %w", err)
	}
	return nil
}

func (s *Service) loadVerifiedEnvelopeFor(vaultID string, credentialID []byte) (*policy.CredentialEnvelope, error) {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return nil, err
	}
	defer zeroServiceBytes(key)
	vaultID, err = s.routeVaultID(vaultID)
	if err != nil {
		return nil, err
	}
	if s.Ledger != nil && s.Ledger.MultiTenantReady() {
		envelope, err := s.Ledger.GetVaultEnvelope(vaultID)
		if err != nil {
			return nil, err
		}
		if envelope != nil {
			if vaultID == program.LeftoverVaultID {
				if err := policy.VerifyCredentialEnvelope(envelope, credentialID, key); err != nil {
					return nil, fmt.Errorf("authoritative credential envelope integrity verification failed: %w; restore a verified backup or use a reviewed migration", err)
				}
			} else if err := policy.VerifyVaultEnvelope(envelope, vaultID, credentialID, key); err != nil {
				return nil, fmt.Errorf("authoritative credential envelope integrity verification failed: %w; restore a verified backup or use a reviewed migration", err)
			}
			return envelope, nil
		}
		if vaultID != program.LeftoverVaultID {
			return nil, nil
		}
	}
	if vaultID != program.LeftoverVaultID {
		return nil, nil
	}
	envelope, err := s.Ledger.GetCredentialEnvelope()
	if err != nil || envelope == nil {
		return envelope, err
	}
	if err := policy.VerifyCredentialEnvelope(envelope, credentialID, key); err != nil {
		return nil, fmt.Errorf("authoritative credential envelope integrity verification failed: %w; restore a verified backup or use a reviewed migration", err)
	}
	return envelope, nil
}

func (s *Service) loadVerifiedCredential() (*policy.Credential, error) {
	return s.loadVerifiedCredentialFor(program.LeftoverVaultID)
}

func (s *Service) loadVerifiedCredentialFor(vaultID string) (*policy.Credential, error) {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return nil, err
	}
	defer zeroServiceBytes(key)
	vaultID, err = s.routeVaultID(vaultID)
	if err != nil {
		return nil, err
	}
	if vaultID == program.LeftoverVaultID {
		cred, err := s.Ledger.GetCredential()
		if err != nil || cred == nil {
			return cred, err
		}
		if err := policy.VerifyCredentialIntegrity(cred, key); err != nil {
			return nil, fmt.Errorf("authoritative credential integrity verification failed: %w; do not delete deployment data: stop the signer and restore a verified backup or use a reviewed migration", err)
		}
		return cred, nil
	}
	rec, vcred, err := s.Ledger.LoadVerifiedVault(vaultID, key)
	if err != nil || rec == nil || vcred == nil {
		return nil, err
	}
	out := rec.ToCredential(*vcred)
	return &out, nil
}

func zeroServiceBytes(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}

// RuntimeConfig returns the validated public identity used by HTTP and the
// browser. Callers receive a value copy and cannot mutate Service state.
func (s *Service) RuntimeConfig() (deployment.Config, error) {
	cfg := s.runtimeConfig()
	return cfg, cfg.Validate()
}

func decodeAssertion(req AuthorizeRequest) (webauthn.Assertion, error) {
	id, err := decodeHex(req.CredentialID)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	cd, err := decodeHex(req.ClientDataJSON)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	ad, err := decodeHex(req.AuthenticatorData)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	sig, err := decodeHex(req.Signature)
	if err != nil {
		return webauthn.Assertion{}, err
	}
	return webauthn.Assertion{
		CredentialID:      id,
		ClientDataJSON:    cd,
		AuthenticatorData: ad,
		DERSignature:      sig,
	}, nil
}

func parseAndVerifyPrevout(raw string) (*psbt.Packet, *wire.MsgTx, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
	if err != nil {
		return nil, nil, fmt.Errorf("psbt: %w", err)
	}
	prev, err := vault.RequireVerifiedPrevout(ptx)
	if err != nil {
		return nil, nil, err
	}
	return ptx, prev, nil
}

func verifyDirectAuth(directPub, digest, compact []byte) error {
	pub, err := webauthn.ParseCompressedP256(directPub)
	if err != nil {
		return fmt.Errorf("direct p256: %w", err)
	}
	if err := webauthn.VerifyDigestLowS(pub, digest, compact); err != nil {
		return fmt.Errorf("direct auth: %w", err)
	}
	return nil
}

func (s *Service) advanceSignCount(vaultID string, credID []byte, count uint32) error {
	if s == nil || s.Ledger == nil {
		return nil
	}
	if err := s.attachLedgerIntegrity(); err != nil {
		return err
	}
	return s.Ledger.AdvanceSignCount(vaultID, credID, count)
}

func rejectPRF(clientDataJSON []byte) error {
	if webauthn.ContainsPRFField(clientDataJSON) {
		return fmt.Errorf("prf material rejected")
	}
	return nil
}

func decodeHex(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex: %w", err)
	}
	return b, nil
}

func init() {
	log.SetFlags(log.LstdFlags)
}
