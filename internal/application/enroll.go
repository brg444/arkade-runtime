package application

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
)

// ErrEnrollmentClosed is returned when multi-tenant enrollment is not armed.
// HTTP maps it to 404 so the live authorizer stays unreachable.
var ErrEnrollmentClosed = errors.New("not found")

const pendingEnrollmentTTL = 5 * time.Minute

// InviteView is the public invite lookup. It never includes consumed_vault_id.
type InviteView struct {
	CanEnroll bool    `json:"canEnroll"`
	VaultID   *string `json:"vaultId"`
}

// EnrollStartRequest is accepted for symmetry; the invite is the header token.
type EnrollStartRequest struct{}

// EnrollStartResponse is the server-assigned vault identity plus create options.
type EnrollStartResponse struct {
	Handle    string `json:"handle"`
	VaultID   string `json:"vaultId"`
	Challenge string `json:"challenge"`
	RPID      string `json:"rpId"`
	RPName    string `json:"rpName"`
	UserID    string `json:"userId"`
	UserName  string `json:"userName"`
	TimeoutMS int    `json:"timeoutMs"`
}

// EnrollFinishRequest binds the pending handle to the created credential.
type EnrollFinishRequest struct {
	Handle            string `json:"handle"`
	UserHandle        string `json:"userHandle"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	AttestationObject string `json:"attestationObject,omitempty"`
	RegisterRequest
}

func (s *Service) requireMultiTenantEnrollment() error {
	if s == nil || !s.MultiTenantEnrollment {
		return ErrEnrollmentClosed
	}
	return nil
}

// InviteStatus reports whether the token can still enroll. Failures are generic.
func (s *Service) InviteStatus(token string) (InviteView, error) {
	if err := s.requireMultiTenantEnrollment(); err != nil {
		return InviteView{}, err
	}
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return InviteView{}, fmt.Errorf("invite not available")
	}
	inv, err := s.Ledger.GetInvite(hash)
	if err != nil {
		return InviteView{}, fmt.Errorf("invite not available")
	}
	if inv == nil {
		return InviteView{}, fmt.Errorf("invite not available")
	}
	if inv.ConsumedVaultID != "" {
		id := inv.ConsumedVaultID
		return InviteView{CanEnroll: false, VaultID: &id}, nil
	}
	if !inv.Usable(s.currentEnrollmentTime()) {
		return InviteView{}, fmt.Errorf("invite not available")
	}
	return InviteView{CanEnroll: true, VaultID: nil}, nil
}

// StartEnrollment assigns a vault id for an unused invite and does not consume it.
func (s *Service) StartEnrollment(token string) (*EnrollStartResponse, error) {
	if err := s.requireMultiTenantEnrollment(); err != nil {
		return nil, err
	}
	if err := s.runtimeConfig().Validate(); err != nil {
		return nil, fmt.Errorf("deployment: %w", err)
	}
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	now := s.currentEnrollmentTime().UTC()
	vaultID, err := newOpaqueVaultID()
	if err != nil {
		return nil, err
	}
	handle, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	challenge, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	pending, err := s.Ledger.ReservePendingEnrollment(policy.PendingEnrollment{
		Handle:    handle,
		VaultID:   vaultID,
		TokenHash: hash,
		Challenge: challenge,
		ExpiresAt: now.Add(pendingEnrollmentTTL).Format(time.RFC3339),
		CreatedAt: now.Format(time.RFC3339),
	})
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	cfg := s.runtimeConfig()
	return &EnrollStartResponse{
		Handle:    pending.Handle,
		VaultID:   pending.VaultID,
		Challenge: hex.EncodeToString(pending.Challenge),
		RPID:      cfg.RPID,
		RPName:    "Arkade Vault",
		UserID:    hex.EncodeToString([]byte(pending.VaultID)),
		UserName:  "vault",
		TimeoutMS: int(pendingEnrollmentTTL / time.Millisecond),
	}, nil
}

// ProposeEnrollment returns the descriptor that Finish will persist. It does
// not consume the invite or write a vault row.
func (s *Service) ProposeEnrollment(token string, req EnrollFinishRequest) (*ProposedEnrollment, error) {
	if err := s.requireMultiTenantEnrollment(); err != nil {
		return nil, err
	}
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	pending, err := s.Ledger.GetPendingByHandle(req.Handle)
	if err != nil || pending == nil {
		return nil, fmt.Errorf("pending enrollment not found")
	}
	if subtle.ConstantTimeCompare(pending.TokenHash, hash) != 1 {
		return nil, fmt.Errorf("pending enrollment not found")
	}
	now := s.currentEnrollmentTime().UTC()
	if pending.ExpiresAt != "" && pending.ExpiresAt < now.Format(time.RFC3339) {
		return nil, fmt.Errorf("pending enrollment expired")
	}
	if req.VaultID != "" && req.VaultID != pending.VaultID {
		return nil, fmt.Errorf("vault id does not match pending enrollment")
	}
	return s.previewTenantDescriptor(pending.VaultID, req.RegisterRequest)
}

func (s *Service) previewTenantDescriptor(vaultID string, req RegisterRequest) (*ProposedEnrollment, error) {
	return s.previewV5Descriptor(vaultID, req)
}

// FinishEnrollment verifies the create ceremony and CAS-consumes the invite.
func (s *Service) FinishEnrollment(ctx context.Context, token string, req EnrollFinishRequest) (*Status, error) {
	if err := s.requireMultiTenantEnrollment(); err != nil {
		return nil, err
	}
	if err := s.attachLedgerIntegrity(); err != nil {
		return nil, err
	}
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	pending, err := s.Ledger.GetPendingByHandle(req.Handle)
	if err != nil {
		return nil, fmt.Errorf("pending enrollment not found")
	}
	if pending == nil {
		if status, ok := s.acceptDuplicateFinishFromToken(hash, req); ok {
			return status, nil
		}
		return nil, fmt.Errorf("pending enrollment not found")
	}
	if subtle.ConstantTimeCompare(pending.TokenHash, hash) != 1 {
		return nil, fmt.Errorf("pending enrollment not found")
	}
	now := s.currentEnrollmentTime().UTC()
	if pending.ExpiresAt != "" && pending.ExpiresAt < now.Format(time.RFC3339) {
		return nil, fmt.Errorf("pending enrollment expired")
	}
	cfg := s.runtimeConfig()
	clientData, err := decodeHex(req.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("clientDataJSON: %w", err)
	}
	authData, err := decodeHex(req.AuthenticatorData)
	if err != nil {
		return nil, fmt.Errorf("authenticatorData: %w", err)
	}
	if req.AttestationObject != "" {
		obj, err := decodeHex(req.AttestationObject)
		if err != nil {
			return nil, fmt.Errorf("attestationObject: %w", err)
		}
		fromObj, err := webauthn.ParseAttestationObject(obj)
		if err != nil {
			return nil, fmt.Errorf("attestationObject: %w", err)
		}
		if !bytesEqualConst(fromObj, authData) {
			return nil, fmt.Errorf("attestationObject authData mismatch")
		}
	}
	created, err := webauthn.ValidateCreate(clientData, authData, pending.Challenge, cfg.ClientOrigin, cfg.RPID)
	if err != nil {
		return nil, fmt.Errorf("webauthn create: %w", err)
	}
	userHandle, err := decodeHex(req.UserHandle)
	if err != nil {
		return nil, fmt.Errorf("userHandle: %w", err)
	}
	if !bytesEqualConst([]byte(pending.VaultID), userHandle) {
		return nil, fmt.Errorf("userHandle does not match assigned vault")
	}
	postedID, err := decodeHex(req.CredentialID)
	if err != nil || !bytesEqualConst(created.CredentialID, postedID) {
		return nil, fmt.Errorf("credential id does not match authenticator")
	}
	postedP256, err := decodeHex(req.WebAuthnP256)
	if err != nil || !bytesEqualConst(created.WebAuthnP256, postedP256) {
		return nil, fmt.Errorf("webauthn p256 does not match authenticator")
	}
	if req.ExternalOwnerWalletXOnly == "" {
		return nil, fmt.Errorf("tenant owner pub required")
	}
	if s.afterLoadPending != nil {
		s.afterLoadPending()
	}
	err = s.createTenantVault(pending.VaultID, pending.TokenHash, req.RegisterRequest, pending)
	if err != nil {
		if status, ok := s.acceptDuplicateFinish(pending.VaultID, req.RegisterRequest); ok {
			return status, nil
		}
		return nil, err
	}
	st, err := s.statusFor(ctx, pending.VaultID)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *Service) acceptDuplicateFinishFromToken(tokenHash []byte, req EnrollFinishRequest) (*Status, bool) {
	inv, err := s.Ledger.GetInvite(tokenHash)
	if err != nil || inv == nil || inv.ConsumedVaultID == "" {
		return nil, false
	}
	userHandle, err := decodeHex(req.UserHandle)
	if err != nil || !bytesEqualConst([]byte(inv.ConsumedVaultID), userHandle) {
		return nil, false
	}
	return s.acceptDuplicateFinish(inv.ConsumedVaultID, req.RegisterRequest)
}

func (s *Service) acceptDuplicateFinish(vaultID string, req RegisterRequest) (*Status, bool) {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return nil, false
	}
	defer zeroServiceBytes(key)
	rec, cred, err := s.Ledger.LoadVerifiedVault(vaultID, key)
	if err != nil || rec == nil || cred == nil {
		return nil, false
	}
	parsed, err := s.parseRegisterRequestIndependent(req)
	if err != nil {
		return nil, false
	}
	if !bytesEqualConst(cred.CredentialID, parsed.id) ||
		!bytesEqualConst(cred.WebAuthnP256, parsed.webauthnP256) ||
		!bytesEqualConst(rec.PhoneDirectP256, parsed.phoneDirectP256) ||
		!bytesEqualConst(rec.PhoneRoutineBIP340, parsed.phoneRoutine.SerializeCompressed()) ||
		!bytesEqualConst(rec.ExternalOwnerWallet, parsed.externalOwner.SerializeCompressed()) {
		return nil, false
	}
	st, err := s.statusFor(context.Background(), vaultID)
	if err != nil {
		return nil, false
	}
	return &st, true
}

func newOpaqueVaultID() (string, error) {
	return randomHex(16)
}

func randomHex(n int) (string, error) {
	raw, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func bytesEqualConst(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
