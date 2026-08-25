package application

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
)

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

// InviteStatus reports whether the token can still enroll. Failures are generic.
func (s *Service) InviteStatus(token string) (InviteView, error) {
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return InviteView{}, fmt.Errorf("invite not available")
	}
	inv, err := s.Stores.Identity.GetInvite(hash)
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
	pending, err := s.Stores.Identity.ReservePendingEnrollment(policy.PendingEnrollment{
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
	return s.proposeEnrollment(token, req, nil)
}

// ProposeVaultBoardV2Enrollment previews the distinct v2 descriptor. It cannot
// be reached by omitting fields from the ordinary v1 enrollment request.
func (s *Service) ProposeVaultBoardV2Enrollment(token string, req EnrollFinishVaultBoardV2Request) (*ProposedEnrollment, error) {
	return s.proposeEnrollment(token, req.EnrollFinishRequest, &req.VaultBoardV2EnrollmentRequest)
}

func (s *Service) proposeEnrollment(token string, req EnrollFinishRequest, boardReq *VaultBoardV2EnrollmentRequest) (*ProposedEnrollment, error) {
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	pending, err := s.Stores.Identity.GetPendingByHandle(req.Handle)
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
	if boardReq != nil {
		return s.previewVaultBoardV2EnrollmentDescriptor(pending.VaultID, req.RegisterRequest, *boardReq)
	}
	return s.previewTenantDescriptor(pending.VaultID, req.RegisterRequest)
}

func (s *Service) previewTenantDescriptor(vaultID string, req RegisterRequest) (*ProposedEnrollment, error) {
	return s.previewSavingsDescriptor(vaultID, req)
}

// FinishEnrollment verifies the create ceremony and CAS-consumes the invite.
func (s *Service) FinishEnrollment(ctx context.Context, token string, req EnrollFinishRequest) (*Status, error) {
	return s.finishEnrollment(ctx, token, req, nil)
}

// FinishVaultBoardV2Enrollment is the only enrollment path that can create a
// vault-board-v2 binding.
func (s *Service) FinishVaultBoardV2Enrollment(ctx context.Context, token string, req EnrollFinishVaultBoardV2Request) (*Status, error) {
	return s.finishEnrollment(ctx, token, req.EnrollFinishRequest, &req.VaultBoardV2EnrollmentRequest)
}

func (s *Service) finishEnrollment(ctx context.Context, token string, req EnrollFinishRequest, boardReq *VaultBoardV2EnrollmentRequest) (*Status, error) {
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		return nil, fmt.Errorf("invite not available")
	}
	pending, err := s.Stores.Identity.GetPendingByHandle(req.Handle)
	if err != nil {
		return nil, fmt.Errorf("pending enrollment not found")
	}
	if pending == nil {
		if status, ok := s.acceptDuplicateFinishFromToken(hash, req, boardReq); ok {
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
	if boardReq == nil {
		err = s.createTenantVault(pending.VaultID, pending.TokenHash, req.RegisterRequest, pending)
	} else {
		err = s.createTenantVault(pending.VaultID, pending.TokenHash, req.RegisterRequest, pending, *boardReq)
	}
	if err != nil {
		if status, ok := s.acceptDuplicateFinish(pending.VaultID, req.RegisterRequest, boardReq); ok {
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

func (s *Service) acceptDuplicateFinishFromToken(tokenHash []byte, req EnrollFinishRequest, boardReq *VaultBoardV2EnrollmentRequest) (*Status, bool) {
	inv, err := s.Stores.Identity.GetInvite(tokenHash)
	if err != nil || inv == nil || inv.ConsumedVaultID == "" {
		return nil, false
	}
	userHandle, err := decodeHex(req.UserHandle)
	if err != nil || !bytesEqualConst([]byte(inv.ConsumedVaultID), userHandle) {
		return nil, false
	}
	return s.acceptDuplicateFinish(inv.ConsumedVaultID, req.RegisterRequest, boardReq)
}

func (s *Service) acceptDuplicateFinish(vaultID string, req RegisterRequest, boardReq ...*VaultBoardV2EnrollmentRequest) (*Status, bool) {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return nil, false
	}
	defer zeroServiceBytes(key)
	rec, cred, err := s.Stores.Identity.LoadVerifiedVault(vaultID, key)
	if err != nil || rec == nil || cred == nil {
		return nil, false
	}
	parsed, err := s.parseRegisterRequestIndependent(req)
	if err != nil {
		return nil, false
	}
	if len(boardReq) > 1 {
		return nil, false
	}
	var preview *ProposedEnrollment
	if len(boardReq) == 1 && boardReq[0] != nil {
		parsed, err = s.applyVaultBoardV2EnrollmentRequest(parsed, *boardReq[0])
		if err == nil {
			preview, err = s.previewVaultBoardV2EnrollmentDescriptor(vaultID, req, *boardReq[0])
		}
	} else {
		preview, err = s.previewTenantDescriptor(vaultID, req)
	}
	if err != nil || req.DescriptorHash == "" || req.DescriptorHash != preview.DescriptorHash {
		return nil, false
	}
	childPub, err := s.keys.enrollmentPublic(vaultID)
	if err != nil {
		return nil, false
	}
	descriptor, _, err := s.mintSavingsCredential(vaultID, parsed, childPub)
	if err != nil {
		return nil, false
	}
	wantRecord := vaultRecordFromDescriptor(descriptor)
	wantCredential := policy.VaultCredential{
		CredentialID: parsed.id, VaultID: vaultID, WebAuthnP256: parsed.webauthnP256,
		UserHandle: []byte(vaultID), Resident: true,
	}
	if policy.VaultRecordsCanonicallyEqual(*rec, wantRecord) != nil ||
		policy.VaultCredentialsCanonicallyEqual(*cred, wantCredential) != nil {
		return nil, false
	}
	if parsed.boardingProgram == program.VaultBoardV2 {
		if s.VaultBoardV2Store == nil {
			return nil, false
		}
		storedBoard, loadErr := s.VaultBoardV2Store.GetVaultBoardV2Enrollment(vaultID)
		wantBoard, _, buildErr := s.mintVaultBoardV2Enrollment(vaultID, parsed)
		if loadErr != nil || buildErr != nil || storedBoard == nil || wantBoard == nil ||
			storedBoard.Program != wantBoard.Program || !bytesEqualConst(storedBoard.BoardingPub, wantBoard.BoardingPub) ||
			!bytesEqualConst(storedBoard.CosignerPub, wantBoard.CosignerPub) || !bytesEqualConst(storedBoard.OperatorPub, wantBoard.OperatorPub) ||
			storedBoard.ExitDelay != wantBoard.ExitDelay || storedBoard.ExitDelayUnit != wantBoard.ExitDelayUnit ||
			!bytesEqualConst(storedBoard.PkScript, wantBoard.PkScript) || storedBoard.Address != wantBoard.Address {
			return nil, false
		}
	} else if s.VaultBoardV2Store != nil {
		// A consumed v2 invite may only be replayed through the explicit v2
		// endpoint. Accepting its ordinary v1 descriptor here would report
		// success for a materially different boarding contract.
		storedBoard, loadErr := s.VaultBoardV2Store.GetVaultBoardV2Enrollment(vaultID)
		if loadErr != nil || storedBoard != nil {
			return nil, false
		}
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
