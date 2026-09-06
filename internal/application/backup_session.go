package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/brg444/arkade-runtime/internal/webauthn"
)

const maxBackupSessions = 256
const backupSessionTTL = 8 * time.Hour

type backupSession struct {
	VaultID      string
	Purpose      string
	ExpiresAt    time.Time
	Binding      RecoveryArchiveBinding
	HeaderDigest [32]byte
}

// Discovery has no tenant lookup or credential enumeration. Each named family
// has a bounded challenge budget and shares one bounded in-memory session map.
func (s *Service) issueBackupChallenge(purpose string) (*PasskeyChallengeResponse, error) {
	idRaw, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	challenge, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	id := base64.RawURLEncoding.EncodeToString(idRaw)
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if s.sessionChallenges == nil {
		s.sessionChallenges = make(map[string]passkeyChallenge)
	}
	now := s.sessionNow()
	n := 0
	for k, v := range s.sessionChallenges {
		if !now.Before(v.ExpiresAt) {
			delete(s.sessionChallenges, k)
		} else if v.Purpose == purpose {
			n++
		}
	}
	if n >= maxBackupSessions {
		return nil, ErrVerificationBusy
	}
	s.sessionChallenges[passkeyChallengeKey("", id)] = passkeyChallenge{Purpose: purpose, Challenge: challenge, ExpiresAt: now.Add(passkeyChallengeTTL)}
	return &PasskeyChallengeResponse{ChallengeID: id, Challenge: hex.EncodeToString(challenge), ExpiresInSeconds: int64(passkeyChallengeTTL / time.Second)}, nil
}

func (s *Service) openBackup(ctx context.Context, req LightBackupOpenRequest, purpose string) (*RecoveryArchiveOpenResponse, error) {
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	challenge, err := s.consumePasskeyChallenge("", req.ChallengeID, purpose)
	if err != nil {
		return nil, failPasskeyAuth("backup challenge", nil)
	}
	cred, err := s.loadVerifiedCredentialFor(req.VaultID)
	if err != nil || !backupCredentialAllowed(cred, purpose) {
		return nil, failPasskeyAuth("backup credential", nil)
	}
	assertion, err := decodeBoundedSessionAssertion(req.SessionAssertionRequest)
	if err != nil || !bytes.Equal(assertion.CredentialID, cred.ID) {
		return nil, failPasskeyAuth("backup assertion", nil)
	}
	if err = rejectPRF(assertion.ClientDataJSON); err != nil {
		return nil, failPasskeyAuth("backup assertion", nil)
	}
	verified, err := webauthn.Validate(assertion, webauthn.Expected{CredentialID: cred.ID, WebAuthnP256: cred.WebAuthnP256, Challenge: challenge, Origin: cred.Origin, RPID: cred.RPID})
	if err != nil {
		return nil, failPasskeyAuth("backup assertion", nil)
	}
	proof, err := decodeFixedHex(req.DirectProof, 64, "backup proof")
	if err != nil {
		return nil, failPasskeyAuth("backup proof", nil)
	}
	if err = verifyDirectAuth(cred.PhoneDirectP256, passkeySessionProofDigest(purpose, challenge, cred.ID), proof); err != nil {
		return nil, failPasskeyAuth("backup proof", nil)
	}
	if err = s.advanceSignCount(req.VaultID, cred.ID, verified.SignCount); err != nil {
		return nil, err
	}
	backup, err := s.Stores.RecoveryBackup.GetRecoveryBackup(req.VaultID)
	if err != nil {
		return nil, err
	}
	session := backupSession{VaultID: req.VaultID, Purpose: purpose}
	if purpose == recoveryArchivePurpose {
		session.Binding, err = s.recoveryArchiveBinding(cred)
		if err != nil {
			return nil, err
		}
		if backup != nil {
			session.HeaderDigest, err = validateRecoveryArchive(backup.Payload, session.Binding)
			if err != nil {
				return nil, err
			}
		}
	}
	token, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(token)
	now := s.sessionNow()
	session.ExpiresAt = now.Add(backupSessionTTL)
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if s.backupSessions == nil {
		s.backupSessions = make(map[[32]byte]backupSession)
	}
	for k, v := range s.backupSessions {
		if !now.Before(v.ExpiresAt) {
			delete(s.backupSessions, k)
		}
	}
	if len(s.backupSessions) >= maxBackupSessions {
		return nil, ErrVerificationBusy
	}
	s.backupSessions[key] = session
	return &RecoveryArchiveOpenResponse{LightBackupOpenResponse: LightBackupOpenResponse{Token: hex.EncodeToString(token), VaultID: req.VaultID, ExpiresAt: session.ExpiresAt.Format(time.RFC3339), Backup: backup}, Binding: session.Binding}, nil
}

func backupCredentialAllowed(cred *policy.Credential, purpose string) bool {
	if cred == nil {
		return false
	}
	switch purpose {
	case lightBackupPurpose:
		return cred.TemplateVersion == light.Profile
	case recoveryArchivePurpose:
		return recoveryArchiveCredentialAllowed(cred)
	default:
		return false
	}
}

// Caller holds sessionMu through any archive write and first-header pin. A token
// cannot cross a named route family; neither expiry nor restart renews authority.
func (s *Service) backupSessionLocked(token, purpose string) ([32]byte, backupSession, error) {
	raw, err := decodeFixedHex(token, 32, "backup session")
	if err != nil {
		return [32]byte{}, backupSession{}, fmt.Errorf("open backup with your passkey")
	}
	key := sha256.Sum256(raw)
	session, ok := s.backupSessions[key]
	if !ok || !s.sessionNow().Before(session.ExpiresAt) {
		delete(s.backupSessions, key)
		return key, backupSession{}, fmt.Errorf("open backup with your passkey")
	}
	if session.Purpose != purpose {
		return key, backupSession{}, fmt.Errorf("backup session belongs to another program")
	}
	return key, session, nil
}
