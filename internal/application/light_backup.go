package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/brg444/arkade-runtime/internal/webauthn"
)

const lightBackupPurpose = "light-backup-open"
const maxLightBackupSessions = 256
const lightBackupSessionTTL = 8 * time.Hour

type lightBackupSession struct {
	VaultID   string
	ExpiresAt time.Time
}
type LightBackupOpenRequest struct {
	VaultID string `json:"vaultId"`
	SessionAssertionRequest
}
type LightBackupRequest struct {
	Token    string `json:"token"`
	Revision uint64 `json:"revision,omitempty"`
	Payload  string `json:"payload,omitempty"`
}
type LightBackupOpenResponse struct {
	Token     string              `json:"token"`
	VaultID   string              `json:"vaultId"`
	ExpiresAt string              `json:"expiresAt"`
	Backup    *policy.LightBackup `json:"backup"`
}

// The discoverable ceremony contains no credential enumeration or tenant read.
func (s *Service) IssueLightBackupChallenge() (*PasskeyChallengeResponse, error) {
	idRaw, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	challenge, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	// Reuse the bounded, single-use challenge machinery with a distinct purpose.
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
		} else if v.Purpose == lightBackupPurpose {
			n++
		}
	}
	if n >= maxLightBackupSessions {
		return nil, ErrVerificationBusy
	}
	s.sessionChallenges[passkeyChallengeKey("", id)] = passkeyChallenge{Purpose: lightBackupPurpose, Challenge: challenge, ExpiresAt: now.Add(passkeyChallengeTTL)}
	return &PasskeyChallengeResponse{ChallengeID: id, Challenge: hex.EncodeToString(challenge), ExpiresInSeconds: int64(passkeyChallengeTTL / time.Second)}, nil
}
func (s *Service) OpenLightBackup(ctx context.Context, req LightBackupOpenRequest) (*LightBackupOpenResponse, error) {
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	challenge, err := s.consumePasskeyChallenge("", req.ChallengeID, lightBackupPurpose)
	if err != nil {
		return nil, failPasskeyAuth("backup challenge", nil)
	}
	cred, err := s.loadVerifiedCredentialFor(req.VaultID)
	if err != nil || cred == nil || cred.TemplateVersion != light.Profile {
		return nil, failPasskeyAuth("backup credential", nil)
	}
	assertion, err := decodeBoundedSessionAssertion(req.SessionAssertionRequest)
	if err != nil {
		return nil, failPasskeyAuth("backup assertion", nil)
	}
	if !bytes.Equal(assertion.CredentialID, cred.ID) {
		return nil, failPasskeyAuth("backup credential", nil)
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
	if err = verifyDirectAuth(cred.PhoneDirectP256, passkeySessionProofDigest(lightBackupPurpose, challenge, cred.ID), proof); err != nil {
		return nil, failPasskeyAuth("backup proof", nil)
	}
	if err = s.advanceSignCount(req.VaultID, cred.ID, verified.SignCount); err != nil {
		return nil, err
	}
	backup, err := s.Stores.LightBackup.GetLightBackup(req.VaultID)
	if err != nil {
		return nil, err
	}
	token, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(token)
	now := s.sessionNow()
	expiry := now.Add(lightBackupSessionTTL)
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if s.lightBackupSessions == nil {
		s.lightBackupSessions = make(map[[32]byte]lightBackupSession)
	}
	for k, v := range s.lightBackupSessions {
		if !now.Before(v.ExpiresAt) {
			delete(s.lightBackupSessions, k)
		}
	}
	if len(s.lightBackupSessions) >= maxLightBackupSessions {
		return nil, ErrVerificationBusy
	}
	s.lightBackupSessions[key] = lightBackupSession{VaultID: req.VaultID, ExpiresAt: expiry}
	return &LightBackupOpenResponse{Token: hex.EncodeToString(token), VaultID: req.VaultID, ExpiresAt: expiry.Format(time.RFC3339), Backup: backup}, nil
}
func (s *Service) lightBackupVault(token string) (string, error) {
	raw, err := decodeFixedHex(token, 32, "backup session")
	if err != nil {
		return "", fmt.Errorf("open backup with your passkey")
	}
	key := sha256.Sum256(raw)
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	session, ok := s.lightBackupSessions[key]
	if !ok || !s.sessionNow().Before(session.ExpiresAt) {
		delete(s.lightBackupSessions, key)
		return "", fmt.Errorf("open backup with your passkey")
	}
	return session.VaultID, nil
}
func (s *Service) ReadLightBackup(req LightBackupRequest) (*policy.LightBackup, error) {
	id, err := s.lightBackupVault(req.Token)
	if err != nil {
		return nil, err
	}
	return s.Stores.LightBackup.GetLightBackup(id)
}
func (s *Service) WriteLightBackup(req LightBackupRequest) (*policy.LightBackup, error) {
	id, err := s.lightBackupVault(req.Token)
	if err != nil {
		return nil, err
	}
	// Strict encrypted-envelope surface: never store a recovery key or unencrypted archive.
	var header struct {
		Name       string          `json:"name"`
		Version    int             `json:"version"`
		Header     json.RawMessage `json:"header"`
		Nonce      string          `json:"nonce"`
		Ciphertext string          `json:"ciphertext"`
	}
	if len(req.Payload) > policy.MaxLightBackupBytes {
		return nil, fmt.Errorf("backup too large")
	}
	dec := json.NewDecoder(bytes.NewBufferString(req.Payload))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&header); err != nil {
		return nil, fmt.Errorf("encrypted backup required")
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("encrypted backup must contain one envelope")
	}
	if header.Name != "vaulted-light-backup" || header.Version != 2 || len(header.Header) > 16384 || len(header.Ciphertext) < 32 {
		return nil, fmt.Errorf("encrypted backup required")
	}
	sealed, err := base64.StdEncoding.Strict().DecodeString(header.Ciphertext)
	if err != nil || len(sealed) <= 16 {
		return nil, fmt.Errorf("invalid encrypted backup ciphertext")
	}
	if _, err = decodeFixedHex(header.Nonce, 12, "backup nonce"); err != nil {
		return nil, err
	}
	var identity struct {
		Descriptor struct {
			VaultID string `json:"vaultId"`
		} `json:"descriptor"`
	}
	if json.Unmarshal(header.Header, &identity) != nil || identity.Descriptor.VaultID != id {
		return nil, fmt.Errorf("backup belongs to another wallet")
	}
	return s.Stores.LightBackup.PutLightBackup(id, req.Revision, req.Payload)
}
func attachLightBackupRoutes(mux *http.ServeMux, s *Service, origin string) {
	mux.HandleFunc("POST /v1/light/backup/challenge", func(w http.ResponseWriter, r *http.Request) {
		var req struct{}
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		v, err := s.IssueLightBackupChallenge()
		writeJSON(w, v, err)
	})
	mux.HandleFunc("POST /v1/light/backup/open", func(w http.ResponseWriter, r *http.Request) {
		var req LightBackupOpenRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		v, err := s.OpenLightBackup(r.Context(), req)
		writeJSON(w, v, err)
	})
	for _, phase := range []string{"read", "write"} {
		mux.HandleFunc("POST /v1/light/backup/"+phase, func(w http.ResponseWriter, r *http.Request) {
			var req LightBackupRequest
			if err := decodeMutation(r, &req, origin); err != nil {
				writeMutationError(w, err)
				return
			}
			var v *policy.LightBackup
			var err error
			if phase == "read" {
				v, err = s.ReadLightBackup(req)
			} else {
				v, err = s.WriteLightBackup(req)
			}
			writeJSON(w, v, err)
		})
	}
}
