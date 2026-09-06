package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
)

const recoveryArchivePurpose = "recovery-archive-open"

// These are enrolled public facts, never values selected by the archive writer.
// DescriptorHash is the existing Savings+boarding composite for legacy Savings,
// or connectorEnrollment.descriptorHash for the connector template.
type RecoveryArchiveBinding struct {
	VaultID              string `json:"vaultId"`
	Network              string `json:"network"`
	TemplateVersion      string `json:"templateVersion"`
	ProtectionTier       string `json:"protectionTier"`
	PolicyVersion        string `json:"policyVersion"`
	SpendingPolicyDigest string `json:"spendingPolicyDigest"`
	DescriptorHash       string `json:"descriptorHash"`
}
type RecoveryArchiveOpenResponse struct {
	LightBackupOpenResponse
	Binding RecoveryArchiveBinding `json:"binding"`
}

func recoveryArchiveCredentialAllowed(cred *policy.Credential) bool {
	return cred != nil && (cred.TemplateVersion == savings.Template || cred.TemplateVersion == connector.Template) &&
		(cred.ProtectionTier == program.ProtectionTierStandard || cred.ProtectionTier == program.ProtectionTierAdvanced)
}
func (s *Service) recoveryArchiveBinding(cred *policy.Credential) (RecoveryArchiveBinding, error) {
	if !recoveryArchiveCredentialAllowed(cred) || cred.Network != s.runtimeConfig().Network || cred.PolicyVersion != program.PolicyVersion {
		return RecoveryArchiveBinding{}, fmt.Errorf("unsupported recovery archive enrollment")
	}
	snap := s.snapshot(cred.VaultID)
	// Reload the authenticated boarding row rather than relying on an in-memory
	// descriptor surviving a subsequent disk mutation.
	board, err := s.Stores.VaultBoard.GetVaultBoardEnrollment(cred.VaultID)
	if err != nil {
		return RecoveryArchiveBinding{}, err
	}
	snap.Board, err = boardSnapshotFromRecord(board)
	if err != nil {
		return RecoveryArchiveBinding{}, err
	}
	var hash string
	if isConnectorCredential(cred) {
		identity, e := s.connectorEnrollmentStatus(cred, snap)
		if e != nil {
			return RecoveryArchiveBinding{}, e
		}
		hash = identity.DescriptorHash
	} else {
		_, hash, err = s.statusVaultBoardDescriptor(cred, snap)
		if err != nil {
			return RecoveryArchiveBinding{}, err
		}
	}
	digest, err := program.SpendingPolicyDigestHexFor(cred.Network, spendingPolicyFromCredential(cred))
	if err != nil {
		return RecoveryArchiveBinding{}, err
	}
	return RecoveryArchiveBinding{VaultID: cred.VaultID, Network: cred.Network, TemplateVersion: cred.TemplateVersion, ProtectionTier: cred.ProtectionTier, PolicyVersion: cred.PolicyVersion, SpendingPolicyDigest: digest, DescriptorHash: hash}, nil
}
func (s *Service) IssueRecoveryArchiveChallenge() (*PasskeyChallengeResponse, error) {
	return s.issueBackupChallenge(recoveryArchivePurpose)
}
func (s *Service) OpenRecoveryArchive(ctx context.Context, req LightBackupOpenRequest) (*RecoveryArchiveOpenResponse, error) {
	return s.openBackup(ctx, req, recoveryArchivePurpose)
}

// The server bounds and authenticates opaque transport. It cannot establish
// ciphertext decryptability or completeness of a client-generated exit graph.
func validateRecoveryArchive(payload string, binding RecoveryArchiveBinding) ([32]byte, error) {
	bad := func() ([32]byte, error) { return [32]byte{}, fmt.Errorf("valid encrypted recovery archive required") }
	if len(payload) == 0 || len(payload) > policy.MaxRecoveryBackupBytes {
		return bad()
	}
	var envelope struct {
		Name       string          `json:"name"`
		Version    int             `json:"version"`
		Header     json.RawMessage `json:"header"`
		Nonce      string          `json:"nonce"`
		Ciphertext string          `json:"ciphertext"`
	}
	dec := json.NewDecoder(bytes.NewBufferString(payload))
	dec.DisallowUnknownFields()
	if dec.Decode(&envelope) != nil || dec.Decode(new(any)) != io.EOF {
		return bad()
	}
	if envelope.Name != "vaulted-recovery-backup" || envelope.Version != 1 || len(envelope.Header) > 96*1024 {
		return bad()
	}
	if _, err := decodeFixedHex(envelope.Nonce, 12, "archive nonce"); err != nil {
		return bad()
	}
	sealed, err := base64.StdEncoding.Strict().DecodeString(envelope.Ciphertext)
	if err != nil || len(sealed) <= 16 {
		return bad()
	}
	var header struct {
		Binding RecoveryArchiveBinding `json:"binding"`
	}
	if json.Unmarshal(envelope.Header, &header) != nil || header.Binding != binding {
		return bad()
	}
	return sha256.Sum256(envelope.Header), nil
}

func (s *Service) verifiedArchiveSessionLocked(token string) ([32]byte, backupSession, error) {
	key, session, err := s.backupSessionLocked(token, recoveryArchivePurpose)
	if err != nil {
		return key, session, err
	}
	cred, err := s.loadVerifiedCredentialFor(session.VaultID)
	if err != nil {
		return key, session, err
	}
	binding, err := s.recoveryArchiveBinding(cred)
	if err != nil {
		return key, session, err
	}
	if binding != session.Binding {
		return key, session, fmt.Errorf("recovery archive enrollment changed; reopen with your passkey")
	}
	return key, session, nil
}
func (s *Service) readArchiveLocked(session *backupSession) (*policy.RecoveryBackup, error) {
	backup, err := s.Stores.RecoveryBackup.GetRecoveryBackup(session.VaultID)
	if err != nil || backup == nil {
		return backup, err
	}
	digest, err := validateRecoveryArchive(backup.Payload, session.Binding)
	if err != nil {
		return nil, err
	}
	if session.HeaderDigest != [32]byte{} && session.HeaderDigest != digest {
		return nil, fmt.Errorf("recovery archive header changed")
	}
	session.HeaderDigest = digest
	return backup, nil
}
func (s *Service) ReadRecoveryArchive(req LightBackupRequest) (*policy.RecoveryBackup, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	key, session, err := s.verifiedArchiveSessionLocked(req.Token)
	if err != nil {
		return nil, err
	}
	backup, err := s.readArchiveLocked(&session)
	if err == nil {
		s.backupSessions[key] = session
	}
	return backup, err
}
func (s *Service) WriteRecoveryArchive(req LightBackupRequest) (*policy.RecoveryBackup, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	key, session, err := s.verifiedArchiveSessionLocked(req.Token)
	if err != nil {
		return nil, err
	}
	// A session opened before another writer's first upload must also honor the
	// persisted header. The shared lock serializes first writes and header pins.
	if _, err = s.readArchiveLocked(&session); err != nil {
		return nil, err
	}
	digest, err := validateRecoveryArchive(req.Payload, session.Binding)
	if err != nil {
		return nil, err
	}
	if session.HeaderDigest != [32]byte{} && session.HeaderDigest != digest {
		return nil, fmt.Errorf("recovery archive header changed")
	}
	saved, err := s.Stores.RecoveryBackup.PutRecoveryBackup(session.VaultID, req.Revision, req.Payload)
	if err != nil {
		return nil, err
	}
	session.HeaderDigest = digest
	s.backupSessions[key] = session
	return saved, nil
}

func attachRecoveryArchiveRoutes(mux *http.ServeMux, s *Service, origin string) {
	mux.HandleFunc("POST /v1/recovery-archive/challenge", func(w http.ResponseWriter, r *http.Request) {
		var req struct{}
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		v, err := s.IssueRecoveryArchiveChallenge()
		writeJSON(w, v, err)
	})
	mux.HandleFunc("POST /v1/recovery-archive/open", func(w http.ResponseWriter, r *http.Request) {
		var req LightBackupOpenRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		v, err := s.OpenRecoveryArchive(r.Context(), req)
		writeJSON(w, v, err)
	})
	for _, phase := range []string{"read", "write"} {
		mux.HandleFunc("POST /v1/recovery-archive/"+phase, func(w http.ResponseWriter, r *http.Request) {
			var req LightBackupRequest
			if err := decodeMutation(r, &req, origin); err != nil {
				writeMutationError(w, err)
				return
			}
			var v *policy.RecoveryBackup
			var err error
			if phase == "read" {
				v, err = s.ReadRecoveryArchive(req)
			} else {
				v, err = s.WriteRecoveryArchive(req)
			}
			writeJSON(w, v, err)
		})
	}
}
