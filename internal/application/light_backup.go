package application

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/brg444/arkade-runtime/internal/policy"
)

const lightBackupPurpose = "light-backup-open"

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
	Token     string                 `json:"token"`
	VaultID   string                 `json:"vaultId"`
	ExpiresAt string                 `json:"expiresAt"`
	Backup    *policy.RecoveryBackup `json:"backup"`
}

func (s *Service) IssueLightBackupChallenge() (*PasskeyChallengeResponse, error) {
	return s.issueBackupChallenge(lightBackupPurpose)
}
func (s *Service) OpenLightBackup(ctx context.Context, req LightBackupOpenRequest) (*LightBackupOpenResponse, error) {
	opened, err := s.openBackup(ctx, req, lightBackupPurpose)
	if err != nil {
		return nil, err
	}
	return &opened.LightBackupOpenResponse, nil
}
func (s *Service) lightBackupVault(token string) (string, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	_, session, err := s.backupSessionLocked(token, lightBackupPurpose)
	if err != nil {
		return "", err
	}
	return session.VaultID, nil
}
func (s *Service) ReadLightBackup(req LightBackupRequest) (*policy.RecoveryBackup, error) {
	id, err := s.lightBackupVault(req.Token)
	if err != nil {
		return nil, err
	}
	return s.Stores.RecoveryBackup.GetRecoveryBackup(id)
}
func (s *Service) WriteLightBackup(req LightBackupRequest) (*policy.RecoveryBackup, error) {
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
	if len(req.Payload) > policy.MaxRecoveryBackupBytes {
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
	return s.Stores.RecoveryBackup.PutRecoveryBackup(id, req.Revision, req.Payload)
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
			var v *policy.RecoveryBackup
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
