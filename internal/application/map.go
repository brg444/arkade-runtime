package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/brg444/arkade-vault-server/internal/policy"
)

type MapWriteRequest struct {
	VaultID string `json:"vaultId"`
	SessionAssertionRequest
	Payload json.RawMessage `json:"payload"`
}

func (s *Service) GetMap(vaultID string) (json.RawMessage, error) {
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	rec, err := s.Stores.Maps.GetVaultMap(vaultID)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, fmt.Errorf("map not found")
	}
	return json.RawMessage(rec.Payload), nil
}

func (s *Service) PutMap(ctx context.Context, req MapWriteRequest) error {
	vaultID := strings.TrimSpace(req.VaultID)
	if vaultID == "" {
		return fmt.Errorf("vault id required")
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		return err
	}
	if _, err := s.authenticatePasskeySession(ctx, passkeyPurposeMapWrite, vaultID, req.SessionAssertionRequest); err != nil {
		return err
	}
	if len(req.Payload) == 0 || len(req.Payload) > 96*1024 {
		return fmt.Errorf("vault map required")
	}
	var parsed map[string]any
	if err := json.Unmarshal(req.Payload, &parsed); err != nil {
		return fmt.Errorf("vault map required")
	}
	if parsed["name"] != "arkade-vault-map" {
		return fmt.Errorf("not a vault map backup")
	}
	kit, _ := parsed["kit"].(map[string]any)
	if kit == nil || kit["name"] != "arkade-recovery-kit" {
		return fmt.Errorf("not a vault map backup")
	}
	desc, _ := kit["descriptor"].(map[string]any)
	if desc == nil || strings.TrimSpace(fmt.Sprint(desc["vaultId"])) != vaultID {
		return fmt.Errorf("map vault id does not match")
	}
	sum := sha256.Sum256(req.Payload)
	return s.Stores.Maps.PutVaultMap(policy.VaultMap{
		VaultID: vaultID,
		KitHash: hex.EncodeToString(sum[:]),
		Payload: string(req.Payload),
	})
}
