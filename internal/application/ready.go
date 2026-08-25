package application

import (
	"context"
	"time"

	"github.com/brg444/arkade-vault-server/internal/vault/savings"
)

const resolverReadyTimeout = 5 * time.Second

// ReadyStatus is the unauthenticated readiness body. It never includes keys,
// tokens, PSBTs, or credential envelopes.
type ReadyStatus struct {
	Ok             bool   `json:"ok"`
	Schema         int    `json:"schema"`
	Network        string `json:"network"`
	EnrollTemplate string `json:"enrollTemplate"`
	ArkadeOrigin   string `json:"arkadeOrigin"`
	ArkadeVersion  string `json:"arkadeVersion"`
	Error          string `json:"error,omitempty"`
}

// Ready checks ledger access and every release-pinned signing dependency.
func (s *Service) Ready(ctx context.Context) ReadyStatus {
	st := ReadyStatus{
		EnrollTemplate: savings.Template,
	}
	if s == nil {
		st.Error = "service unavailable"
		return st
	}
	cfg := s.runtimeConfig()
	st.Network = cfg.Network
	st.ArkadeOrigin = s.ArkadeCosignerOrigin
	st.ArkadeVersion = s.ArkadeCosignerVersion
	if err := cfg.Validate(); err != nil {
		st.Error = "deployment not ready"
		return st
	}
	if err := s.Stores.Validate(); err != nil {
		st.Error = "ledger unavailable"
		return st
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		st.Error = "ledger integrity unavailable"
		return st
	}
	ver, err := s.Stores.Identity.SchemaVersion()
	if err != nil {
		st.Error = "schema unread"
		return st
	}
	st.Schema = ver
	if s.VaultCosignerPub == nil || s.ArkadeCosignerOrigin == "" || s.ArkadeCosignerVersion == "" ||
		s.ArkadeCosignerPub == nil || s.keys.Validate() != nil {
		st.Error = "arkade signer not pinned"
		return st
	}
	if err := validateReleaseContractPack(s.contractPackJSON); err != nil {
		st.Error = "contract pack mismatch"
		return st
	}
	if s.VaultBoardV2Store != nil {
		runtime, err := s.requireVaultBoardV2Runtime()
		if err != nil || runtime.batchExpiry == 0 {
			st.Error = "vault-board-v2 runtime unavailable"
			return st
		}
	}
	if isNilInterface(s.ArkResolver) {
		st.Error = "Arkade resolver unavailable"
		return st
	}
	if s.ArkResolver.Network() != cfg.Network {
		st.Error = "Arkade resolver network mismatch"
		return st
	}
	if err := validateArkResolverPolicy(cfg.Network, s.ArkResolver.CheckpointTapscript(), s.ArkResolver.OperatorSignerPub()); err != nil {
		st.Error = "Arkade resolver policy mismatch"
		return st
	}
	readyCtx, cancel := context.WithTimeout(ctx, resolverReadyTimeout)
	defer cancel()
	if _, err := s.ArkResolver.IntentFeePolicy(readyCtx); err != nil {
		st.Error = "Arkade resolver unavailable"
		return st
	}
	st.Ok = true
	return st
}
