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
	if s.Ledger == nil {
		st.Error = "ledger unavailable"
		return st
	}
	ver, err := s.Ledger.SchemaVersion()
	if err != nil {
		st.Error = "schema unread"
		return st
	}
	st.Schema = ver
	if s.ArkadeCosignerOrigin == "" || s.ArkadeCosignerVersion == "" || s.ArkadeCosignerPub == nil {
		st.Error = "arkade signer not pinned"
		return st
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
