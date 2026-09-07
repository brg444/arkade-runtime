package application

import (
	"context"
	"time"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
)

const (
	resolverReadyTimeout = 5 * time.Second
	resolverReadyTTL     = 30 * time.Second
)

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
	// Keep the nonempty legacy field for deployed clients without publishing
	// the transport locator. Actual signer readiness is checked below.
	st.ArkadeOrigin = "configured"
	st.ArkadeVersion = s.ArkadeCosignerVersion
	if err := cfg.Validate(); err != nil {
		st.Error = "deployment not ready"
		return st
	}
	// Preserve the established readiness precedence: the five original ledger
	// capabilities fail before integrity and signer checks, while the profile's
	// boarding capability retains its release-specific error below.
	if s.Stores.Identity == nil || s.Stores.Allowance == nil || s.Stores.VtxoOperations == nil ||
		s.Stores.RecoveryOperations == nil || s.Stores.Maps == nil {
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
	if err := validateReleaseContractPackFor(cfg.Network, s.contractPackJSON); err != nil {
		st.Error = "contract pack mismatch"
		return st
	}
	if s.Stores.VaultBoard == nil {
		st.Error = "vault-board-v1 store unavailable"
		return st
	}
	if err := s.Stores.Validate(); err != nil {
		st.Error = "ledger unavailable"
		return st
	}
	runtime, err := s.requireVaultBoardRuntime()
	if err != nil {
		st.Error = "vault-board-v1 runtime unavailable"
		return st
	}
	id, err := deployment.IdentityFor(cfg.Network)
	if err != nil || runtime.batchExpiry != id.VtxoTreeExpirySeconds {
		st.Error = "vault-board-v1 runtime unavailable"
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
	if err := s.cachedResolverReadiness(ctx); err != nil {
		st.Error = "Arkade resolver unavailable"
		return st
	}
	st.Ok = true
	return st
}

// cachedResolverReadiness bounds the unauthenticated readiness endpoint to at
// most one external Operator and Bitcoin checkpoint probe per TTL. The mutex
// also coalesces concurrent probes, preventing upstream amplification.
func (s *Service) cachedResolverReadiness(_ context.Context) error {
	s.resolverReadyMu.Lock()
	defer s.resolverReadyMu.Unlock()
	now := time.Now()
	if !s.resolverReadyAt.IsZero() && now.Sub(s.resolverReadyAt) < resolverReadyTTL {
		return s.resolverReadyErr
	}
	// A public caller must not be able to poison the cached result by
	// cancelling its own request while the shared probe is in flight.
	readyCtx, cancel := context.WithTimeout(context.Background(), resolverReadyTimeout)
	defer cancel()
	_, err := s.ArkResolver.IntentFeePolicy(readyCtx)
	if err == nil {
		var runtime *vaultBoardRuntime
		runtime, err = s.requireVaultBoardRuntime()
		if err == nil {
			err = runtime.chain.verifyCheckpoint(readyCtx, s.runtimeConfig().Network)
		}
	}
	s.resolverReadyAt = now
	s.resolverReadyErr = err
	return err
}

func (s *Service) resetResolverReadinessCache() {
	s.resolverReadyMu.Lock()
	defer s.resolverReadyMu.Unlock()
	s.resolverReadyAt = time.Time{}
	s.resolverReadyErr = nil
}
