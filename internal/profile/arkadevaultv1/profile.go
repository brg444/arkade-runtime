// Package arkadevaultv1 declares the first compiled Arkade Runtime profile.
// It is one composed product profile, not a menu of independently enrollable
// Savings, boarding, Spending, or allowance modules.
package arkadevaultv1

import (
	"net/http"

	"github.com/brg444/arkade-runtime/internal/program"
	arkaderuntime "github.com/brg444/arkade-runtime/internal/runtime"
)

const (
	ProfileID = "arkade-vault-v1"
	ModuleID  = "arkade-vault-v1"

	SavingsRecoveryProgram  = "savings-recovery-v1"
	SavingsConnectorProgram = "savings-connector-v1"
	SpendingPolicy          = "vault-spending-policy-v1"
)

// Definition returns a fresh compile-time profile definition. Policy values,
// program parameters, and Contract Pack bytes are not runtime configuration.
func Definition() arkaderuntime.ProfileDefinition {
	return arkaderuntime.ProfileDefinition{
		ID: ProfileID,
		Modules: []arkaderuntime.ModuleDefinition{{
			ID: ModuleID,
			Programs: []string{
				SavingsRecoveryProgram,
				SavingsConnectorProgram,
				program.VaultBoardV1,
				program.VaultPolicyV1,
			},
			Policies: []string{SpendingPolicy},
			Stores: []string{
				"identity-store",
				"allowance-store",
				"vtxo-operation-store",
				"recovery-operation-store",
				"map-store",
				"vault-board-store",
				"connector-store",
			},
			KeyScopes: []string{
				"enrollment-derivation",
				"savings-recovery-authorization",
				"savings-connector-authorization",
				"vtxo-transaction-authorization",
				"vtxo-checkpoint-authorization",
				"vault-board-authorization",
				"public-emulator-operation",
			},
		}},
		Routes: routes(),
	}
}

func routes() []arkaderuntime.Route {
	return []arkaderuntime.Route{
		{Method: http.MethodGet, Path: "/v1/status"},
		{Method: http.MethodOptions, Path: "/v1/status"},
		{Method: http.MethodGet, Path: "/v1/invite"},
		{Method: http.MethodOptions, Path: "/v1/invite"},
		{Method: http.MethodPost, Path: "/v1/enroll/session"},
		{Method: http.MethodOptions, Path: "/v1/enroll/session"},
		{Method: http.MethodPost, Path: "/v1/enroll/start"},
		{Method: http.MethodOptions, Path: "/v1/enroll/start"},
		{Method: http.MethodPost, Path: "/v1/enroll/propose"},
		{Method: http.MethodOptions, Path: "/v1/enroll/propose"},
		{Method: http.MethodPost, Path: "/v1/enroll/finish"},
		{Method: http.MethodOptions, Path: "/v1/enroll/finish"},
		{Method: http.MethodPost, Path: "/v1/initiate"},
		{Method: http.MethodOptions, Path: "/v1/initiate"},
		{Method: http.MethodPost, Path: "/v1/clawback"},
		{Method: http.MethodOptions, Path: "/v1/clawback"},
		{Method: http.MethodPost, Path: "/v1/passkey/challenge"},
		{Method: http.MethodOptions, Path: "/v1/passkey/challenge"},
		{Method: http.MethodPost, Path: "/v1/passkey/binding"},
		{Method: http.MethodOptions, Path: "/v1/passkey/binding"},
		{Method: http.MethodPost, Path: "/v1/passkey/install"},
		{Method: http.MethodOptions, Path: "/v1/passkey/install"},
		{Method: http.MethodPost, Path: "/v1/passkey/recover"},
		{Method: http.MethodOptions, Path: "/v1/passkey/recover"},
		{Method: http.MethodGet, Path: "/v1/map"},
		{Method: http.MethodPost, Path: "/v1/map"},
		{Method: http.MethodOptions, Path: "/v1/map"},
		{Method: http.MethodPost, Path: "/v1/vtxo/reserve"},
		{Method: http.MethodOptions, Path: "/v1/vtxo/reserve"},
		{Method: http.MethodPost, Path: "/v1/vtxo/authorize"},
		{Method: http.MethodOptions, Path: "/v1/vtxo/authorize"},
		{Method: http.MethodPost, Path: "/v1/vtxo/checkpoints/authorize"},
		{Method: http.MethodOptions, Path: "/v1/vtxo/checkpoints/authorize"},
		{Method: http.MethodPost, Path: "/v1/vtxo/finalize"},
		{Method: http.MethodOptions, Path: "/v1/vtxo/finalize"},
		{Method: http.MethodGet, Path: "/v1/vtxo/operation"},
		{Method: http.MethodOptions, Path: "/v1/vtxo/operation"},
		{Method: http.MethodPost, Path: "/v1/vtxo/abort"},
		{Method: http.MethodOptions, Path: "/v1/vtxo/abort"},
		{Method: http.MethodPost, Path: "/v1/vtxo/board/prepare"},
		{Method: http.MethodOptions, Path: "/v1/vtxo/board/prepare"},
		{Method: http.MethodPost, Path: "/v1/vtxo/board/register"},
		{Method: http.MethodOptions, Path: "/v1/vtxo/board/register"},
		{Method: http.MethodPost, Path: "/v1/vtxo/board/release"},
		{Method: http.MethodOptions, Path: "/v1/vtxo/board/release"},
		{Method: http.MethodPost, Path: "/v1/vtxo/board/final"},
		{Method: http.MethodOptions, Path: "/v1/vtxo/board/final"},
		{Method: http.MethodPost, Path: "/v1/connector/withdraw/authorize"},
		{Method: http.MethodOptions, Path: "/v1/connector/withdraw/authorize"},
		{Method: http.MethodGet, Path: "/v1/connector/operation"},
		{Method: http.MethodOptions, Path: "/v1/connector/operation"},
	}
}
