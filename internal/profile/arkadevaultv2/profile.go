// Package arkadevaultv2 is the explicit fresh Mutinynet profile that replaces
// vault-board-v1 with vault-board-v2 authorization. It is never compiled into
// the existing v1 startup path.
package arkadevaultv2

import (
	"net/http"

	"github.com/brg444/arkade-vault-server/internal/profile/arkadevaultv1"
	"github.com/brg444/arkade-vault-server/internal/program"
	arkaderuntime "github.com/brg444/arkade-vault-server/internal/runtime"
)

const (
	ProfileID = "arkade-vault-v2-mutinynet"
	ModuleID  = "arkade-vault-v2-mutinynet"
)

func Definition() arkaderuntime.ProfileDefinition {
	definition := arkadevaultv1.Definition()
	definition.ID = ProfileID
	module := &definition.Modules[0]
	module.ID = ModuleID
	for i, namedProgram := range module.Programs {
		if namedProgram == program.VaultBoardV1 {
			module.Programs[i] = program.VaultBoardV2
		}
	}
	module.Stores = append(module.Stores, "vault-board-v2-store")
	module.KeyScopes = append(module.KeyScopes, "vault-board-v2-authorization")
	definition.Routes = append(definition.Routes,
		arkaderuntime.Route{Method: http.MethodPost, Path: "/v1/vtxo/board/enroll/propose"},
		arkaderuntime.Route{Method: http.MethodOptions, Path: "/v1/vtxo/board/enroll/propose"},
		arkaderuntime.Route{Method: http.MethodPost, Path: "/v1/vtxo/board/enroll/finish"},
		arkaderuntime.Route{Method: http.MethodOptions, Path: "/v1/vtxo/board/enroll/finish"},
	)
	return definition
}
