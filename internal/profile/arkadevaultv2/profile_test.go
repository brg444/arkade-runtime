package arkadevaultv2

import (
	"testing"

	"github.com/brg444/arkade-vault-server/internal/program"
	arkaderuntime "github.com/brg444/arkade-vault-server/internal/runtime"
)

func TestDefinitionIsExplicitVaultBoardV2Profile(t *testing.T) {
	definition := Definition()
	if definition.ID != ProfileID || len(definition.Modules) != 1 || definition.Modules[0].ID != ModuleID {
		t.Fatalf("definition = %+v", definition)
	}
	for _, namedProgram := range definition.Modules[0].Programs {
		if namedProgram == program.VaultBoardV1 {
			t.Fatal("v2 profile retained vault-board-v1")
		}
	}
	if _, err := arkaderuntime.Compile(definition); err != nil {
		t.Fatal(err)
	}
}
