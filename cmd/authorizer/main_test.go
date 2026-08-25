package main

import (
	"os"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/authorizer"
)

func TestClearGatewaySecretEnv(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "startup-only-secret")
	if err := clearGatewaySecretEnv(); err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("VAULT_GATEWAY_SECRET"); ok {
		t.Fatal("gateway secret remained in the process environment")
	}
}

func TestExplicitBoardingProgramSelectionRejectsMissingOrUnknown(t *testing.T) {
	for _, value := range []string{"", "vault-board-v3"} {
		runtime, err := openRuntime(t.Context(), authorizer.Config{}, value)
		if err == nil || runtime != nil {
			t.Fatalf("boarding program %q selected a runtime", value)
		}
	}
}

func TestExplicitBoardingProgramSelection(t *testing.T) {
	for _, test := range []struct {
		program string
		v2      bool
	}{
		{program: "vault-board-v1"},
		{program: "vault-board-v2", v2: true},
	} {
		got, err := selectVaultBoardV2(test.program)
		if err != nil || got != test.v2 {
			t.Fatalf("select %q = %v, %v", test.program, got, err)
		}
	}
}
