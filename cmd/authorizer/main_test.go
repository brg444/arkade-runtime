package main

import (
	"os"
	"testing"
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
