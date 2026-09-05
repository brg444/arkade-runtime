package main

import (
	"os"
	"testing"
)

func TestInviteOnlyConfigDefaultsClosedAndRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"", "true"} {
		got, err := parseInviteOnly(value)
		if err != nil || !got {
			t.Fatalf("%q must require invitations", value)
		}
	}
	if got, err := parseInviteOnly("false"); err != nil || got {
		t.Fatal("false must enable open enrollment")
	}
	if got, err := parseInviteOnly("typo"); err == nil || !got {
		t.Fatal("invalid configuration must fail closed")
	}
}

func TestClearGatewaySecretEnv(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "startup-only-secret")
	if err := clearGatewaySecretEnv(); err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("VAULT_GATEWAY_SECRET"); ok {
		t.Fatal("gateway secret remained in the process environment")
	}
}
