package pack_test

import (
	"os"
	"strings"
	"testing"
)

func TestLinuxGuardianEnvExamplePinsVaultedAndOmitsSecrets(t *testing.T) {
	body, err := os.ReadFile("deploy/linux/guardian.env.example")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, required := range []string{
		"VAULT_NETWORK=mainnet",
		"VAULT_CLIENT_ORIGIN=https://app.getvaulted.xyz",
		"VAULT_RP_ID=app.getvaulted.xyz",
		"VAULT_AUTHORIZER_ADDR=127.0.0.1:8788",
		"VAULT_COSIGNER_KEY_UNLINK=after-load",
		"VAULT_STORAGE_ISOLATION=independent-authorities",
		"VAULT_EDGE_RATE_LIMIT=shared-durable",
		"VAULT_MAINNET_ACK=fresh-state-v1",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %s", required)
		}
	}
	if strings.Contains(text, "VAULT_GATEWAY_SECRET=") && !strings.Contains(text, "# VAULT_GATEWAY_SECRET") {
		t.Fatal("gateway secret value present")
	}
	if strings.Contains(text, "VAULT_COSIGNER_KEY_HEX=") && !strings.Contains(text, "# VAULT_COSIGNER_KEY_HEX") {
		t.Fatal("key hex value present")
	}
	if strings.Contains(text, "mutinynet") {
		t.Fatal("mutinynet leaked into linux mainnet env example")
	}
}

func TestLinuxGuardianUnitIsHardenedAndNotEnabledOnBoot(t *testing.T) {
	body, err := os.ReadFile("deploy/linux/vaulted-guardian.service")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, required := range []string{
		"NoNewPrivileges=true",
		"PrivateTmp=true",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"PrivateDevices=true",
		"CapabilityBoundingSet=",
		"VAULT_AUTHORIZER_ADDR is set in guardian.env to 127.0.0.1:8788",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %s", required)
		}
	}
	if strings.Contains(text, "\nWantedBy=") || strings.Contains(text, "\n[Install]\n") {
		t.Fatal("authorizer must not start unattended after reboot")
	}
}
