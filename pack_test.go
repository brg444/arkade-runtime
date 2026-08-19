package pack_test

import (
	"encoding/json"
	"os"
	"testing"

	v5 "github.com/brg444/arkade-vault-server/internal/vault/v5"
)

func TestContractPackMatchesLiveEnroll(t *testing.T) {
	raw, err := os.ReadFile("contract-pack.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Programs struct {
			Staged struct {
				Status     string `json:"status"`
				Enrollable *bool  `json:"enrollable"`
				Template   string `json:"template"`
				Recovery   string `json:"recovery"`
			} `json:"staged"`
		} `json:"programs"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	if pack.Programs.Staged.Status != "live" || pack.Programs.Staged.Template != v5.Template {
		t.Fatalf("live enroll: %+v want template %s", pack.Programs.Staged, v5.Template)
	}
	if pack.Programs.Staged.Enrollable == nil || !*pack.Programs.Staged.Enrollable {
		t.Fatalf("staged program must be enrollable: %+v", pack.Programs.Staged)
	}
	if pack.Programs.Staged.Recovery != "optional" {
		t.Fatalf("recovery %q, want optional", pack.Programs.Staged.Recovery)
	}
}

func TestContractPackListsVaultPolicyV1WithExitAndTunnel(t *testing.T) {
	raw, err := os.ReadFile("contract-pack.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]any
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	programs, ok := pack["programs"].(map[string]any)
	if !ok {
		t.Fatal("programs object required")
	}
	if _, ok := programs["staged"].(map[string]any); !ok {
		t.Fatal("staged program must remain")
	}
	listed, ok := programs["vault-policy-v1"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 must be listed beside staged")
	}
	if listed["status"] != "listed" || listed["module"] != "vtxo" {
		t.Fatalf("vault-policy-v1 listing: %+v", listed)
	}
	if listed["schema"] != "arkade-vault/vtxo-policy-v1" || listed["template"] != "vault-policy-v1-collaborative-4pub" {
		t.Fatalf("vault-policy-v1 identity: %+v", listed)
	}
	exit, ok := listed["exit"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 must declare exit")
	}
	if exit["delay"] != "2048" || exit["delayUnit"] != "seconds" {
		t.Fatalf("vault-policy-v1 exit delay: %+v", exit)
	}
	if exit["twoGuardian"] != "device-and-hardware-after-exitDelay" || exit["threeGuardian"] != "hardware-and-recovery-after-exitDelay" {
		t.Fatalf("vault-policy-v1 exit guardians: %+v", exit)
	}
	tunnel, ok := listed["tunnel"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 must declare tunnel")
	}
	if tunnel["opcode"] != "OP_TUNNEL" || tunnel["leaf"] != "tweaked-tunnel-emulator-and-arkd" {
		t.Fatalf("vault-policy-v1 tunnel: %+v", tunnel)
	}
	if tunnel["note"] != "Different ArkScript tweak from spend. Kernel is the delegate. No vault HTTP." {
		t.Fatalf("vault-policy-v1 tunnel note: %+v", tunnel)
	}
	if listed["notes"] != "Spending only. Savings stays L1. No staged Pending/Quarantine. Exit delay frozen from Spike 0 UnilateralExitDelay=2048 seconds." {
		t.Fatalf("vault-policy-v1 notes: %v", listed["notes"])
	}
	caps, ok := listed["caps"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 caps required")
	}
	if caps["txRecipientSats"] != float64(50000) || caps["periodAllowanceSats"] != float64(100000) {
		t.Fatalf("vault-policy-v1 caps: %+v", caps)
	}
}
