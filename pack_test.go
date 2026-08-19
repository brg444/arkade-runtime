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

func TestContractPackListsVaultPolicyV1WithoutExit(t *testing.T) {
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
	if _, hasExit := listed["exit"]; hasExit {
		t.Fatal("vault-policy-v1 must omit exit until the leaf PR")
	}
	if _, hasTunnel := listed["tunnel"]; hasTunnel {
		t.Fatal("vault-policy-v1 must omit tunnel until the leaf PR")
	}
	caps, ok := listed["caps"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 caps required")
	}
	if caps["txRecipientSats"] != float64(50000) || caps["periodAllowanceSats"] != float64(100000) {
		t.Fatalf("vault-policy-v1 caps: %+v", caps)
	}
}
