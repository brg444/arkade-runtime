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
