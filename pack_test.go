package pack_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/brg444/arkade-vault-server/fixture"
	v5 "github.com/brg444/arkade-vault-server/internal/vault/v5"
)

func TestContractPackMatchesLiveEnroll(t *testing.T) {
	raw, err := os.ReadFile("contract-pack.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Programs struct {
			V4 struct {
				Status   string `json:"status"`
				Template string `json:"template"`
			} `json:"v4"`
			V5 struct {
				Status   string `json:"status"`
				Template string `json:"template"`
				Recovery string `json:"recovery"`
			} `json:"v5"`
		} `json:"programs"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	if pack.Programs.V5.Status != "live" || pack.Programs.V5.Template != v5.Template {
		t.Fatalf("live enroll: %+v want template %s", pack.Programs.V5, v5.Template)
	}
	if pack.Programs.V5.Recovery != "optional" {
		t.Fatalf("recovery %q, want optional", pack.Programs.V5.Recovery)
	}
	if pack.Programs.V4.Status != "leftover" || pack.Programs.V4.Template != fixture.TemplateVersion {
		t.Fatalf("leftover v4: %+v want template %s", pack.Programs.V4, fixture.TemplateVersion)
	}
}
