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
				Status     string `json:"status"`
				Enrollable *bool  `json:"enrollable"`
				Template   string `json:"template"`
			} `json:"v4"`
			V5 struct {
				Status     string `json:"status"`
				Enrollable *bool  `json:"enrollable"`
				Template   string `json:"template"`
				Recovery   string `json:"recovery"`
			} `json:"v5"`
			V6 struct {
				Status     string `json:"status"`
				Enrollable *bool  `json:"enrollable"`
				Template   string `json:"template"`
				Recovery   string `json:"recovery"`
			} `json:"v6"`
		} `json:"programs"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	if pack.Programs.V6.Status != "live" || pack.Programs.V6.Template != v5.TemplateV6 {
		t.Fatalf("live enroll: %+v want template %s", pack.Programs.V6, v5.TemplateV6)
	}
	if pack.Programs.V6.Enrollable == nil || !*pack.Programs.V6.Enrollable {
		t.Fatalf("staged program must be enrollable: %+v", pack.Programs.V6)
	}
	if pack.Programs.V6.Recovery != "optional" {
		t.Fatalf("recovery %q, want optional", pack.Programs.V6.Recovery)
	}
	if pack.Programs.V5.Status != "leftover" || pack.Programs.V5.Template != v5.Template {
		t.Fatalf("v5 leftover: %+v", pack.Programs.V5)
	}
	if pack.Programs.V5.Enrollable == nil || *pack.Programs.V5.Enrollable {
		t.Fatalf("v5 is not enrollable, still signing: %+v", pack.Programs.V5)
	}
	if pack.Programs.V4.Status != "leftover" || pack.Programs.V4.Template != fixture.TemplateVersion {
		t.Fatalf("daily program pack: %+v want template %s", pack.Programs.V4, fixture.TemplateVersion)
	}
	if pack.Programs.V4.Enrollable == nil || *pack.Programs.V4.Enrollable {
		t.Fatalf("daily program is not enrollable, still signing: %+v", pack.Programs.V4)
	}
}
