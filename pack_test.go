package pack_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/contractpack"
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

func TestContractPackListsVaultPolicyV1WithExitAndDelegate(t *testing.T) {
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
	if listed["schema"] != "arkade-vault/vtxo-policy-v1" || listed["template"] != "vault-policy-v1-collaborative-3key" {
		t.Fatalf("vault-policy-v1 identity: %+v", listed)
	}
	spend, ok := listed["spend"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 must declare 3-key collaborative spend")
	}
	if spend["leaf"] != "user-and-vtxo-vault-cosigner-and-arkd" {
		t.Fatalf("vault-policy-v1 spend leaf: %+v", spend)
	}
	if spend["note"] != "3-key collaborative spend/intent [user, VTXO VaultCosigner, Arkade Operator]. The required VaultCosigner independently enforces the Vault Program." {
		t.Fatalf("vault-policy-v1 spend note: %+v", spend)
	}
	exit, ok := listed["exit"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 must declare exit")
	}
	if exit["delay"] != "4608" || exit["delayUnit"] != "seconds" {
		t.Fatalf("vault-policy-v1 exit delay: %+v", exit)
	}
	if exit["arkdMinimum"] != "2048" || exit["bip68SecondsMod"] != "512" {
		t.Fatalf("vault-policy-v1 exit validation pins: %+v", exit)
	}
	if exit["twoGuardian"] != "device-and-hardware-after-exitDelay" || exit["threeGuardian"] != "hardware-and-recovery-after-exitDelay" {
		t.Fatalf("vault-policy-v1 exit guardians: %+v", exit)
	}
	if _, ok := listed["tunnel"]; ok {
		t.Fatal("vault-policy-v1 must not declare tunnel or OP_TUNNEL")
	}
	delegate, ok := listed["delegate"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 must declare delegate")
	}
	if delegate["leaf"] != "user-and-vtxo-vault-cosigner-and-pinned-public-delegate-and-arkd" {
		t.Fatalf("vault-policy-v1 delegate leaf: %+v", delegate)
	}
	if delegate["pinnedPublicDelegate"] != "032903b15efe236d9609da10e536fb32cdf1d144778797bbf32a9b94e86601be6a" {
		t.Fatalf("vault-policy-v1 pinned delegate: %+v", delegate)
	}
	if delegate["origin"] != "https://delegator.mutinynet.arkade.sh" {
		t.Fatalf("vault-policy-v1 delegate origin: %+v", delegate)
	}
	if delegate["capability"] != "multi-presigned-signature" {
		t.Fatalf("vault-policy-v1 delegate capability: %+v", delegate)
	}
	if delegate["note"] != "SDK 0.4.28 DelegatorManager matches any Multisig containing the delegate pub. 4-key delegate-forfeit. Not DelegateVtxo.Script. Not OP_TUNNEL. Fulmine forwarding stays fail-closed until this capability is advertised." {
		t.Fatalf("vault-policy-v1 delegate note: %+v", delegate)
	}
	if listed["notes"] != "Spending only. Savings stays L1. No staged Pending/Quarantine. No OP_TUNNEL. Guardian delay is product-chosen 4608 seconds, not arkd's 2048-second minimum. L1 board remains inactive. Exactly one guardian CSV exit leaf. Collaborative spend is 3-key [user, VTXO VaultCosigner, Arkade Operator]. The required VaultCosigner independently enforces the Vault Program." {
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

func TestEmbeddedContractPackMatchesRootFile(t *testing.T) {
	raw, err := os.ReadFile("contract-pack.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(contractpack.JSON) {
		t.Fatal("embedded contract pack drifted from repo root")
	}
}

func TestContractPackDoesNotPublishEnrollmentProofs(t *testing.T) {
	raw, err := os.ReadFile("contract-pack.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Programs map[string]map[string]any `json:"programs"`
		Domains  map[string]string         `json:"domains"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	if _, ok := pack.Domains["enrollmentPop"]; ok {
		t.Fatal("contract pack must not publish an enrollment proof domain")
	}
	if _, ok := pack.Programs["staged"]["recoveryPopTag"]; ok {
		t.Fatal("staged program must not publish a recovery proof tag")
	}
}
