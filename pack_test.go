package pack_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/contractpack"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
)

func TestContractPackMatchesLiveEnroll(t *testing.T) {
	raw, err := os.ReadFile("contract-pack.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Version  int `json:"version"`
		Programs struct {
			Savings struct {
				Status          string `json:"status"`
				Enrollable      *bool  `json:"enrollable"`
				Template        string `json:"template"`
				ProtectionTiers map[string]struct {
					RecoveryKey string `json:"recoveryKey"`
				} `json:"protectionTiers"`
			} `json:"savings-recovery-v1"`
		} `json:"programs"`
		Formats struct {
			RecoveryKit int `json:"recoveryKit"`
			MapBackup   int `json:"mapBackup"`
		} `json:"formats"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	if pack.Programs.Savings.Status != "live" || pack.Programs.Savings.Template != savings.Template {
		t.Fatalf("live enroll: %+v want template %s", pack.Programs.Savings, savings.Template)
	}
	if pack.Programs.Savings.Enrollable == nil || !*pack.Programs.Savings.Enrollable {
		t.Fatalf("Savings program must be enrollable: %+v", pack.Programs.Savings)
	}
	if pack.Version != 2 || pack.Formats.RecoveryKit != 3 || pack.Formats.MapBackup != 3 ||
		pack.Programs.Savings.ProtectionTiers["standard"].RecoveryKey != "forbidden" ||
		pack.Programs.Savings.ProtectionTiers["advanced"].RecoveryKey != "required" {
		t.Fatalf("protection/formats contract: %+v", pack)
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
	if _, ok := programs["savings-recovery-v1"].(map[string]any); !ok {
		t.Fatal("Savings recovery program must be listed")
	}
	listed, ok := programs["vault-policy-v1"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 must be listed beside Savings recovery")
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
	note, ok := delegate["note"].(string)
	if !ok ||
		!strings.Contains(note, "SDK 0.4.65") ||
		!strings.Contains(note, "DelegatorManager matches any Multisig containing the delegate pub") ||
		!strings.Contains(note, "4-key delegate-forfeit") ||
		!strings.Contains(note, "Not OP_TUNNEL") ||
		!strings.Contains(note, "stays fail-closed until this capability is advertised") {
		t.Fatalf("vault-policy-v1 delegate note: %+v", delegate)
	}
	if listed["notes"] != "Spending only. Savings stays L1. VTXO Spending does not reuse the Savings Pending or Quarantine trees. No OP_TUNNEL. Guardian delay is product-chosen 4608 seconds, not arkd's 2048-second minimum. Boarding enters through the separately listed vault-board-v1 intermediate. Exactly one guardian CSV exit leaf. Collaborative spend is 3-key [user, VTXO VaultCosigner, Arkade Operator]. The required VaultCosigner independently enforces the Vault Program." {
		t.Fatalf("vault-policy-v1 notes: %v", listed["notes"])
	}
	board, ok := programs["vault-board-v1"].(map[string]any)
	if !ok || board["status"] != "live" || board["destination"] != "vault-policy-v1" {
		t.Fatalf("vault-board-v1: %#v", programs["vault-board-v1"])
	}
	exit, ok = board["exit"].(map[string]any)
	if !ok || exit["delay"] != "604672" || exit["delayUnit"] != "seconds" {
		t.Fatalf("vault-board-v1 exit: %#v", board["exit"])
	}
	policySchema, ok := listed["policySchema"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 policy schema required")
	}
	if policySchema["program"] != "vault-policy-v1" ||
		policySchema["schema"] != "vault-spending-policy-v1" ||
		policySchema["period"] != "rolling-24h" ||
		policySchema["immutableAfterEnrollment"] != true {
		t.Fatalf("vault-policy-v1 policy identity: %+v", policySchema)
	}
	bounds, ok := policySchema["bounds"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 policy bounds required")
	}
	txBound, ok := bounds["txRecipientCapSats"].(map[string]any)
	if !ok || txBound["min"] != float64(330) || txBound["max"] != float64(100000000) {
		t.Fatalf("vault-policy-v1 transaction cap bounds: %+v", bounds)
	}
	feeBound, ok := bounds["absoluteFeeCapSats"].(map[string]any)
	feerateBound, rateOK := bounds["feerateCapSatPerV"].(map[string]any)
	if !ok || !rateOK || feeBound["min"] != float64(5000) || feeBound["max"] != float64(5000) ||
		feerateBound["min"] != float64(10) || feerateBound["max"] != float64(10) {
		t.Fatalf("vault-policy-v1 release-managed fee bounds: %+v", bounds)
	}
	presets, ok := policySchema["presets"].(map[string]any)
	if !ok {
		t.Fatal("vault-policy-v1 policy presets required")
	}
	lower, lowerOK := presets["lower-exposure"].(map[string]any)
	everyday, everydayOK := presets["everyday"].(map[string]any)
	if !lowerOK || !everydayOK || len(presets) != 2 ||
		lower["txRecipientCapSats"] != float64(25000) || lower["periodAllowanceSats"] != float64(50000) ||
		everyday["txRecipientCapSats"] != float64(50000) || everyday["periodAllowanceSats"] != float64(100000) {
		t.Fatalf("vault-policy-v1 exposure presets: %+v", presets)
	}
	tiers, ok := listed["protectionTiers"].(map[string]any)
	if !ok || len(tiers) != 2 {
		t.Fatalf("vault-policy-v1 protection tiers: %+v", listed["protectionTiers"])
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
	if err := contractpack.ValidateBytes(raw); err != nil {
		t.Fatal(err)
	}
	if err := contractpack.Validate(); err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), raw...)
	mutated[0] ^= 1
	if err := contractpack.ValidateBytes(mutated); err == nil {
		t.Fatal("modified Contract Pack matched the release digest")
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
	if pack.Domains["recoveryBinding"] != "arkade-vault/recovery-binding/v4" {
		t.Fatalf("recovery binding domain = %q", pack.Domains["recoveryBinding"])
	}
	if _, ok := pack.Programs["savings-recovery-v1"]["recoveryPopTag"]; ok {
		t.Fatal("Savings recovery program must not publish a recovery proof tag")
	}
}
