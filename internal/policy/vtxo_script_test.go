package policy

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type vaultPolicyV1Golden struct {
	Name     string `json:"name"`
	Exit     struct {
		Delay    string `json:"delay"`
		DelayUnit string `json:"delayUnit"`
		ArkdMinimum string `json:"arkdMinimum"`
	} `json:"exit"`
	Fixtures map[string]string `json:"fixtures"`
	Leaves   struct {
		Spend           string `json:"spend"`
		ExitTwoGuardian string `json:"exitTwoGuardian"`
		ExitThreeGuardian string `json:"exitThreeGuardian"`
		Delegate        string `json:"delegate"`
	} `json:"leaves"`
	TwoGuardian struct {
		TapKey   string `json:"tapKey"`
		PkScript string `json:"pkScript"`
	} `json:"twoGuardian"`
	ThreeGuardian struct {
		TapKey   string `json:"tapKey"`
		PkScript string `json:"pkScript"`
	} `json:"threeGuardian"`
}

func loadVaultPolicyV1Golden(t *testing.T) vaultPolicyV1Golden {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vault-policy-v1-tree.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g vaultPolicyV1Golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func goldenXOnly(t *testing.T, g vaultPolicyV1Golden, name string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(g.Fixtures[name])
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(raw) == 33 {
		return raw[1:]
	}
	if len(raw) != 32 {
		t.Fatalf("%s length %d", name, len(raw))
	}
	return raw
}

func twoGuardianParams(t *testing.T, g vaultPolicyV1Golden) VaultPolicyV1Params {
	t.Helper()
	return VaultPolicyV1Params{
		UserPub:              goldenXOnly(t, g, "userPub"),
		VtxoVaultCosignerPub: goldenXOnly(t, g, "vtxoVaultCosignerPub"),
		TweakedEmulatorPub:   goldenXOnly(t, g, "tweakedEmulatorPub"),
		ArkdServerPub:        goldenXOnly(t, g, "arkdServerPub"),
		DelegatePub:          goldenXOnly(t, g, "delegatePub"),
		ExitDevicePub:        goldenXOnly(t, g, "exitDevicePub"),
		ExitHardwarePub:      goldenXOnly(t, g, "exitHardwarePub"),
	}
}

func TestBuildVaultPolicyV1TreeMatchesSharedGolden(t *testing.T) {
	g := loadVaultPolicyV1Golden(t)
	if g.Exit.Delay != "4608" || g.Exit.DelayUnit != "seconds" || g.Exit.ArkdMinimum != "2048" {
		t.Fatalf("golden delay %+v", g.Exit)
	}
	two, err := BuildVaultPolicyV1Tree(twoGuardianParams(t, g))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(two.SpendScript) != g.Leaves.Spend {
		t.Fatalf("spend\n got %x\nwant %s", two.SpendScript, g.Leaves.Spend)
	}
	if hex.EncodeToString(two.ExitScript) != g.Leaves.ExitTwoGuardian {
		t.Fatalf("exit two\n got %x\nwant %s", two.ExitScript, g.Leaves.ExitTwoGuardian)
	}
	if hex.EncodeToString(two.DelegateScript) != g.Leaves.Delegate {
		t.Fatalf("delegate\n got %x\nwant %s", two.DelegateScript, g.Leaves.Delegate)
	}
	if hex.EncodeToString(two.TapKey) != g.TwoGuardian.TapKey {
		t.Fatalf("tapKey two\n got %x\nwant %s", two.TapKey, g.TwoGuardian.TapKey)
	}
	if hex.EncodeToString(two.PkScript) != g.TwoGuardian.PkScript {
		t.Fatalf("pkScript two\n got %x\nwant %s", two.PkScript, g.TwoGuardian.PkScript)
	}
	if n := countCSVLeaves(two); n != 1 {
		t.Fatalf("exit leaves = %d", n)
	}

	threeParams := twoGuardianParams(t, g)
	threeParams.ExitRecoveryPub = goldenXOnly(t, g, "exitRecoveryPub")
	three, err := BuildVaultPolicyV1Tree(threeParams)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(three.ExitScript) != g.Leaves.ExitThreeGuardian {
		t.Fatalf("exit three\n got %x\nwant %s", three.ExitScript, g.Leaves.ExitThreeGuardian)
	}
	if hex.EncodeToString(three.ExitScript) == hex.EncodeToString(two.ExitScript) {
		t.Fatal("recovery must replace the two-guardian exit, not add a second exit")
	}
	if hex.EncodeToString(three.TapKey) != g.ThreeGuardian.TapKey {
		t.Fatalf("tapKey three\n got %x\nwant %s", three.TapKey, g.ThreeGuardian.TapKey)
	}
	if hex.EncodeToString(three.PkScript) != g.ThreeGuardian.PkScript {
		t.Fatalf("pkScript three\n got %x\nwant %s", three.PkScript, g.ThreeGuardian.PkScript)
	}
	if n := countCSVLeaves(three); n != 1 {
		t.Fatalf("three-guardian exit leaves = %d", n)
	}
}

func TestBuildVaultPolicyV1TreeUsesPinnedDelegateXOnly(t *testing.T) {
	g := loadVaultPolicyV1Golden(t)
	p := twoGuardianParams(t, g)
	p.DelegatePub = mustHexBytes(t, program.VaultPolicyV1PinnedDelegate)
	tree, err := BuildVaultPolicyV1Tree(p)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(g.Leaves.Delegate)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(tree.DelegateScript) != hex.EncodeToString(want) {
		t.Fatalf("pinned compressed delegate must encode the same leaf as x-only golden")
	}
	pub, err := parsePolicyPub(p.DelegatePub, "delegatePub")
	if err != nil {
		t.Fatal(err)
	}
	xonly := schnorr.SerializePubKey(pub)
	if hex.EncodeToString(xonly) != g.Fixtures["delegatePub"] {
		t.Fatalf("pinned delegate x-only %x want %s", xonly, g.Fixtures["delegatePub"])
	}
}

func countCSVLeaves(tree *VaultPolicyV1Tree) int {
	n := 0
	for _, raw := range [][]byte{tree.SpendScript, tree.ExitScript, tree.DelegateScript} {
		c, err := arkscript.DecodeClosure(raw)
		if err != nil {
			continue
		}
		if _, ok := c.(*arkscript.CSVMultisigClosure); ok {
			n++
		}
	}
	return n
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
