package savings

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/brg444/arkade-runtime/internal/program"
)

type ledgerFamilyVectorTree struct {
	Address      string             `json:"address"`
	Script       string             `json:"script"`
	WalletPolicy LedgerWalletPolicy `json:"walletPolicy"`
	Scripts      []string           `json:"scripts"`
}
type ledgerFamilyVector struct {
	Input          LedgerSavingsKeyContext `json:"input"`
	SpendingPolicy program.SpendingPolicy  `json:"spendingPolicy"`
	WalletPolicy   LedgerWalletPolicy      `json:"walletPolicy"`
	Receive        ledgerFamilyVectorTree  `json:"receive"`
	Change         ledgerFamilyVectorTree  `json:"change"`
	Recovery       map[string]struct {
		Claimant   string                 `json:"claimant"`
		Guardians  []string               `json:"guardians"`
		Delay      uint32                 `json:"delay"`
		Pending    ledgerFamilyVectorTree `json:"pending"`
		Quarantine ledgerFamilyVectorTree `json:"quarantine"`
	} `json:"recovery"`
}

func ledgerFamilyVectors(t *testing.T) []ledgerFamilyVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/ledger-family-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []ledgerFamilyVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 4 {
		t.Fatal("expected two networks and two tiers")
	}
	return vectors
}
func TestLedgerNativeRecoveryFamilyVectors(t *testing.T) {
	for _, v := range ledgerFamilyVectors(t) {
		tier := "standard"
		if v.Input.Recovery != nil {
			tier = "advanced"
		}
		t.Run(v.Input.Network+"/"+tier, func(t *testing.T) {
			family, err := BuildLedgerNativeFamily(v.Input, v.SpendingPolicy)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(family.WalletPolicy, v.WalletPolicy) {
				t.Fatal("normal wallet policy mismatch")
			}
			for _, pair := range []struct {
				got  Tree
				want ledgerFamilyVectorTree
			}{{family.Receive.Tree, v.Receive}, {family.Change.Tree, v.Change}} {
				if pair.got.Address != pair.want.Address || hex.EncodeToString(pair.got.PkScript) != pair.want.Script {
					t.Fatal("normal tree mismatch")
				}
			}
			if len(family.Recovery) != len(v.Recovery) {
				t.Fatal("claimant count mismatch")
			}
			for claimant, want := range v.Recovery {
				got := family.Recovery[claimant]
				if got.Claimant != want.Claimant || got.Delay != want.Delay || !reflect.DeepEqual(got.Guardians, want.Guardians) {
					t.Fatal("recovery authority mismatch")
				}

				for _, pair := range []struct {
					got  LedgerRecoveryTree
					want ledgerFamilyVectorTree
				}{{got.Pending, want.Pending}, {got.Quarantine, want.Quarantine}} {
					if pair.got.Address != pair.want.Address || hex.EncodeToString(pair.got.PkScript) != pair.want.Script || !reflect.DeepEqual(pair.got.WalletPolicy, pair.want.WalletPolicy) {
						t.Fatal("recovery policy or tree mismatch")
					}
					var scripts []string
					for _, s := range pair.got.Scripts {
						scripts = append(scripts, hex.EncodeToString(s))
					}
					if !reflect.DeepEqual(scripts, pair.want.Scripts) {
						t.Fatal("recovery leaf mismatch")
					}
				}
			}
		})
	}
}
func TestLedgerNativeFamilyRejectsChangedPolicy(t *testing.T) {
	v := ledgerFamilyVectors(t)[0]
	changed := v.Input
	changed.PolicyDigest = "00"
	if _, err := BuildLedgerNativeFamily(changed, v.SpendingPolicy); err == nil {
		t.Fatal("accepted changed digest")
	}
	p, err := program.DefaultSpendingPolicyFor("mainnet")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildLedgerNativeFamily(v.Input, p); err == nil {
		t.Fatal("accepted wrong network policy")
	}
	account, err := LedgerAccountKey(v.Input.Hardware, v.Input.Network)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LedgerRecoveryChild(account, "unknown"); err == nil {
		t.Fatal("accepted unknown role")
	}
	if _, err := LedgerRecoveryInternalParent(v.Input, "recovery", "pending"); err == nil {
		t.Fatal("accepted absent claimant")
	}
	if _, err := LedgerRecoveryInternalParent(v.Input, "phone", "unknown"); err == nil {
		t.Fatal("accepted unknown stage")
	}
}

func TestLedgerGuardianFamilyValidatesFullPolicy(t *testing.T) {
	f := newLedgerGuardianFixture(t, false)
	for _, mutate := range []func(*program.SpendingPolicy){
		func(p *program.SpendingPolicy) { p.Program = "unknown" },
		func(p *program.SpendingPolicy) { p.Schema = "unknown" },
		func(p *program.SpendingPolicy) { p.Period = "unknown" },
		func(p *program.SpendingPolicy) { p.TxRecipientCapSats = 0 },
		func(p *program.SpendingPolicy) { p.PeriodAllowanceSats = 0 },
		func(p *program.SpendingPolicy) { p.AbsoluteFeeCapSats-- },
		func(p *program.SpendingPolicy) { p.FeerateCapSatPerV-- },
	} {
		changed := f.policy
		mutate(&changed)
		if _, err := BuildLedgerNativeFamily(f.context, changed); err == nil {
			t.Fatal("invalid full policy accepted")
		}
	}
}
