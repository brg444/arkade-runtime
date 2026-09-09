package savings

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

type ledgerParentVector struct {
	Xpub     string   `json:"xpub"`
	Children []string `json:"children"`
}
type ledgerKeyVector struct {
	Input         LedgerSavingsKeyContext `json:"input"`
	ContextDigest string                  `json:"contextDigest"`
	Internal      ledgerParentVector      `json:"internal"`
	Accounts      map[string][]string     `json:"accounts"`
	Guardian      struct {
		Xpub     string `json:"xpub"`
		Children []struct {
			Kind     string `json:"kind"`
			Claimant string `json:"claimant"`
			Guardian string `json:"guardian"`
			Change   uint32 `json:"change"`
			Branch   uint32 `json:"branch"`
			Pubkey   string `json:"pubkey"`
		} `json:"children"`
	} `json:"guardian"`
	Normal struct {
		WalletPolicy LedgerWalletPolicy `json:"walletPolicy"`
		Receive      savingsVectorTree  `json:"receive"`
		Change       savingsVectorTree  `json:"change"`
	} `json:"normal"`
}

func ledgerVectors(t *testing.T) []ledgerKeyVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/ledger-key-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"arkadeCosignerBase", "programParents"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("Guardian-only vector contains %s", forbidden)
		}
	}
	var vectors []ledgerKeyVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 4 {
		t.Fatal("expected two networks and two tiers")
	}
	return vectors
}
func ledgerKeyHex(t *testing.T, key *hdkeychain.ExtendedKey) string {
	t.Helper()
	pub, err := key.ECPubKey()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub.SerializeCompressed())
}
func ledgerChildHex(t *testing.T, parent *hdkeychain.ExtendedKey, branch uint32) string {
	t.Helper()
	child, err := LedgerSavingsChild(parent, branch, 0)
	if err != nil {
		t.Fatal(err)
	}
	return ledgerKeyHex(t, child)
}
func TestLedgerGuardianKeyVectors(t *testing.T) {
	for _, v := range ledgerVectors(t) {
		tier := "standard"
		if v.Input.Recovery != nil {
			tier = "advanced"
		}
		t.Run(v.Input.Network+"/"+tier, func(t *testing.T) {
			in := v.Input
			normal, err := BuildLedgerNativeSavings(in)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(normal.WalletPolicy, v.Normal.WalletPolicy) {
				t.Fatal("Ledger policy differs from wallet")
			}
			assertVectorTree(t, "Ledger receive", normal.Receive.Tree, v.Normal.Receive)
			assertVectorTree(t, "Ledger change", normal.Change.Tree, v.Normal.Change)
			digest, err := LedgerSavingsContextDigest(in)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(digest) != v.ContextDigest {
				t.Fatal("context differs from wallet")
			}
			internal, err := LedgerSavingsInternalParent(in)
			if err != nil {
				t.Fatal(err)
			}
			if internal.String() != v.Internal.Xpub {
				t.Fatal("NUMS parent differs from wallet")
			}
			for i, expected := range v.Internal.Children {
				if ledgerChildHex(t, internal, uint32(i)) != expected {
					t.Fatal("NUMS child differs from wallet")
				}
			}
			accounts := map[string]LedgerAccountOrigin{"phone": in.Phone, "hardware": in.Hardware}
			if in.Recovery != nil {
				accounts["recovery"] = *in.Recovery
			}
			for role, origin := range accounts {
				key, err := LedgerAccountKey(origin, in.Network)
				if err != nil {
					t.Fatal(err)
				}
				for i, expected := range v.Accounts[role] {
					if ledgerChildHex(t, key, uint32(i)) != expected {
						t.Fatal("account child differs from wallet")
					}
				}
			}
			parent, err := LedgerSavingsGuardianParent(in)
			if err != nil {
				t.Fatal(err)
			}
			if parent.String() != v.Guardian.Xpub {
				t.Fatal("Guardian parent differs from wallet")
			}
			if ledgerKeyHex(t, parent) != in.VaultCosignerBase {
				t.Fatal("Guardian parent must retain raw base point")
			}
			scalar := make([]byte, 32)
			scalar[31] = 14
			base, _ := btcec.PrivKeyFromBytes(scalar)
			defer base.Zero()
			params, _ := networkParams(in.Network)
			private := hdkeychain.NewExtendedKey(params.HDPrivateKeyID[:], base.Serialize(), parent.ChainCode(), make([]byte, 4), 0, 0, true)
			defer private.Zero()
			count := 6
			if in.Recovery != nil {
				count = 12
			}
			if len(v.Guardian.Children) != count {
				t.Fatal("incomplete Guardian coordinate vectors")
			}
			for _, expected := range v.Guardian.Children {
				for _, p := range []*hdkeychain.ExtendedKey{parent, private} {
					var child *hdkeychain.ExtendedKey
					var branch uint32
					switch expected.Kind {
					case "initiate":
						branch, err = LedgerGuardianInitiateBranch(in, expected.Claimant, expected.Change)
						if err == nil {
							child, err = LedgerGuardianInitiateChild(in, p, expected.Claimant, expected.Change)
						}
					case "clawback":
						branch, err = LedgerGuardianClawbackBranch(in, expected.Claimant, expected.Guardian)
						if err == nil {
							child, err = LedgerGuardianClawbackChild(in, p, expected.Claimant, expected.Guardian)
						}
					default:
						t.Fatalf("unknown vector kind %s", expected.Kind)
					}
					if err != nil {
						t.Fatal(err)
					}
					if branch != expected.Branch || ledgerKeyHex(t, child) != expected.Pubkey {
						t.Fatal("Guardian private/public coordinate differs from wallet")
					}
				}
			}
		})
	}
}

func TestLedgerGuardianRejectsSubstitution(t *testing.T) {
	f := newLedgerGuardianFixture(t, false)
	in, origin := f.context, f.context.Hardware
	key, err := LedgerAccountKey(origin, in.Network)
	if err != nil {
		t.Fatal(err)
	}
	for _, coordinate := range [][2]uint32{{4, 0}, {0, 1}, {0, hdkeychain.HardenedKeyStart}} {
		if _, err := LedgerSavingsChild(key, coordinate[0], coordinate[1]); err == nil {
			t.Fatal("accepted unenrolled coordinate")
		}
	}
	if _, err := LedgerAccountKey(origin, "mainnet"); err == nil {
		t.Fatal("accepted wrong network")
	}
	for _, mutate := range []func(*LedgerAccountOrigin){
		func(o *LedgerAccountOrigin) { o.Fingerprint = "AABBCCDD" },
		func(o *LedgerAccountOrigin) {
			o.Path = []uint32{hdkeychain.HardenedKeyStart + 84, hdkeychain.HardenedKeyStart + 1, hdkeychain.HardenedKeyStart}
		},
		func(o *LedgerAccountOrigin) {
			o.Path = []uint32{hdkeychain.HardenedKeyStart + 86, hdkeychain.HardenedKeyStart + 1, hdkeychain.HardenedKeyStart + 1}
		},
		func(o *LedgerAccountOrigin) { child, _ := key.Derive(0); o.Xpub = child.String() },
	} {
		changed := origin
		mutate(&changed)
		if _, err := LedgerAccountKey(changed, in.Network); err == nil {
			t.Fatal("accepted substituted account")
		}
	}
	for _, mutate := range []func(*LedgerSavingsKeyContext){
		func(c *LedgerSavingsKeyContext) { c.Phone = c.Hardware },
		func(c *LedgerSavingsKeyContext) { c.VaultCosignerBase = ledgerKeyHex(t, key) },
		func(c *LedgerSavingsKeyContext) { c.PolicyDigest = "" },
		func(c *LedgerSavingsKeyContext) { c.VaultID = strings.ToUpper(c.VaultID) },
		func(c *LedgerSavingsKeyContext) { c.PhoneDirectP256 = strings.Repeat("00", 33) },
		func(c *LedgerSavingsKeyContext) { c.TemplateVersion = Template },
		func(c *LedgerSavingsKeyContext) { c.TemplateVersion = "phone-ledger-recovery-savings-v1" },
	} {
		changed := in
		mutate(&changed)
		if _, err := LedgerSavingsContextDigest(changed); err == nil {
			t.Fatal("accepted invalid context")
		}
	}
	base, _ := LedgerSavingsContextDigest(in)
	for _, mutate := range []func(*LedgerSavingsKeyContext){
		func(c *LedgerSavingsKeyContext) { c.VaultID = strings.Repeat("11", 16) },
		func(c *LedgerSavingsKeyContext) { c.PolicyDigest = strings.Repeat("22", 32) },
		func(c *LedgerSavingsKeyContext) { c.Hardware.Fingerprint = "00000001" },
	} {
		changed := in
		mutate(&changed)
		digest, err := LedgerSavingsContextDigest(changed)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(base, digest) {
			t.Fatal("context substitution not bound")
		}
		if _, err := LedgerGuardianInitiateChild(changed, f.guardian, "phone", 0); err == nil {
			t.Fatal("accepted context-substituted Guardian parent")
		}
	}
	for _, claimant := range []string{"", "recovery", "arkade", "vault"} {
		if _, err := LedgerGuardianInitiateChild(in, f.guardian, claimant, 0); err == nil {
			t.Fatal("accepted inapplicable claimant")
		}
	}
	for _, change := range []uint32{2, 3, hdkeychain.HardenedKeyStart} {
		if _, err := LedgerGuardianInitiateChild(in, f.guardian, "phone", change); err == nil {
			t.Fatal("accepted unenrolled change")
		}
	}
	for _, roles := range [][2]string{{"phone", "phone"}, {"phone", "recovery"}, {"recovery", "hardware"}, {"hardware", "guardian"}} {
		if _, err := LedgerGuardianClawbackChild(in, f.guardian, roles[0], roles[1]); err == nil {
			t.Fatal("accepted inapplicable clawback roles")
		}
	}
	for _, parent := range []*hdkeychain.ExtendedKey{nil, key} {
		if _, err := LedgerGuardianInitiateChild(in, parent, "phone", 0); err == nil {
			t.Fatal("accepted substituted Guardian parent")
		}
	}
}
