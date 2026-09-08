package savings

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

type ledgerParentVector struct {
	Xpub     string   `json:"xpub"`
	Children []string `json:"children"`
}
type ledgerProgramVector struct {
	ledgerParentVector
	Claimant string `json:"claimant"`
	Cosigner string `json:"cosigner"`
	Program  string `json:"program"`
}
type ledgerKeyVector struct {
	Input          LedgerSavingsKeyContext `json:"input"`
	ContextDigest  string                  `json:"contextDigest"`
	Internal       ledgerParentVector      `json:"internal"`
	Accounts       map[string][]string     `json:"accounts"`
	ProgramParents []ledgerProgramVector   `json:"programParents"`
	Normal         struct {
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
	var vectors []ledgerKeyVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 4 {
		t.Fatal("expected two networks and two tiers")
	}
	return vectors
}

func ledgerChildHex(t *testing.T, parent *hdkeychain.ExtendedKey, branch uint32) string {
	t.Helper()
	child, err := LedgerSavingsChild(parent, branch, 0)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := child.ECPubKey()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub.SerializeCompressed())
}

func TestLedgerNativeKeyVectors(t *testing.T) {
	for _, vector := range ledgerVectors(t) {
		tier := "standard"
		if vector.Input.Recovery != nil {
			tier = "advanced"
		}
		t.Run(vector.Input.Network+"/"+tier, func(t *testing.T) {
			in := vector.Input
			programs := map[string]string{}
			for _, p := range vector.ProgramParents {
				programs[p.Claimant] = p.Program
			}
			normal, err := BuildLedgerNativeSavings(in, programs)
			if err != nil {
				t.Fatal(err)
			}
			gotPolicy, _ := json.Marshal(normal.WalletPolicy)
			wantPolicy, _ := json.Marshal(vector.Normal.WalletPolicy)
			if !bytes.Equal(gotPolicy, wantPolicy) {
				t.Fatal("Ledger policy differs from wallet")
			}
			assertVectorTree(t, "Ledger receive", normal.Receive, vector.Normal.Receive)
			assertVectorTree(t, "Ledger change", normal.Change, vector.Normal.Change)
			digest, err := LedgerSavingsContextDigest(in)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(digest) != vector.ContextDigest {
				t.Fatal("context differs from wallet")
			}
			internal, err := LedgerSavingsInternalParent(in)
			if err != nil {
				t.Fatal(err)
			}
			if internal.String() != vector.Internal.Xpub {
				t.Fatal("NUMS parent differs from wallet")
			}
			for i, expected := range vector.Internal.Children {
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
				for i, expected := range vector.Accounts[role] {
					if ledgerChildHex(t, key, uint32(i)) != expected {
						t.Fatal("account child differs from wallet")
					}
				}
			}
			for _, expected := range vector.ProgramParents {
				script, err := hex.DecodeString(expected.Program)
				if err != nil {
					t.Fatal(err)
				}
				parent, err := LedgerRecoveryProgramParent(in, expected.Claimant, expected.Cosigner, script)
				if err != nil {
					t.Fatal(err)
				}
				if parent.String() != expected.Xpub {
					t.Fatal("program parent differs from wallet")
				}
				// Private derivation stays in this public-fixture test. Production key
				// backends still require the evaluated named-operation boundary.
				scalar := make([]byte, 32)
				scalar[31] = 14
				if expected.Cosigner == "arkade" {
					scalar[31] = 15
				}
				base, _ := btcec.PrivKeyFromBytes(scalar)
				secret := arkade.ComputeArkadeScriptPrivateKey(base, arkade.ArkadeScriptHash(script))
				params, _ := networkParams(in.Network)
				private := hdkeychain.NewExtendedKey(params.HDPrivateKeyID[:], secret.Serialize(), parent.ChainCode(), make([]byte, 4), 0, 0, true)
				for i, child := range expected.Children {
					if ledgerChildHex(t, parent, uint32(i)) != child || ledgerChildHex(t, private, uint32(i)) != child {
						t.Fatal("private/public child disagreement")
					}
				}
				private.Zero()
				secret.Zero()
				base.Zero()
			}
		})
	}
}

func TestLedgerNativeRejectsSubstitution(t *testing.T) {
	in := ledgerVectors(t)[0].Input
	origin := in.Hardware
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
		func(o *LedgerAccountOrigin) { o.Fingerprint = strings.ToUpper(o.Fingerprint) },
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
		func(c *LedgerSavingsKeyContext) { c.ArkadeCosignerBase = c.VaultCosignerBase },
		func(c *LedgerSavingsKeyContext) { c.PolicyDigest = "" },
		func(c *LedgerSavingsKeyContext) { c.VaultID = strings.ToUpper(c.VaultID) },
		func(c *LedgerSavingsKeyContext) { c.PhoneDirectP256 = strings.Repeat("00", 33) },
		func(c *LedgerSavingsKeyContext) { c.TemplateVersion = Template },
	} {
		changed := in
		mutate(&changed)
		if _, err := LedgerSavingsContextDigest(changed); err == nil {
			t.Fatal("accepted invalid context")
		}
	}
	if _, err := LedgerRecoveryProgramParent(in, "recovery", "vault", []byte{0x51}); err == nil {
		t.Fatal("accepted absent recovery key")
	}
	if _, err := LedgerRecoveryProgramParent(in, "phone", "vault", nil); err == nil {
		t.Fatal("accepted empty program")
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
	}
}
