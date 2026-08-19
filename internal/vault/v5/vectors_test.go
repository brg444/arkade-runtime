package v5

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

type stagedVectorFile struct {
	RequiredGuardians map[string]struct {
		WithRecovery    []string `json:"withRecovery"`
		WithoutRecovery []string `json:"withoutRecovery"`
	} `json:"requiredGuardians"`
	WitnessBytes struct {
		InitiateDailyPhoneOrHardwareWithRecovery int64 `json:"initiateDailyPhoneOrHardwareWithRecovery"`
		InitiateOtherwiseWithRecovery            int64 `json:"initiateOtherwiseWithRecovery"`
		InitiateSavingsHardwareWithoutRecovery   int64 `json:"initiateSavingsHardwareWithoutRecovery"`
		Clawback                                 int64 `json:"clawback"`
		ClawbackServerFreeWithRecovery           int64 `json:"clawbackServerFreeWithRecovery"`
	} `json:"witnessBytes"`
	Vectors []struct {
		Name           string            `json:"name"`
		Template       string            `json:"template"`
		Recovery       bool              `json:"recovery"`
		Daily          string            `json:"daily"`
		Savings        string            `json:"savings"`
		DescriptorHash string            `json:"descriptorHash"`
		Pending        map[string]string `json:"pending"`
		Quarantine     map[string]string `json:"quarantine"`
		InitiateAuth   map[string]string `json:"initiateAuth"`
		ClawbackAuth   map[string]string `json:"clawbackAuth"`
		GuardianExit   map[string]string `json:"guardianExit"`
	} `json:"vectors"`
}

func loadStagedVectors(t *testing.T) stagedVectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/staged-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file stagedVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestFrozenStagedVectors(t *testing.T) {
	file := loadStagedVectors(t)
	if file.WitnessBytes.ClawbackServerFreeWithRecovery != 431 {
		t.Fatalf("server-free clawback witness %d", file.WitnessBytes.ClawbackServerFreeWithRecovery)
	}
	if !equalStrings(file.RequiredGuardians["phone"].WithRecovery, []string{"hardware", "recovery"}) {
		t.Fatal("phone remaining keys drifted")
	}
	if !equalStrings(file.RequiredGuardians["hardware"].WithoutRecovery, []string{"phone"}) {
		t.Fatal("hardware remaining keys drifted")
	}
	for _, vec := range file.Vectors {
		in := fixtureFamilyInput(t)
		in.TemplateVersion = vec.Template
		in.ServerFreeClawback = vec.Template == Template
		if !vec.Recovery {
			in.Recovery = nil
		}
		fam, err := BuildFamily(in)
		if err != nil {
			t.Fatalf("%s family: %v", vec.Name, err)
		}
		desc, _, err := BuildPublicDescriptor(in, "http://emulator.local", "v5-fixture")
		if err != nil {
			t.Fatalf("%s descriptor: %v", vec.Name, err)
		}
		hash, err := HashPublicDescriptor(desc)
		if err != nil {
			t.Fatalf("%s hash: %v", vec.Name, err)
		}
		if fam.Daily.Address != vec.Daily || fam.Savings.Address != vec.Savings {
			t.Fatalf("%s normal addresses drifted", vec.Name)
		}
		if hash != vec.DescriptorHash {
			t.Fatalf("%s hash %s want %s", vec.Name, hash, vec.DescriptorHash)
		}
		for key, want := range vec.Pending {
			if fam.Pending[key].Address != want {
				t.Fatalf("%s pending %s = %s want %s", vec.Name, key, fam.Pending[key].Address, want)
			}
		}
		for key, want := range vec.Quarantine {
			if fam.Quarantine[key].Address != want {
				t.Fatalf("%s quarantine %s = %s want %s", vec.Name, key, fam.Quarantine[key].Address, want)
			}
		}
		for key, want := range vec.InitiateAuth {
			got := hex.EncodeToString(fam.InitiateAuth[key])
			if got != want {
				t.Fatalf("%s initiateAuth %s drifted", vec.Name, key)
			}
		}
		for key, want := range vec.ClawbackAuth {
			got := hex.EncodeToString(fam.ClawbackAuth[key])
			if got != want {
				t.Fatalf("%s clawbackAuth %s drifted", vec.Name, key)
			}
		}
		if vec.Template == Template {
			for key, want := range vec.GuardianExit {
				got, err := guardianExitScript(in, key)
				if err != nil {
					t.Fatalf("%s guardianExit %s: %v", vec.Name, key, err)
				}
				if hex.EncodeToString(got) != want {
					t.Fatalf("%s guardianExit %s drifted", vec.Name, key)
				}
			}
		}
	}
}

func guardianExitScript(in FamilyInput, key string) ([]byte, error) {
	parts := strings.Split(key, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("family key %q", key)
	}
	claimant := parts[1]
	roles := map[string]*btcec.PublicKey{"phone": in.Phone, "hardware": in.Hardware, "recovery": in.Recovery}
	var pubs []*btcec.PublicKey
	for _, g := range familyClaimants(in.Recovery != nil) {
		if g == claimant {
			continue
		}
		pubs = append(pubs, roles[g])
	}
	return checksig(pubs...)
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
