package savings

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type savingsVectorTree struct {
	Address string `json:"address"`
	Script  string `json:"script"`
}

type savingsVector struct {
	Name           string                       `json:"name"`
	ProtectionTier string                       `json:"protectionTier"`
	Recovery       bool                         `json:"recovery"`
	DescriptorHash string                       `json:"descriptorHash"`
	Savings        savingsVectorTree            `json:"savings"`
	Pending        map[string]savingsVectorTree `json:"pending"`
	Quarantine     map[string]savingsVectorTree `json:"quarantine"`
}

func TestSavingsV1ConformanceVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/savings-v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []savingsVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 2 {
		t.Fatalf("want recovery and no-recovery vectors, got %d", len(vectors))
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			in := fixtureFamilyInput(t)
			in.ProtectionTier = vector.ProtectionTier
			if !vector.Recovery {
				in.Recovery = nil
			}
			descriptor, family, err := BuildPublicDescriptor(in, "https://operator.example", "savings-v1-fixture")
			if err != nil {
				t.Fatal(err)
			}
			hash, err := HashPublicDescriptor(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if hash != vector.DescriptorHash {
				t.Fatalf("descriptor hash = %s, want %s", hash, vector.DescriptorHash)
			}
			assertVectorTree(t, "savings", family.Savings, vector.Savings)
			if len(family.Pending) != len(vector.Pending) || len(family.Quarantine) != len(vector.Quarantine) {
				t.Fatalf("tree count pending=%d/%d quarantine=%d/%d", len(family.Pending), len(vector.Pending), len(family.Quarantine), len(vector.Quarantine))
			}
			for name, want := range vector.Pending {
				assertVectorTree(t, "pending "+name, family.Pending[name], want)
			}
			for name, want := range vector.Quarantine {
				assertVectorTree(t, "quarantine "+name, family.Quarantine[name], want)
			}
		})
	}
}

func assertVectorTree(t *testing.T, name string, got Tree, want savingsVectorTree) {
	t.Helper()
	if got.Address != want.Address || hex.EncodeToString(got.PkScript) != want.Script {
		t.Fatalf("%s = %s/%x, want %s/%s", name, got.Address, got.PkScript, want.Address, want.Script)
	}
}
