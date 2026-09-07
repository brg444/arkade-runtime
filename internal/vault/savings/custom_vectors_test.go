package savings

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/brg444/arkade-runtime/internal/program"
)

type customSavingsVector struct {
	Name  string `json:"name"`
	Input struct {
		Network        string                 `json:"network"`
		ProtectionTier string                 `json:"protectionTier"`
		SpendingPolicy program.SpendingPolicy `json:"spendingPolicy"`
	} `json:"input"`
	Descriptor     PublicDescriptor `json:"descriptor"`
	DescriptorHash string           `json:"descriptorHash"`
}

func customSavingsInput(t *testing.T, vector customSavingsVector) FamilyInput {
	t.Helper()
	in := fixtureFamilyInput(t)
	in.Network = vector.Input.Network
	in.ProtectionTier = vector.Input.ProtectionTier
	in.SpendingPolicy = vector.Input.SpendingPolicy
	if in.ProtectionTier == program.ProtectionTierStandard {
		in.Recovery = nil
	}
	return in
}

func TestSavingsCustomPolicyConformanceVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/savings-custom-policy-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []customSavingsVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 4 {
		t.Fatal("expected both networks and protection tiers")
	}
	seen := map[string]bool{}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			in := customSavingsInput(t, vector)
			key := in.Network + "/" + in.ProtectionTier
			if seen[key] {
				t.Fatal("duplicate network/tier")
			}
			seen[key] = true
			if in.SpendingPolicy.TxRecipientCapSats != 23_456 || in.SpendingPolicy.PeriodAllowanceSats != 78_901 {
				t.Fatal("custom limits required")
			}
			descriptor, _, err := BuildPublicDescriptor(in, "https://operator.example", "savings-v1-fixture")
			if err != nil {
				t.Fatal(err)
			}
			hash, err := HashPublicDescriptor(descriptor)
			if err != nil || hash != vector.DescriptorHash || !reflect.DeepEqual(descriptor, vector.Descriptor) {
				t.Fatalf("custom descriptor changed: %s %v", hash, err)
			}
			digest, err := program.SpendingPolicyDigestHexFor(in.Network, in.SpendingPolicy)
			if err != nil || digest != descriptor.Policy.Digest {
				t.Fatal("custom policy commitment changed")
			}
			in.SpendingPolicy.TxRecipientCapSats++
			mutated, _, err := BuildPublicDescriptor(in, "https://operator.example", "savings-v1-fixture")
			if err != nil {
				t.Fatal(err)
			}
			mutatedHash, err := HashPublicDescriptor(mutated)
			if err != nil || mutatedHash == hash || mutated.Policy.Digest == digest {
				t.Fatal("policy mutation did not change commitments")
			}
		})
	}
}
