package pack_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// TestArkadeVaultV1CompatibilityArtifacts pins the exact manifests and
// cross-language vectors that define the current arkade-vault-v1 behavior.
// The package-level conformance tests prove that the implementation matches
// each vector; these digests make changing a vector an explicit compatibility
// decision rather than an incidental fixture update.
func TestArkadeVaultV1CompatibilityArtifacts(t *testing.T) {
	want := map[string]string{
		"internal/application/testdata/renewal-set-v1.json":            "7f1eb0af4b7b68c346677c840c95c512d0069c841602a3d24a9459b799c1ec47",
		"internal/application/testdata/renewal-context-v1.json":        "75abc40808225f78b3e38a9dd0937f75c45ced819341a3b2881eb3f9488eefbf",
		"internal/application/testdata/ledger-enrollment-vectors.json": "39d3618de4fd2bf846f2f842094df6a0c554e0f66c1e1118164e1c3eb7a8e882",
		"internal/application/testdata/ledger-recovery-vectors.json":   "ce9857af7d4255b09175e06272eab5cf34a6b28d035d8d7881200d2929ff3569",
		"internal/vault/savings/testdata/ledger-key-vectors.json":      "34c30d64fc0facd4a172e53d61d75983b5f15afadc7d0f665cb20a60e8d5a84b",
		"internal/vault/savings/testdata/ledger-family-vectors.json":   "5dd692720ef47174f6b2ad7e6e9c09def0ea3197d4ac7d7534a9c0e7ff0e47e5",
		"contract-pack.json":                               "2e0fe83070119b52946bef904fdde59787bb8de489b336e77f8a955abf9560e3",
		"internal/contractpack/contract-pack.json":         "2e0fe83070119b52946bef904fdde59787bb8de489b336e77f8a955abf9560e3",
		"contract-pack.mainnet.json":                       "e629e269c1acf735d794f95e1c8ee10691bdddaffe8906606085368db7438618",
		"internal/contractpack/contract-pack.mainnet.json": "e629e269c1acf735d794f95e1c8ee10691bdddaffe8906606085368db7438618",
		// Eleven direct-hardware descriptor shapes retired; retained routes and shapes are unchanged.
		"internal/application/testdata/http-v1-compatibility.json":    "bf8a52a6d8fd28f4344fdd341185f1b9cc1a2b27532b49fa09f7f7dd334d42ed",
		"internal/policy/testdata/hkdf-sha256-v1.json":                "0739edebb44f122e70aee6153e9aaf6875c73a01412469d8f16124a8f9186cde",
		"internal/policy/testdata/vtxo-hkdf-sha256-v1.json":           "9b376662c2d33f51981d2e8b1aa1f0134ccb06b556aa2536c5f93ad2c48b1285",
		"internal/policy/testdata/vault-policy-v1-tree.json":          "2774756345e8cc01aa43743f62afe831baa9cbba0f4f7117e7b9a2f38776e993",
		"internal/application/testdata/sdk-0.4.65-pending-proof.json": "519d6efe60517d8a5cc9702857f7ec056693afb32163ec1464367efb523a7eb5",
	}
	for path, expected := range want {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != expected {
			t.Fatalf("%s digest = %s, want %s", path, got, expected)
		}
	}
}
