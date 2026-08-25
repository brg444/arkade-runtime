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
		"contract-pack.json":                                          "a229aeda7b21ec8e23396cbc16f6b072d3458f22f9c57392f2fc8b46c4745040",
		"internal/contractpack/contract-pack.json":                    "a229aeda7b21ec8e23396cbc16f6b072d3458f22f9c57392f2fc8b46c4745040",
		"internal/policy/testdata/hkdf-sha256-v1.json":                "0739edebb44f122e70aee6153e9aaf6875c73a01412469d8f16124a8f9186cde",
		"internal/policy/testdata/vtxo-hkdf-sha256-v1.json":           "9b376662c2d33f51981d2e8b1aa1f0134ccb06b556aa2536c5f93ad2c48b1285",
		"internal/policy/testdata/vault-policy-v1-tree.json":          "2774756345e8cc01aa43743f62afe831baa9cbba0f4f7117e7b9a2f38776e993",
		"internal/vault/savings/testdata/savings-v1-vectors.json":     "1c9e828af70f7f9f8555e64b65fbf6c8d938483446fb5cd4bb0697b5d646289e",
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
