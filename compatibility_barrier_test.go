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
		"experiments/connector/testdata/dual-vectors.json":                "2fe59062431d2f93d4612f41f5c169409543bf3c417dbf5d44af4d7ab1f78089",
		"internal/application/testdata/connector-enrollment-vectors.json": "7c9fd567b0d1da2ab93edbf24649fefc5d4ba8fa0124345ed79850cf929613a2",
		"contract-pack.json":                                          "a9ccccb8505a2da22fbb0ca39ca9903d839317389c56a95176093099f6f88aa6",
		"internal/contractpack/contract-pack.json":                    "a9ccccb8505a2da22fbb0ca39ca9903d839317389c56a95176093099f6f88aa6",
		"contract-pack.mainnet.json":                                  "804f535d54afd67eb3bdb8cb0241612222ff76917e8ad1e8dfa3400546b605f0",
		"internal/contractpack/contract-pack.mainnet.json":            "804f535d54afd67eb3bdb8cb0241612222ff76917e8ad1e8dfa3400546b605f0",
		"internal/application/testdata/http-v1-compatibility.json":    "8cf14b8b54f79bdfa7edfb3cd7fb22cf287dc0c3a8dbe71877e95412a7ac958c",
		"internal/policy/testdata/hkdf-sha256-v1.json":                "0739edebb44f122e70aee6153e9aaf6875c73a01412469d8f16124a8f9186cde",
		"internal/policy/testdata/vtxo-hkdf-sha256-v1.json":           "9b376662c2d33f51981d2e8b1aa1f0134ccb06b556aa2536c5f93ad2c48b1285",
		"internal/policy/testdata/vault-policy-v1-tree.json":          "2774756345e8cc01aa43743f62afe831baa9cbba0f4f7117e7b9a2f38776e993",
		"internal/vault/savings/testdata/savings-v1-vectors.json":     "d49d3a162cdef07585d147ea27cd506faba245b211a6e795a055d10b476a155a",
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
