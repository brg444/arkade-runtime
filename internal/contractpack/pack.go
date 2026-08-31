// Package contractpack embeds the named-program pack. Production loads this
// byte slice at startup; it is not a process-relative file path.
package contractpack

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
)

// SHA256 is the release-pinned digest of the exact Contract Pack bytes.
// Updating the pack requires an explicit binary release with a reviewed pin.
const SHA256 = "a6858ae95fda53558f2f9dbf7f1b979dbab6217d8397e41cd6598293b4b84493"

// JSON is the exact contract-pack.json committed at the repo root.
//
//go:embed contract-pack.json
var JSON []byte

// ValidateBytes rejects a missing or modified Contract Pack. The pack is a
// release artifact rather than runtime configuration.
func ValidateBytes(raw []byte) error {
	if len(raw) == 0 {
		return fmt.Errorf("contract pack is missing")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != SHA256 {
		return fmt.Errorf("contract pack digest does not match the release pin")
	}
	return nil
}

// Validate checks the embedded release artifact.
func Validate() error {
	return ValidateBytes(JSON)
}
