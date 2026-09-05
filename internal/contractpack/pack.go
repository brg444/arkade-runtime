// Package contractpack embeds the named-program pack. Production loads this
// byte slice at startup; it is not a process-relative file path.
package contractpack

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
)

// SHA256 is the Mutinynet release-pinned digest of contract-pack.json.
// Updating the pack requires an explicit binary release with a reviewed pin.
const SHA256 = "3a30b9819a071d6bcec4d5ae5a27a0bae20a1e3445293998a60402525ba44526"

// MainnetSHA256 is the mainnet release-pinned digest of contract-pack.mainnet.json.
const MainnetSHA256 = "7d78c79aaebf4b85e1996fb8e7ad119dd37aae610bdf6ac794a4304a71abfcd3"

// JSON is the exact Mutinynet contract-pack.json committed at the repo root.
//
//go:embed contract-pack.json
var JSON []byte

//go:embed contract-pack.mainnet.json
var mainnetJSON []byte

// JSONFor returns the embedded pack for a product network.
func JSONFor(network string) ([]byte, error) {
	switch network {
	case "mutinynet":
		return append([]byte(nil), JSON...), nil
	case "mainnet":
		return append([]byte(nil), mainnetJSON...), nil
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
}

// DigestFor returns the frozen digest for a product network.
func DigestFor(network string) (string, error) {
	switch network {
	case "mutinynet":
		return SHA256, nil
	case "mainnet":
		return MainnetSHA256, nil
	default:
		return "", fmt.Errorf("unsupported network %q", network)
	}
}

// ValidateBytes rejects a missing or modified Mutinynet Contract Pack.
func ValidateBytes(raw []byte) error {
	return ValidateBytesFor("mutinynet", raw)
}

// ValidateBytesFor rejects a missing or modified Contract Pack for network.
func ValidateBytesFor(network string, raw []byte) error {
	if len(raw) == 0 {
		return fmt.Errorf("contract pack is missing")
	}
	want, err := DigestFor(network)
	if err != nil {
		return err
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
		return fmt.Errorf("contract pack digest does not match the release pin")
	}
	return nil
}

// Validate checks the embedded Mutinynet release artifact.
func Validate() error {
	return ValidateFor("mutinynet")
}

// ValidateFor checks the embedded pack for network.
func ValidateFor(network string) error {
	raw, err := JSONFor(network)
	if err != nil {
		return err
	}
	return ValidateBytesFor(network, raw)
}
