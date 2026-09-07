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
const SHA256 = "a9ccccb8505a2da22fbb0ca39ca9903d839317389c56a95176093099f6f88aa6"

// MainnetSHA256 is the mainnet release-pinned digest of contract-pack.mainnet.json.
const MainnetSHA256 = "804f535d54afd67eb3bdb8cb0241612222ff76917e8ad1e8dfa3400546b605f0"

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
