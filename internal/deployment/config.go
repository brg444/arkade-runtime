// Package deployment defines the runtime identity of one vault deployment.
// Policy and template versions stay code-pinned; operators may choose only
// the WebAuthn origin/RP ID and one explicitly supported non-mainnet network.
package deployment

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	NetworkMutinynet = "mutinynet"
	// MutinynetCheckpoint1 distinguishes the intended custom signet from every
	// other signet. Custom signets share the standard signet genesis and all
	// report getblockchaininfo.chain="signet".
	MutinynetCheckpoint1 = "000002855893a0a9b24eaffc5efc770558a326fee4fc10c9da22fc19cd2954f9"

	// MutinynetArkadeCosigner* pin the public routine cosigner into the release.
	// Changing any value requires an explicit reviewed binary release; the
	// Mutinynet Compose interface deliberately provides no environment
	// override for this custody role.
	MutinynetArkadeCosignerOrigin  = "https://emulator.mutinynet.arkade.sh"
	MutinynetArkadeCosignerPubHex  = "03f823b9b2febc81f4af967e77aed2f541cbd3397c6d8f5a72e32eb7b471af889a"
	MutinynetArkadeCosignerVersion = "v0.0.7-rc.1"

	// MutinynetArkIndexerOrigin is the public Mutinynet arkd HTTPS gateway.
	// There is no environment override.
	MutinynetArkIndexerOrigin = "https://mutinynet.arkade.sh"
	// MutinynetEsploraOrigin is the public Mutinynet Bitcoin indexer used only
	// to prove confirmed board outpoints and BIP68 Median Time Past. There is no
	// environment override.
	MutinynetEsploraOrigin = "https://mempool.mutinynet.arkade.sh/api"
	// MutinynetVtxoTreeExpirySeconds is the immutable Batch Output expiry for
	// this release. Stock arkd origin/master e2d9ed44 defines the seconds-based
	// default as 604672. The deployed public Mutinynet Operator independently
	// emitted 604672 in BatchStarted 289d7586-8f32-4b05-8af8-a5b1cc9295ef,
	// and indexed batches d9f814... and 15706b... each have createdAt-to-
	// expiresAt deltas of exactly 604672. It is not inferred from the unrelated
	// boarding exit delay and has no environment override.
	MutinynetVtxoTreeExpirySeconds = uint32(604672)

	// MutinynetOperator* pin the Operator identity and checkpoint fallback
	// policy into the release. GetInfo is discovery data, not a policy oracle.
	MutinynetOperatorSignerPubHex    = "03301078808e4f7bc0dadfe29e34b1df8eaf0108ef06b1722274075ebc107a127a"
	MutinynetCheckpointForfeitPubHex = "02dfcaec558c7e78cf3e38b898ba8a43cfb5727266bae32c5c5b3aeb32c558aa0b"
	MutinynetCheckpointTapscriptHex  = "03080040b27520dfcaec558c7e78cf3e38b898ba8a43cfb5727266bae32c5c5b3aeb32c558aa0bac"
	MutinynetCheckpointDelaySeconds  = uint32(4096)
)

// Config is persisted into the vault descriptor at enrollment. Changing any
// field after enrollment must make startup fail instead of silently deriving a
// different vault or accepting assertions for a different relying party.
type Config struct {
	ClientOrigin string
	RPID         string
	Network      string
}

// BitcoinCheckpoint returns the release-pinned custom-signet checkpoint.
func (c Config) BitcoinCheckpoint() (int64, string, error) {
	if c.Network != NetworkMutinynet {
		return 0, "", fmt.Errorf("unsupported network %q", c.Network)
	}
	return 1, MutinynetCheckpoint1, nil
}

// Validate accepts only the release-pinned Mutinynet candidate. The RP ID is
// required to equal the secure origin hostname, which prevents a broader
// parent-domain credential scope.
func (c Config) Validate() error {
	if c.ClientOrigin == "" || c.RPID == "" || c.Network == "" {
		return fmt.Errorf("origin, rp id and network are required")
	}
	u, err := url.Parse(c.ClientOrigin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid origin")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return fmt.Errorf("origin must contain only scheme and authority")
	}
	if c.ClientOrigin != u.Scheme+"://"+u.Host || u.Scheme != strings.ToLower(u.Scheme) || u.Host != strings.ToLower(u.Host) {
		return fmt.Errorf("client origin must be canonical lowercase scheme://host[:port]")
	}
	port, err := canonicalPort(u)
	if err != nil {
		return err
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		return fmt.Errorf("client origin must omit the default port")
	}
	host := strings.ToLower(u.Hostname())
	if strings.IndexFunc(host, func(r rune) bool { return r > 127 }) >= 0 {
		return fmt.Errorf("client origin hostname must use canonical ASCII form")
	}
	rp := strings.ToLower(strings.TrimSuffix(c.RPID, "."))
	if c.RPID != rp {
		return fmt.Errorf("rp id must be canonical lowercase without a trailing dot")
	}
	if host == "" || rp == "" || host != rp || strings.Contains(c.RPID, ":") {
		return fmt.Errorf("rp id must equal the origin hostname")
	}
	if net.ParseIP(rp) != nil {
		return fmt.Errorf("IP relying party is not supported")
	}
	if c.Network != NetworkMutinynet {
		return fmt.Errorf("unsupported network %q", c.Network)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("mutinynet requires an https origin")
	}
	return nil
}

func canonicalPort(u *url.URL) (string, error) {
	authority := u.Host
	port := ""
	if strings.HasPrefix(authority, "[") {
		end := strings.LastIndex(authority, "]")
		if end < 0 {
			return "", fmt.Errorf("invalid origin host")
		}
		suffix := authority[end+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return "", fmt.Errorf("invalid origin port")
			}
			port = strings.TrimPrefix(suffix, ":")
		}
	} else if strings.Contains(authority, ":") {
		_, port, _ = strings.Cut(authority, ":")
	}
	if port == "" {
		if strings.HasSuffix(authority, ":") {
			return "", fmt.Errorf("client origin port is empty")
		}
		return "", nil
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != port {
		return "", fmt.Errorf("client origin port must be canonical decimal 1..65535")
	}
	return port, nil
}
