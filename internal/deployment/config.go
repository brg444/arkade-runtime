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

	"github.com/brg444/arkade-vault-server/internal/program"
)

const (
	NetworkRegtest   = "regtest"
	NetworkMutinynet = "mutinynet"
	// MaxCSVBlockDelay is the largest block-based relative locktime BIP68 can
	// encode. Higher bits select time units or disable relative locktime.
	MaxCSVBlockDelay = uint32(1<<16 - 1)
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
)

// Config is persisted into the vault descriptor at enrollment. Changing any
// field after enrollment must make startup fail instead of silently deriving a
// different vault or accepting assertions for a different relying party.
type Config struct {
	ClientOrigin         string
	RPID                 string
	Network              string
	OperationalCSVBlocks uint32
	SavingsCSVBlocks     uint32
}

// BitcoinCheckpoint returns an additional required checkpoint when a chain
// name is not unique. A zero height/hash means the local regtest launcher owns
// the node identity and no public-network checkpoint is needed.
func (c Config) BitcoinCheckpoint() (int64, string, error) {
	switch c.Network {
	case NetworkRegtest:
		return 0, "", nil
	case NetworkMutinynet:
		return 1, MutinynetCheckpoint1, nil
	default:
		return 0, "", fmt.Errorf("unsupported network %q", c.Network)
	}
}

// Default is the local regtest demonstration identity.
func Default() Config {
	return Config{
		ClientOrigin: program.RegtestOrigin, RPID: program.RegtestRPID, Network: NetworkRegtest,
		OperationalCSVBlocks: program.OperationalCSVBlocks,
		SavingsCSVBlocks:     program.SavingsCSVBlocks,
	}
}

// WithDefaults preserves the zero-value Service configuration used by unit
// tests and the existing regtest launcher. A partially configured deployment
// is not filled in: it is rejected by Validate.
func (c Config) WithDefaults() Config {
	if c == (Config{}) {
		return Default()
	}
	return c
}

// Validate accepts only regtest or Mutinynet. Mutinynet is a custom signet,
// uses Bitcoin's signet/testnet address encoding, and requires a secure web
// origin. The RP ID is intentionally required to equal the origin hostname;
// this POC does not permit a broader parent-domain credential scope.
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
	if net.ParseIP(rp) != nil && rp != "127.0.0.1" && rp != "::1" {
		return fmt.Errorf("non-loopback IP relying party is not supported")
	}

	switch c.Network {
	case NetworkRegtest:
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("regtest origin must use http or https")
		}
		if u.Scheme == "http" && host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return fmt.Errorf("insecure origin is allowed only on loopback regtest")
		}
	case NetworkMutinynet:
		if u.Scheme != "https" {
			return fmt.Errorf("mutinynet requires an https origin")
		}
	default:
		return fmt.Errorf("unsupported network %q", c.Network)
	}
	if c.OperationalCSVBlocks == 0 || c.SavingsCSVBlocks == 0 {
		return fmt.Errorf("operational and savings CSV blocks are required")
	}
	if c.OperationalCSVBlocks > MaxCSVBlockDelay || c.SavingsCSVBlocks > MaxCSVBlockDelay {
		return fmt.Errorf("operational and savings CSV block delays must not exceed %d", MaxCSVBlockDelay)
	}
	if c.OperationalCSVBlocks <= c.SavingsCSVBlocks {
		return fmt.Errorf("device-only CSV blocks must exceed hardware-only CSV blocks")
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
