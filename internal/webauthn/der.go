package webauthn

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// CompactLowS converts a DER ES256 signature to fixed-width 64-byte r||s
// with s normalized to the lower half of the P-256 order.
func CompactLowS(der []byte) ([]byte, error) {
	var parsed struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil {
		return nil, fmt.Errorf("der ecdsa: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("der ecdsa: trailing bytes")
	}
	if parsed.R == nil || parsed.S == nil {
		return nil, fmt.Errorf("der ecdsa: missing r or s")
	}
	if err := canonicalScalar(parsed.R, "r"); err != nil {
		return nil, err
	}
	if err := canonicalScalar(parsed.S, "s"); err != nil {
		return nil, err
	}

	n := elliptic.P256().Params().N
	if parsed.R.Sign() <= 0 || parsed.R.Cmp(n) >= 0 {
		return nil, fmt.Errorf("der ecdsa: r out of range")
	}
	if parsed.S.Sign() <= 0 || parsed.S.Cmp(n) >= 0 {
		return nil, fmt.Errorf("der ecdsa: s out of range")
	}
	half := new(big.Int).Rsh(n, 1)
	if parsed.S.Cmp(half) > 0 {
		parsed.S.Sub(n, parsed.S)
	}

	out := make([]byte, 64)
	parsed.R.FillBytes(out[:32])
	parsed.S.FillBytes(out[32:])
	return out, nil
}

func canonicalScalar(v *big.Int, name string) error {
	if v.Sign() < 0 {
		return fmt.Errorf("der ecdsa: negative %s", name)
	}
	if v.Sign() == 0 {
		return fmt.Errorf("der ecdsa: zero %s", name)
	}
	return nil
}
