package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

// ParseCompressedP256 rejects the wrong length and off-curve points.
func ParseCompressedP256(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 33 {
		return nil, fmt.Errorf("p256 must be 33-byte compressed")
	}
	if b[0] != 0x02 && b[0] != 0x03 {
		return nil, fmt.Errorf("p256 compressed prefix")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
	if x == nil {
		return nil, fmt.Errorf("p256 point is off-curve")
	}
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	x.FillBytes(uncompressed[1:33])
	y.FillBytes(uncompressed[33:])
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, fmt.Errorf("p256 point is off-curve")
	}
	return pub, nil
}

// VerifyES256 checks compact r||s over Digest(authData, clientDataJSON).
func VerifyES256(pub *ecdsa.PublicKey, authenticatorData, clientDataJSON, compact []byte) error {
	if pub == nil {
		return fmt.Errorf("nil p256 public key")
	}
	if len(compact) != 64 {
		return fmt.Errorf("compact signature must be 64 bytes")
	}
	n := elliptic.P256().Params().N
	r := new(big.Int).SetBytes(compact[:32])
	s := new(big.Int).SetBytes(compact[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return fmt.Errorf("compact signature out of range")
	}
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		return fmt.Errorf("compact signature is not low-S")
	}
	if !ecdsa.Verify(pub, Digest(authenticatorData, clientDataJSON), r, s) {
		return fmt.Errorf("es256 signature invalid")
	}
	return nil
}

// VerifyDigestLowS checks a compact low-S P-256 ECDSA signature over digest.
// digest is the message itself (the Arkade sighash), not SHA-256(digest).
func VerifyDigestLowS(pub *ecdsa.PublicKey, digest, compact []byte) error {
	if pub == nil {
		return fmt.Errorf("nil p256 public key")
	}
	if len(digest) != 32 {
		return fmt.Errorf("digest must be 32 bytes")
	}
	if len(compact) != 64 {
		return fmt.Errorf("compact signature must be 64 bytes")
	}
	n := elliptic.P256().Params().N
	r := new(big.Int).SetBytes(compact[:32])
	s := new(big.Int).SetBytes(compact[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return fmt.Errorf("compact signature out of range")
	}
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		return fmt.Errorf("compact signature is not low-S")
	}
	if !ecdsa.Verify(pub, digest, r, s) {
		return fmt.Errorf("direct p256 signature invalid")
	}
	return nil
}

// SignDigestLowS produces a compact 64-byte low-S P-256 signature over digest.
func SignDigestLowS(priv *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("nil p256 private key")
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes")
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return nil, err
	}
	n := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		s.Sub(n, s)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}
