package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
)

// Synth builds a structurally valid WebAuthn assertion over challenge.
func Synth(priv *ecdsa.PrivateKey, credID, challenge []byte, origin, rpID string, uv, up bool) (Assertion, error) {
	return SynthWithSignCount(priv, credID, challenge, origin, rpID, uv, up, 0)
}

// SynthWithSignCount builds a structurally valid test assertion with an
// explicit authenticator counter.
func SynthWithSignCount(priv *ecdsa.PrivateKey, credID, challenge []byte, origin, rpID string, uv, up bool, signCount uint32) (Assertion, error) {
	cd := []byte(`{"type":"webauthn.get","challenge":"` + EncodeChallenge(challenge) + `","origin":"` + origin + `","crossOrigin":false}`)
	auth := make([]byte, 37)
	sum := sha256.Sum256([]byte(rpID))
	copy(auth[:32], sum[:])
	var flags byte
	if up {
		flags |= flagUP
	}
	if uv {
		flags |= flagUV
	}
	auth[32] = flags
	binary.BigEndian.PutUint32(auth[33:37], signCount)

	digest := Digest(auth, cd)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return Assertion{}, err
	}
	der, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		return Assertion{}, err
	}
	return Assertion{
		CredentialID:      append([]byte(nil), credID...),
		ClientDataJSON:    cd,
		AuthenticatorData: auth,
		DERSignature:      der,
	}, nil
}

// CompressedP256 returns the 33-byte compressed form of priv's public key.
func CompressedP256(priv *ecdsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	uncompressed, err := priv.PublicKey.Bytes()
	if err != nil || len(uncompressed) != 65 || uncompressed[0] != 0x04 {
		return nil
	}
	out := make([]byte, 33)
	out[0] = 0x02 | (uncompressed[64] & 1)
	copy(out[1:], uncompressed[1:33])
	return out
}

// NewP256 generates a P-256 key.
func NewP256() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
