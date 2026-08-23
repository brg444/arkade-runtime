package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
)

// Synth builds a structurally valid WebAuthn assertion over challenge.
func Synth(priv *ecdsa.PrivateKey, credID, challenge []byte, origin, rpID string, uv, up bool) (Assertion, error) {
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
	return elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
}

// NewP256 generates a P-256 key.
func NewP256() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
