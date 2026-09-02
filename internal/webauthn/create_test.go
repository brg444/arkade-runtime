package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"testing"
)

func TestP256EncodingMatchesSEC1AndCOSEVector(t *testing.T) {
	raw := make([]byte, 32)
	raw[31] = 1
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		t.Fatal(err)
	}
	const compressedHex = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
	const uncompressedHex = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
	const coseHex = "a50102032620012158206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
	compressed := CompressedP256(priv)
	if hex.EncodeToString(compressed) != compressedHex {
		t.Fatalf("compressed P-256 = %x", compressed)
	}
	pub, err := ParseCompressedP256(compressed)
	if err != nil {
		t.Fatal(err)
	}
	uncompressed, err := pub.Bytes()
	if err != nil || hex.EncodeToString(uncompressed) != uncompressedHex {
		t.Fatalf("uncompressed P-256 = %x, %v", uncompressed, err)
	}
	cose, err := EncodeCOSEES256(compressed)
	if err != nil || hex.EncodeToString(cose) != coseHex {
		t.Fatalf("COSE ES256 = %x, %v", cose, err)
	}
}

func TestValidateCreateRequiresAttestedES256Key(t *testing.T) {
	challenge := bytes32(0xaa)
	origin := "https://vault.example.com"
	rpID := "vault.example.com"
	cd := []byte(`{"type":"webauthn.create","challenge":"` + EncodeChallenge(challenge) + `","origin":"` + origin + `","crossOrigin":false}`)
	priv, err := NewP256()
	if err != nil {
		t.Fatal(err)
	}
	compressed := CompressedP256(priv)
	credID := []byte{1, 2, 3, 4}
	auth, err := AttestedAuthenticatorData(rpID, credID, compressed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ValidateCreate(cd, auth, challenge, origin, rpID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.CredentialID, credID) {
		t.Fatalf("cred id = %x", got.CredentialID)
	}
	if !bytes.Equal(got.WebAuthnP256, compressed) {
		t.Fatalf("p256 = %x", got.WebAuthnP256)
	}

	noAT := make([]byte, 37)
	copy(noAT, auth[:37])
	noAT[32] = flagUP | flagUV
	if _, err := ValidateCreate(cd, noAT, challenge, origin, rpID); err == nil {
		t.Fatal("accepted create without attested credential data")
	}
	if _, err := ValidateCreate(bytes.Repeat([]byte("a"), maxClientDataJSON+1), auth, challenge, origin, rpID); err == nil {
		t.Fatal("accepted oversized clientDataJSON")
	}

	get := []byte(`{"type":"webauthn.get","challenge":"` + EncodeChallenge(challenge) + `","origin":"` + origin + `","crossOrigin":false}`)
	if _, err := ValidateCreate(get, auth, challenge, origin, rpID); err == nil {
		t.Fatal("accepted a get ceremony as create")
	}

	badCOSE := append(append([]byte{}, auth[:37+16+2+len(credID)]...), 0xa1, 0x01, 0x01)
	if _, err := ValidateCreate(cd, badCOSE, challenge, origin, rpID); err == nil {
		t.Fatal("accepted unsupported cose key")
	}

	prfAuth, err := AttestedAuthenticatorDataPRF(rpID, credID, compressed)
	if err != nil {
		t.Fatal(err)
	}
	gotPRF, err := ValidateCreate(cd, prfAuth, challenge, origin, rpID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPRF.CredentialID, credID) || !bytes.Equal(gotPRF.WebAuthnP256, compressed) {
		t.Fatal("PRF/hmac-secret extensions changed the attested credential")
	}

	edNoMap := append(append([]byte{}, auth...), 0x01)
	edNoMap[32] |= flagED
	if _, err := ValidateCreate(cd, edNoMap, challenge, origin, rpID); err == nil {
		t.Fatal("accepted ED without an extension map")
	}
	trailing := append(append([]byte{}, prfAuth...), 0xa0)
	if _, err := ValidateCreate(cd, trailing, challenge, origin, rpID); err == nil {
		t.Fatal("accepted trailing bytes after extension map")
	}
}

func TestParseAttestationObjectRequiresFmtNone(t *testing.T) {
	rpID := "vault.example.com"
	priv, err := NewP256()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := AttestedAuthenticatorData(rpID, []byte("cred"), CompressedP256(priv))
	if err != nil {
		t.Fatal(err)
	}
	obj := EncodeNoneAttestationObject(auth)
	got, err := ParseAttestationObject(obj)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, auth) {
		t.Fatal("authData mismatch")
	}
	packed := bytes.Replace(obj, []byte("none"), []byte("pack"), 1)
	if _, err := ParseAttestationObject(packed); err == nil {
		t.Fatal("accepted packed attestation without verification")
	}
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
