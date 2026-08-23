package webauthn

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
)

const (
	flagAT = 1 << 6
	flagED = 1 << 7
)

const (
	coseKtyEC2   = 2
	coseAlgES256 = -7
	coseCrvP256  = 1
)

// CreateResult is the authenticator-bound credential extracted from a create ceremony.
type CreateResult struct {
	CredentialID []byte
	WebAuthnP256 []byte
}

// ValidateCreate checks a WebAuthn create ceremony and returns the attested
// credential ID plus its compressed ES256 P-256 public key. Missing AT,
// unsupported COSE parameters, or a truncated public key fail closed.
func ValidateCreate(clientDataJSON, authenticatorData, challenge []byte, origin, rpID string) (CreateResult, error) {
	if len(challenge) != 32 {
		return CreateResult{}, fmt.Errorf("challenge must be 32 bytes")
	}
	if len(authenticatorData) < 37 {
		return CreateResult{}, fmt.Errorf("authenticatorData too short")
	}
	if len(clientDataJSON) == 0 || len(clientDataJSON) > maxClientDataJSON {
		return CreateResult{}, fmt.Errorf("clientDataJSON too large")
	}
	var cd ClientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return CreateResult{}, fmt.Errorf("clientDataJSON: %w", err)
	}
	if cd.Type != "webauthn.create" {
		return CreateResult{}, fmt.Errorf("clientDataJSON type %q", cd.Type)
	}
	if cd.Origin != origin {
		return CreateResult{}, fmt.Errorf("origin")
	}
	if cd.CrossOrigin == nil || *cd.CrossOrigin {
		return CreateResult{}, fmt.Errorf("crossOrigin must be false")
	}
	gotChallenge, err := decodeChallenge(cd.Challenge)
	if err != nil {
		return CreateResult{}, err
	}
	if !bytes.Equal(gotChallenge, challenge) {
		return CreateResult{}, fmt.Errorf("challenge mismatch")
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(authenticatorData[:32], rpHash[:]) {
		return CreateResult{}, fmt.Errorf("rpIdHash mismatch")
	}
	flags := authenticatorData[32]
	if flags&flagUP == 0 {
		return CreateResult{}, fmt.Errorf("user presence required")
	}
	if flags&flagUV == 0 {
		return CreateResult{}, fmt.Errorf("user verification required")
	}
	if flags&flagAT == 0 {
		return CreateResult{}, fmt.Errorf("attested credential data required")
	}
	return extractAttestedCredential(authenticatorData)
}

// ParseAttestationObject accepts only fmt=none WebAuthn attestation objects
// and returns the embedded authenticator data.
func ParseAttestationObject(raw []byte) ([]byte, error) {
	val, rest, err := decodeCBOR(raw)
	if err != nil {
		return nil, fmt.Errorf("attestationObject: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("attestationObject trailing data")
	}
	fmtVal, ok := val.mapText("fmt")
	if !ok || fmtVal.kind != cborText {
		return nil, fmt.Errorf("attestationObject fmt required")
	}
	if fmtVal.text != "none" {
		return nil, fmt.Errorf("unsupported attestation format %q", fmtVal.text)
	}
	auth, ok := val.mapText("authData")
	if !ok || auth.kind != cborBytes || len(auth.bytes) < 37 {
		return nil, fmt.Errorf("attestationObject authData required")
	}
	return append([]byte(nil), auth.bytes...), nil
}

func extractAttestedCredential(auth []byte) (CreateResult, error) {
	const header = 37 + 16 + 2
	if len(auth) < header {
		return CreateResult{}, fmt.Errorf("attested credential data truncated")
	}
	credLen := int(binary.BigEndian.Uint16(auth[53:55]))
	if credLen == 0 || header+credLen >= len(auth) {
		return CreateResult{}, fmt.Errorf("attested credential id truncated")
	}
	credID := append([]byte(nil), auth[header:header+credLen]...)
	compressed, rest, err := parseCOSEES256(auth[header+credLen:])
	if err != nil {
		return CreateResult{}, err
	}
	if auth[32]&flagED != 0 {
		if len(rest) == 0 {
			return CreateResult{}, fmt.Errorf("authenticator extensions required")
		}
		ext, rest, err := decodeCBOR(rest)
		if err != nil {
			return CreateResult{}, fmt.Errorf("authenticator extensions: %w", err)
		}
		if ext.kind != cborMap || len(ext.mapVal) == 0 {
			return CreateResult{}, fmt.Errorf("authenticator extensions must be a non-empty map")
		}
		if len(rest) != 0 {
			return CreateResult{}, fmt.Errorf("trailing authenticator extension data")
		}
	} else if len(rest) != 0 {
		return CreateResult{}, fmt.Errorf("unexpected trailing authenticator data")
	}
	return CreateResult{CredentialID: credID, WebAuthnP256: compressed}, nil
}

func parseCOSEES256(raw []byte) ([]byte, []byte, error) {
	val, rest, err := decodeCBOR(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("cose key: %w", err)
	}
	kty, ok := val.mapInt(1)
	if !ok || kty.kind != cborInt || kty.intVal != coseKtyEC2 {
		return nil, nil, fmt.Errorf("cose kty must be EC2")
	}
	alg, ok := val.mapInt(3)
	if !ok || alg.kind != cborInt || alg.intVal != coseAlgES256 {
		return nil, nil, fmt.Errorf("cose alg must be ES256")
	}
	crv, ok := val.mapInt(-1)
	if !ok || crv.kind != cborInt || crv.intVal != coseCrvP256 {
		return nil, nil, fmt.Errorf("cose curve must be P-256")
	}
	x, ok := val.mapInt(-2)
	if !ok || x.kind != cborBytes || len(x.bytes) != 32 {
		return nil, nil, fmt.Errorf("cose x must be 32 bytes")
	}
	y, ok := val.mapInt(-3)
	if !ok || y.kind != cborBytes || len(y.bytes) != 32 {
		return nil, nil, fmt.Errorf("cose y must be 32 bytes")
	}
	compressed, err := compressedP256XY(x.bytes, y.bytes)
	if err != nil {
		return nil, nil, err
	}
	return compressed, rest, nil
}

func compressedP256XY(x, y []byte) ([]byte, error) {
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("p256 coordinates")
	}
	px := new(big.Int).SetBytes(x)
	py := new(big.Int).SetBytes(y)
	if !elliptic.P256().IsOnCurve(px, py) {
		return nil, fmt.Errorf("p256 point is off-curve")
	}
	out := make([]byte, 33)
	out[0] = 0x02
	if py.Bit(0) == 1 {
		out[0] = 0x03
	}
	copy(out[1:], x)
	if _, err := ParseCompressedP256(out); err != nil {
		return nil, err
	}
	return out, nil
}

// EncodeCOSEES256 is the deterministic EC2/ES256/P-256 COSE encoding used by tests.
func EncodeCOSEES256(compressed []byte) ([]byte, error) {
	pub, err := ParseCompressedP256(compressed)
	if err != nil {
		return nil, err
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	pairs := [][]byte{
		append(encodeCBORUnsigned(1), encodeCBORUnsigned(coseKtyEC2)...),
		append(encodeCBORUnsigned(3), encodeCBORNegative(coseAlgES256)...),
		append(encodeCBORNegative(-1), encodeCBORUnsigned(coseCrvP256)...),
		append(encodeCBORNegative(-2), encodeCBORBytes(x)...),
		append(encodeCBORNegative(-3), encodeCBORBytes(y)...),
	}
	return encodeCBORMap(pairs), nil
}

// EncodeNoneAttestationObject wraps authenticator data in a fmt=none object.
func EncodeNoneAttestationObject(authData []byte) []byte {
	pairs := [][]byte{
		append(encodeCBORText("fmt"), encodeCBORText("none")...),
		append(encodeCBORText("authData"), encodeCBORBytes(authData)...),
		append(encodeCBORText("attStmt"), encodeCBORMap(nil)...),
	}
	return encodeCBORMap(pairs)
}

// AttestedAuthenticatorData builds UP+UV+AT authenticator data for tests.
func AttestedAuthenticatorData(rpID string, credID, compressedP256 []byte) ([]byte, error) {
	return attestedAuthenticatorData(rpID, credID, compressedP256, nil)
}

// AttestedAuthenticatorDataPRF builds UP+UV+AT+ED data with hmac-secret/PRF
// create-time extension output after the COSE key.
func AttestedAuthenticatorDataPRF(rpID string, credID, compressedP256 []byte) ([]byte, error) {
	prfEnabled := encodeCBORMap([][]byte{
		append(encodeCBORText("enabled"), encodeCBORBool(true)...),
	})
	ext := encodeCBORMap([][]byte{
		append(encodeCBORText("hmac-secret"), encodeCBORBool(true)...),
		append(encodeCBORText("prf"), prfEnabled...),
	})
	return attestedAuthenticatorData(rpID, credID, compressedP256, ext)
}

func attestedAuthenticatorData(rpID string, credID, compressedP256, extensions []byte) ([]byte, error) {
	cose, err := EncodeCOSEES256(compressedP256)
	if err != nil {
		return nil, err
	}
	if len(credID) == 0 || len(credID) > 1024 {
		return nil, fmt.Errorf("credential id required")
	}
	flags := byte(flagUP | flagUV | flagAT)
	if len(extensions) > 0 {
		flags |= flagED
	}
	out := make([]byte, 0, 37+16+2+len(credID)+len(cose)+len(extensions))
	sum := sha256.Sum256([]byte(rpID))
	out = append(out, sum[:]...)
	out = append(out, flags)
	out = append(out, 0, 0, 0, 0)
	out = append(out, make([]byte, 16)...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(credID)))
	out = append(out, lenBuf[:]...)
	out = append(out, credID...)
	out = append(out, cose...)
	out = append(out, extensions...)
	return out, nil
}
