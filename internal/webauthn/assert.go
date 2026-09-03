package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const (
	flagUP = 1 << 0
	flagUV = 1 << 2

	// maxClientDataJSON matches maxCBORBytes: legitimate WebAuthn client
	// data is well under 1 KiB.
	maxClientDataJSON = 4096
)

// Assertion is the explicit field-by-field provider payload. It never includes
// WebAuthn extension results.
type Assertion struct {
	CredentialID      []byte
	ClientDataJSON    []byte
	AuthenticatorData []byte
	DERSignature      []byte
}

// ClientData is the parsed WebAuthn client data object.
type ClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin *bool  `json:"crossOrigin"`
}

// Expected is the trusted-provider semantic check set.
type Expected struct {
	CredentialID []byte
	WebAuthnP256 []byte
	Challenge    []byte
	Origin       string
	RPID         string
}

// Verified is a semantically valid assertion plus its compact signature.
// Authenticator signCount is not persisted: many platform passkeys report 0,
// and spend replay is already bound to a 32-byte sighash challenge.
type Verified struct {
	Assertion
	CompactSig []byte
	ClientData ClientData
	SignCount  uint32
}

// Validate parses the original clientDataJSON bytes and checks credential,
// type, challenge, origin, crossOrigin, RP ID hash, UP and UV.
func Validate(a Assertion, exp Expected) (*Verified, error) {
	if !bytes.Equal(a.CredentialID, exp.CredentialID) {
		return nil, fmt.Errorf("unknown credential")
	}
	if len(exp.WebAuthnP256) != 33 {
		return nil, fmt.Errorf("registered webauthn p256 key must be 33-byte compressed")
	}
	if len(exp.Challenge) != 32 {
		return nil, fmt.Errorf("challenge must be 32-byte arkade sighash")
	}
	if len(a.AuthenticatorData) < 37 {
		return nil, fmt.Errorf("authenticatorData too short")
	}
	if len(a.ClientDataJSON) == 0 || len(a.ClientDataJSON) > maxClientDataJSON {
		return nil, fmt.Errorf("clientDataJSON too large")
	}

	var cd ClientData
	if err := json.Unmarshal(a.ClientDataJSON, &cd); err != nil {
		return nil, fmt.Errorf("clientDataJSON: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return nil, fmt.Errorf("clientDataJSON type %q", cd.Type)
	}
	if cd.Origin != exp.Origin {
		return nil, fmt.Errorf("origin %q", cd.Origin)
	}
	if cd.CrossOrigin == nil || *cd.CrossOrigin {
		return nil, fmt.Errorf("crossOrigin must be false")
	}
	gotChallenge, err := decodeChallenge(cd.Challenge)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(gotChallenge, exp.Challenge) {
		return nil, fmt.Errorf("challenge mismatch")
	}

	rpHash := sha256.Sum256([]byte(exp.RPID))
	if !bytes.Equal(a.AuthenticatorData[:32], rpHash[:]) {
		return nil, fmt.Errorf("rpIdHash mismatch")
	}
	flags := a.AuthenticatorData[32]
	if flags&flagUP == 0 {
		return nil, fmt.Errorf("user presence required")
	}
	if flags&flagUV == 0 {
		return nil, fmt.Errorf("user verification required")
	}

	compact, err := CompactLowS(a.DERSignature)
	if err != nil {
		return nil, err
	}
	pub, err := ParseCompressedP256(exp.WebAuthnP256)
	if err != nil {
		return nil, err
	}
	if err := VerifyES256(pub, a.AuthenticatorData, a.ClientDataJSON, compact); err != nil {
		return nil, err
	}
	return &Verified{Assertion: a, CompactSig: compact, ClientData: cd, SignCount: SignCount(a.AuthenticatorData)}, nil
}

// SignCount is the authenticator counter from authenticatorData. Many
// platform passkeys report 0; a stored non-zero value must not go backwards.
func SignCount(authData []byte) uint32 {
	if len(authData) < 37 {
		return 0
	}
	return uint32(authData[33])<<24 | uint32(authData[34])<<16 | uint32(authData[35])<<8 | uint32(authData[36])
}

func decodeChallenge(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("challenge encoding: %w", err)
	}
	return raw, nil
}

// ChallengeFromClientDataJSON returns the 32-byte WebAuthn challenge the
// authenticator signed. Spend authorization binds the payment with
// PhoneDirectP256 over the bundle digest, so this challenge is user-presence,
// not the sighash.
func ChallengeFromClientDataJSON(clientDataJSON []byte) ([]byte, error) {
	var cd ClientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return nil, fmt.Errorf("clientDataJSON: %w", err)
	}
	raw, err := decodeChallenge(cd.Challenge)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("challenge must be 32 bytes")
	}
	return raw, nil
}

// EncodeChallenge returns the base64url form browsers put in clientDataJSON.
func EncodeChallenge(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// SignedMessage is authenticatorData || SHA256(clientDataJSON).
func SignedMessage(authenticatorData, clientDataJSON []byte) []byte {
	sum := sha256.Sum256(clientDataJSON)
	out := make([]byte, 0, len(authenticatorData)+32)
	out = append(out, authenticatorData...)
	return append(out, sum[:]...)
}

// Digest is SHA256(SignedMessage), the 32-byte value CSFS verifies.
func Digest(authenticatorData, clientDataJSON []byte) []byte {
	msg := SignedMessage(authenticatorData, clientDataJSON)
	sum := sha256.Sum256(msg)
	return sum[:]
}

// ContainsPRFField reports whether a JSON object looks like it leaked PRF
// extension results. Used to reject confused client payloads.
func ContainsPRFField(raw []byte) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	if _, ok := obj["prf"]; ok {
		return true
	}
	if ext, ok := obj["clientExtensionResults"]; ok {
		var extObj map[string]json.RawMessage
		if json.Unmarshal(ext, &extObj) == nil {
			if _, ok := extObj["prf"]; ok {
				return true
			}
		}
	}
	return false
}
