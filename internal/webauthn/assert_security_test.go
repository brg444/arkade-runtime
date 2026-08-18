package webauthn

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

const (
	testOrigin = "http://localhost:8787"
	testRPID   = "localhost"
)

// This is a cryptographically real ES256 unit fixture, not evidence of a
// navigator.credentials.get browser ceremony.
func TestValidateAcceptsCryptographicallyValidES256AssertionFixture(t *testing.T) {
	t.Parallel()

	priv, err := NewP256()
	if err != nil {
		t.Fatal(err)
	}
	credentialID := bytes.Repeat([]byte{0x42}, 32)
	challenge := sha256.Sum256([]byte("exact arkade sighash"))
	assertion, err := Synth(priv, credentialID, challenge[:], testOrigin, testRPID, true, true)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := Validate(assertion, Expected{
		CredentialID: credentialID,
		WebAuthnP256: CompressedP256(priv),
		Challenge:    challenge[:],
		Origin:       testOrigin,
		RPID:         testRPID,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(verified.CompactSig) != 64 {
		t.Fatalf("compact signature length = %d, want 64", len(verified.CompactSig))
	}
	if !bytes.Equal(verified.ClientDataJSON, assertion.ClientDataJSON) {
		t.Fatal("Validate did not preserve the exact signed clientDataJSON bytes")
	}
	clientHash := sha256.Sum256(assertion.ClientDataJSON)
	message := append(append([]byte(nil), assertion.AuthenticatorData...), clientHash[:]...)
	if !bytes.Equal(Digest(assertion.AuthenticatorData, assertion.ClientDataJSON), sha256Digest(message)) {
		t.Fatal("Digest does not match SHA256(authenticatorData || SHA256(clientDataJSON))")
	}
}

func TestValidateRejectsSignatureFromDifferentCredentialKey(t *testing.T) {
	t.Parallel()

	registered, err := NewP256()
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := NewP256()
	if err != nil {
		t.Fatal(err)
	}
	credentialID := []byte("registered-credential")
	challenge := sha256.Sum256([]byte("issued transaction"))
	assertion, err := Synth(attacker, credentialID, challenge[:], testOrigin, testRPID, true, true)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Validate(assertion, Expected{
		CredentialID: credentialID,
		WebAuthnP256: CompressedP256(registered),
		Challenge:    challenge[:],
		Origin:       testOrigin,
		RPID:         testRPID,
	}); err == nil {
		t.Fatal("Validate accepted an assertion signed by an unregistered P-256 key; verify ES256 against Expected.WebAuthnP256 before returning success (including idempotent retries)")
	}
}

func TestValidateRejectsSemanticMismatches(t *testing.T) {
	priv, err := NewP256()
	if err != nil {
		t.Fatal(err)
	}
	credentialID := []byte("credential-id")
	challenge := sha256.Sum256([]byte("expected challenge"))
	valid, err := Synth(priv, credentialID, challenge[:], testOrigin, testRPID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	expected := Expected{
		CredentialID: credentialID,
		WebAuthnP256: CompressedP256(priv),
		Challenge:    challenge[:],
		Origin:       testOrigin,
		RPID:         testRPID,
	}

	tests := []struct {
		name   string
		mutate func(*Assertion, *Expected)
	}{
		{name: "credential id", mutate: func(a *Assertion, _ *Expected) { a.CredentialID = []byte("other") }},
		{name: "type", mutate: func(a *Assertion, _ *Expected) {
			a.ClientDataJSON = bytes.Replace(a.ClientDataJSON, []byte("webauthn.get"), []byte("payment.get"), 1)
		}},
		{name: "challenge", mutate: func(a *Assertion, _ *Expected) {
			a.ClientDataJSON = bytes.Replace(a.ClientDataJSON, []byte(EncodeChallenge(challenge[:])), []byte(EncodeChallenge(bytes.Repeat([]byte{9}, 32))), 1)
		}},
		{name: "padded challenge encoding", mutate: func(a *Assertion, _ *Expected) {
			a.ClientDataJSON = bytes.Replace(a.ClientDataJSON, []byte(EncodeChallenge(challenge[:])), []byte(base64.URLEncoding.EncodeToString(challenge[:])), 1)
		}},
		{name: "origin", mutate: func(a *Assertion, _ *Expected) {
			a.ClientDataJSON = bytes.Replace(a.ClientDataJSON, []byte(testOrigin), []byte("https://evil.example"), 1)
		}},
		{name: "cross origin true", mutate: func(a *Assertion, _ *Expected) {
			a.ClientDataJSON = bytes.Replace(a.ClientDataJSON, []byte(`"crossOrigin":false`), []byte(`"crossOrigin":true`), 1)
		}},
		{name: "cross origin absent", mutate: func(a *Assertion, _ *Expected) {
			a.ClientDataJSON = bytes.Replace(a.ClientDataJSON, []byte(`,"crossOrigin":false`), nil, 1)
		}},
		{name: "rp id hash", mutate: func(a *Assertion, _ *Expected) { a.AuthenticatorData[0] ^= 1 }},
		{name: "user presence", mutate: func(a *Assertion, _ *Expected) { a.AuthenticatorData[32] &^= flagUP }},
		{name: "user verification", mutate: func(a *Assertion, _ *Expected) { a.AuthenticatorData[32] &^= flagUV }},
		{name: "short authenticator data", mutate: func(a *Assertion, _ *Expected) { a.AuthenticatorData = a.AuthenticatorData[:36] }},
		{name: "malformed client data", mutate: func(a *Assertion, _ *Expected) { a.ClientDataJSON = []byte(`{"type":`) }},
		{name: "wrong expected challenge length", mutate: func(_ *Assertion, e *Expected) { e.Challenge = e.Challenge[:31] }},
		{name: "wrong expected p256 length", mutate: func(_ *Assertion, e *Expected) { e.WebAuthnP256 = e.WebAuthnP256[:32] }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := cloneAssertion(valid)
			e := expected
			e.CredentialID = append([]byte(nil), expected.CredentialID...)
			e.WebAuthnP256 = append([]byte(nil), expected.WebAuthnP256...)
			e.Challenge = append([]byte(nil), expected.Challenge...)
			tc.mutate(&a, &e)
			if _, err := Validate(a, e); err == nil {
				t.Fatal("Validate accepted mismatched assertion")
			}
		})
	}
}

func TestDecodeChallengeRequiresRawBase64URL(t *testing.T) {
	t.Parallel()

	raw := bytes.Repeat([]byte{0xfb}, 32)
	encoded := EncodeChallenge(raw)
	if strings.ContainsAny(encoded, "+/=") {
		t.Fatalf("EncodeChallenge returned non-base64url string %q", encoded)
	}
	got, err := decodeChallenge(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("decoded challenge = %x, want %x", got, raw)
	}
	if _, err := decodeChallenge(encoded + "="); err == nil {
		t.Fatal("decodeChallenge accepted padded base64url")
	}
}

func TestParseCompressedP256AndVerifyES256FailClosed(t *testing.T) {
	t.Parallel()

	priv, err := NewP256()
	if err != nil {
		t.Fatal(err)
	}
	challenge := sha256.Sum256([]byte("p256 verification"))
	assertion, err := Synth(priv, []byte("credential"), challenge[:], testOrigin, testRPID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := CompactLowS(assertion.DERSignature)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseCompressedP256(CompressedP256(priv))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyES256(pub, assertion.AuthenticatorData, assertion.ClientDataJSON, compact); err != nil {
		t.Fatalf("VerifyES256 valid fixture: %v", err)
	}

	badPoint := make([]byte, 33)
	badPoint[0] = 0x02
	elliptic.P256().Params().P.FillBytes(badPoint[1:])
	for name, encoded := range map[string][]byte{
		"empty":         nil,
		"wrong length":  make([]byte, 32),
		"wrong prefix":  append([]byte{0x04}, CompressedP256(priv)[1:]...),
		"off curve x=p": badPoint,
	} {
		if _, err := ParseCompressedP256(encoded); err == nil {
			t.Fatalf("ParseCompressedP256 accepted %s key %x", name, encoded)
		}
	}

	tamperedClient := append([]byte(nil), assertion.ClientDataJSON...)
	tamperedClient[0] ^= 1
	if err := VerifyES256(pub, assertion.AuthenticatorData, tamperedClient, compact); err == nil {
		t.Fatal("VerifyES256 accepted a signature for different clientDataJSON")
	}
	if err := VerifyES256(pub, assertion.AuthenticatorData, assertion.ClientDataJSON, compact[:63]); err == nil {
		t.Fatal("VerifyES256 accepted a short compact signature")
	}
	zero := make([]byte, 64)
	if err := VerifyES256(pub, assertion.AuthenticatorData, assertion.ClientDataJSON, zero); err == nil {
		t.Fatal("VerifyES256 accepted zero scalars")
	}
}

func TestContainsPRFField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want bool
	}{
		{raw: `{"credentialId":"abc"}`, want: false},
		{raw: `{"prf":{"results":{"first":"secret"}}}`, want: true},
		{raw: `{"clientExtensionResults":{"prf":{"results":{"first":"secret"}}}}`, want: true},
		{raw: `not-json`, want: false},
	}
	for _, tc := range tests {
		if got := ContainsPRFField([]byte(tc.raw)); got != tc.want {
			t.Fatalf("ContainsPRFField(%s) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func cloneAssertion(a Assertion) Assertion {
	return Assertion{
		CredentialID:      append([]byte(nil), a.CredentialID...),
		ClientDataJSON:    append([]byte(nil), a.ClientDataJSON...),
		AuthenticatorData: append([]byte(nil), a.AuthenticatorData...),
		DERSignature:      append([]byte(nil), a.DERSignature...),
	}
}

func sha256Digest(msg []byte) []byte {
	sum := sha256.Sum256(msg)
	return sum[:]
}
