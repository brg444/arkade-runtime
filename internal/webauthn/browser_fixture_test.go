package webauthn

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/brg444/arkade-runtime/fixture"
)

// Fixture is a captured navigator.credentials.get() assertion.
// Produce it with: bun poc/2fa-vault/web/e2e/capture.mjs
type Fixture struct {
	CredentialID      string `json:"credentialId"`
	P256              string `json:"p256"`
	Challenge         string `json:"challenge"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
}

func TestBrowserAssertionFixture(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "webauthn_get.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skip("no browser fixture at testdata/webauthn_get.json; run web/e2e/capture.mjs")
	}
	var fx Fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	must := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a := Assertion{
		CredentialID:      must(fx.CredentialID),
		ClientDataJSON:    must(fx.ClientDataJSON),
		AuthenticatorData: must(fx.AuthenticatorData),
		DERSignature:      must(fx.Signature),
	}
	got, err := Validate(a, Expected{
		CredentialID: must(fx.CredentialID),
		WebAuthnP256: must(fx.P256),
		Challenge:    must(fx.Challenge),
		Origin:       fixture.Origin,
		RPID:         fixture.RPID,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = got
}
