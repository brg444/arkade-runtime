package vault

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/brg444/arkade-runtime/internal/webauthn"
)

func TestBrowserAssertionFixtureIsOffChainWebAuthnEvidence(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "webauthn_get.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skip("no browser fixture; run web/e2e/capture.mjs")
	}
	var fx struct {
		P256              string `json:"p256"`
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
	}
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
	if _, err := webauthn.ParseCompressedP256(must(fx.P256)); err != nil {
		t.Fatal(err)
	}
	if _, err := webauthn.CompactLowS(must(fx.Signature)); err != nil {
		t.Fatal(err)
	}
	if len(must(fx.ClientDataJSON)) == 0 || len(must(fx.AuthenticatorData)) == 0 {
		t.Fatal("browser fixture missing WebAuthn evidence")
	}
}
