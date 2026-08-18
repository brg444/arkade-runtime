package provider

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestFirstEnrollmentRequiresBootstrapAndTokenCannotReplaceEnrollment(t *testing.T) {
	ledger, err := policy.OpenLedger(filepath.Join(t.TempDir(), "bootstrap.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	externalOwner, _ := btcec.NewPrivateKey()
	offline, _ := btcec.NewPrivateKey()
	_ = offline
	providerKey, _ := btcec.NewPrivateKey()
	arkadeKey, _ := btcec.NewPrivateKey()
	hot, _ := btcec.NewPrivateKey()
	passkey, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7a}, 32))
	digestRaw, err := HashEnrollmentToken(token)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		Ledger: ledger, ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerPub: providerKey.PubKey(), ArkadeCosignerPub: arkadeKey.PubKey(),
		VaultSigner: LocalSigner{Priv: providerKey}, ArkadeCosignerSigner: LocalSigner{Priv: arkadeKey}, EnrollmentTokenHash: digestRaw,
		EnrollmentDeadline: time.Now().Add(time.Hour),
	}
	req := RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("credential-a")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passkey)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}
	for _, attempt := range []string{"", "wrong and must never be reflected"} {
		err := svc.RegisterWithBootstrap(req, attempt)
		if err == nil || !strings.Contains(err.Error(), "bootstrap authorization failed") {
			t.Fatalf("bootstrap %q: %v", attempt, err)
		}
		if strings.Contains(err.Error(), attempt) && attempt != "" {
			t.Fatal("bootstrap error reflected token material")
		}
		cred, getErr := ledger.GetCredential()
		if getErr != nil || cred != nil {
			t.Fatalf("failed bootstrap mutated enrollment: cred=%v err=%v", cred, getErr)
		}
	}
	if err := svc.RegisterWithBootstrap(req, token); err != nil {
		t.Fatalf("correct bootstrap: %v", err)
	}
	if len(svc.EnrollmentTokenHash) != 0 {
		t.Fatal("successful enrollment retained the bootstrap token hash")
	}

	// Crash-recovery idempotency no longer depends on the bootstrap token.
	if err := svc.RegisterWithBootstrap(req, ""); err != nil {
		t.Fatalf("exact post-enrollment retry: %v", err)
	}

	otherHot, _ := btcec.NewPrivateKey()
	forged := req
	forged.PhoneRoutineBIP340Pub = hex.EncodeToString(otherHot.PubKey().SerializeCompressed())
	if err := svc.RegisterWithBootstrap(forged, token); err == nil || !strings.Contains(err.Error(), "enrollment locked") {
		t.Fatalf("consumed bootstrap token replaced enrollment: %v", err)
	}
}
