package application

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	v5 "github.com/brg444/arkade-vault-server/internal/vault/v5"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestSignTransitionRequiresClaimantSignature(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	req := attestedFinish(t, svc, start, pass, []byte("cred-transition-auth"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	})
	if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SignTransition(context.Background(), TransitionRequest{
		VaultID: start.VaultID, Purpose: "initiate", PSBT: "cHNidP8BAHECAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AQAAAAAAAAAA",
	}); err == nil {
		t.Fatal("signed a transition without a claimant signature")
	}
	st, err := svc.StatusFor(context.Background(), start.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if st.TemplateVersion != v5.Template {
		t.Fatalf("template %s", st.TemplateVersion)
	}
	if len(st.Warnings) == 0 {
		t.Fatal("expected recovery warnings on status")
	}
	if !strings.Contains(strings.Join(st.Warnings, " "), "cosigners") {
		t.Fatalf("warnings = %v", st.Warnings)
	}
}
