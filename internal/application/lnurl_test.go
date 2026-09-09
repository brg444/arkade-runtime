package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
)

func lnurlAssertion(t *testing.T, f lightEnrolledFixture, action string) LightBackupOpenRequest {
	t.Helper()
	c, err := f.env.svc.IssueLNURLChallenge(action)
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := hex.DecodeString(c.Challenge)
	cfg := f.env.svc.runtimeConfig()
	a, err := webauthn.Synth(f.env.p256, f.env.credID, challenge, cfg.ClientOrigin, cfg.RPID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := webauthn.SignDigestLowS(f.env.direct, passkeySessionProofDigest("lnurl-"+action, challenge, f.env.credID))
	if err != nil {
		t.Fatal(err)
	}
	return LightBackupOpenRequest{VaultID: f.start.VaultID, SessionAssertionRequest: SessionAssertionRequest{
		ChallengeID: c.ChallengeID, CredentialID: hex.EncodeToString(f.env.credID), ClientDataJSON: hex.EncodeToString(a.ClientDataJSON),
		AuthenticatorData: hex.EncodeToString(a.AuthenticatorData), Signature: hex.EncodeToString(a.DERSignature), DirectProof: hex.EncodeToString(proof)}}
}

func TestLNURLRegistrationBindsEnrollmentAndConsumesAssertion(t *testing.T) {
	f := enrolledBackupFixture(t)
	s := f.env.svc
	calls := 0
	s.LNURLRegistrar = func(_ context.Context, action string, b LNURLBinding) (json.RawMessage, error) {
		calls++
		st, err := s.StatusFor(t.Context(), f.start.VaultID)
		if err != nil {
			t.Fatal(err)
		}
		if action != "register" || b.VaultID != f.start.VaultID || b.SpendingAddress != st.SpendingArkAddress ||
			b.SpendingScript != st.SpendingArkScript || b.ClaimPublicKey != st.PhoneBIP340Pub || b.DescriptorHash != st.LightDescriptorHash {
			t.Fatal("registration did not bind enrolled public facts")
		}
		return json.RawMessage(`{"active":true}`), nil
	}
	req := lnurlAssertion(t, f, "register")
	if _, err := s.ConfigureLNURL(t.Context(), "register", req); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfigureLNURL(t.Context(), "register", req); err == nil {
		t.Fatal("replayed registration")
	}
	if calls != 1 {
		t.Fatalf("bridge calls: %d", calls)
	}
}

func TestLNURLCannotReuseBackupOrRevokeAuthority(t *testing.T) {
	f := enrolledBackupFixture(t)
	s := f.env.svc
	s.LNURLRegistrar = func(context.Context, string, LNURLBinding) (json.RawMessage, error) {
		t.Fatal("unauthorized bridge call")
		return nil, nil
	}
	if _, err := s.ConfigureLNURL(t.Context(), "register", backupAssertion(t, f)); err == nil {
		t.Fatal("accepted backup assertion")
	}
	if _, err := s.ConfigureLNURL(t.Context(), "revoke", lnurlAssertion(t, f, "register")); err == nil {
		t.Fatal("accepted registration on revoke")
	}
	for _, mutate := range []func(*LightBackupOpenRequest){
		func(r *LightBackupOpenRequest) { r.VaultID = strings.Repeat("ff", 16) },
		func(r *LightBackupOpenRequest) { r.DirectProof = strings.Repeat("00", 64) },
		func(r *LightBackupOpenRequest) { r.Signature = "aaaa" },
	} {
		req := lnurlAssertion(t, f, "register")
		mutate(&req)
		if _, err := s.ConfigureLNURL(t.Context(), "register", req); err == nil {
			t.Fatal("accepted forged request")
		}
	}
}

func TestLNURLConnectorEnrollmentAfterGuardianRestart(t *testing.T) {
	for _, tier := range []string{program.ProtectionTierStandard, program.ProtectionTierAdvanced} {
		t.Run(tier, func(t *testing.T) {
			f := newConnectorFixture(t, "mutinynet")
			phone, _ := btcec.NewPrivateKey()
			hardware, _ := btcec.NewPrivateKey()
			boarding, _ := btcec.NewPrivateKey()
			var recovery *btcec.PrivateKey
			if tier == program.ProtectionTierAdvanced {
				recovery, _ = btcec.NewPrivateKey()
			}
			req := connectorEnrollRequest(t, phone, hardware, boarding, tier, recovery, connector.NativeSegwit)
			pass, _ := webauthn.NewP256()
			direct, _ := webauthn.NewP256()
			req.WebAuthnP256 = hex.EncodeToString(webauthn.CompressedP256(pass))
			req.PhoneDirectP256 = hex.EncodeToString(webauthn.CompressedP256(direct))
			vaultID, err := newOpaqueVaultID()
			if err != nil {
				t.Fatal(err)
			}
			token := bytes.Repeat([]byte{0x77}, 32)
			putConnectorInvite(t, f.led, token)
			req = enrollConnectorVault(t, f.svc, vaultID, token, req)
			f.reopen(t)
			calls := 0
			f.svc.LNURLRegistrar = func(_ context.Context, action string, b LNURLBinding) (json.RawMessage, error) {
				calls++
				status, err := f.svc.StatusFor(t.Context(), vaultID)
				if err != nil {
					t.Fatal(err)
				}
				if b.ProtectionTier != tier || b.VaultID != vaultID || b.DescriptorHash != req.DescriptorHash || b.ClaimPublicKey != req.PhoneBIP340Pub || b.SpendingScript != status.SpendingArkScript || b.SpendingAddress != status.SpendingArkAddress {
					t.Fatal("connector receiving binding mismatch")
				}
				return json.RawMessage(`{"active":true}`), nil
			}
			for _, action := range []string{"register", "revoke"} {
				challenge, err := f.svc.IssueLNURLChallenge(action)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := hex.DecodeString(challenge.Challenge)
				credID, _ := hex.DecodeString(req.CredentialID)
				assertion, err := webauthn.Synth(pass, credID, raw, f.origin, f.rpid, true, true)
				if err != nil {
					t.Fatal(err)
				}
				proof, err := webauthn.SignDigestLowS(direct, passkeySessionProofDigest("lnurl-"+action, raw, credID))
				if err != nil {
					t.Fatal(err)
				}
				request := LightBackupOpenRequest{VaultID: vaultID, SessionAssertionRequest: SessionAssertionRequest{ChallengeID: challenge.ChallengeID, CredentialID: req.CredentialID, ClientDataJSON: hex.EncodeToString(assertion.ClientDataJSON), AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData), Signature: hex.EncodeToString(assertion.DERSignature), DirectProof: hex.EncodeToString(proof)}}
				if _, err := f.svc.ConfigureLNURL(t.Context(), action, request); err != nil {
					t.Fatal(err)
				}
			}
			if calls != 2 {
				t.Fatal("missing bridge operation")
			}
		})
	}
}
