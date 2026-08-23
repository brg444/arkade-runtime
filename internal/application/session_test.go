package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestPasskeyEnvelopeInstallAndCrossDeviceRecover(t *testing.T) {
	e := newEnv(t)
	status, err := e.svc.StatusFor(context.Background(), fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if status.PasskeyLoginAvailable {
		t.Fatal("fresh enrollment unexpectedly has a recovery envelope")
	}

	nonce := strings.Repeat("11", 12)
	ciphertext := strings.Repeat("22", 48)
	binding, err := e.svc.BuildRecoveryBindingFor(fixture.VaultID, RecoveryBindingRequest{
		EnvelopeNonce: nonce, EnvelopeCiphertext: ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	bindingDigest, err := hex.DecodeString(binding.BindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	directBindingSig, err := webauthn.SignDigestLowS(e.direct, bindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	phoneBindingSig, err := schnorr.Sign(e.hot, bindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	installChallenge, installAssertion := passkeySessionAssertion(t, e, passkeyPurposeInstall)
	if err := e.svc.InstallCredentialEnvelope(context.Background(), InstallCredentialEnvelopeRequest{
		VaultID:                 fixture.VaultID,
		SessionAssertionRequest: installAssertion,
		RecoveryBindingRequest: RecoveryBindingRequest{
			EnvelopeNonce: nonce, EnvelopeCiphertext: ciphertext,
		},
		Binding: binding.Binding, BindingDirectSig: hex.EncodeToString(directBindingSig),
		BindingPhoneSig: hex.EncodeToString(phoneBindingSig.Serialize()),
	}); err != nil {
		t.Fatalf("install envelope: %v (challenge %s)", err, installChallenge.ChallengeID)
	}
	status, err = e.svc.StatusFor(context.Background(), fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if !status.PasskeyLoginAvailable {
		t.Fatal("installed envelope not reported")
	}

	_, recoveryAssertion := passkeySessionAssertion(t, e, passkeyPurposeRecover)
	recovered, err := e.svc.RecoverCredentialEnvelope(context.Background(), RecoverCredentialEnvelopeRequest{
		VaultID:                 fixture.VaultID,
		SessionAssertionRequest: recoveryAssertion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Binding != binding.Binding || recovered.BindingDigest != binding.BindingDigest ||
		recovered.EnvelopeNonce != nonce || recovered.EnvelopeCiphertext != ciphertext ||
		recovered.BindingDirectSig != hex.EncodeToString(directBindingSig) ||
		recovered.BindingPhoneSig != hex.EncodeToString(phoneBindingSig.Serialize()) {
		t.Fatalf("recovered envelope mismatch: %+v", recovered)
	}
}

func passkeySessionAssertion(t *testing.T, e *env, purpose string) (*PasskeyChallengeResponse, SessionAssertionRequest) {
	t.Helper()
	issued, err := e.svc.IssuePasskeyChallengeFor(context.Background(), fixture.VaultID, purpose)
	if err != nil {
		t.Fatal(err)
	}
	if issued.AllowCredentialID != hex.EncodeToString(e.credID) {
		t.Fatalf("challenge allowCredentialId = %s, want enrolled cred", issued.AllowCredentialID)
	}
	challenge, err := hex.DecodeString(issued.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := webauthn.Synth(e.p256, e.credID, challenge, fixture.Origin, fixture.RPID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	proofDigest := passkeySessionProofDigest(purpose, challenge, e.credID)
	directProof, err := webauthn.SignDigestLowS(e.direct, proofDigest)
	if err != nil {
		t.Fatal(err)
	}
	return issued, SessionAssertionRequest{
		ChallengeID: issued.ChallengeID, CredentialID: hex.EncodeToString(e.credID),
		ClientDataJSON:    hex.EncodeToString(assertion.ClientDataJSON),
		AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData),
		Signature:         hex.EncodeToString(assertion.DERSignature),
		DirectProof:       hex.EncodeToString(directProof),
	}
}

func TestPasskeySessionRejectsADifferentCredential(t *testing.T) {
	e := newEnv(t)
	_, req := passkeySessionAssertion(t, e, passkeyPurposeInstall)
	req.CredentialID = hex.EncodeToString(bytes.Repeat([]byte{0x99}, len(e.credID)))
	_, err := e.svc.authenticatePasskeySession(context.Background(), passkeyPurposeInstall, fixture.VaultID, req)
	if err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("wrong credential: %v", err)
	}
}

func TestPasskeyChallengeIsPurposeBoundExpiringAndOneUse(t *testing.T) {
	e := newEnv(t)
	now := time.Unix(1_700_000_000, 0)
	e.svc.SessionNow = func() time.Time { return now }
	issued, req := passkeySessionAssertion(t, e, passkeyPurposeInstall)

	wrong := req
	if _, err := e.svc.RecoverCredentialEnvelope(context.Background(), RecoverCredentialEnvelopeRequest{VaultID: fixture.VaultID, SessionAssertionRequest: wrong}); err == nil {
		t.Fatal("wrong-purpose challenge accepted")
	}
	if _, err := e.svc.consumePasskeyChallenge(fixture.VaultID, issued.ChallengeID, passkeyPurposeInstall); err != nil {
		t.Fatalf("wrong-purpose attempt burned the challenge: %v", err)
	}

	issued, req = passkeySessionAssertion(t, e, passkeyPurposeInstall)
	now = now.Add(passkeyChallengeTTL)
	if err := e.svc.InstallCredentialEnvelope(context.Background(), InstallCredentialEnvelopeRequest{
		VaultID:                 fixture.VaultID,
		SessionAssertionRequest: req,
	}); err == nil {
		t.Fatalf("expired challenge %s accepted", issued.ChallengeID)
	}
}

func TestPasskeyChallengeConcurrentReplayHasOneConsumer(t *testing.T) {
	e := newEnv(t)
	_, req := passkeySessionAssertion(t, e, passkeyPurposeInstall)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := e.svc.authenticatePasskeySession(context.Background(), passkeyPurposeInstall, fixture.VaultID, req)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var successes int
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent challenge consumers succeeded %d times", successes)
	}
}

func TestPasskeySessionBrowserDigestParityVectors(t *testing.T) {
	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i)
	}
	if got, want := hex.EncodeToString(passkeySessionProofDigest(passkeyPurposeRecover, challenge, []byte{0xaa, 0xbb, 0xcc})), "84dc9646da544458148af17e91f1df49e97221c203dcb23dd92e5895b7ce8230"; got != want {
		t.Fatalf("passkey proof digest = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(recoveryBindingDigest(`{"version":2}`)), "16ea7a20802e97036a68d00d11666c5600598ab41c68ab457807f4f916e32327"; got != want {
		t.Fatalf("recovery binding digest = %s, want %s", got, want)
	}
}

func TestPasskeyEnvelopeRejectsBindingAndSignatureSubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*InstallCredentialEnvelopeRequest)
	}{
		{"binding", func(req *InstallCredentialEnvelopeRequest) { req.Binding += " " }},
		{"direct signature", func(req *InstallCredentialEnvelopeRequest) { req.BindingDirectSig = strings.Repeat("01", 64) }},
		{"phone signature", func(req *InstallCredentialEnvelopeRequest) { req.BindingPhoneSig = strings.Repeat("01", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := newEnv(t)
			nonce := strings.Repeat("33", 12)
			ciphertext := strings.Repeat("44", 48)
			binding, err := e.svc.BuildRecoveryBindingFor(fixture.VaultID, RecoveryBindingRequest{
				EnvelopeNonce: nonce, EnvelopeCiphertext: ciphertext,
			})
			if err != nil {
				t.Fatal(err)
			}
			digest, _ := hex.DecodeString(binding.BindingDigest)
			directSig, _ := webauthn.SignDigestLowS(e.direct, digest)
			phoneSig, _ := schnorr.Sign(e.hot, digest)
			_, assertion := passkeySessionAssertion(t, e, passkeyPurposeInstall)
			req := InstallCredentialEnvelopeRequest{
				VaultID:                 fixture.VaultID,
				SessionAssertionRequest: assertion,
				RecoveryBindingRequest: RecoveryBindingRequest{
					EnvelopeNonce: nonce, EnvelopeCiphertext: ciphertext,
				},
				Binding: binding.Binding, BindingDirectSig: hex.EncodeToString(directSig),
				BindingPhoneSig: hex.EncodeToString(phoneSig.Serialize()),
			}
			test.mutate(&req)
			if err := e.svc.InstallCredentialEnvelope(context.Background(), req); err == nil {
				t.Fatal("substitution accepted")
			}
			envelope, err := e.svc.Ledger.GetVaultEnvelope(fixture.VaultID)
			if err != nil {
				t.Fatal(err)
			}
			if envelope != nil {
				t.Fatal("failed install persisted an envelope")
			}
		})
	}
}
