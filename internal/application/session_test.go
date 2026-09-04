package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brg444/vaulted-guardian/fixture"
	"github.com/brg444/vaulted-guardian/internal/deployment"
	"github.com/brg444/vaulted-guardian/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestPasskeyEnvelopeInstallAndCrossDeviceRecover(t *testing.T) {
	e := newRecoveryEnv(t)
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

func newRecoveryEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	checkpoint, err := hex.DecodeString(deployment.MutinynetCheckpointTapscriptHex)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := hex.DecodeString(deployment.MutinynetOperatorSignerPubHex)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.ArkResolver = readyArkResolver{
		network: deployment.NetworkMutinynet, checkpoint: checkpoint, signer: signer,
	}
	return e
}

func TestRecoveryBindingV4BindsProtectionSpendingAndBoardingDescriptor(t *testing.T) {
	e := newRecoveryEnv(t)
	status, err := e.svc.StatusFor(context.Background(), fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	// The recovery descriptor must rebuild from the authenticated credential,
	// not trust the mutable status projection.
	e.svc.published.Store(&publishedIndex{
		byVault: map[string]*enrolledSnapshot{}, byCred: map[string]string{},
	})
	response, err := e.svc.BuildRecoveryBindingFor(fixture.VaultID, RecoveryBindingRequest{
		EnvelopeNonce: strings.Repeat("55", 12), EnvelopeCiphertext: strings.Repeat("66", 48),
	})
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(response.Binding))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		t.Fatalf("recovery binding opening token = %v, %v", token, err)
	}
	var keys []string
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key.(string))
		if _, err := decoder.Token(); err != nil {
			t.Fatal(err)
		}
	}
	wantKeys := strings.Join([]string{
		"version", "credentialId", "webauthnP256", "phoneDirectP256", "phoneBip340Pub",
		"externalOwnerWalletPub", "vaultCosignerBasePub", "arkadeCosignerBasePub",
		"arkadeCosignerOrigin", "arkadeCosignerVersion", "clientOrigin", "rpId", "network",
		"vaultId", "templateVersion", "policyVersion", "protectionTier", "savingsAddress", "savingsScript",
		"vtxoVaultCosignerPub", "vtxoExitDelay", "vtxoExitDelayUnit", "spendingArkAddress",
		"spendingArkScript", "vtxoDelegatePub", "vtxoBoardingActive", "vtxoBoardingProgram",
		"vtxoBoardingAddress", "vtxoBoardingScript", "vtxoBoardingExitDelay",
		"vtxoBoardingExitDelayUnit", "recipientDustSats", "txRecipientCapSats",
		"periodAllowanceSats", "absoluteFeeCapSats", "feerateCapSatVb", "envelopeNonce",
		"envelopeCiphertext",
	}, ",")
	if got := strings.Join(keys, ","); got != wantKeys {
		t.Fatalf("recovery binding field order = %s, want %s", got, wantKeys)
	}
	var got recoveryBinding
	if err := json.Unmarshal([]byte(response.Binding), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != 4 || got.ProtectionTier != status.ProtectionTier {
		t.Fatalf("recovery binding identity = %d/%q", got.Version, got.ProtectionTier)
	}
	type derivedDescriptor struct {
		VtxoVaultCosignerPub, VtxoExitDelayUnit                      string
		SpendingArkAddress, SpendingArkScript, VtxoDelegatePub       string
		VtxoBoardingProgram, VtxoBoardingAddress, VtxoBoardingScript string
		VtxoBoardingExitDelayUnit                                    string
		VtxoExitDelay, VtxoBoardingExitDelay                         uint32
		VtxoBoardingActive                                           bool
	}
	derived := derivedDescriptor{
		VtxoVaultCosignerPub: got.VtxoVaultCosignerPub,
		VtxoExitDelay:        got.VtxoExitDelay, VtxoExitDelayUnit: got.VtxoExitDelayUnit,
		SpendingArkAddress: got.SpendingArkAddress, SpendingArkScript: got.SpendingArkScript,
		VtxoDelegatePub:           got.VtxoDelegatePub,
		VtxoBoardingActive:        got.VtxoBoardingActive,
		VtxoBoardingProgram:       got.VtxoBoardingProgram,
		VtxoBoardingAddress:       got.VtxoBoardingAddress,
		VtxoBoardingScript:        got.VtxoBoardingScript,
		VtxoBoardingExitDelay:     got.VtxoBoardingExitDelay,
		VtxoBoardingExitDelayUnit: got.VtxoBoardingExitDelayUnit,
	}
	want := derivedDescriptor{
		VtxoVaultCosignerPub: status.VtxoVaultCosignerPub,
		VtxoExitDelay:        status.VtxoExitDelay, VtxoExitDelayUnit: status.VtxoExitDelayUnit,
		SpendingArkAddress: status.SpendingArkAddress, SpendingArkScript: status.SpendingArkScript,
		VtxoDelegatePub:           status.VtxoDelegatePub,
		VtxoBoardingActive:        status.VtxoBoardingActive,
		VtxoBoardingProgram:       status.VtxoBoardingProgram,
		VtxoBoardingAddress:       status.VtxoBoardingAddress,
		VtxoBoardingScript:        status.VtxoBoardingScript,
		VtxoBoardingExitDelay:     status.VtxoBoardingExitDelay,
		VtxoBoardingExitDelayUnit: status.VtxoBoardingExitDelayUnit,
	}
	if derived != want {
		t.Fatalf("derived recovery descriptor = %+v, want %+v", derived, want)
	}
	if got.VtxoVaultCosignerPub == "" || got.VtxoExitDelay == 0 || got.VtxoExitDelayUnit == "" ||
		got.SpendingArkAddress == "" || got.SpendingArkScript == "" || got.VtxoDelegatePub == "" ||
		!got.VtxoBoardingActive || got.VtxoBoardingProgram == "" || got.VtxoBoardingAddress == "" ||
		got.VtxoBoardingScript == "" || got.VtxoBoardingExitDelay == 0 || got.VtxoBoardingExitDelayUnit == "" {
		t.Fatalf("derived recovery descriptor incomplete: %+v", derived)
	}
	if response.BindingDigest != hex.EncodeToString(recoveryBindingDigest(response.Binding)) {
		t.Fatal("recovery binding digest does not cover canonical v3 payload")
	}
}

func TestRecoveryBindingFailsClosedWithoutPinnedArkadeResolver(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Service)
		want      string
	}{
		{
			name: "missing",
			configure: func(svc *Service) {
				svc.ArkResolver = nil
			},
			want: "Arkade resolver required",
		},
		{
			name: "substituted signer",
			configure: func(svc *Service) {
				resolver := svc.ArkResolver.(readyArkResolver)
				resolver.signer = append([]byte(nil), resolver.signer...)
				resolver.signer[len(resolver.signer)-1] ^= 1
				svc.ArkResolver = resolver
			},
			want: "Arkade resolver policy",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := newRecoveryEnv(t)
			test.configure(e.svc)
			_, err := e.svc.BuildRecoveryBindingFor(fixture.VaultID, RecoveryBindingRequest{
				EnvelopeNonce: strings.Repeat("77", 12), EnvelopeCiphertext: strings.Repeat("88", 48),
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unpinned Arkade resolver: %v", err)
			}
		})
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
	if got, want := hex.EncodeToString(recoveryBindingDigest(`{"version":4}`)), "4a854f298d7eeb1671d26330a22f480e6f83a5f0c9fafadc43586d72759e9103"; got != want {
		t.Fatalf("recovery binding digest = %s, want %s", got, want)
	}
}

func TestPasskeyEnvelopeRejectsBindingAndSignatureSubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*InstallCredentialEnvelopeRequest)
	}{
		{"binding", func(req *InstallCredentialEnvelopeRequest) { req.Binding += " " }},
		{"derived field", func(req *InstallCredentialEnvelopeRequest) {
			req.Binding = strings.Replace(req.Binding, `"vtxoBoardingActive":true`, `"vtxoBoardingActive":false`, 1)
		}},
		{"direct signature", func(req *InstallCredentialEnvelopeRequest) { req.BindingDirectSig = strings.Repeat("01", 64) }},
		{"phone signature", func(req *InstallCredentialEnvelopeRequest) { req.BindingPhoneSig = strings.Repeat("01", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := newRecoveryEnv(t)
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
			envelope, err := e.ledger.GetVaultEnvelope(fixture.VaultID)
			if err != nil {
				t.Fatal(err)
			}
			if envelope != nil {
				t.Fatal("failed install persisted an envelope")
			}
		})
	}
}
