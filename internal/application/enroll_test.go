package application

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/vault/savings"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestEnrollmentRequestHasNoOwnershipProofFields(t *testing.T) {
	typ := reflect.TypeOf(RegisterRequest{})
	for _, forbidden := range []string{"externalOwnerProof", "recoveryPoP", "recoveryProof"} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if strings.EqualFold(field.Name, forbidden) || strings.Split(field.Tag.Get("json"), ",")[0] == forbidden {
				t.Fatalf("retired enrollment proof field %q was reintroduced", forbidden)
			}
		}
	}
}

func proposedDescriptor(t *testing.T, svc *Service, vaultID string, req RegisterRequest) RegisterRequest {
	t.Helper()
	if req.RecoveryXOnly == "" && req.RecoveryKeyXOnly != "" {
		req.RecoveryXOnly = req.RecoveryKeyXOnly
	}
	preview, err := svc.previewTenantDescriptor(vaultID, req)
	if err != nil {
		t.Fatal(err)
	}
	req.DescriptorHash = preview.DescriptorHash
	return req
}

func TestInviteStartFinishCASAndVaultScopedStatus(t *testing.T) {
	led, err := policy.OpenMainnetLedger(filepath.Join(t.TempDir(), "enroll.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	if err := led.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
		t.Fatal(err)
	}
	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	hot, _ := btcec.NewPrivateKey()
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	svc := &Service{
		Stores: testStores(t, led), VaultCosignerPub: master.PubKey(), ArkadeCosignerPub: arkade.PubKey(),
		vaultIKM: master, ArkadeCosignerSigner: LocalSigner{Priv: arkade},
		ArkadeCosignerOrigin: testArkadeCosignerOrigin, ArkadeCosignerVersion: testArkadeCosignerVersion,
		CredentialIntegrityKey: append([]byte(nil), testCredentialIntegrityKey...),
		Deployment: deployment.Config{
			ClientOrigin: fixture.Origin, RPID: fixture.RPID, Network: deployment.NetworkMutinynet,
		},
	}
	raw := bytes.Repeat([]byte{0x3c}, 32)
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := led.PutInvite(hash, now, now); err != nil {
		t.Fatal(err)
	}

	view, err := svc.InviteStatus(token)
	if err != nil || !view.CanEnroll || view.VaultID != nil {
		t.Fatalf("unused invite: %+v %v", view, err)
	}

	first, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	if first.VaultID != replay.VaultID || first.Handle != replay.Handle {
		t.Fatalf("start replay changed identity: %+v vs %+v", first, replay)
	}
	if first.UserID != hex.EncodeToString([]byte(first.VaultID)) {
		t.Fatal("user.id is not the assigned vault id bytes")
	}
	if first.Challenge != replay.Challenge {
		t.Fatal("unexpired start replay rotated the challenge")
	}

	req := attestedFinish(t, svc, replay, pass, []byte("cred-b"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	})
	missing := req
	missing.ExternalOwnerWalletXOnly = ""
	if _, err := svc.FinishEnrollment(context.Background(), token, missing); err == nil {
		t.Fatal("finish accepted a tenant without owner pub")
	}
	st, err := svc.FinishEnrollment(context.Background(), token, req)
	if err != nil {
		t.Fatal(err)
	}
	if st.VaultID != replay.VaultID || st.SavingsAddr == "" {
		t.Fatalf("finish status: %+v", st)
	}
	if st.TemplateVersion != savings.Template {
		t.Fatalf("skip-recovery enroll minted %q, want %s", st.TemplateVersion, savings.Template)
	}
	if st.RecoveryKeyPub != "" {
		t.Fatalf("skip-recovery status leaked recovery: %+v", st)
	}
	again, err := svc.FinishEnrollment(context.Background(), token, req)
	if err != nil || again.VaultID != st.VaultID {
		t.Fatalf("duplicate finish: %+v %v", again, err)
	}
	forgedDescriptor := req
	forgedDescriptor.DescriptorHash = strings.Repeat("ab", 32)
	if _, err := svc.FinishEnrollment(context.Background(), token, forgedDescriptor); err == nil {
		t.Fatal("duplicate finish accepted a different descriptor hash")
	}
	otherRecovery, _ := btcec.NewPrivateKey()
	forgedRecovery := req
	forgedRecovery.RecoveryXOnly = hex.EncodeToString(schnorr.SerializePubKey(otherRecovery.PubKey()))
	forgedRecovery.RegisterRequest = proposedDescriptor(t, svc, replay.VaultID, forgedRecovery.RegisterRequest)
	if _, err := svc.FinishEnrollment(context.Background(), token, forgedRecovery); err == nil {
		t.Fatal("duplicate finish accepted a different recovery key")
	}
	view, err = svc.InviteStatus(token)
	if err != nil || view.CanEnroll || view.VaultID == nil || *view.VaultID != replay.VaultID {
		t.Fatalf("consumed invite view: %+v %v", view, err)
	}

	other, _ := btcec.NewPrivateKey()
	forged := req
	forged.PhoneBIP340Pub = hex.EncodeToString(other.PubKey().SerializeCompressed())
	if _, err := svc.FinishEnrollment(context.Background(), token, forged); err == nil {
		t.Fatal("forged finish replaced the tenant")
	}
}

func TestDuplicateFinishWithRecoveryRequiresExactReplay(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	req := attestedFinish(t, svc, start, pass, []byte("cred-recovery-replay"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(hardware.PubKey())),
		RecoveryXOnly:            hex.EncodeToString(schnorr.SerializePubKey(recovery.PubKey())),
	})
	first, err := svc.FinishEnrollment(context.Background(), token, req)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := svc.FinishEnrollment(context.Background(), token, req)
	if err != nil || replay.VaultID != first.VaultID {
		t.Fatalf("exact lost-response replay: %+v %v", replay, err)
	}
	withoutRecovery := req
	withoutRecovery.RecoveryXOnly = ""
	withoutRecovery.RegisterRequest = proposedDescriptor(t, svc, start.VaultID, withoutRecovery.RegisterRequest)
	if _, err := svc.FinishEnrollment(context.Background(), token, withoutRecovery); err == nil {
		t.Fatal("recovery enrollment replayed as no-recovery enrollment")
	}
}

func TestCurrentSavingsDescriptorRebuildsExactlyAfterRestart(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	phone, _ := btcec.NewPrivateKey()
	hardware, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	req := attestedFinish(t, svc, start, pass, []byte("cred-restart"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(phone.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(hardware.PubKey())),
		RecoveryXOnly:            hex.EncodeToString(schnorr.SerializePubKey(recovery.PubKey())),
	})
	before, err := svc.FinishEnrollment(context.Background(), token, req)
	if err != nil {
		t.Fatal(err)
	}

	restarted := New(Deps{
		Stores:                svc.Stores,
		Deployment:            svc.Deployment,
		IntegrityKey:          append([]byte(nil), svc.CredentialIntegrityKey...),
		MasterIKM:             svc.vaultIKM,
		VaultCosignerPub:      svc.VaultCosignerPub,
		ArkadeCosignerPub:     svc.ArkadeCosignerPub,
		ArkadeCosignerOrigin:  svc.ArkadeCosignerOrigin,
		ArkadeCosignerVersion: svc.ArkadeCosignerVersion,
		ArkadeSigner:          svc.ArkadeCosignerSigner,
		ArkResolver:           svc.ArkResolver,
	})
	if err := restarted.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	after, err := restarted.StatusFor(context.Background(), before.VaultID)
	if err != nil {
		t.Fatal(err)
	}

	type immutableStatus struct {
		VaultID, TemplateVersion, PolicyVersion                      string
		SavingsAddr, SavingsScript                                   string
		PhoneBIP340Pub, PhoneDirectP256                              string
		ExternalOwnerWalletPub, RecoveryKeyPub                       string
		VaultCosignerBasePub, ArkadeCosignerBasePub                  string
		ArkadeCosignerOrigin, ArkadeCosignerVersion                  string
		SpendingArkAddress, SpendingArkScript                        string
		VtxoVaultCosignerPub, VtxoDelegatePub                        string
		VtxoBoardingProgram, VtxoBoardingAddress, VtxoBoardingScript string
	}
	project := func(st Status) immutableStatus {
		return immutableStatus{
			VaultID: st.VaultID, TemplateVersion: st.TemplateVersion, PolicyVersion: st.PolicyVersion,
			SavingsAddr: st.SavingsAddr, SavingsScript: st.SavingsScript,
			PhoneBIP340Pub: st.PhoneBIP340Pub, PhoneDirectP256: st.PhoneDirectP256,
			ExternalOwnerWalletPub: st.ExternalOwnerWalletPub, RecoveryKeyPub: st.RecoveryKeyPub,
			VaultCosignerBasePub: st.VaultCosignerBasePub, ArkadeCosignerBasePub: st.ArkadeCosignerBasePub,
			ArkadeCosignerOrigin: st.ArkadeCosignerOrigin, ArkadeCosignerVersion: st.ArkadeCosignerVersion,
			SpendingArkAddress: st.SpendingArkAddress, SpendingArkScript: st.SpendingArkScript,
			VtxoVaultCosignerPub: st.VtxoVaultCosignerPub, VtxoDelegatePub: st.VtxoDelegatePub,
			VtxoBoardingProgram: st.VtxoBoardingProgram,
			VtxoBoardingAddress: st.VtxoBoardingAddress, VtxoBoardingScript: st.VtxoBoardingScript,
		}
	}
	if got, want := project(after), project(*before); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart rebuilt different descriptor facts:\n got: %+v\nwant: %+v", got, want)
	}
}

func TestProposeBindsDescriptorIntoEnrollment(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	base := RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	}
	req := attestedFinish(t, svc, start, pass, []byte("cred-desc"), base)
	if req.DescriptorHash == "" {
		t.Fatal("propose did not fill descriptor hash")
	}
	wrong := req
	wrong.DescriptorHash = strings.Repeat("ab", 32)
	if _, err := svc.FinishEnrollment(context.Background(), token, wrong); err == nil {
		t.Fatal("finish accepted the wrong proposed descriptor")
	}
	if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
		t.Fatal(err)
	}
}

func TestFinishDoesNotInheritProcessOwnerPubs(t *testing.T) {
	led, err := policy.OpenMainnetLedger(filepath.Join(t.TempDir(), "inherit.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	if err := led.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
		t.Fatal(err)
	}
	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	hot, _ := btcec.NewPrivateKey()
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	svc := &Service{
		Stores:           testStores(t, led),
		VaultCosignerPub: master.PubKey(), ArkadeCosignerPub: arkade.PubKey(),
		vaultIKM: master, ArkadeCosignerSigner: LocalSigner{Priv: arkade},
		ArkadeCosignerOrigin: testArkadeCosignerOrigin, ArkadeCosignerVersion: testArkadeCosignerVersion,
		CredentialIntegrityKey: append([]byte(nil), testCredentialIntegrityKey...),
		Deployment: deployment.Config{
			ClientOrigin: fixture.Origin, RPID: fixture.RPID, Network: deployment.NetworkMutinynet,
		},
	}
	raw := bytes.Repeat([]byte{0x4d}, 32)
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash, _ := HashEnrollmentToken(token)
	now := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := led.PutInvite(hash, now, now); err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.FinishEnrollment(context.Background(), token, attestedFinish(t, svc, start, pass, []byte("cred-x"), RegisterRequest{
		PhoneDirectP256: hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:  hex.EncodeToString(hot.PubKey().SerializeCompressed()),
	}))
	if err == nil {
		t.Fatal("finish inherited process-level owner/recovery pubs")
	}
}

func TestFinishAcceptsPRFShapedAuthenticatorExtensions(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	challenge, _ := hex.DecodeString(start.Challenge)
	credID := []byte("prf-cred")
	auth, err := webauthn.AttestedAuthenticatorDataPRF(fixture.RPID, credID, webauthn.CompressedP256(pass))
	if err != nil {
		t.Fatal(err)
	}
	req := EnrollFinishRequest{
		Handle:            start.Handle,
		UserHandle:        start.UserID,
		ClientDataJSON:    hex.EncodeToString([]byte(`{"type":"webauthn.create","challenge":"` + webauthn.EncodeChallenge(challenge) + `","origin":"` + fixture.Origin + `","crossOrigin":false}`)),
		AuthenticatorData: hex.EncodeToString(auth),
		AttestationObject: hex.EncodeToString(webauthn.EncodeNoneAttestationObject(auth)),
		RegisterRequest: proposedDescriptor(t, svc, start.VaultID, RegisterRequest{
			CredentialID:             hex.EncodeToString(credID),
			WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(pass)),
			PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
			PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
			ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
		}),
	}
	if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
		t.Fatal(err)
	}
}

func TestFinishCannotConsumeAfterConcurrentChallengeRotation(t *testing.T) {
	svc, token, start := enrollReady(t)
	loaded := make(chan struct{})
	release := make(chan struct{})
	svc.afterLoadPending = func() {
		select {
		case <-loaded:
		default:
			close(loaded)
		}
		<-release
	}

	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	stale := attestedFinish(t, svc, start, pass, []byte("stale-race"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	})

	errCh := make(chan error, 1)
	go func() {
		_, err := svc.FinishEnrollment(context.Background(), token, stale)
		errCh <- err
	}()
	select {
	case <-loaded:
	case err := <-errCh:
		t.Fatalf("finish returned before interleaving: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("finish did not reach pending load")
	}
	now := time.Now().UTC()
	svc.EnrollmentNow = func() time.Time { return now.Add(pendingEnrollmentTTL + time.Minute) }
	rotated, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Challenge == start.Challenge {
		t.Fatal("start did not rotate the expired challenge")
	}
	close(release)
	if err := <-errCh; err == nil {
		t.Fatal("stale finish consumed the invite after rotation")
	}
	fresh, _ := webauthn.NewP256()
	if _, err := svc.FinishEnrollment(context.Background(), token, attestedFinish(t, svc, rotated, fresh, []byte("fresh-race"), stale.RegisterRequest)); err != nil {
		t.Fatal(err)
	}
}

func TestProposeMintsSavingsDescriptor(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	req := attestedFinish(t, svc, start, pass, []byte("cred-savings"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
		RecoveryXOnly:            hex.EncodeToString(schnorr.SerializePubKey(recovery.PubKey())),
	})
	proposed, err := svc.ProposeEnrollment(token, req)
	if err != nil {
		t.Fatal(err)
	}
	desc, ok := proposed.Descriptor.(savings.PublicDescriptor)
	if !ok || desc.Schema != savings.Schema || desc.TemplateVersion != savings.Template {
		t.Fatalf("propose did not mint Savings: %+v", proposed.Descriptor)
	}
	if desc.Savings.Address == "" || desc.Keys.Recovery == "" {
		t.Fatalf("Savings descriptor missing trees: %+v", desc)
	}
	st, err := svc.FinishEnrollment(context.Background(), token, req)
	if err != nil {
		t.Fatal(err)
	}
	if st.TemplateVersion != savings.Template || st.RecoveryKeyPub == "" || st.SavingsAddr != desc.Savings.Address {
		t.Fatalf("finish status: %+v", st)
	}
	if _, err := svc.SignTransition(context.Background(), TransitionRequest{
		VaultID: start.VaultID, Purpose: "claim", PSBT: "00",
	}); err == nil {
		t.Fatal("signed a claim")
	}
	if _, err := svc.SignTransition(context.Background(), TransitionRequest{
		VaultID: start.VaultID, Purpose: "initiate", PSBT: "cHNidP8BAHECAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AQAAAAAAAAAA",
	}); err == nil {
		t.Fatal("signed a transition without a verified prevout")
	}
}

func TestProposeMintsSavingsWithoutRecovery(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	req := attestedFinish(t, svc, start, pass, []byte("cred-savings-skip"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	})
	proposed, err := svc.ProposeEnrollment(token, req)
	if err != nil {
		t.Fatal(err)
	}
	desc, ok := proposed.Descriptor.(savings.PublicDescriptor)
	if !ok || desc.Schema != savings.Schema || desc.TemplateVersion != savings.Template {
		t.Fatalf("skip-recovery propose did not mint Savings: %+v", proposed.Descriptor)
	}
	if desc.Keys.Recovery != "" {
		t.Fatalf("skip-recovery descriptor included recovery: %+v", desc.Keys)
	}
	if _, ok := desc.Pending["savings-recovery"]; ok {
		t.Fatal("skip-recovery descriptor included a recovery pending tree")
	}
	if len(desc.Pending) != 2 || len(desc.Quarantine) != 2 {
		t.Fatalf("want 2-guardian pending/quarantine, got pending=%d quarantine=%d", len(desc.Pending), len(desc.Quarantine))
	}
	st, err := svc.FinishEnrollment(context.Background(), token, req)
	if err != nil {
		t.Fatal(err)
	}
	if st.TemplateVersion != savings.Template || st.RecoveryKeyPub != "" || st.SavingsAddr != desc.Savings.Address {
		t.Fatalf("skip-recovery finish status: %+v", st)
	}
}

func TestCredentialCannotOperateAnotherVault(t *testing.T) {
	svc := &Service{}
	svc.publishEnrollmentAt("vault-a", []byte("cred-a"), nil, nil)
	svc.publishEnrollmentAt("vault-b", []byte("cred-b"), nil, nil)
	if err := svc.rejectCrossVaultCredential("vault-b", []byte("cred-a")); err == nil {
		t.Fatal("credential A operated vault B")
	}
	if err := svc.rejectCrossVaultCredential("vault-a", []byte("cred-a")); err != nil {
		t.Fatal(err)
	}
}

func attestedFinish(t *testing.T, svc *Service, start *EnrollStartResponse, pass *ecdsa.PrivateKey, credID []byte, extra RegisterRequest) EnrollFinishRequest {
	t.Helper()
	challenge, err := hex.DecodeString(start.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	compressed := webauthn.CompressedP256(pass)
	auth, err := webauthn.AttestedAuthenticatorData(fixture.RPID, credID, compressed)
	if err != nil {
		t.Fatal(err)
	}
	obj := webauthn.EncodeNoneAttestationObject(auth)
	extra.CredentialID = hex.EncodeToString(credID)
	extra.WebAuthnP256 = hex.EncodeToString(compressed)
	if extra.ExternalOwnerWalletXOnly != "" {
		extra = proposedDescriptor(t, svc, start.VaultID, extra)
	}
	return EnrollFinishRequest{
		Handle:            start.Handle,
		UserHandle:        start.UserID,
		ClientDataJSON:    hex.EncodeToString([]byte(`{"type":"webauthn.create","challenge":"` + webauthn.EncodeChallenge(challenge) + `","origin":"` + fixture.Origin + `","crossOrigin":false}`)),
		AuthenticatorData: hex.EncodeToString(auth),
		AttestationObject: hex.EncodeToString(obj),
		RegisterRequest:   extra,
	}
}

func TestFinishRejectsUnattestedOrMismatchedCreate(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	req := attestedFinish(t, svc, start, pass, []byte("cred-at"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	})
	noAT := req
	auth := make([]byte, 37)
	copy(auth[:32], mustDecode(t, req.AuthenticatorData)[:32])
	auth[32] = 0x05
	noAT.AuthenticatorData = hex.EncodeToString(auth)
	noAT.AttestationObject = ""
	if _, err := svc.FinishEnrollment(context.Background(), token, noAT); err == nil {
		t.Fatal("finish accepted create without AT")
	}
	mismatch := req
	other, _ := webauthn.NewP256()
	mismatch.WebAuthnP256 = hex.EncodeToString(webauthn.CompressedP256(other))
	if _, err := svc.FinishEnrollment(context.Background(), token, mismatch); err == nil {
		t.Fatal("finish accepted a posted P-256 that was not attested")
	}
}

func TestStaleStartChallengeCannotFinishAfterExpiryRotation(t *testing.T) {
	svc, token, start := enrollReady(t)
	stale := start.Challenge
	now := time.Now().UTC()
	svc.EnrollmentNow = func() time.Time { return now.Add(pendingEnrollmentTTL + time.Minute) }
	rotated, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Challenge == stale {
		t.Fatal("expired start did not rotate the challenge")
	}
	start.Challenge = stale
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	staleReq := attestedFinish(t, svc, start, pass, []byte("stale"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	})
	if _, err := svc.FinishEnrollment(context.Background(), token, staleReq); err == nil {
		t.Fatal("stale challenge finished after rotation")
	}
	fresh, _ := webauthn.NewP256()
	if _, err := svc.FinishEnrollment(context.Background(), token, attestedFinish(t, svc, rotated, fresh, []byte("fresh"), staleReq.RegisterRequest)); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentFinishAndStatusDoNotRaceSharedKeyFields(t *testing.T) {
	svc, token, start := enrollReady(t)
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	req := attestedFinish(t, svc, start, pass, []byte("race"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:           hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	})
	if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for i := 0; i < 8; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
				errCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := svc.StatusFor(context.Background(), start.VaultID); err != nil {
				errCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := svc.statusFor(context.Background(), start.VaultID); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func enrollReady(t *testing.T) (*Service, string, *EnrollStartResponse) {
	t.Helper()
	led, err := policy.OpenMainnetLedger(filepath.Join(t.TempDir(), "ready.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	svc := enrollService(t, led)
	raw := bytes.Repeat([]byte{0x3c}, 32)
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := led.PutInvite(hash, now, now); err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	return svc, token, start
}

func enrollService(t *testing.T, led *policy.Ledger) *Service {
	t.Helper()
	if err := led.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
		t.Fatal(err)
	}
	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	return &Service{
		Stores: testStores(t, led), VaultCosignerPub: master.PubKey(), ArkadeCosignerPub: arkade.PubKey(),
		vaultIKM: master, ArkadeCosignerSigner: LocalSigner{Priv: arkade},
		ArkadeCosignerOrigin: testArkadeCosignerOrigin, ArkadeCosignerVersion: testArkadeCosignerVersion,
		CredentialIntegrityKey: append([]byte(nil), testCredentialIntegrityKey...),
		Deployment: deployment.Config{
			ClientOrigin: fixture.Origin, RPID: fixture.RPID, Network: deployment.NetworkMutinynet,
		},
	}
}

func mustDecode(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
