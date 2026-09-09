package application

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type ledgerEnrollmentFixture struct {
	ledger  *policy.Ledger
	dbPath  string
	svc     *Service
	token   string
	start   *EnrollStartResponse
	request EnrollFinishRequest
	pass    *ecdsa.PrivateKey
	hot     *btcec.PrivateKey
	signer  ledgerTransitionFixture
}

func ledgerEnrollmentReady(t *testing.T, advanced bool) ledgerEnrollmentFixture {
	t.Helper()
	tier := program.ProtectionTierStandard
	if advanced {
		tier = program.ProtectionTierAdvanced
	}
	dbPath := filepath.Join(t.TempDir(), "ledger.sqlite")
	ledger, err := policy.OpenLedger(dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	svc := enrollService(t, ledger)
	token, start := startTestEnrollmentWithTier(t, svc, ledger, 0x3c, program.DefaultSpendingPolicy(), tier)
	svc.LedgerSavingsEnabled = true
	svc.ArkResolver = readyArkResolver{network: deployment.NetworkMutinynet, checkpoint: mustDecode(t, deployment.MutinynetCheckpointTapscriptHex), signer: mustDecode(t, deployment.MutinynetOperatorSignerPubHex)}
	signer := newLedgerTransitionFixture(t, advanced)
	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hot.Zero)
	pass, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	hardware, err := savings.LedgerSpendingExitKey(signer.in.Hardware, signer.in.Network)
	if err != nil {
		t.Fatal(err)
	}
	hPub, err := hardware.ECPubKey()
	if err != nil {
		t.Fatal(err)
	}
	raw := RegisterRequest{PhoneDirectP256: hex.EncodeToString(webauthn.CompressedP256(signer.direct)), PhoneBIP340Pub: hex.EncodeToString(hot.PubKey().SerializeCompressed()), ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(hPub))}
	if advanced {
		r, err := savings.LedgerSpendingExitKey(*signer.in.Recovery, signer.in.Network)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := r.ECPubKey()
		if err != nil {
			t.Fatal(err)
		}
		raw.RecoveryXOnly = hex.EncodeToString(schnorr.SerializePubKey(pub))
	}
	req := attestedFinish(t, svc, start, pass, []byte("ledger-integration-passkey"), raw)
	req.LedgerSavings = &LedgerSavingsEnrollmentRequest{TemplateVersion: savings.LedgerNativeTemplate, Phone: signer.in.Phone, Hardware: signer.in.Hardware, Recovery: signer.in.Recovery}
	proposed, err := svc.ProposeEnrollment(token, req)
	if err != nil {
		t.Fatal(err)
	}
	req.DescriptorHash = proposed.DescriptorHash
	return ledgerEnrollmentFixture{ledger: ledger, dbPath: dbPath, svc: svc, token: token, start: start, request: req, pass: pass, hot: hot, signer: signer}
}
func (f *ledgerEnrollmentFixture) restart(t *testing.T) {
	t.Helper()
	if err := f.ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := policy.OpenLedger(f.dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	if err := ledger.SetIntegrityKey(testCredentialIntegrityKey); err != nil {
		t.Fatal(err)
	}
	f.ledger = ledger
	f.svc.Stores = testStores(t, ledger)
	f.svc.backupSessions = nil
	f.svc.published.Store(&publishedIndex{byVault: map[string]*enrolledSnapshot{}, byCred: map[string]string{}})
	if err := f.svc.LoadVaults(); err != nil {
		t.Fatal(err)
	}
}
func (f *ledgerEnrollmentFixture) finish(t *testing.T) Status {
	t.Helper()
	status, err := f.svc.FinishEnrollment(t.Context(), f.token, f.request)
	if err != nil {
		t.Fatal(err)
	}
	if status.LedgerSavings == nil {
		t.Fatal("missing Ledger Savings identity")
	}
	f.signer.in = status.LedgerSavings.Context
	return *status
}
func (f ledgerEnrollmentFixture) assertion(t *testing.T, purpose string) SessionAssertionRequest {
	t.Helper()
	issued, err := f.svc.IssuePasskeyChallengeFor(t.Context(), f.start.VaultID, purpose)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := hex.DecodeString(issued.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := hex.DecodeString(f.request.CredentialID)
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.svc.runtimeConfig()
	assertion, err := webauthn.Synth(f.pass, cred, challenge, cfg.ClientOrigin, cfg.RPID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := webauthn.SignDigestLowS(f.signer.direct, passkeySessionProofDigest(purpose, challenge, cred))
	if err != nil {
		t.Fatal(err)
	}
	return SessionAssertionRequest{ChallengeID: issued.ChallengeID, CredentialID: f.request.CredentialID, ClientDataJSON: hex.EncodeToString(assertion.ClientDataJSON), AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData), Signature: hex.EncodeToString(assertion.DERSignature), DirectProof: hex.EncodeToString(proof)}
}
func (f ledgerEnrollmentFixture) transition(t *testing.T, kind, claimant, remaining string) TransitionRequest {
	t.Helper()
	req := f.signer.request(t, kind, claimant, remaining, 0)
	change := uint32(0)
	out := TransitionRequest{VaultID: f.start.VaultID, Purpose: kind, PSBT: req.retainedPSBT, LedgerSavings: &LedgerSavingsTransitionRequest{Claimant: claimant, RemainingUser: remaining, Change: &change}}
	actor := claimant
	if kind == "clawback" {
		actor = remaining
	}
	if actor == "phone" {
		packet, err := parsePSBT(req.retainedPSBT)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := LedgerSavingsTransitionDigest(req.keyContext, kind, claimant, remaining, 0, packet.UnsignedTx, packet.Inputs[0].WitnessUtxo)
		if err != nil {
			t.Fatal(err)
		}
		out.PhoneAuthorization = &LedgerSavingsPhoneAuthorization{Digest: hex.EncodeToString(digest), Signature: hex.EncodeToString(req.directProof)}
		out.SessionAssertionRequest = f.assertion(t, passkeyPurposeTransition)
	}
	return out
}
func TestLedgerSavingsEnrollmentPersistenceAndSpendingIsolation(t *testing.T) {
	for _, advanced := range []bool{false, true} {
		f := ledgerEnrollmentReady(t, advanced)
		status := f.finish(t)
		if status.TemplateVersion != savings.LedgerNativeTemplate || status.LedgerSavings.DescriptorHash != f.request.DescriptorHash {
			t.Fatal("new immutable identity mismatch")
		}
		if status.PhoneBIP340Pub != f.request.PhoneBIP340Pub || status.ExternalOwnerWalletPub != "02"+f.request.ExternalOwnerWalletXOnly || status.VaultCosignerBasePub == status.LedgerSavings.Context.VaultCosignerBase {
			t.Fatal("Spending identities were replaced by Savings identities")
		}
		spending, err := f.svc.spendingRenewalContext(f.start.VaultID)
		if err != nil || spending.Binding.OwnerPub != hex.EncodeToString(schnorr.SerializePubKey(f.hot.PubKey())) || spending.Binding.ScriptPubKey != status.SpendingArkScript {
			t.Fatal("original Spending capability changed", err)
		}
		replay, err := f.svc.FinishEnrollment(t.Context(), f.token, f.request)
		if err != nil || !reflect.DeepEqual(*replay, status) {
			t.Fatal("finish replay changed identity", err)
		}
		f.svc.LedgerSavingsEnabled = false
		f.restart(t)
		restarted, err := f.svc.StatusFor(t.Context(), f.start.VaultID)
		if err != nil || !reflect.DeepEqual(restarted, status) {
			t.Fatal("restart changed immutable enrollment", err)
		}
		changed := f.request
		copyRequest := *changed.LedgerSavings
		copyRequest.Hardware.Fingerprint = "00000001"
		changed.LedgerSavings = &copyRequest
		if _, err := f.svc.FinishEnrollment(t.Context(), f.token, changed); err == nil {
			t.Fatal("duplicate finish accepted changed account metadata")
		}
		if _, err := f.svc.SignTransition(t.Context(), f.transition(t, "initiate", "hardware", "")); err != nil {
			t.Fatal("existing Ledger vault unusable after admission disabled", err)
		}
	}
}
func TestLedgerSavingsEnrollmentRejectsUnqualifiedAndWrongSpendingAuthority(t *testing.T) {
	f := ledgerEnrollmentReady(t, false)
	f.svc.LedgerSavingsEnabled = false
	public, err := f.svc.PublicStatus()
	if err != nil || public.LedgerSavingsCapability != nil {
		t.Fatal("disabled candidate advertised", err)
	}
	if _, err := f.svc.ProposeEnrollment(f.token, f.request); err == nil {
		t.Fatal("candidate enrollment admitted while disabled")
	}
	f.svc.LedgerSavingsEnabled = true
	wrong := f.request
	other, _ := btcec.NewPrivateKey()
	defer other.Zero()
	wrong.ExternalOwnerWalletXOnly = hex.EncodeToString(schnorr.SerializePubKey(other.PubKey()))
	if _, err := f.svc.ProposeEnrollment(f.token, wrong); err == nil {
		t.Fatal("Spending H was not bound to /12/0")
	}
}

type failingLedgerSavingsAuthorizer struct{ ledgerSavingsAuthorizer }

func (f failingLedgerSavingsAuthorizer) authorizeTransition(context.Context, ledgerSavingsTransitionAuthorization) (string, error) {
	return "", fmt.Errorf("injected signer failure")
}
func TestLedgerSavingsDurableFailureRetryReplacementAndRestart(t *testing.T) {
	f := ledgerEnrollmentReady(t, false)
	f.finish(t)
	req := f.transition(t, "initiate", "hardware", "")
	capability := f.svc.keys.ledgerSavings
	f.svc.keys.ledgerSavings = failingLedgerSavingsAuthorizer{capability}
	if _, err := f.svc.SignTransition(t.Context(), req); err == nil {
		t.Fatal("injected failure ignored")
	}
	different := f.signer.request(t, "initiate", "hardware", "", 0)
	packet, err := parsePSBT(different.retainedPSBT)
	if err != nil {
		t.Fatal(err)
	}
	packet.UnsignedTx.TxOut[0].Value--
	f.signer.approve(t, &different, packet)
	conflicting := req
	conflicting.PSBT = different.retainedPSBT
	if _, err := f.svc.SignTransition(t.Context(), conflicting); err == nil {
		t.Fatal("conflicting pending candidate accepted")
	}
	f.svc.keys.ledgerSavings = capability
	f.restart(t)
	signed, err := f.svc.SignTransition(t.Context(), req)
	if err != nil || !signed.Replay {
		t.Fatal("pending retry did not resume", err)
	}
	replay, err := f.svc.SignTransition(t.Context(), req)
	if err != nil || !replay.Replay || replay.SignedPSBT != signed.SignedPSBT {
		t.Fatal("signed retry mismatch", err)
	}
	replacement, err := f.svc.SignTransition(t.Context(), conflicting)
	if err != nil || replacement.SignedPSBT == signed.SignedPSBT {
		t.Fatal("same-destination fee replacement failed", err)
	}
	f.restart(t)
	replay, err = f.svc.SignTransition(t.Context(), conflicting)
	if err != nil || replay.SignedPSBT != replacement.SignedPSBT {
		t.Fatal("replacement replay after restart failed", err)
	}
}
func TestLedgerSavingsV6BindingRestoresRegistrationAndEncryptedSeed(t *testing.T) {
	f := ledgerEnrollmentReady(t, true)
	status := f.finish(t)
	family, err := savings.BuildLedgerNativeFamily(status.LedgerSavings.Context, status.SpendingPolicy)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := savings.LedgerSavingsContextDigest(status.LedgerSavings.Context)
	if err != nil {
		t.Fatal(err)
	}
	d := hex.EncodeToString(digest)
	backup := &LedgerSavingsBackup{Registration: LedgerSavingsRegistration{Name: "vaulted-ledger-registration", Version: 1, ContextDigest: d, WalletID: ledgerSavingsWalletPolicyID(family.WalletPolicy), WalletHMAC: strings.Repeat("11", 32), WalletPolicy: family.WalletPolicy, ReceiveAddress: family.Receive.Address, ChangeAddress: family.Change.Address}, PhoneSeedBackup: LedgerSavingsPhoneSeedBackup{Name: "vaulted-ledger-savings-phone-seed", Version: 1, Purpose: "passkey-prf", ContextDigest: d, PhoneOrigin: status.LedgerSavings.Context.Phone, Salt: strings.Repeat("22", 32), Nonce: strings.Repeat("33", 12), Ciphertext: strings.Repeat("44", 48)}}
	request := RecoveryBindingRequest{EnvelopeNonce: strings.Repeat("55", 12), EnvelopeCiphertext: strings.Repeat("66", 48), LedgerSavings: backup}
	binding, err := f.svc.BuildRecoveryBindingFor(f.start.VaultID, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(binding.Binding) > 16384 {
		t.Fatalf("binding exceeds16KiB: %d", len(binding.Binding))
	}
	var parsed recoveryBinding
	if err := json.Unmarshal([]byte(binding.Binding), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Version != 6 || parsed.LedgerSavingsContextDigest != d || parsed.LedgerSavingsDescriptorHash != f.request.DescriptorHash {
		t.Fatal("Ledger binding omitted immutable identity")
	}
	bindingDigest, err := hex.DecodeString(binding.BindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	directSig, err := webauthn.SignDigestLowS(f.signer.direct, bindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	phoneSig, err := schnorr.Sign(f.hot, bindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	install := InstallCredentialEnvelopeRequest{VaultID: f.start.VaultID, SessionAssertionRequest: f.assertion(t, passkeyPurposeInstall), RecoveryBindingRequest: request, Binding: binding.Binding, BindingDirectSig: hex.EncodeToString(directSig), BindingPhoneSig: hex.EncodeToString(phoneSig.Serialize())}
	if err := f.svc.InstallCredentialEnvelope(t.Context(), install); err != nil {
		t.Fatal(err)
	}
	f.restart(t)
	recovered, err := f.svc.RecoverCredentialEnvelope(t.Context(), RecoverCredentialEnvelopeRequest{VaultID: f.start.VaultID, SessionAssertionRequest: f.assertion(t, passkeyPurposeRecover)})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recovered.LedgerSavings, backup) || recovered.EnvelopeCiphertext != request.EnvelopeCiphertext {
		t.Fatal("recovery changed encrypted secret domains")
	}
	changed := *backup
	changed.PhoneSeedBackup.Ciphertext = strings.Repeat("77", 48)
	request.LedgerSavings = &changed
	other, err := f.svc.BuildRecoveryBindingFor(f.start.VaultID, request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(recoveryBindingDigest(binding.Binding), recoveryBindingDigest(other.Binding)) {
		t.Fatal("encrypted Ledger seed not signed into binding")
	}
	request.LedgerSavings = nil
	if _, err := f.svc.BuildRecoveryBindingFor(f.start.VaultID, request); err == nil {
		t.Fatal("Ledger envelope accepted without seed")
	}
}

func TestLedgerSavingsStatusHTTPReturnsCompositeBoarding(t *testing.T) {
	f := ledgerEnrollmentReady(t, false)
	status := f.finish(t)
	raw := httpJSON(t, testAuthorizer(f.svc), "GET", "/v1/status?vault="+f.start.VaultID, nil)
	var got struct {
		Status
		Boarding vaultBoardPublicDescriptor `json:"vtxoBoardingDescriptor"`
		Hash     string                     `json:"vtxoBoardingDescriptorHash"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Hash != status.LedgerSavings.DescriptorHash || got.Boarding.Address != status.VtxoBoardingAddress || got.LedgerSavings == nil {
		t.Fatal("HTTP Ledger composite mismatch")
	}
	public := httpJSON(t, testAuthorizer(f.svc), "GET", "/v1/status", nil)
	var advertised PublicStatus
	if err := json.Unmarshal(public, &advertised); err != nil {
		t.Fatal(err)
	}
	if advertised.LedgerSavingsCapability == nil || advertised.LedgerSavingsCapability.TemplateVersion != savings.LedgerNativeTemplate {
		t.Fatal("enabled capability absent")
	}
}
func TestLedgerSavingsPhoneRequiresSessionAndDetachedTransactionProof(t *testing.T) {
	for _, action := range []struct{ kind, claimant, remaining string }{{"initiate", "phone", ""}, {"clawback", "hardware", "phone"}} {
		t.Run(action.kind, func(t *testing.T) {
			f := ledgerEnrollmentReady(t, false)
			f.finish(t)
			req := f.transition(t, action.kind, action.claimant, action.remaining)
			missing := req
			missing.SessionAssertionRequest = SessionAssertionRequest{}
			if _, err := f.svc.SignTransition(t.Context(), missing); err == nil {
				t.Fatal("missing session accepted")
			}
			missing = req
			missing.PhoneAuthorization = nil
			if _, err := f.svc.SignTransition(t.Context(), missing); err == nil {
				t.Fatal("missing transaction proof accepted")
			}
			wrong := req
			proof := *req.PhoneAuthorization
			proof.Digest = strings.Repeat("ff", 32)
			wrong.PhoneAuthorization = &proof
			if _, err := f.svc.SignTransition(t.Context(), wrong); err == nil {
				t.Fatal("wrong transaction digest accepted")
			}
			if _, err := f.svc.SignTransition(t.Context(), req); err != nil {
				t.Fatal("valid phone transition", err)
			}
			if _, err := f.svc.SignTransition(t.Context(), req); err == nil {
				t.Fatal("used passkey session replayed")
			}
			req.SessionAssertionRequest = f.assertion(t, passkeyPurposeTransition)
			if replay, err := f.svc.SignTransition(t.Context(), req); err != nil || !replay.Replay {
				t.Fatal("fresh authenticated retry", err)
			}
		})
	}
}

func TestLedgerSavingsRecoveryArchivePersistsCompositeAcrossRestart(t *testing.T) {
	for _, advanced := range []bool{false, true} {
		f := ledgerEnrollmentReady(t, advanced)
		f.finish(t)
		f.svc.LedgerSavingsEnabled = false
		auth := func() LightBackupOpenRequest {
			return archiveAssertion(t, f.svc, f.start.VaultID, f.pass, f.signer.direct, mustDecode(t, f.request.CredentialID), recoveryArchivePurpose)
		}
		opened, err := f.svc.OpenRecoveryArchive(t.Context(), auth())
		if err != nil || opened.Binding.DescriptorHash != f.request.DescriptorHash {
			t.Fatal("archive identity", err)
		}
		payload := archivePayload(opened.Binding, "immutable-ledger-header", strings.Repeat("A", 64))
		saved, err := f.svc.WriteRecoveryArchive(LightBackupRequest{Token: opened.Token, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		wrong := opened.Binding
		wrong.TemplateVersion = savings.Template
		if _, err := f.svc.WriteRecoveryArchive(LightBackupRequest{Token: opened.Token, Revision: 1, Payload: archivePayload(wrong, "immutable-ledger-header", strings.Repeat("A", 64))}); err == nil {
			t.Fatal("archive contract substituted")
		}
		f.restart(t)
		if _, err := f.svc.ReadRecoveryArchive(LightBackupRequest{Token: opened.Token}); err == nil {
			t.Fatal("old archive session survived restart")
		}
		recovered, err := f.svc.OpenRecoveryArchive(t.Context(), auth())
		if err != nil || recovered.Backup == nil || *recovered.Backup != *saved || recovered.Binding != opened.Binding {
			t.Fatal("archive restart", err)
		}
	}
}

func TestLedgerSavingsCrossLanguageEnrollmentAndRegistration(t *testing.T) {
	raw, err := os.ReadFile("testdata/ledger-enrollment-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Network               string
		Advanced              bool
		Descriptor            ledgerSavingsEnrollmentDescriptor
		DescriptorHash        string
		Registration          LedgerSavingsRegistration
		RecoveryBinding       string
		RecoveryBindingDigest string
		LedgerSavings         LedgerSavingsBackup
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 4 {
		t.Fatal("network/tier matrix absent")
	}
	for _, v := range vectors {
		t.Run(fmt.Sprintf("%s/%v", v.Network, v.Advanced), func(t *testing.T) {
			var binding recoveryBinding
			if err := json.Unmarshal([]byte(v.RecoveryBinding), &binding); err != nil {
				t.Fatal(err)
			}
			if binding.Version != 6 || hex.EncodeToString(recoveryBindingDigest(v.RecoveryBinding)) != v.RecoveryBindingDigest {
				t.Fatal("v6 digest mismatch")
			}
			backupJSON, err := marshalLedgerSavingsJSON(v.LedgerSavings)
			if err != nil || string(backupJSON) != binding.LedgerSavingsBackup {
				t.Fatal("v6 canonical backup JSON mismatch", err)
			}
			canonicalBinding, err := marshalLedgerSavingsJSON(binding)
			if err != nil || string(canonicalBinding) != v.RecoveryBinding {
				t.Fatal("v6 canonical binding JSON mismatch", err)
			}
			if binding.LedgerSavingsDescriptorHash != v.DescriptorHash {
				t.Fatal("v6 composite identity mismatch")
			}
			hash, err := hashLedgerSavingsEnrollment(v.Descriptor)
			if err != nil || hash != v.DescriptorHash {
				t.Fatal("composite hash", hash, err)
			}
			family, err := savings.BuildLedgerNativeFamily(v.Descriptor.Savings.Context, v.Descriptor.Savings.SpendingPolicy)
			if err != nil {
				t.Fatal(err)
			}
			if v.Registration.WalletID != ledgerSavingsWalletPolicyID(family.WalletPolicy) || !reflect.DeepEqual(v.Registration.WalletPolicy, family.WalletPolicy) || v.Registration.ReceiveAddress != family.Receive.Address || v.Registration.ChangeAddress != family.Change.Address {
				t.Fatal("registration BIP388 or address mismatch")
			}
			in := v.Descriptor.Savings.Context
			for _, role := range []struct {
				origin *savings.LedgerAccountOrigin
				raw    string
			}{{&in.Hardware, v.Descriptor.SpendingAuthorities.ExternalOwnerWalletPub}, {in.Recovery, v.Descriptor.SpendingAuthorities.RecoveryKeyPub}} {
				if role.origin == nil {
					if role.raw != "" {
						t.Fatal("standard recovery authority")
					}
					continue
				}
				key, err := savings.LedgerSpendingExitKey(*role.origin, v.Network)
				if err != nil {
					t.Fatal(err)
				}
				pub, err := key.ECPubKey()
				if err != nil || role.raw != "02"+hex.EncodeToString(schnorr.SerializePubKey(pub)) {
					t.Fatal("canonical Spending /12/0 key", err)
				}
			}
		})
	}
}
