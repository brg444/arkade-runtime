package application

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const (
	passkeyPurposeRecover        = "recover"
	passkeyPurposeInstall        = "install-envelope"
	passkeyChallengeTTL          = 2 * time.Minute
	maxPasskeyChallengesPerVault = 16
	recoveryBindingDomain        = "arkade-2fa-vault/recovery-binding/v1"
	passkeyProofDomain           = "arkade-2fa-vault/passkey-proof/v1"
)

type passkeyChallenge struct {
	VaultID   string
	Purpose   string
	Challenge []byte
	ExpiresAt time.Time
}

type PasskeyChallengeRequest struct {
	Purpose string `json:"purpose"`
	VaultID string `json:"vaultId,omitempty"`
}

type PasskeyChallengeResponse struct {
	ChallengeID       string `json:"challengeId"`
	Challenge         string `json:"challenge"`
	AllowCredentialID string `json:"allowCredentialId"`
	ExpiresInSeconds  int64  `json:"expiresInSeconds"`
}

// SessionAssertionRequest contains only the field-by-field WebAuthn assertion
// plus a PRF-derived DirectP256 proof. Browser extension results never cross
// the API. userHandle is deliberately omitted: this singleton RP binds the
// exact returned raw credential ID to its one stored ES256 public key.
type SessionAssertionRequest struct {
	ChallengeID       string `json:"challengeId"`
	CredentialID      string `json:"credentialId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	DirectProof       string `json:"directProof"`
}

type RecoveryBindingRequest struct {
	EnvelopeNonce      string `json:"envelopeNonce"`
	EnvelopeCiphertext string `json:"envelopeCiphertext"`
}

type RecoveryBindingResponse struct {
	Binding       string `json:"binding"`
	BindingDigest string `json:"bindingDigest"`
}

type InstallCredentialEnvelopeRequest struct {
	VaultID string `json:"vaultId"`
	SessionAssertionRequest
	RecoveryBindingRequest
	Binding          string `json:"binding"`
	BindingDirectSig string `json:"bindingDirectSig"`
	BindingPhoneSig  string `json:"bindingPhoneSig"`
}

type RecoverCredentialEnvelopeRequest struct {
	VaultID string `json:"vaultId"`
	SessionAssertionRequest
}

type RecoverCredentialEnvelopeResponse struct {
	Binding            string `json:"binding"`
	BindingDigest      string `json:"bindingDigest"`
	EnvelopeNonce      string `json:"envelopeNonce"`
	EnvelopeCiphertext string `json:"envelopeCiphertext"`
	BindingDirectSig   string `json:"bindingDirectSig"`
	BindingPhoneSig    string `json:"bindingPhoneSig"`
}

// recoveryBinding is the complete public v3 descriptor plus the encrypted
// PhoneRoutine envelope. The original device signs its exact JSON encoding;
// a fresh device verifies those signatures before treating status as trusted.
type recoveryBinding struct {
	Version                    uint32 `json:"version"`
	CredentialID               string `json:"credentialId"`
	WebAuthnP256               string `json:"webauthnP256"`
	PhoneDirectP256            string `json:"phoneDirectP256"`
	PhoneRoutineBIP340Pub      string `json:"phoneRoutineBip340Pub"`
	ExternalOwnerWalletPub     string `json:"externalOwnerWalletPub"`
	VaultCosignerBasePub       string `json:"vaultCosignerBasePub"`
	TweakedVaultCosignerXOnly  string `json:"tweakedVaultCosignerXOnly"`
	ArkadeCosignerBasePub      string `json:"arkadeCosignerBasePub"`
	TweakedArkadeCosignerXOnly string `json:"tweakedArkadeCosignerXOnly"`
	ArkadeCosignerOrigin       string `json:"arkadeCosignerOrigin"`
	ArkadeCosignerVersion      string `json:"arkadeCosignerVersion"`
	ClientOrigin               string `json:"clientOrigin"`
	RPID                       string `json:"rpId"`
	Network                    string `json:"network"`
	VaultID                    string `json:"vaultId"`
	TemplateVersion            string `json:"templateVersion"`
	PolicyVersion              string `json:"policyVersion"`
	OperationalCSVType         int64  `json:"operationalCsvType"`
	OperationalCSVValue        uint32 `json:"operationalCsvValue"`
	SavingsCSVType             int64  `json:"savingsCsvType"`
	SavingsCSVValue            uint32 `json:"savingsCsvValue"`
	OperationalAddress         string `json:"operationalAddress"`
	OperationalScript          string `json:"operationalScript"`
	SavingsAddress             string `json:"savingsAddress"`
	SavingsScript              string `json:"savingsScript"`
	RecipientDustSats          int64  `json:"recipientDustSats"`
	TxRecipientCapSats         int64  `json:"txRecipientCapSats"`
	PeriodAllowanceSats        int64  `json:"periodAllowanceSats"`
	AbsoluteFeeCapSats         int64  `json:"absoluteFeeCapSats"`
	FeerateCapSatPerV          int64  `json:"feerateCapSatVb"`
	EnvelopeNonce              string `json:"envelopeNonce"`
	EnvelopeCiphertext         string `json:"envelopeCiphertext"`
}

func (s *Service) sessionNow() time.Time {
	if s.SessionNow != nil {
		return s.SessionNow()
	}
	return time.Now()
}

func passkeyChallengeKey(vaultID, challengeID string) string {
	return vaultID + "\x00" + challengeID
}

func (s *Service) routePasskeyVaultID(vaultID string) (string, error) {
	return s.routeVaultID(vaultID)
}

func (s *Service) IssuePasskeyChallenge(ctx context.Context, purpose string) (*PasskeyChallengeResponse, error) {
	return s.IssuePasskeyChallengeFor(ctx, program.LeftoverVaultID, purpose)
}

func (s *Service) IssuePasskeyChallengeFor(ctx context.Context, vaultID, purpose string) (*PasskeyChallengeResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if purpose != passkeyPurposeRecover && purpose != passkeyPurposeInstall {
		return nil, fmt.Errorf("invalid passkey challenge purpose")
	}
	vaultID, err := s.routePasskeyVaultID(vaultID)
	if err != nil {
		return nil, err
	}
	cred, err := s.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("not enrolled")
	}
	if purpose == passkeyPurposeRecover {
		envelope, err := s.loadVerifiedEnvelopeFor(vaultID, cred.ID)
		if err != nil {
			return nil, err
		}
		if envelope == nil {
			return nil, fmt.Errorf("passkey sign-in has not been enabled on the original device")
		}
	}
	idRaw := make([]byte, 16)
	challenge := make([]byte, 32)
	if _, err := rand.Read(idRaw); err != nil {
		return nil, fmt.Errorf("passkey challenge id: %w", err)
	}
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("passkey challenge: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(idRaw)
	now := s.sessionNow()
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if s.sessionChallenges == nil {
		s.sessionChallenges = make(map[string]passkeyChallenge)
	}
	pendingForVault := 0
	for key, pending := range s.sessionChallenges {
		if !now.Before(pending.ExpiresAt) {
			delete(s.sessionChallenges, key)
			continue
		}
		if pending.VaultID == vaultID {
			pendingForVault++
		}
	}
	if pendingForVault >= maxPasskeyChallengesPerVault {
		return nil, ErrVerificationBusy
	}
	s.sessionChallenges[passkeyChallengeKey(vaultID, id)] = passkeyChallenge{
		VaultID: vaultID, Purpose: purpose, Challenge: append([]byte(nil), challenge...), ExpiresAt: now.Add(passkeyChallengeTTL),
	}
	return &PasskeyChallengeResponse{
		ChallengeID: id, Challenge: hex.EncodeToString(challenge),
		AllowCredentialID: hex.EncodeToString(cred.ID),
		ExpiresInSeconds:  int64(passkeyChallengeTTL / time.Second),
	}, nil
}

func (s *Service) consumePasskeyChallenge(vaultID, id, purpose string) ([]byte, error) {
	if len(id) != 22 {
		return nil, fmt.Errorf("passkey authentication failed")
	}
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(raw) != 16 || base64.RawURLEncoding.EncodeToString(raw) != id {
		return nil, fmt.Errorf("passkey authentication failed")
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	key := passkeyChallengeKey(vaultID, id)
	pending, ok := s.sessionChallenges[key]
	delete(s.sessionChallenges, key)
	if !ok || pending.VaultID != vaultID || pending.Purpose != purpose || !s.sessionNow().Before(pending.ExpiresAt) {
		return nil, fmt.Errorf("passkey authentication failed")
	}
	return append([]byte(nil), pending.Challenge...), nil
}

func (s *Service) authenticatePasskeySession(ctx context.Context, purpose, vaultID string, req SessionAssertionRequest) (*policy.Credential, error) {
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	vaultID, err = s.routePasskeyVaultID(vaultID)
	if err != nil {
		return nil, err
	}
	challenge, err := s.consumePasskeyChallenge(vaultID, req.ChallengeID, purpose)
	if err != nil {
		return nil, failPasskeyAuth("challenge", err)
	}
	cred, err := s.loadVerifiedCredentialFor(vaultID)
	if err != nil || cred == nil {
		if err == nil {
			err = fmt.Errorf("not enrolled")
		}
		return nil, failPasskeyAuth("credential", err)
	}
	assertion, err := decodeBoundedSessionAssertion(req)
	if err != nil {
		return nil, failPasskeyAuth("assertion", err)
	}
	if !bytes.Equal(assertion.CredentialID, cred.ID) {
		return nil, fmt.Errorf("this passkey does not belong to this vault")
	}
	if err := rejectPRF(assertion.ClientDataJSON); err != nil {
		return nil, failPasskeyAuth("prf", err)
	}
	if _, err := webauthn.Validate(assertion, webauthn.Expected{
		CredentialID: cred.ID, WebAuthnP256: cred.WebAuthnP256, Challenge: challenge,
		Origin: cred.Origin, RPID: cred.RPID,
	}); err != nil {
		return nil, failPasskeyAuth("webauthn", err)
	}
	directProof, err := decodeFixedHex(req.DirectProof, 64, "direct proof")
	if err != nil {
		return nil, failPasskeyAuth("proof", err)
	}
	proofDigest := passkeySessionProofDigest(purpose, challenge, cred.ID)
	if err := verifyDirectAuth(cred.PhoneDirectP256, proofDigest, directProof); err != nil {
		return nil, failPasskeyAuth("proof", err)
	}
	return cred, nil
}

func failPasskeyAuth(stage string, err error) error {
	if err != nil {
		log.Printf("passkey authentication failed (%s): %v", stage, err)
	} else {
		log.Printf("passkey authentication failed (%s)", stage)
	}
	return fmt.Errorf("passkey authentication failed")
}

func decodeBoundedSessionAssertion(req SessionAssertionRequest) (webauthn.Assertion, error) {
	assertion, err := decodeAssertion(AuthorizeRequest{
		CredentialID: req.CredentialID, ClientDataJSON: req.ClientDataJSON,
		AuthenticatorData: req.AuthenticatorData, Signature: req.Signature,
	})
	if err != nil {
		return webauthn.Assertion{}, err
	}
	if len(assertion.CredentialID) == 0 || len(assertion.CredentialID) > 1024 ||
		len(assertion.ClientDataJSON) == 0 || len(assertion.ClientDataJSON) > 4096 ||
		len(assertion.AuthenticatorData) < 37 || len(assertion.AuthenticatorData) > 1024 ||
		len(assertion.DERSignature) == 0 || len(assertion.DERSignature) > 128 {
		return webauthn.Assertion{}, fmt.Errorf("assertion field size")
	}
	return assertion, nil
}

func passkeySessionProofDigest(purpose string, challenge, credentialID []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(passkeyProofDomain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(purpose))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(challenge)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(credentialID)
	return h.Sum(nil)
}

func (s *Service) BuildRecoveryBinding(req RecoveryBindingRequest) (*RecoveryBindingResponse, error) {
	return s.BuildRecoveryBindingFor("", req)
}

func (s *Service) BuildRecoveryBindingFor(vaultID string, req RecoveryBindingRequest) (*RecoveryBindingResponse, error) {
	vaultID, err := s.routePasskeyVaultID(vaultID)
	if err != nil {
		return nil, err
	}
	cred, err := s.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("not enrolled")
	}
	nonce, err := decodeFixedHex(req.EnvelopeNonce, 12, "credential envelope nonce")
	if err != nil {
		return nil, err
	}
	ciphertext, err := decodeFixedHex(req.EnvelopeCiphertext, 48, "credential envelope ciphertext")
	if err != nil {
		return nil, err
	}
	binding, err := canonicalRecoveryBinding(cred, nonce, ciphertext)
	if err != nil {
		return nil, err
	}
	digest := recoveryBindingDigest(binding)
	return &RecoveryBindingResponse{Binding: binding, BindingDigest: hex.EncodeToString(digest)}, nil
}

func canonicalRecoveryBinding(cred *policy.Credential, nonce, ciphertext []byte) (string, error) {
	if cred == nil {
		return "", fmt.Errorf("credential required")
	}
	binding := recoveryBinding{
		Version:      1,
		CredentialID: hex.EncodeToString(cred.ID), WebAuthnP256: hex.EncodeToString(cred.WebAuthnP256),
		PhoneDirectP256: hex.EncodeToString(cred.PhoneDirectP256), PhoneRoutineBIP340Pub: hex.EncodeToString(cred.PhoneRoutineBIP340),
		ExternalOwnerWalletPub:     hex.EncodeToString(cred.ExternalOwnerWallet),
		VaultCosignerBasePub:       hex.EncodeToString(cred.VaultCosignerBase),
		TweakedVaultCosignerXOnly:  hex.EncodeToString(cred.TweakedVaultCosigner[1:]),
		ArkadeCosignerBasePub:      hex.EncodeToString(cred.ArkadeCosignerBase),
		TweakedArkadeCosignerXOnly: hex.EncodeToString(cred.TweakedArkadeCosigner[1:]),
		ArkadeCosignerOrigin:       cred.ArkadeCosignerOrigin, ArkadeCosignerVersion: cred.ArkadeCosignerVersion,
		ClientOrigin: cred.Origin, RPID: cred.RPID, Network: cred.Network, VaultID: cred.VaultID,
		TemplateVersion: cred.TemplateVersion, PolicyVersion: cred.PolicyVersion,
		OperationalCSVType: cred.OperationalCSVType, OperationalCSVValue: cred.OperationalCSVValue,
		SavingsCSVType: cred.SavingsCSVType, SavingsCSVValue: cred.SavingsCSVValue,
		OperationalAddress: cred.OperationalAddress, OperationalScript: hex.EncodeToString(cred.OperationalScript),
		SavingsAddress: cred.SavingsAddress, SavingsScript: hex.EncodeToString(cred.SavingsScript),
		RecipientDustSats: cred.RecipientDustSats, TxRecipientCapSats: cred.TxRecipientCapSats,
		PeriodAllowanceSats: cred.PeriodAllowanceSats, AbsoluteFeeCapSats: cred.AbsoluteFeeCapSats,
		FeerateCapSatPerV: cred.FeerateCapSatPerV,
		EnvelopeNonce:     hex.EncodeToString(nonce), EnvelopeCiphertext: hex.EncodeToString(ciphertext),
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func recoveryBindingDigest(binding string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(recoveryBindingDomain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(binding))
	return h.Sum(nil)
}

func (s *Service) InstallCredentialEnvelope(ctx context.Context, req InstallCredentialEnvelopeRequest) error {
	vaultID, err := s.routePasskeyVaultID(req.VaultID)
	if err != nil {
		return err
	}
	cred, err := s.authenticatePasskeySession(ctx, passkeyPurposeInstall, vaultID, req.SessionAssertionRequest)
	if err != nil {
		return err
	}
	nonce, err := decodeFixedHex(req.EnvelopeNonce, 12, "credential envelope nonce")
	if err != nil {
		return err
	}
	ciphertext, err := decodeFixedHex(req.EnvelopeCiphertext, 48, "credential envelope ciphertext")
	if err != nil {
		return err
	}
	expectedBinding, err := canonicalRecoveryBinding(cred, nonce, ciphertext)
	if err != nil {
		return err
	}
	if req.Binding != expectedBinding {
		return fmt.Errorf("credential envelope binding mismatch")
	}
	digest := recoveryBindingDigest(expectedBinding)
	directSig, err := decodeFixedHex(req.BindingDirectSig, 64, "binding DirectP256 signature")
	if err != nil {
		return err
	}
	if err := verifyDirectAuth(cred.PhoneDirectP256, digest, directSig); err != nil {
		return fmt.Errorf("credential envelope binding: %w", err)
	}
	phoneSigRaw, err := decodeFixedHex(req.BindingPhoneSig, 64, "binding PhoneRoutine signature")
	if err != nil {
		return err
	}
	phonePub, err := btcec.ParsePubKey(cred.PhoneRoutineBIP340)
	if err != nil {
		return fmt.Errorf("stored PhoneRoutineBIP340: %w", err)
	}
	phoneSig, err := schnorr.ParseSignature(phoneSigRaw)
	if err != nil || !phoneSig.Verify(digest, phonePub) {
		return fmt.Errorf("credential envelope binding PhoneRoutine signature invalid")
	}
	envelope := policy.CredentialEnvelope{
		Version: policy.CredentialEnvelopeVersion, Binding: expectedBinding,
		Nonce: nonce, Ciphertext: ciphertext, DirectSig: directSig, PhoneSig: phoneSigRaw,
	}
	vaultID, err = s.routePasskeyVaultID(firstNonEmpty(vaultID, cred.VaultID))
	if err != nil {
		return err
	}
	if vaultID != program.LeftoverVaultID {
		if err := s.sealVaultEnvelope(&envelope, vaultID, cred.ID); err != nil {
			return err
		}
		return s.Ledger.StoreVaultEnvelopeIfAbsent(vaultID, envelope)
	}
	if err := s.sealCredentialEnvelope(&envelope, cred.ID); err != nil {
		return err
	}
	return s.Ledger.StoreCredentialEnvelopeIfAbsent(envelope)
}

func (s *Service) RecoverCredentialEnvelope(ctx context.Context, req RecoverCredentialEnvelopeRequest) (*RecoverCredentialEnvelopeResponse, error) {
	vaultID, err := s.routePasskeyVaultID(req.VaultID)
	if err != nil {
		return nil, err
	}
	cred, err := s.authenticatePasskeySession(ctx, passkeyPurposeRecover, vaultID, req.SessionAssertionRequest)
	if err != nil {
		return nil, err
	}
	vaultID, err = s.routePasskeyVaultID(firstNonEmpty(vaultID, cred.VaultID))
	if err != nil {
		return nil, err
	}
	envelope, err := s.loadVerifiedEnvelopeFor(vaultID, cred.ID)
	if err != nil {
		return nil, err
	}
	if envelope == nil {
		return nil, fmt.Errorf("passkey sign-in has not been enabled on the original device")
	}
	return &RecoverCredentialEnvelopeResponse{
		Binding: envelope.Binding, BindingDigest: hex.EncodeToString(recoveryBindingDigest(envelope.Binding)),
		EnvelopeNonce: hex.EncodeToString(envelope.Nonce), EnvelopeCiphertext: hex.EncodeToString(envelope.Ciphertext),
		BindingDirectSig: hex.EncodeToString(envelope.DirectSig), BindingPhoneSig: hex.EncodeToString(envelope.PhoneSig),
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (s *Service) sealVaultEnvelope(envelope *policy.CredentialEnvelope, vaultID string, credentialID []byte) error {
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return err
	}
	defer zeroServiceBytes(key)
	if err := policy.SealVaultEnvelope(envelope, vaultID, credentialID, key); err != nil {
		return fmt.Errorf("seal credential envelope: %w", err)
	}
	return nil
}

func decodeFixedHex(encoded string, size int, name string) ([]byte, error) {
	if len(encoded) != size*2 || encoded != string(bytes.ToLower([]byte(encoded))) {
		return nil, fmt.Errorf("%s must be canonical %d-byte lowercase hex", name, size)
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != size {
		return nil, fmt.Errorf("%s must be canonical %d-byte lowercase hex", name, size)
	}
	return raw, nil
}
