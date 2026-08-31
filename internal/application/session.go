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
	passkeyPurposeTransition     = "transition"
	passkeyPurposeMapWrite       = "map-write"
	passkeyChallengeTTL          = 2 * time.Minute
	maxPasskeyChallengesPerVault = 16
	recoveryBindingDomain        = "arkade-vault/recovery-binding/v3"
	recoveryBindingDomainV2      = "arkade-vault/recovery-binding/v2"
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

// WebAuthnAssertionRequest is the field-by-field assertion shared by the
// passkey-authenticated workflows. Browser extension results and userHandle
// never cross the API.
type WebAuthnAssertionRequest struct {
	CredentialID      string `json:"credentialId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
}

// SessionAssertionRequest adds the issued challenge and the DirectP256 proof
// required by passkey-authenticated session workflows.
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

// recoveryBinding is the complete current descriptor plus the encrypted
// phone-key envelope. The original device signs its exact JSON encoding;
// a fresh device verifies those signatures before treating status as trusted.
type recoveryBinding struct {
	Version                   uint32 `json:"version"`
	CredentialID              string `json:"credentialId"`
	WebAuthnP256              string `json:"webauthnP256"`
	PhoneDirectP256           string `json:"phoneDirectP256"`
	PhoneBIP340Pub            string `json:"phoneBip340Pub"`
	ExternalOwnerWalletPub    string `json:"externalOwnerWalletPub"`
	VaultCosignerBasePub      string `json:"vaultCosignerBasePub"`
	ArkadeCosignerBasePub     string `json:"arkadeCosignerBasePub"`
	ArkadeCosignerOrigin      string `json:"arkadeCosignerOrigin"`
	ArkadeCosignerVersion     string `json:"arkadeCosignerVersion"`
	ClientOrigin              string `json:"clientOrigin"`
	RPID                      string `json:"rpId"`
	Network                   string `json:"network"`
	VaultID                   string `json:"vaultId"`
	TemplateVersion           string `json:"templateVersion"`
	PolicyVersion             string `json:"policyVersion"`
	SavingsAddress            string `json:"savingsAddress"`
	SavingsScript             string `json:"savingsScript"`
	VtxoVaultCosignerPub      string `json:"vtxoVaultCosignerPub"`
	VtxoExitDelay             uint32 `json:"vtxoExitDelay"`
	VtxoExitDelayUnit         string `json:"vtxoExitDelayUnit"`
	SpendingArkAddress        string `json:"spendingArkAddress"`
	SpendingArkScript         string `json:"spendingArkScript"`
	VtxoDelegatePub           string `json:"vtxoDelegatePub"`
	VtxoBoardingActive        bool   `json:"vtxoBoardingActive"`
	VtxoBoardingProgram       string `json:"vtxoBoardingProgram"`
	VtxoBoardingAddress       string `json:"vtxoBoardingAddress"`
	VtxoBoardingScript        string `json:"vtxoBoardingScript"`
	VtxoBoardingExitDelay     uint32 `json:"vtxoBoardingExitDelay"`
	VtxoBoardingExitDelayUnit string `json:"vtxoBoardingExitDelayUnit"`
	RecipientDustSats         int64  `json:"recipientDustSats"`
	TxRecipientCapSats        int64  `json:"txRecipientCapSats"`
	PeriodAllowanceSats       int64  `json:"periodAllowanceSats"`
	AbsoluteFeeCapSats        int64  `json:"absoluteFeeCapSats"`
	FeerateCapSatPerV         int64  `json:"feerateCapSatVb"`
	EnvelopeNonce             string `json:"envelopeNonce"`
	EnvelopeCiphertext        string `json:"envelopeCiphertext"`
}

// recoveryBindingV2 is retained only to authenticate and replace an envelope
// written by the immediately preceding Mutinynet release. New installs and
// recoveries continue to use the complete v3 Vault Program binding.
type recoveryBindingV2 struct {
	Version                uint32 `json:"version"`
	CredentialID           string `json:"credentialId"`
	WebAuthnP256           string `json:"webauthnP256"`
	PhoneDirectP256        string `json:"phoneDirectP256"`
	PhoneBIP340Pub         string `json:"phoneBip340Pub"`
	ExternalOwnerWalletPub string `json:"externalOwnerWalletPub"`
	VaultCosignerBasePub   string `json:"vaultCosignerBasePub"`
	ArkadeCosignerBasePub  string `json:"arkadeCosignerBasePub"`
	ArkadeCosignerOrigin   string `json:"arkadeCosignerOrigin"`
	ArkadeCosignerVersion  string `json:"arkadeCosignerVersion"`
	ClientOrigin           string `json:"clientOrigin"`
	RPID                   string `json:"rpId"`
	Network                string `json:"network"`
	VaultID                string `json:"vaultId"`
	TemplateVersion        string `json:"templateVersion"`
	PolicyVersion          string `json:"policyVersion"`
	SavingsAddress         string `json:"savingsAddress"`
	SavingsScript          string `json:"savingsScript"`
	RecipientDustSats      int64  `json:"recipientDustSats"`
	TxRecipientCapSats     int64  `json:"txRecipientCapSats"`
	PeriodAllowanceSats    int64  `json:"periodAllowanceSats"`
	AbsoluteFeeCapSats     int64  `json:"absoluteFeeCapSats"`
	FeerateCapSatPerV      int64  `json:"feerateCapSatVb"`
	EnvelopeNonce          string `json:"envelopeNonce"`
	EnvelopeCiphertext     string `json:"envelopeCiphertext"`
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

func (s *Service) IssuePasskeyChallengeFor(ctx context.Context, vaultID, purpose string) (*PasskeyChallengeResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if purpose != passkeyPurposeRecover && purpose != passkeyPurposeInstall &&
		purpose != passkeyPurposeTransition && purpose != passkeyPurposeMapWrite {
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
	if !ok {
		return nil, fmt.Errorf("passkey authentication failed")
	}
	if !s.sessionNow().Before(pending.ExpiresAt) {
		delete(s.sessionChallenges, key)
		return nil, fmt.Errorf("passkey authentication failed")
	}
	if pending.VaultID != vaultID || pending.Purpose != purpose {
		return nil, fmt.Errorf("passkey authentication failed")
	}
	delete(s.sessionChallenges, key)
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
	verified, err := webauthn.Validate(assertion, webauthn.Expected{
		CredentialID: cred.ID, WebAuthnP256: cred.WebAuthnP256, Challenge: challenge,
		Origin: cred.Origin, RPID: cred.RPID,
	})
	if err != nil {
		return nil, failPasskeyAuth("webauthn", err)
	}
	if err := s.advanceSignCount(vaultID, cred.ID, verified.SignCount); err != nil {
		return nil, failPasskeyAuth("sign-count", err)
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
	assertion, err := decodeAssertion(WebAuthnAssertionRequest{
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
	binding, err := s.canonicalRecoveryBinding(cred, nonce, ciphertext)
	if err != nil {
		return nil, err
	}
	digest := recoveryBindingDigest(binding)
	return &RecoveryBindingResponse{Binding: binding, BindingDigest: hex.EncodeToString(digest)}, nil
}

func (s *Service) canonicalRecoveryBinding(cred *policy.Credential, nonce, ciphertext []byte) (string, error) {
	if cred == nil {
		return "", fmt.Errorf("credential required")
	}
	cfg := s.runtimeConfig()
	if err := cfg.Validate(); err != nil {
		return "", fmt.Errorf("recovery binding deployment: %w", err)
	}
	phone, externalOwner, recovery, _, _, _, err := s.rebuildFromCredential(cred)
	if err != nil {
		return "", fmt.Errorf("recovery binding credential: %w", err)
	}
	if isNilInterface(s.ArkResolver) {
		return "", fmt.Errorf("recovery binding Arkade resolver required")
	}
	if s.ArkResolver.Network() != cfg.Network {
		return "", fmt.Errorf("recovery binding Arkade resolver network mismatch")
	}
	if err := validateArkResolverPolicy(cfg.Network, s.ArkResolver.CheckpointTapscript(), s.ArkResolver.OperatorSignerPub()); err != nil {
		return "", fmt.Errorf("recovery binding Arkade resolver policy: %w", err)
	}
	if err := program.ValidateVaultPolicyV1ExitDelay(program.VaultPolicyV1ExitDelay, program.VaultPolicyV1ExitDelayUnit); err != nil {
		return "", fmt.Errorf("recovery binding Spending exit: %w", err)
	}
	if err := program.ValidateVaultBoardV1ExitDelay(program.VaultBoardV1ExitDelay, program.VaultBoardV1ExitDelayUnit); err != nil {
		return "", fmt.Errorf("recovery binding boarding exit: %w", err)
	}
	snap := enrolledSnapshot{
		VaultID: cred.VaultID, PhoneBIP340: phone,
		ExternalOwnerWallet: externalOwner, RecoveryKey: recovery,
	}
	spending, err := s.buildVtxoPolicyTree(cred.VaultID, snap)
	if err != nil {
		return "", fmt.Errorf("recovery binding Spending descriptor: %w", err)
	}
	if spending == nil || spending.CosignerPub == nil || spending.DelegatePub == nil ||
		spending.ArkAddress == "" || len(spending.PkScript) == 0 {
		return "", fmt.Errorf("recovery binding Spending descriptor incomplete")
	}
	boarding, err := s.buildVtxoBoardTree(snap)
	if err != nil {
		return "", fmt.Errorf("recovery binding boarding descriptor: %w", err)
	}
	if boarding == nil || boarding.OnchainAddress == "" || len(boarding.PkScript) == 0 || program.VaultBoardV1 == "" {
		return "", fmt.Errorf("recovery binding boarding descriptor incomplete")
	}
	binding := recoveryBinding{
		Version:      3,
		CredentialID: hex.EncodeToString(cred.ID), WebAuthnP256: hex.EncodeToString(cred.WebAuthnP256),
		PhoneDirectP256: hex.EncodeToString(cred.PhoneDirectP256), PhoneBIP340Pub: hex.EncodeToString(cred.PhoneBIP340),
		ExternalOwnerWalletPub: hex.EncodeToString(cred.ExternalOwnerWallet),
		VaultCosignerBasePub:   hex.EncodeToString(cred.VaultCosignerBase),
		ArkadeCosignerBasePub:  hex.EncodeToString(cred.ArkadeCosignerBase),
		ArkadeCosignerOrigin:   cred.ArkadeCosignerOrigin, ArkadeCosignerVersion: cred.ArkadeCosignerVersion,
		ClientOrigin: cred.Origin, RPID: cred.RPID, Network: cred.Network, VaultID: cred.VaultID,
		TemplateVersion: cred.TemplateVersion, PolicyVersion: cred.PolicyVersion,
		SavingsAddress: cred.SavingsAddress, SavingsScript: hex.EncodeToString(cred.SavingsScript),
		VtxoVaultCosignerPub:      hex.EncodeToString(spending.CosignerPub.SerializeCompressed()),
		VtxoExitDelay:             program.VaultPolicyV1ExitDelay,
		VtxoExitDelayUnit:         program.VaultPolicyV1ExitDelayUnit,
		SpendingArkAddress:        spending.ArkAddress,
		SpendingArkScript:         hex.EncodeToString(spending.PkScript),
		VtxoDelegatePub:           hex.EncodeToString(spending.DelegatePub.SerializeCompressed()),
		VtxoBoardingActive:        true,
		VtxoBoardingProgram:       program.VaultBoardV1,
		VtxoBoardingAddress:       boarding.OnchainAddress,
		VtxoBoardingScript:        hex.EncodeToString(boarding.PkScript),
		VtxoBoardingExitDelay:     program.VaultBoardV1ExitDelay,
		VtxoBoardingExitDelayUnit: program.VaultBoardV1ExitDelayUnit,
		RecipientDustSats:         cred.RecipientDustSats,
		TxRecipientCapSats:        cred.TxRecipientCapSats,
		PeriodAllowanceSats:       cred.PeriodAllowanceSats,
		AbsoluteFeeCapSats:        cred.AbsoluteFeeCapSats,
		FeerateCapSatPerV:         cred.FeerateCapSatPerV,
		EnvelopeNonce:             hex.EncodeToString(nonce), EnvelopeCiphertext: hex.EncodeToString(ciphertext),
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func recoveryBindingDigest(binding string) []byte {
	return recoveryBindingDigestForDomain(recoveryBindingDomain, binding)
}

func recoveryBindingDigestForDomain(domain, binding string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(binding))
	return h.Sum(nil)
}

func canonicalRecoveryBindingV2(cred *policy.Credential, nonce, ciphertext []byte) (string, error) {
	if cred == nil {
		return "", fmt.Errorf("credential required")
	}
	binding := recoveryBindingV2{
		Version:      2,
		CredentialID: hex.EncodeToString(cred.ID), WebAuthnP256: hex.EncodeToString(cred.WebAuthnP256),
		PhoneDirectP256: hex.EncodeToString(cred.PhoneDirectP256), PhoneBIP340Pub: hex.EncodeToString(cred.PhoneBIP340),
		ExternalOwnerWalletPub: hex.EncodeToString(cred.ExternalOwnerWallet),
		VaultCosignerBasePub:   hex.EncodeToString(cred.VaultCosignerBase),
		ArkadeCosignerBasePub:  hex.EncodeToString(cred.ArkadeCosignerBase),
		ArkadeCosignerOrigin:   cred.ArkadeCosignerOrigin, ArkadeCosignerVersion: cred.ArkadeCosignerVersion,
		ClientOrigin: cred.Origin, RPID: cred.RPID, Network: cred.Network, VaultID: cred.VaultID,
		TemplateVersion: cred.TemplateVersion, PolicyVersion: cred.PolicyVersion,
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

func verifyRecoveryBindingV2Upgrade(cred *policy.Credential, envelope *policy.CredentialEnvelope) error {
	if cred == nil || envelope == nil {
		return fmt.Errorf("previous credential envelope required")
	}
	expected, err := canonicalRecoveryBindingV2(cred, envelope.Nonce, envelope.Ciphertext)
	if err != nil {
		return err
	}
	if envelope.Binding != expected {
		return fmt.Errorf("credential envelope locked")
	}
	digest := recoveryBindingDigestForDomain(recoveryBindingDomainV2, expected)
	if err := verifyDirectAuth(cred.PhoneDirectP256, digest, envelope.DirectSig); err != nil {
		return fmt.Errorf("previous credential envelope binding: %w", err)
	}
	phonePub, err := btcec.ParsePubKey(cred.PhoneBIP340)
	if err != nil {
		return fmt.Errorf("stored PhoneBIP340: %w", err)
	}
	phoneSig, err := schnorr.ParseSignature(envelope.PhoneSig)
	if err != nil || !phoneSig.Verify(digest, phonePub) {
		return fmt.Errorf("previous credential envelope binding Phone signature invalid")
	}
	return nil
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
	expectedBinding, err := s.canonicalRecoveryBinding(cred, nonce, ciphertext)
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
	phoneSigRaw, err := decodeFixedHex(req.BindingPhoneSig, 64, "binding Phone signature")
	if err != nil {
		return err
	}
	phonePub, err := btcec.ParsePubKey(cred.PhoneBIP340)
	if err != nil {
		return fmt.Errorf("stored PhoneBIP340: %w", err)
	}
	phoneSig, err := schnorr.ParseSignature(phoneSigRaw)
	if err != nil || !phoneSig.Verify(digest, phonePub) {
		return fmt.Errorf("credential envelope binding Phone signature invalid")
	}
	envelope := policy.CredentialEnvelope{
		Version: policy.CredentialEnvelopeVersion, Binding: expectedBinding,
		Nonce: nonce, Ciphertext: ciphertext, DirectSig: directSig, PhoneSig: phoneSigRaw,
	}
	vaultID, err = s.routePasskeyVaultID(firstNonEmpty(vaultID, cred.VaultID))
	if err != nil {
		return err
	}
	if err := s.sealVaultEnvelope(&envelope, vaultID, cred.ID); err != nil {
		return err
	}
	existing, err := s.loadVerifiedEnvelopeFor(vaultID, cred.ID)
	if err != nil {
		return err
	}
	if existing == nil {
		return s.Stores.Identity.StoreVaultEnvelopeIfAbsent(vaultID, envelope)
	}
	if credentialEnvelopesEqual(*existing, envelope) {
		return nil
	}
	if !bytes.Equal(existing.Nonce, envelope.Nonce) || !bytes.Equal(existing.Ciphertext, envelope.Ciphertext) {
		return fmt.Errorf("credential envelope locked")
	}
	if err := verifyRecoveryBindingV2Upgrade(cred, existing); err != nil {
		return err
	}
	return s.Stores.Identity.ReplaceVaultEnvelope(vaultID, *existing, envelope)
}

func credentialEnvelopesEqual(a, b policy.CredentialEnvelope) bool {
	return a.Version == b.Version && a.Binding == b.Binding &&
		bytes.Equal(a.Nonce, b.Nonce) && bytes.Equal(a.Ciphertext, b.Ciphertext) &&
		bytes.Equal(a.DirectSig, b.DirectSig) && bytes.Equal(a.PhoneSig, b.PhoneSig) &&
		bytes.Equal(a.IntegrityMAC, b.IntegrityMAC)
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
