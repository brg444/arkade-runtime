package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/brg444/arkade-runtime/internal/webauthn"
)

// LNURLBinding contains enrolled public facts only. The receiving service holds
// invoice preimages but never receives a phone, recovery, or Guardian signing key.
type LNURLBinding struct {
	VaultID              string `json:"vaultId"`
	Network              string `json:"network"`
	TemplateVersion      string `json:"templateVersion"`
	ProtectionTier       string `json:"protectionTier"`
	PolicyVersion        string `json:"policyVersion"`
	DescriptorHash       string `json:"descriptorHash"`
	SpendingPolicyDigest string `json:"spendingPolicyDigest"`
	SpendingAddress      string `json:"spendingAddress"`
	SpendingScript       string `json:"spendingScript"`
	ClaimPublicKey       string `json:"claimPublicKey"`
}

// LNURLRegistrar is a configured bridge to the separate receiving process. It
// cannot select a transaction, spending destination, or signing operation.
type LNURLRegistrar func(context.Context, string, LNURLBinding, string) (json.RawMessage, error)

var lnurlNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,31}$`)
var lnurlGeneratedNamePattern = regexp.MustCompile(`^v[0-9a-f]{16}$`)

func lnurlPurpose(action, name string) (string, error) {
	if action != "register" && action != "revoke" {
		return "", fmt.Errorf("invalid Lightning address action")
	}
	if name != "" {
		if action != "register" || !lnurlNamePattern.MatchString(name) || lnurlGeneratedNamePattern.MatchString(name) || strings.Contains("|admin|support|security|abuse|postmaster|vaulted|root|system|api|www|lnurl|", "|"+name+"|") {
			return "", fmt.Errorf("invalid Lightning address name")
		}
		return "lnurl-" + action + ":" + name, nil
	}
	return "lnurl-" + action, nil
}

func (s *Service) IssueLNURLChallenge(action, name string) (*PasskeyChallengeResponse, error) {
	if s.LNURLRegistrar == nil {
		return nil, fmt.Errorf("Lightning addresses are unavailable")
	}
	purpose, err := lnurlPurpose(action, name)
	if err != nil {
		return nil, err
	}
	return s.issuePasskeyChallenge("", purpose, "", nil)
}

func (s *Service) ConfigureLNURL(ctx context.Context, action, name string, req LightBackupOpenRequest) (json.RawMessage, error) {
	if s.LNURLRegistrar == nil {
		return nil, fmt.Errorf("Lightning addresses are unavailable")
	}
	purpose, err := lnurlPurpose(action, name)
	if err != nil {
		return nil, err
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	record, err := s.readPasskeyChallenge("", req.ChallengeID, purpose)
	if err != nil {
		return nil, failPasskeyAuth("Lightning address challenge", nil)
	}
	cred, err := s.loadVerifiedCredentialFor(req.VaultID)
	if err != nil || cred == nil || (cred.TemplateVersion != light.Profile && !recoveryArchiveCredentialAllowed(cred)) {
		return nil, failPasskeyAuth("Lightning address credential", nil)
	}
	assertion, err := decodeBoundedSessionAssertion(req.SessionAssertionRequest)
	if err != nil || !bytes.Equal(assertion.CredentialID, cred.ID) || rejectPRF(assertion.ClientDataJSON) != nil {
		return nil, failPasskeyAuth("Lightning address assertion", nil)
	}
	verified, err := webauthn.Validate(assertion, webauthn.Expected{CredentialID: cred.ID, WebAuthnP256: cred.WebAuthnP256, Challenge: record.Challenge, Origin: cred.Origin, RPID: cred.RPID})
	if err != nil {
		return nil, failPasskeyAuth("Lightning address assertion", nil)
	}
	proof, err := decodeFixedHex(req.DirectProof, 64, "Lightning address proof")
	if err != nil || verifyDirectAuth(cred.PhoneDirectP256, passkeySessionProofDigest("lnurl-"+action, record.Challenge, cred.ID), proof) != nil {
		return nil, failPasskeyAuth("Lightning address proof", nil)
	}
	if _, err = s.consumePasskeyChallenge(req.VaultID, req.ChallengeID, purpose); err != nil {
		return nil, failPasskeyAuth("Lightning address challenge", err)
	}
	if err = s.advanceSignCount(req.VaultID, cred.ID, verified.SignCount); err != nil {
		return nil, err
	}
	status, err := s.StatusFor(ctx, req.VaultID)
	if err != nil {
		return nil, err
	}
	descriptorHash := status.LightDescriptorHash
	if cred.TemplateVersion != light.Profile {
		archive, err := s.recoveryArchiveBinding(cred)
		if err != nil {
			return nil, err
		}
		descriptorHash = archive.DescriptorHash
	}
	if descriptorHash == "" || status.SpendingArkAddress == "" || status.SpendingArkScript == "" || status.SpendingPolicyDigest == "" {
		return nil, fmt.Errorf("incomplete enrolled receiving destination")
	}
	binding := LNURLBinding{VaultID: req.VaultID, Network: cred.Network, TemplateVersion: cred.TemplateVersion,
		ProtectionTier: cred.ProtectionTier, PolicyVersion: cred.PolicyVersion, DescriptorHash: descriptorHash,
		SpendingPolicyDigest: status.SpendingPolicyDigest, SpendingAddress: status.SpendingArkAddress,
		SpendingScript: status.SpendingArkScript, ClaimPublicKey: hex.EncodeToString(cred.PhoneBIP340)}
	return s.LNURLRegistrar(ctx, action, binding, name)
}

func attachLNURLRoutes(mux *http.ServeMux, s *Service, origin string) {
	mux.HandleFunc("POST /v1/lnurl/challenge", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action string `json:"action"`
			Name   string `json:"name"`
		}
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		value, err := s.IssueLNURLChallenge(req.Action, req.Name)
		writeJSON(w, value, err)
	})
	for _, action := range []string{"register", "revoke"} {
		mux.HandleFunc("POST /v1/lnurl/"+action, func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				LightBackupOpenRequest
				Name string `json:"name"`
			}
			if err := decodeMutation(r, &req, origin); err != nil {
				writeMutationError(w, err)
				return
			}
			value, err := s.ConfigureLNURL(r.Context(), action, req.Name, req.LightBackupOpenRequest)
			writeJSON(w, value, err)
		})
	}
}
