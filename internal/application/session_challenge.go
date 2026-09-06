package application

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	passkeyChallengeTicketPrefix         = "v1."
	passkeyChallengeTicketLimit          = 2048
	maxConsumedPasskeyChallenges         = 4096
	maxConsumedPasskeyChallengesPerVault = 256
)

type consumedPasskeyChallenge struct {
	VaultID   string
	ExpiresAt time.Time
}

// Challenge issuance has no per-request server state. Only successful owner
// authentication admits a spent ticket until its original expiry. The random
// process key makes outstanding tickets unusable after restart.
func (s *Service) issuePasskeyChallenge(vaultID, purpose, candidateTxid string, credentialID []byte) (*PasskeyChallengeResponse, error) {
	challenge, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	record := passkeyChallenge{VaultID: vaultID, Purpose: purpose, CandidateTxid: candidateTxid, Challenge: challenge, ExpiresAt: s.sessionNow().Add(passkeyChallengeTTL)}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(payload)+sha256.Size > passkeyChallengeTicketLimit {
		return nil, fmt.Errorf("passkey challenge identity too large")
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if len(s.sessionChallengeKey) == 0 {
		s.sessionChallengeKey, err = randomBytes(32)
		if err != nil {
			return nil, err
		}
	}
	mac := hmac.New(sha256.New, s.sessionChallengeKey)
	_, _ = mac.Write([]byte("vaulted/passkey-challenge/v1\x00"))
	_, _ = mac.Write(payload)
	raw := append(payload, mac.Sum(nil)...)
	return &PasskeyChallengeResponse{
		ChallengeID: passkeyChallengeTicketPrefix + base64.RawURLEncoding.EncodeToString(raw),
		Challenge:   hex.EncodeToString(challenge), AllowCredentialID: hex.EncodeToString(credentialID),
		ExpiresInSeconds: int64(passkeyChallengeTTL / time.Second),
	}, nil
}

// Caller holds sessionMu. Validate encoding and authentication before using
// any ticket fields; the replay identity uses decoded authenticated bytes.
func (s *Service) passkeyChallengeLocked(vaultID, id, purpose string) (passkeyChallenge, [32]byte, error) {
	fail := func() (passkeyChallenge, [32]byte, error) {
		return passkeyChallenge{}, [32]byte{}, fmt.Errorf("passkey authentication failed")
	}
	if !strings.HasPrefix(id, passkeyChallengeTicketPrefix) || len(id) > len(passkeyChallengeTicketPrefix)+base64.RawURLEncoding.EncodedLen(passkeyChallengeTicketLimit) || len(s.sessionChallengeKey) != 32 {
		return fail()
	}
	encoded := strings.TrimPrefix(id, passkeyChallengeTicketPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) <= sha256.Size || len(raw) > passkeyChallengeTicketLimit || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return fail()
	}
	payload, tag := raw[:len(raw)-sha256.Size], raw[len(raw)-sha256.Size:]
	mac := hmac.New(sha256.New, s.sessionChallengeKey)
	_, _ = mac.Write([]byte("vaulted/passkey-challenge/v1\x00"))
	_, _ = mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return fail()
	}
	var record passkeyChallenge
	if json.Unmarshal(payload, &record) != nil {
		return fail()
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(payload, canonical) || record.VaultID != vaultID || record.Purpose != purpose || len(record.Challenge) != 32 || !s.sessionNow().Before(record.ExpiresAt) {
		return fail()
	}
	digest := sha256.Sum256(raw)
	if _, used := s.consumedPasskeyChallenges[digest]; used {
		return fail()
	}
	return record, digest, nil
}

func (s *Service) readPasskeyChallenge(vaultID, id, purpose string) (passkeyChallenge, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	record, _, err := s.passkeyChallengeLocked(vaultID, id, purpose)
	return record, err
}

// Call only after WebAuthn and DirectP256 verification. Claim before updating
// counters or performing the authenticated action, including for zero-counter
// passkeys. A later failure must not make a verified assertion replayable.
func (s *Service) consumePasskeyChallenge(vaultID, id, purpose string) ([]byte, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	ticketVaultID := vaultID
	if purpose == lightBackupPurpose || purpose == recoveryArchivePurpose {
		ticketVaultID = ""
	}
	if vaultID == "" {
		return nil, fmt.Errorf("authenticated challenge owner required")
	}
	record, digest, err := s.passkeyChallengeLocked(ticketVaultID, id, purpose)
	if err != nil {
		return nil, err
	}
	now := s.sessionNow()
	ownerCount := 0
	for key, spent := range s.consumedPasskeyChallenges {
		if !now.Before(spent.ExpiresAt) {
			delete(s.consumedPasskeyChallenges, key)
		} else if spent.VaultID == vaultID {
			ownerCount++
		}
	}
	if len(s.consumedPasskeyChallenges) >= maxConsumedPasskeyChallenges || ownerCount >= maxConsumedPasskeyChallengesPerVault {
		return nil, ErrVerificationBusy
	}
	if s.consumedPasskeyChallenges == nil {
		s.consumedPasskeyChallenges = make(map[[32]byte]consumedPasskeyChallenge)
	}
	s.consumedPasskeyChallenges[digest] = consumedPasskeyChallenge{VaultID: vaultID, ExpiresAt: record.ExpiresAt}
	return record.Challenge, nil
}
