package application

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/webauthn"
)

func TestPasskeyChallengeFloodDoesNotStarveOwner(t *testing.T) {
	e := newEnv(t)
	_, owner := passkeySessionAssertion(t, e, passkeyPurposeInstall)
	for i := 0; i < 64; i++ {
		for _, purpose := range []string{passkeyPurposeInstall, passkeyPurposeTransition, passkeyPurposeMapWrite} {
			if _, err := e.svc.IssuePasskeyChallengeFor(t.Context(), fixture.VaultID, purpose); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(e.svc.consumedPasskeyChallenges) != 0 {
		t.Fatal("issuance allocated pending state")
	}
	if _, err := e.svc.authenticatePasskeySession(t.Context(), passkeyPurposeInstall, fixture.VaultID, owner); err != nil {
		t.Fatalf("owner starved: %v", err)
	}
	if len(e.svc.consumedPasskeyChallenges) != 1 {
		t.Fatal("authenticated ticket not claimed")
	}
}

func TestPasskeyChallengeBadProofDoesNotBurnOwnerTicket(t *testing.T) {
	for _, stage := range []string{"webauthn", "direct"} {
		t.Run(stage, func(t *testing.T) {
			e := newEnv(t)
			_, req := passkeySessionAssertion(t, e, passkeyPurposeInstall)
			bad := req
			if stage == "webauthn" {
				bad.Signature = strings.Repeat("00", 64)
			} else {
				bad.DirectProof = strings.Repeat("00", 64)
			}
			if _, err := e.svc.authenticatePasskeySession(t.Context(), passkeyPurposeInstall, fixture.VaultID, bad); err == nil {
				t.Fatal("bad proof accepted")
			}
			if len(e.svc.consumedPasskeyChallenges) != 0 {
				t.Fatal("failed authentication admitted replay state")
			}
			if _, err := e.svc.authenticatePasskeySession(t.Context(), passkeyPurposeInstall, fixture.VaultID, req); err != nil {
				t.Fatalf("owner ticket burned: %v", err)
			}
			if _, err := e.svc.authenticatePasskeySession(t.Context(), passkeyPurposeInstall, fixture.VaultID, req); err == nil {
				t.Fatal("verified assertion replayed")
			}
		})
	}
}

func TestPasskeyChallengeTicketAuthenticatesEveryFieldAndCanonicalEncoding(t *testing.T) {
	s := &Service{}
	issued, err := s.issuePasskeyChallenge("vault", passkeyPurposeConnectorWithdraw, strings.Repeat("ab", 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(issued.ChallengeID, passkeyChallengeTicketPrefix))
	if err != nil {
		t.Fatal(err)
	}
	payload, tag := raw[:len(raw)-32], raw[len(raw)-32:]
	var record map[string]any
	if err = json.Unmarshal(payload, &record); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"VaultID", "Purpose", "CandidateTxid", "Challenge", "ExpiresAt"} {
		t.Run(field, func(t *testing.T) {
			altered := make(map[string]any, len(record))
			for k, v := range record {
				altered[k] = v
			}
			altered[field] = "attacker"
			b, _ := json.Marshal(altered)
			ticket := passkeyChallengeTicketPrefix + base64.RawURLEncoding.EncodeToString(append(b, tag...))
			if _, err := s.readPasskeyChallenge("vault", ticket, passkeyPurposeConnectorWithdraw); err == nil {
				t.Fatal("unsigned field substitution accepted")
			}
		})
	}
	for _, alias := range []string{issued.ChallengeID + "\r\n", issued.ChallengeID + "=", strings.Replace(issued.ChallengeID, "v1.", "v2.", 1), issued.ChallengeID[:len(issued.ChallengeID)-1], strings.Repeat("x", 4096)} {
		if _, err := s.readPasskeyChallenge("vault", alias, passkeyPurposeConnectorWithdraw); err == nil {
			t.Fatal("noncanonical ticket accepted")
		}
	}
	if _, err = s.readPasskeyChallenge("another-vault", issued.ChallengeID, passkeyPurposeConnectorWithdraw); err == nil {
		t.Fatal("cross-vault ticket accepted")
	}
	if _, err = s.readPasskeyChallenge("vault", issued.ChallengeID, passkeyPurposeMapWrite); err == nil {
		t.Fatal("cross-purpose ticket accepted")
	}
	got, err := s.readPasskeyChallenge("vault", issued.ChallengeID, passkeyPurposeConnectorWithdraw)
	if err != nil || hex.EncodeToString(got.Challenge) != issued.Challenge || got.CandidateTxid != strings.Repeat("ab", 32) {
		t.Fatal("exact ticket changed", err)
	}
	if _, err = s.consumePasskeyChallenge("vault", issued.ChallengeID, passkeyPurposeConnectorWithdraw); err != nil {
		t.Fatal(err)
	}
	if _, err = s.readPasskeyChallenge("vault", issued.ChallengeID, passkeyPurposeConnectorWithdraw); err == nil {
		t.Fatal("spent ticket accepted")
	}
}

func TestPasskeyChallengeExpiryAndRestartInvalidateAuthority(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := &Service{SessionNow: func() time.Time { return now }}
	issued, err := s.issuePasskeyChallenge("vault", passkeyPurposeInstall, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.readPasskeyChallenge("vault", issued.ChallengeID, passkeyPurposeInstall); err != nil {
		t.Fatal(err)
	}
	now = now.Add(passkeyChallengeTTL)
	if _, err = s.consumePasskeyChallenge("vault", issued.ChallengeID, passkeyPurposeInstall); err == nil {
		t.Fatal("expired during verification accepted")
	}
	issued, err = s.issuePasskeyChallenge("vault", passkeyPurposeInstall, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Service{SessionNow: s.SessionNow}
	if _, err = restarted.readPasskeyChallenge("vault", issued.ChallengeID, passkeyPurposeInstall); err == nil || len(restarted.sessionChallengeKey) != 0 {
		t.Fatal("validation created an epoch key")
	}
	if _, err = restarted.issuePasskeyChallenge("vault", passkeyPurposeInstall, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.readPasskeyChallenge("vault", issued.ChallengeID, passkeyPurposeInstall); err == nil {
		t.Fatal("ticket survived restart")
	}
	key := s.sessionChallengeKey
	s.WipeSecrets()
	if !bytes.Equal(key, make([]byte, 32)) || len(s.consumedPasskeyChallenges) != 0 {
		t.Fatal("challenge authority survived shutdown")
	}
}

func TestPasskeyChallengeSpentCapacityNeverEvictsLiveReplayEvidence(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := &Service{SessionNow: func() time.Time { return now }}
	spent, err := s.issuePasskeyChallenge("vault", passkeyPurposeInstall, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.consumePasskeyChallenge("vault", spent.ChallengeID, passkeyPurposeInstall); err != nil {
		t.Fatal(err)
	}
	for i := 1; len(s.consumedPasskeyChallenges) < maxConsumedPasskeyChallenges; i++ {
		var k [32]byte
		binary.BigEndian.PutUint64(k[:8], uint64(i))
		s.consumedPasskeyChallenges[k] = consumedPasskeyChallenge{VaultID: "other", ExpiresAt: now.Add(passkeyChallengeTTL)}
	}
	fresh, err := s.issuePasskeyChallenge("vault", passkeyPurposeInstall, "", nil)
	if err != nil {
		t.Fatalf("full spent cache prevented stateless issuance: %v", err)
	}
	if _, err = s.consumePasskeyChallenge("vault", fresh.ChallengeID, passkeyPurposeInstall); !errors.Is(err, ErrVerificationBusy) {
		t.Fatalf("expected bounded authenticated admission: %v", err)
	}
	if _, err = s.consumePasskeyChallenge("vault", spent.ChallengeID, passkeyPurposeInstall); err == nil {
		t.Fatal("live replay entry evicted")
	}
	now = now.Add(passkeyChallengeTTL)
	fresh, err = s.issuePasskeyChallenge("vault", passkeyPurposeInstall, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.consumePasskeyChallenge("vault", fresh.ChallengeID, passkeyPurposeInstall); err != nil {
		t.Fatal("expired replay entries not pruned", err)
	}
	if len(s.consumedPasskeyChallenges) != 1 {
		t.Fatal("stale replay state retained")
	}
}

func TestBackupChallengeFloodAndInvalidProofPreserveOwnerAuthentication(t *testing.T) {
	f := enrolledBackupFixture(t)
	s := f.env.svc
	req := backupAssertion(t, f)
	for i := 0; i < maxBackupSessions*2; i++ {
		for _, purpose := range []string{lightBackupPurpose, recoveryArchivePurpose} {
			if _, err := s.issueBackupChallenge(purpose); err != nil {
				t.Fatal(err)
			}
		}
	}
	bad := req
	bad.DirectProof = strings.Repeat("00", 64)
	if _, err := s.OpenLightBackup(context.Background(), bad); err == nil {
		t.Fatal("invalid backup proof accepted")
	}
	if len(s.consumedPasskeyChallenges) != 0 {
		t.Fatal("anonymous backup request allocated replay entry")
	}
	if _, err := s.OpenLightBackup(context.Background(), req); err != nil {
		t.Fatal("owner backup request starved", err)
	}
	if _, err := s.OpenLightBackup(context.Background(), req); err == nil {
		t.Fatal("backup assertion replayed")
	}
}

func TestPasskeyChallengeAuthenticatedCapacityIsIsolatedPerOwner(t *testing.T) {
	s := &Service{}
	var last *PasskeyChallengeResponse
	for i := 0; i < maxConsumedPasskeyChallengesPerVault; i++ {
		var err error
		last, err = s.issuePasskeyChallenge("busy-owner", passkeyPurposeInstall, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.consumePasskeyChallenge("busy-owner", last.ChallengeID, passkeyPurposeInstall); err != nil {
			t.Fatal(err)
		}
	}
	next, err := s.issuePasskeyChallenge("busy-owner", passkeyPurposeInstall, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.consumePasskeyChallenge("busy-owner", next.ChallengeID, passkeyPurposeInstall); !errors.Is(err, ErrVerificationBusy) {
		t.Fatal("owner replay budget unbounded", err)
	}
	other, err := s.issuePasskeyChallenge("other-owner", passkeyPurposeInstall, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.consumePasskeyChallenge("other-owner", other.ChallengeID, passkeyPurposeInstall); err != nil {
		t.Fatal("one owner starved another", err)
	}
	if _, err = s.consumePasskeyChallenge("busy-owner", last.ChallengeID, passkeyPurposeInstall); err == nil {
		t.Fatal("capacity evicted replay evidence")
	}
	// Unbound backup discovery still charges its authenticated owner.
	backup, err := s.issueBackupChallenge(recoveryArchivePurpose)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.consumePasskeyChallenge("busy-owner", backup.ChallengeID, recoveryArchivePurpose); !errors.Is(err, ErrVerificationBusy) {
		t.Fatal("backup bypassed authenticated owner limit", err)
	}
}

func TestPasskeyChallengeBadDirectProofCannotAdvanceCounter(t *testing.T) {
	e := newEnv(t)
	issued, req := passkeySessionAssertion(t, e, passkeyPurposeInstall)
	challenge, err := hex.DecodeString(issued.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	withCounter := func(count uint32) SessionAssertionRequest {
		a, err := webauthn.SynthWithSignCount(e.p256, e.credID, challenge, fixture.Origin, fixture.RPID, true, true, count)
		if err != nil {
			t.Fatal(err)
		}
		copy := req
		copy.AuthenticatorData = hex.EncodeToString(a.AuthenticatorData)
		copy.Signature = hex.EncodeToString(a.DERSignature)
		return copy
	}
	bad := withCounter(7)
	bad.DirectProof = strings.Repeat("00", 64)
	if _, err = e.svc.authenticatePasskeySession(t.Context(), passkeyPurposeInstall, fixture.VaultID, bad); err == nil {
		t.Fatal("invalid direct proof accepted")
	}
	if _, err = e.svc.authenticatePasskeySession(t.Context(), passkeyPurposeInstall, fixture.VaultID, withCounter(6)); err != nil {
		t.Fatal("invalid proof advanced counter or burned ticket", err)
	}
}

func TestPasskeyChallengeConnectorCandidateMismatchDoesNotBurnTicket(t *testing.T) {
	w := newWithdrawalFixture(t)
	req := w.assertion(t, w.txid)
	if _, err := w.f.svc.authenticateConnectorWithdrawSession(t.Context(), w.id, req, strings.Repeat("ab", 32)); err == nil {
		t.Fatal("wrong candidate accepted")
	}
	if len(w.f.svc.consumedPasskeyChallenges) != 0 {
		t.Fatal("candidate mismatch consumed ticket")
	}
	if _, err := w.f.svc.authenticateConnectorWithdrawSession(t.Context(), w.id, req, w.txid); err != nil {
		t.Fatal("bound candidate ticket burned", err)
	}
	if _, err := w.f.svc.authenticateConnectorWithdrawSession(t.Context(), w.id, req, w.txid); err == nil {
		t.Fatal("candidate ticket replayed")
	}
}
