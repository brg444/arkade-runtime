package application

import (
	"context"
	"encoding/hex"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"strings"
	"testing"
	"time"
)

func backupAssertion(t *testing.T, f spendingOnlyFixture) BackupOpenRequest {
	t.Helper()
	c, err := f.env.svc.IssueRecoveryArchiveChallenge()
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := hex.DecodeString(c.Challenge)
	cfg := f.env.svc.runtimeConfig()
	a, err := webauthn.Synth(f.env.p256, f.env.credID, challenge, cfg.ClientOrigin, cfg.RPID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := webauthn.SignDigestLowS(f.env.direct, passkeySessionProofDigest(recoveryArchivePurpose, challenge, f.env.credID))
	if err != nil {
		t.Fatal(err)
	}
	return BackupOpenRequest{VaultID: f.start.VaultID, SessionAssertionRequest: SessionAssertionRequest{ChallengeID: c.ChallengeID, CredentialID: hex.EncodeToString(f.env.credID), ClientDataJSON: hex.EncodeToString(a.ClientDataJSON), AuthenticatorData: hex.EncodeToString(a.AuthenticatorData), Signature: hex.EncodeToString(a.DERSignature), DirectProof: hex.EncodeToString(proof)}}
}
func enrolledBackupFixture(t *testing.T) spendingOnlyFixture {
	t.Helper()
	f := newSpendingOnlyFixture(t, true)
	if _, err := f.env.svc.FinishEnrollment(context.Background(), f.token, f.request); err != nil {
		t.Fatal(err)
	}
	return f
}
func TestSpendingOnlyArchiveAuthenticationIsolationAndPersistence(t *testing.T) {
	f := enrolledBackupFixture(t)
	s := f.env.svc
	req := backupAssertion(t, f)
	opened, err := s.OpenRecoveryArchive(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Backup != nil {
		t.Fatal("unexpected backup")
	}
	if _, err = s.OpenRecoveryArchive(context.Background(), req); err == nil {
		t.Fatal("replayed ceremony")
	}
	if _, err = s.ReadRecoveryArchive(BackupRequest{Token: strings.Repeat("00", 32)}); err == nil {
		t.Fatal("anonymous read")
	}
	payload := archivePayload(opened.Binding, "stable", strings.Repeat("A", 64))
	saved, err := s.WriteRecoveryArchive(BackupRequest{Token: opened.Token, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 {
		t.Fatal("revision")
	}
	if _, err = s.WriteRecoveryArchive(BackupRequest{Token: opened.Token, Payload: archivePayload(RecoveryArchiveBinding{VaultID: strings.Repeat("ff", 32)}, "stable", strings.Repeat("A", 64)), Revision: 1}); err == nil {
		t.Fatal("cross-wallet write")
	}
	if _, err = s.WriteRecoveryArchive(BackupRequest{Token: opened.Token, Payload: `{"ownerKey":"leak"}`, Revision: 1}); err == nil {
		t.Fatal("unencrypted write")
	}
	s.sessionMu.Lock()
	s.backupSessions = nil
	s.sessionMu.Unlock()
	if _, err = s.ReadRecoveryArchive(BackupRequest{Token: opened.Token}); err == nil {
		t.Fatal("session survives restart")
	}
	restored, err := s.OpenRecoveryArchive(context.Background(), backupAssertion(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if restored.Backup == nil || restored.Backup.Payload != payload || restored.Backup.Revision != 1 {
		t.Fatal("backup did not persist")
	}
	s.SessionNow = func() time.Time { return time.Now().Add(9 * time.Hour) }
	if _, err = s.ReadRecoveryArchive(BackupRequest{Token: restored.Token}); err == nil {
		t.Fatal("expired session")
	}
}
func TestSpendingOnlyArchiveRejectsForgedCeremonies(t *testing.T) {
	for _, mutate := range []func(*BackupOpenRequest){
		func(r *BackupOpenRequest) { r.VaultID = strings.Repeat("ff", 32) },
		func(r *BackupOpenRequest) { r.DirectProof = strings.Repeat("00", 64) },
		func(r *BackupOpenRequest) { r.CredentialID = "aaaa" },
		func(r *BackupOpenRequest) { r.Signature = "aaaa" },
	} {
		f := enrolledBackupFixture(t)
		req := backupAssertion(t, f)
		mutate(&req)
		if _, err := f.env.svc.OpenRecoveryArchive(context.Background(), req); err == nil {
			t.Fatal("forged ceremony")
		}
	}
}

func TestSpendingOnlyArchiveRejectsMalformedEnvelopeBeforeReplacingSnapshot(t *testing.T) {
	f := enrolledBackupFixture(t)
	s := f.env.svc
	opened, err := s.OpenRecoveryArchive(context.Background(), backupAssertion(t, f))
	if err != nil {
		t.Fatal(err)
	}
	payload := archivePayload(opened.Binding, "stable", strings.Repeat("A", 64))
	if _, err := s.WriteRecoveryArchive(BackupRequest{Token: opened.Token, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		payload + `{}`, payload + ` trailing`,
		strings.Replace(payload, strings.Repeat("A", 64), strings.Repeat("!", 64), 1),
	} {
		if _, err := s.WriteRecoveryArchive(BackupRequest{Token: opened.Token, Revision: 1, Payload: bad}); err == nil {
			t.Fatal("malformed envelope stored")
		}
	}
	got, err := s.ReadRecoveryArchive(BackupRequest{Token: opened.Token})
	if err != nil || got.Revision != 1 || got.Payload != payload {
		t.Fatal("previous backup changed", err)
	}
}
