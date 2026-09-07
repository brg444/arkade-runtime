package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"strings"
	"testing"
	"time"
)

func backupAssertion(t *testing.T, f lightEnrolledFixture) LightBackupOpenRequest {
	t.Helper()
	c, err := f.env.svc.IssueLightBackupChallenge()
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := hex.DecodeString(c.Challenge)
	cfg := f.env.svc.runtimeConfig()
	a, err := webauthn.Synth(f.env.p256, f.env.credID, challenge, cfg.ClientOrigin, cfg.RPID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := webauthn.SignDigestLowS(f.env.direct, passkeySessionProofDigest(lightBackupPurpose, challenge, f.env.credID))
	if err != nil {
		t.Fatal(err)
	}
	return LightBackupOpenRequest{VaultID: f.start.VaultID, SessionAssertionRequest: SessionAssertionRequest{ChallengeID: c.ChallengeID, CredentialID: hex.EncodeToString(f.env.credID), ClientDataJSON: hex.EncodeToString(a.ClientDataJSON), AuthenticatorData: hex.EncodeToString(a.AuthenticatorData), Signature: hex.EncodeToString(a.DERSignature), DirectProof: hex.EncodeToString(proof)}}
}
func enrolledBackupFixture(t *testing.T) lightEnrolledFixture {
	t.Helper()
	f := newLightEnrollmentFixture(t, true)
	if _, err := f.env.svc.FinishLightEnrollment(context.Background(), f.token, f.request); err != nil {
		t.Fatal(err)
	}
	return f
}
func backupPayload(id string) string {
	raw, _ := json.Marshal(map[string]any{"name": "vaulted-light-backup", "version": 2, "header": map[string]any{"descriptor": map[string]any{"vaultId": id}}, "nonce": strings.Repeat("12", 12), "ciphertext": strings.Repeat("A", 64)})
	return string(raw)
}
func TestLightBackupAuthenticationIsolationAndPersistence(t *testing.T) {
	f := enrolledBackupFixture(t)
	s := f.env.svc
	req := backupAssertion(t, f)
	opened, err := s.OpenLightBackup(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Backup != nil {
		t.Fatal("unexpected backup")
	}
	if _, err = s.OpenLightBackup(context.Background(), req); err == nil {
		t.Fatal("replayed ceremony")
	}
	if _, err = s.ReadLightBackup(LightBackupRequest{Token: strings.Repeat("00", 32)}); err == nil {
		t.Fatal("anonymous read")
	}
	payload := backupPayload(f.start.VaultID)
	saved, err := s.WriteLightBackup(LightBackupRequest{Token: opened.Token, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 {
		t.Fatal("revision")
	}
	if _, err = s.WriteLightBackup(LightBackupRequest{Token: opened.Token, Payload: backupPayload(strings.Repeat("ff", 32)), Revision: 1}); err == nil {
		t.Fatal("cross-wallet write")
	}
	if _, err = s.WriteLightBackup(LightBackupRequest{Token: opened.Token, Payload: `{"ownerKey":"leak"}`, Revision: 1}); err == nil {
		t.Fatal("unencrypted write")
	}
	s.sessionMu.Lock()
	s.backupSessions = nil
	s.sessionMu.Unlock()
	if _, err = s.ReadLightBackup(LightBackupRequest{Token: opened.Token}); err == nil {
		t.Fatal("session survives restart")
	}
	restored, err := s.OpenLightBackup(context.Background(), backupAssertion(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if restored.Backup == nil || restored.Backup.Payload != payload || restored.Backup.Revision != 1 {
		t.Fatal("backup did not persist")
	}
	s.SessionNow = func() time.Time { return time.Now().Add(9 * time.Hour) }
	if _, err = s.ReadLightBackup(LightBackupRequest{Token: restored.Token}); err == nil {
		t.Fatal("expired session")
	}
}
func TestLightBackupRejectsForgedCeremonies(t *testing.T) {
	for _, mutate := range []func(*LightBackupOpenRequest){
		func(r *LightBackupOpenRequest) { r.VaultID = strings.Repeat("ff", 32) },
		func(r *LightBackupOpenRequest) { r.DirectProof = strings.Repeat("00", 64) },
		func(r *LightBackupOpenRequest) { r.CredentialID = "aaaa" },
		func(r *LightBackupOpenRequest) { r.Signature = "aaaa" },
	} {
		f := enrolledBackupFixture(t)
		req := backupAssertion(t, f)
		mutate(&req)
		if _, err := f.env.svc.OpenLightBackup(context.Background(), req); err == nil {
			t.Fatal("forged ceremony")
		}
	}
}

func TestLightBackupRejectsMalformedEnvelopeBeforeReplacingSnapshot(t *testing.T) {
	f := enrolledBackupFixture(t)
	s := f.env.svc
	opened, err := s.OpenLightBackup(context.Background(), backupAssertion(t, f))
	if err != nil {
		t.Fatal(err)
	}
	payload := backupPayload(f.start.VaultID)
	if _, err := s.WriteLightBackup(LightBackupRequest{Token: opened.Token, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		payload + `{}`, payload + ` trailing`,
		strings.Replace(payload, strings.Repeat("A", 64), strings.Repeat("!", 64), 1),
	} {
		if _, err := s.WriteLightBackup(LightBackupRequest{Token: opened.Token, Revision: 1, Payload: bad}); err == nil {
			t.Fatal("malformed envelope stored")
		}
	}
	got, err := s.ReadLightBackup(LightBackupRequest{Token: opened.Token})
	if err != nil || got.Revision != 1 || got.Payload != payload {
		t.Fatal("previous backup changed", err)
	}
}
