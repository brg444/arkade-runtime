package application

import (
	"bytes"
	"crypto/ecdsa"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
)

func archiveAssertion(t *testing.T, s *Service, id string, pass, direct *ecdsa.PrivateKey, credID []byte, purpose string) LightBackupOpenRequest {
	t.Helper()
	c, err := s.issueBackupChallenge(purpose)
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := hex.DecodeString(c.Challenge)
	cfg := s.runtimeConfig()
	a, err := webauthn.Synth(pass, credID, challenge, cfg.ClientOrigin, cfg.RPID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := webauthn.SignDigestLowS(direct, passkeySessionProofDigest(purpose, challenge, credID))
	if err != nil {
		t.Fatal(err)
	}
	return LightBackupOpenRequest{VaultID: id, SessionAssertionRequest: SessionAssertionRequest{ChallengeID: c.ChallengeID, CredentialID: hex.EncodeToString(credID), ClientDataJSON: hex.EncodeToString(a.ClientDataJSON), AuthenticatorData: hex.EncodeToString(a.AuthenticatorData), Signature: hex.EncodeToString(a.DERSignature), DirectProof: hex.EncodeToString(proof)}}
}
func archivePayload(binding RecoveryArchiveBinding, headerTag, body string) string {
	raw, _ := json.Marshal(map[string]any{"name": "vaulted-recovery-backup", "version": 1, "header": map[string]any{"binding": binding, "testHeader": headerTag}, "nonce": strings.Repeat("12", 12), "ciphertext": body})
	return string(raw)
}

func TestRecoveryArchiveEnrollmentFamiliesAndRestart(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		for _, template := range []string{savings.Template, connector.Template} {
			for _, tier := range []string{program.ProtectionTierStandard, program.ProtectionTierAdvanced} {
				t.Run(network+"/"+template+"/"+tier, func(t *testing.T) {
					f := newConnectorFixture(t, network)
					phone, _ := btcec.NewPrivateKey()
					hardware, _ := btcec.NewPrivateKey()
					board, _ := btcec.NewPrivateKey()
					var recovery *btcec.PrivateKey
					if tier == program.ProtectionTierAdvanced {
						recovery, _ = btcec.NewPrivateKey()
					}
					req := connectorEnrollRequestForNetwork(t, network, phone, hardware, board, tier, recovery, connector.NativeSegwit, false)
					pass, _ := webauthn.NewP256()
					direct, _ := webauthn.NewP256()
					req.WebAuthnP256 = hex.EncodeToString(webauthn.CompressedP256(pass))
					req.PhoneDirectP256 = hex.EncodeToString(webauthn.CompressedP256(direct))
					id, _ := newOpaqueVaultID()
					token := bytes.Repeat([]byte{0x71}, 32)
					putConnectorInvite(t, f.led, token)
					if template == savings.Template {
						req.ConnectorType = ""
						req.ConnectorPub = ""
						req.ConnectorFingerprint = 0
						req.ConnectorPath = nil
						proposed, err := f.svc.previewVaultBoardEnrollmentDescriptor(id, req)
						if err != nil {
							t.Fatal(err)
						}
						req.DescriptorHash = proposed.DescriptorHash
						if err := f.svc.CreateTenantVault(id, token, req); err != nil {
							t.Fatal(err)
						}
					} else {
						req = enrollConnectorVault(t, f.svc, id, token, req)
					}
					credID, _ := hex.DecodeString(req.CredentialID)
					auth := func() LightBackupOpenRequest {
						return archiveAssertion(t, f.svc, id, pass, direct, credID, recoveryArchivePurpose)
					}
					assertion := auth()
					opened, err := f.svc.OpenRecoveryArchive(t.Context(), assertion)
					if err != nil {
						t.Fatal(err)
					}
					if opened.Binding.DescriptorHash != req.DescriptorHash || opened.Binding.ProtectionTier != tier || opened.Binding.Network != network || opened.Backup != nil {
						t.Fatalf("binding: %+v", opened)
					}
					if _, err := f.svc.OpenRecoveryArchive(t.Context(), assertion); err == nil {
						t.Fatal("ceremony replay")
					}
					payload := archivePayload(opened.Binding, "stable", strings.Repeat("A", 64))
					saved, err := f.svc.WriteRecoveryArchive(LightBackupRequest{Token: opened.Token, Payload: payload})
					if err != nil || saved.Revision != 1 {
						t.Fatal(saved, err)
					}
					retry, err := f.svc.WriteRecoveryArchive(LightBackupRequest{Token: opened.Token, Payload: payload})
					if err != nil || *retry != *saved {
						t.Fatal("exact retry", err)
					}
					f.reopen(t)
					if _, err := f.svc.ReadRecoveryArchive(LightBackupRequest{Token: opened.Token}); err == nil {
						t.Fatal("session survived restart")
					}
					restored, err := f.svc.OpenRecoveryArchive(t.Context(), auth())
					if err != nil || restored.Backup == nil || *restored.Backup != *saved || restored.Binding != opened.Binding {
						t.Fatal("restore", err)
					}
					f.svc.SessionNow = func() time.Time { return time.Now().Add(8*time.Hour + time.Minute) }
					if _, err := f.svc.ReadRecoveryArchive(LightBackupRequest{Token: restored.Token}); err == nil {
						t.Fatal("expired token")
					}
				})
			}
		}
	}
}

func TestRecoveryArchiveRejectsAuthenticationAndFamilySubstitution(t *testing.T) {
	e := newEnv(t)
	auth := func(purpose string) LightBackupOpenRequest {
		return archiveAssertion(t, e.svc, fixture.VaultID, e.p256, e.direct, e.credID, purpose)
	}
	for name, mutate := range map[string]func(*LightBackupOpenRequest){
		"vault":        func(r *LightBackupOpenRequest) { r.VaultID = strings.Repeat("ff", 32) },
		"credential":   func(r *LightBackupOpenRequest) { r.CredentialID = "abcd" },
		"signature":    func(r *LightBackupOpenRequest) { r.Signature = "abcd" },
		"direct proof": func(r *LightBackupOpenRequest) { r.DirectProof = strings.Repeat("00", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			r := auth(recoveryArchivePurpose)
			mutate(&r)
			if _, err := e.svc.OpenRecoveryArchive(t.Context(), r); err == nil {
				t.Fatal("forged auth")
			}
		})
	}
	if _, err := e.svc.OpenRecoveryArchive(t.Context(), auth(lightBackupPurpose)); err == nil {
		t.Fatal("Light challenge crossed route")
	}
	if _, err := e.svc.OpenLightBackup(t.Context(), auth(lightBackupPurpose)); err == nil {
		t.Fatal("Savings entered Light backup")
	}
	opened, err := e.svc.OpenRecoveryArchive(t.Context(), auth(recoveryArchivePurpose))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ReadLightBackup(LightBackupRequest{Token: opened.Token}); err == nil {
		t.Fatal("Savings token entered Light route")
	}
	l := enrolledBackupFixture(t)
	if _, err := l.env.svc.OpenRecoveryArchive(t.Context(), archiveAssertion(t, l.env.svc, l.start.VaultID, l.env.p256, l.env.direct, l.env.credID, recoveryArchivePurpose)); err == nil {
		t.Fatal("Light entered Savings backup")
	}
	lightOpen, err := l.env.svc.OpenLightBackup(t.Context(), backupAssertion(t, l))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.env.svc.ReadRecoveryArchive(LightBackupRequest{Token: lightOpen.Token}); err == nil {
		t.Fatal("Light token entered Savings route")
	}
	for _, template := range []string{"", light.Profile, "future-savings-v99"} {
		if recoveryArchiveCredentialAllowed(&policy.Credential{TemplateVersion: template, ProtectionTier: program.ProtectionTierStandard}) {
			t.Fatal("unknown template", template)
		}
	}
	for _, tier := range []string{"", "light", "future-tier"} {
		if recoveryArchiveCredentialAllowed(&policy.Credential{TemplateVersion: savings.Template, ProtectionTier: tier}) {
			t.Fatal("unknown tier", tier)
		}
	}
}

func TestRecoveryArchiveHeaderBindingCASAndMalformedWrites(t *testing.T) {
	e := newEnv(t)
	s := e.svc
	auth := func() *RecoveryArchiveOpenResponse {
		o, err := s.OpenRecoveryArchive(t.Context(), archiveAssertion(t, s, fixture.VaultID, e.p256, e.direct, e.credID, recoveryArchivePurpose))
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	first, second := auth(), auth()
	body := strings.Repeat("A", 64)
	payload := archivePayload(first.Binding, "immutable", body)
	if _, err := s.WriteRecoveryArchive(LightBackupRequest{Token: first.Token, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RecoveryArchiveBinding){
		"vault": func(b *RecoveryArchiveBinding) { b.VaultID = strings.Repeat("ff", 32) }, "network": func(b *RecoveryArchiveBinding) { b.Network = "mainnet" },
		"template": func(b *RecoveryArchiveBinding) { b.TemplateVersion = connector.Template }, "tier": func(b *RecoveryArchiveBinding) { b.ProtectionTier = "advanced" },
		"policy": func(b *RecoveryArchiveBinding) { b.PolicyVersion = "invalid" }, "policy digest": func(b *RecoveryArchiveBinding) { b.SpendingPolicyDigest = strings.Repeat("11", 32) },
		"descriptor": func(b *RecoveryArchiveBinding) { b.DescriptorHash = strings.Repeat("11", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			b := first.Binding
			mutate(&b)
			if _, err := s.WriteRecoveryArchive(LightBackupRequest{Token: first.Token, Revision: 1, Payload: archivePayload(b, "immutable", body)}); err == nil {
				t.Fatal("substituted binding")
			}
		})
	}
	for _, bad := range []string{`{"phoneKey":"plaintext"}`, payload + `{}`, strings.Replace(payload, body, "bad!", 1), strings.Replace(payload, strings.Repeat("12", 12), "ff", 1), strings.Repeat("x", policy.MaxRecoveryBackupBytes+1), archivePayload(first.Binding, "different", body)} {
		for _, token := range []string{first.Token, second.Token} {
			if _, err := s.WriteRecoveryArchive(LightBackupRequest{Token: token, Revision: 1, Payload: bad}); err == nil {
				t.Fatal("invalid archive replaced valid snapshot")
			}
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i, token := range []string{first.Token, second.Token} {
		wg.Add(1)
		go func(i int, token string) {
			defer wg.Done()
			_, err := s.WriteRecoveryArchive(LightBackupRequest{Token: token, Revision: 1, Payload: archivePayload(first.Binding, "immutable", strings.Repeat(string(rune('B'+i)), 64))})
			errs <- err
		}(i, token)
	}
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("CAS winners", success)
	}
	restored := auth()
	if restored.Backup == nil || restored.Backup.Revision != 2 {
		t.Fatal("reopen")
	}
	if _, err := s.WriteRecoveryArchive(LightBackupRequest{Token: restored.Token, Revision: 2, Payload: archivePayload(first.Binding, "different", body)}); err == nil {
		t.Fatal("reopen allowed header replacement")
	}
	// Disk row MACs are verified by the store; an authenticated different descriptor
	// still cannot inherit a session. Exercise the pin independently of SQL MAC tests.
	s.sessionMu.Lock()
	for k, v := range s.backupSessions {
		v.Binding.DescriptorHash = strings.Repeat("ff", 32)
		s.backupSessions[k] = v
	}
	s.sessionMu.Unlock()
	if _, err := s.ReadRecoveryArchive(LightBackupRequest{Token: restored.Token}); err == nil {
		t.Fatal("enrollment change not rechecked")
	}
}

func TestRecoveryArchiveSessionAndChallengeBudgets(t *testing.T) {
	e := newEnv(t)
	s := e.svc
	for i := 0; i < maxBackupSessions*2; i++ {
		if _, err := s.IssueRecoveryArchiveChallenge(); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.consumedPasskeyChallenges) != 0 {
		t.Fatal("anonymous issuance allocated replay state")
	}
	s.SessionNow = nil
	s.sessionMu.Lock()
	s.backupSessions = make(map[[32]byte]backupSession)
	for i := 0; i < maxBackupSessions; i++ {
		var k [32]byte
		k[0] = byte(i)
		s.backupSessions[k] = backupSession{ExpiresAt: time.Now().Add(time.Hour)}
	}
	s.sessionMu.Unlock()
	req := archiveAssertion(t, s, fixture.VaultID, e.p256, e.direct, e.credID, recoveryArchivePurpose)
	if _, err := s.OpenRecoveryArchive(t.Context(), req); err == nil {
		t.Fatal("unbounded session map")
	}
}

func TestRecoveryArchiveHTTPBoundary(t *testing.T) {
	e := newEnv(t)
	s := e.svc
	h := testAuthorizer(s)
	req := archiveAssertion(t, s, fixture.VaultID, e.p256, e.direct, e.credID, recoveryArchivePurpose)
	raw, _ := json.Marshal(req)
	openedResponse := boundaryHTTPCall(t, h, http.MethodPost, "/v1/recovery-archive/open", "application/json", fixture.Origin, string(raw))
	if openedResponse.Code != http.StatusOK {
		t.Fatal(openedResponse.Code, openedResponse.Body.String())
	}
	var opened RecoveryArchiveOpenResponse
	if err := json.Unmarshal(openedResponse.Body.Bytes(), &opened); err != nil {
		t.Fatal(err)
	}
	payload := archivePayload(opened.Binding, "fixed", strings.Repeat("A", 1_100_000))
	write, _ := json.Marshal(LightBackupRequest{Token: opened.Token, Payload: payload})
	response := boundaryHTTPCall(t, h, http.MethodPost, "/v1/recovery-archive/write", "application/json", fixture.Origin, string(write))
	if response.Code != http.StatusOK {
		t.Fatal("archive over ordinary mutation cap failed", response.Code, response.Body.String())
	}
	for _, phase := range []string{"challenge", "open", "read", "write"} {
		path := "/v1/recovery-archive/" + phase
		r := boundaryHTTPCall(t, h, http.MethodPost, path, "application/json", "https://attacker.invalid", `{}`)
		if r.Code != http.StatusForbidden {
			t.Fatal(path, "cross-origin", r.Code)
		}
		r = boundaryHTTPCall(t, h, http.MethodPost, path, "application/json", fixture.Origin, `{"prf":"rejected"}`)
		if r.Code != http.StatusBadRequest {
			t.Fatal(path, "unknown field", r.Code)
		}
	}
	tooLarge := `{"payload":"` + strings.Repeat("A", 3_100_001) + `"}`
	response = boundaryHTTPCall(t, h, http.MethodPost, "/v1/recovery-archive/write", "application/json", fixture.Origin, tooLarge)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatal("body cap", response.Code)
	}
}

func TestRecoveryArchiveRejectsTamperedEnrollmentBeforeReadOrWrite(t *testing.T) {
	e := newEnv(t)
	s := e.svc
	auth := func() LightBackupOpenRequest {
		return archiveAssertion(t, s, fixture.VaultID, e.p256, e.direct, e.credID, recoveryArchivePurpose)
	}
	opened, err := s.OpenRecoveryArchive(t.Context(), auth())
	if err != nil {
		t.Fatal(err)
	}
	payload := archivePayload(opened.Binding, "fixed", strings.Repeat("A", 64))
	if _, err := s.WriteRecoveryArchive(LightBackupRequest{Token: opened.Token, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE vault SET network='mainnet' WHERE vault_id=?`, fixture.VaultID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRecoveryArchive(LightBackupRequest{Token: opened.Token}); err == nil {
		t.Fatal("tampered enrollment read")
	}
	if _, err := s.WriteRecoveryArchive(LightBackupRequest{Token: opened.Token, Revision: 1, Payload: payload}); err == nil {
		t.Fatal("tampered enrollment write")
	}
	if _, err := s.OpenRecoveryArchive(t.Context(), auth()); err == nil {
		t.Fatal("tampered enrollment open")
	}
	var stored string
	var revision int
	if err := db.QueryRow(`SELECT revision,payload FROM recovery_backup WHERE vault_id=?`, fixture.VaultID).Scan(&revision, &stored); err != nil {
		t.Fatal(err)
	}
	if revision != 1 || stored != payload {
		t.Fatal("rejected mutation changed archive")
	}
}
