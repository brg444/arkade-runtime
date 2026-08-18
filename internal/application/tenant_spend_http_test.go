package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"strings"
)

func TestHTTPTenantBDraftBindAuthorizePublishLeavesAUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "http-spend.sqlite")
	led, err := policy.OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	ownerA, _ := btcec.NewPrivateKey()
	recA, _ := btcec.NewPrivateKey()
	_ = recA
	hotA, _ := btcec.NewPrivateKey()
	passA, _ := webauthn.NewP256()
	dirA, _ := webauthn.NewP256()
	broadcast := &recordingBroadcast{}
	svc := &Service{
		Ledger:               led,
		ExternalOwnerWallet:  ownerA.PubKey(),
		VaultCosignerPub:     master.PubKey(),
		ArkadeCosignerPub:    arkade.PubKey(),
		VaultSigner:          LocalSigner{Priv: master},
		ArkadeCosignerSigner: LocalSigner{Priv: arkade},
		Broadcaster:          broadcast,
	}
	if err := svc.Register(RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("cred-a")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passA)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(dirA)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hotA.PubKey().SerializeCompressed()),
	}); err != nil {
		t.Fatal(err)
	}
	key, err := svc.credentialIntegrityKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateIssuanceIntegrity(key); err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{0x5b}, 32)
	now := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := led.PutInvite(token, now, now); err != nil {
		t.Fatal(err)
	}
	ownerB, _ := btcec.NewPrivateKey()
	recB, _ := btcec.NewPrivateKey()
	_ = recB
	hotB, _ := btcec.NewPrivateKey()
	passB, _ := webauthn.NewP256()
	dirB, _ := webauthn.NewP256()
	credB := []byte("cred-b-spend")
	const tenantB = "tenant-spend-b"
	if err := svc.CreateTenantVault(tenantB, token, proposedPoP(t, svc, tenantB, ownerB, recB, RegisterRequest{
		CredentialID:             hex.EncodeToString(credB),
		WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(passB)),
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(dirB)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hotB.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(ownerB.PubKey())),
	})); err != nil {
		t.Fatal(err)
	}
	addrA := svc.snapshot(fixture.VaultID).Operational.Address
	spentA, err := led.SpentInPeriod(context.Background(), fixture.VaultID, "")
	if err != nil {
		t.Fatal(err)
	}

	opB := svc.snapshot(tenantB).Operational
	prevTx := wire.NewMsgTx(2)
	prevTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: ^uint32(0)}, SignatureScript: []byte{0x01}, Sequence: wire.MaxTxInSequenceNum})
	prevTx.AddTxOut(&wire.TxOut{Value: 90_000, PkScript: opB.PkScript})
	var prevRaw bytes.Buffer
	if err := prevTx.Serialize(&prevRaw); err != nil {
		t.Fatal(err)
	}
	destKey, _ := btcec.NewPrivateKey()
	dest, err := txscript.PayToTaprootScript(destKey.PubKey())
	if err != nil {
		t.Fatal(err)
	}

	h := AuthorizerHandler(svc)
	draftRaw := httpJSON(t, h, http.MethodPost, "/v1/draft", map[string]any{
		"vaultId": tenantB, "prevTxHex": hex.EncodeToString(prevRaw.Bytes()), "vout": 0,
		"recipientScript": hex.EncodeToString(dest), "recipientAmount": 20_000, "fee": 500,
	})
	var draftOut struct {
		PSBT string `json:"psbt"`
	}
	if err := json.Unmarshal(draftRaw, &draftOut); err != nil || draftOut.PSBT == "" {
		t.Fatalf("draft: %s", draftRaw)
	}
	preRaw := httpJSON(t, h, http.MethodPost, "/v1/preflight", map[string]any{
		"vaultId": tenantB, "psbt": draftOut.PSBT,
	})
	var pre OutChallenge
	if err := json.Unmarshal(preRaw, &pre); err != nil || pre.Challenge == "" {
		t.Fatalf("preflight: %s", preRaw)
	}
	challenge, err := hex.DecodeString(pre.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := webauthn.Synth(passB, credB, challenge, fixture.Origin, fixture.RPID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	directSig, err := webauthn.SignDigestLowS(dirB, challenge)
	if err != nil {
		t.Fatal(err)
	}
	bindRaw := httpJSON(t, h, http.MethodPost, "/v1/bind", map[string]any{
		"vaultId": tenantB, "psbt": draftOut.PSBT,
		"credentialId":      hex.EncodeToString(credB),
		"clientDataJSON":    hex.EncodeToString(assertion.ClientDataJSON),
		"authenticatorData": hex.EncodeToString(assertion.AuthenticatorData),
		"signature":         hex.EncodeToString(assertion.DERSignature),
		"directSig":         hex.EncodeToString(directSig),
	})
	var bindOut struct {
		PSBT string `json:"psbt"`
	}
	if err := json.Unmarshal(bindRaw, &bindOut); err != nil || bindOut.PSBT == "" {
		t.Fatalf("bind: %s", bindRaw)
	}
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(bindOut.PSBT), true)
	if err != nil {
		t.Fatal(err)
	}
	hotSig, err := vault.SignLeaf(ptx.UnsignedTx, ptx.Inputs[0].WitnessUtxo, opB.Leaves.Routine.Script, hotB)
	if err != nil {
		t.Fatal(err)
	}
	vault.AddPartialSig(ptx, hotB.PubKey(), opB.Leaves.Routine.Hash, hotSig)
	signedPhone, err := ptx.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	authRaw := httpJSON(t, h, http.MethodPost, "/v1/authorize", map[string]any{
		"vaultId": tenantB, "psbt": signedPhone,
		"credentialId":      hex.EncodeToString(credB),
		"clientDataJSON":    hex.EncodeToString(assertion.ClientDataJSON),
		"authenticatorData": hex.EncodeToString(assertion.AuthenticatorData),
		"signature":         hex.EncodeToString(assertion.DERSignature),
	})
	var authOut struct {
		SignedPSBT string `json:"signedPsbt"`
	}
	if err := json.Unmarshal(authRaw, &authOut); err != nil || authOut.SignedPSBT == "" {
		t.Fatalf("authorize: %s", authRaw)
	}
	pubRaw := httpJSON(t, h, http.MethodPost, "/v1/publish", map[string]any{
		"vaultId": tenantB, "challenge": pre.Challenge,
	})
	var pubOut struct {
		Txid string `json:"txid"`
	}
	if err := json.Unmarshal(pubRaw, &pubOut); err != nil || pubOut.Txid == "" {
		t.Fatalf("publish: %s", pubRaw)
	}
	if broadcast.callCount() != 1 {
		t.Fatalf("broadcasts = %d", broadcast.callCount())
	}

	spentA2, err := led.SpentInPeriod(context.Background(), fixture.VaultID, "")
	if err != nil {
		t.Fatal(err)
	}
	if spentA2 != spentA {
		t.Fatalf("B spend changed A allowance %d -> %d", spentA, spentA2)
	}
	stA, err := svc.StatusFor(context.Background(), fixture.VaultID)
	if err != nil || stA.OperationalAddr != addrA {
		t.Fatalf("A descriptor after B spend: %+v %v", stA, err)
	}
	spentB, err := led.SpentInPeriod(context.Background(), tenantB, "")
	if err != nil || spentB != 20_500 {
		t.Fatalf("B spent = %d err=%v", spentB, err)
	}
}

func TestPublicStatusIsRedactedWhileVaultQueryKeepsFirstVaultKiosk(t *testing.T) {
	e := newEnv(t)
	h := AuthorizerHandler(e.svc)
	rec := boundaryHTTPCall(t, h, http.MethodGet, "/v1/status", "", fixture.Origin, "")
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	var pub map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &pub); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"vaultId", "operationalAddress", "periodRemaining", "externalOwnerWalletPub"} {
		if _, ok := pub[leak]; ok {
			t.Fatalf("public status leaked %s: %s", leak, rec.Body.String())
		}
	}
	rec = boundaryHTTPCall(t, h, http.MethodGet, "/v1/status?vault="+fixture.VaultID, "", fixture.Origin, "")
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	var st Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Enrolled || st.VaultID != fixture.VaultID || st.OperationalAddr == "" {
		t.Fatalf("first-vault query: %+v", st)
	}
}

type OutChallenge struct {
	Challenge string `json:"challenge"`
}
