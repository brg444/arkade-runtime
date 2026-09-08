package application

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/brg444/arkade-runtime/internal/webauthn"
)

func TestRollingServiceRequiresBoundOwnerProofBeforeDurableSignatures(t *testing.T) {
	e, manager, _, _, proposal := rollingApplicationFixture(t)
	op, err := manager.Reserve(t.Context(), proposal)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := rolling.AuthorizationDigest(manager.contract, fixture.VaultID, op.Operation.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	config := e.svc.runtimeConfig()
	assertion, err := webauthn.SynthWithSignCount(e.p256, e.credID, digest[:], config.ClientOrigin, config.RPID, true, true, 7)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.SignDigestLowS(e.direct, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	req := rollingAuthorizationRequest{VaultID: fixture.VaultID, OperationID: op.Operation.OperationID, DirectSig: hex.EncodeToString(direct), WebAuthnAssertionRequest: WebAuthnAssertionRequest{CredentialID: hex.EncodeToString(e.credID), ClientDataJSON: hex.EncodeToString(assertion.ClientDataJSON), AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData), Signature: hex.EncodeToString(assertion.DERSignature)}}
	bad := req
	bad.DirectSig = strings.Repeat("00", 64)
	if _, err = e.svc.authorizeRollingOperation(t.Context(), manager, bad); err == nil {
		t.Fatal("unbound device proof authorized")
	}
	records, err := e.ledger.RollingOperations(t.Context(), fixture.VaultID)
	if err != nil || len(records[0].Events) != 0 {
		t.Fatal("failed proof persisted authority", err)
	}
	first, err := e.svc.authorizeRollingOperation(t.Context(), manager, req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.svc.authorizeRollingOperation(t.Context(), manager, req)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("lost response retry changed signatures", err)
	}
	records, err = e.ledger.RollingOperations(t.Context(), fixture.VaultID)
	if err != nil || len(records[0].Events) != 1 || records[0].Events["authorized"].Evidence == "" {
		t.Fatal("signature transcript not durable", err)
	}
	bad = req
	bad.VaultID = "different-vault"
	if _, err = e.svc.authorizeRollingOperation(t.Context(), manager, bad); err == nil {
		t.Fatal("cross-vault authorization accepted")
	}
}
