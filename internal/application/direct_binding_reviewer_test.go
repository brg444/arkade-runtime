package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

func TestReviewerBindPublishesOnlyExecutableDirectP256Signature(t *testing.T) {
	e := newBoundaryEnv(t)
	draft := e.canonicalDraft(t, 90_000, 20_000, 500)
	challenge, err := vault.Challenge(draft, e.service.Operational)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := webauthn.Synth(
		e.passkeyPriv, e.credentialID, challenge,
		fixture.Origin, fixture.RPID, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	directSig, err := webauthn.SignDigestLowS(e.directPriv, challenge)
	if err != nil {
		t.Fatal(err)
	}
	draftB64, err := draft.B64Encode()
	if err != nil {
		t.Fatal(err)
	}

	boundB64, err := e.service.Bind(BindRequest{
		PSBT:              draftB64,
		CredentialID:      hex.EncodeToString(e.credentialID),
		ClientDataJSON:    hex.EncodeToString(assertion.ClientDataJSON),
		AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData),
		Signature:         hex.EncodeToString(assertion.DERSignature),
		DirectSig:         hex.EncodeToString(directSig),
	})
	if err != nil {
		t.Fatalf("bind valid separate-key authorization: %v", err)
	}
	bound, err := psbt.NewFromRawBytes(strings.NewReader(boundB64), true)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := arkade.FindEmulatorPacket(bound.UnsignedTx)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 1 || len(packet[0].Witness) != 1 ||
		!bytes.Equal(packet[0].Witness[0], directSig) {
		t.Fatalf("bound packet is not exactly the one-item direct signature: %#v", packet)
	}
	if len(packet[0].Witness[0]) != 64 {
		t.Fatalf("direct witness length = %d, want 64", len(packet[0].Witness[0]))
	}
	if !bytes.Contains(packet[0].Script, webauthn.CompressedP256(e.directPriv)) {
		t.Fatal("authorization script does not commit the PhoneDirectP256 public key")
	}
	if bytes.Contains(packet[0].Script, webauthn.CompressedP256(e.passkeyPriv)) {
		t.Fatal("authorization script commits the WebAuthn credential public key")
	}
	if _, err := (LocalSigner{Priv: e.providerPriv}).Sign(context.Background(), bound); err != nil {
		t.Fatalf("raw Arkade signer rejected Bind's direct packet: %v", err)
	}
}

func TestReviewerBindRejectsDirectP256SignatureFromAnotherTransaction(t *testing.T) {
	e := newBoundaryEnv(t)
	spendA := e.canonicalDraft(t, 90_000, 20_000, 500)
	spendB := e.canonicalDraft(t, 90_000, 21_000, 500)
	challengeA, err := vault.Challenge(spendA, e.service.Operational)
	if err != nil {
		t.Fatal(err)
	}
	challengeB, err := vault.Challenge(spendB, e.service.Operational)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(challengeA, challengeB) {
		t.Fatal("test setup failed: changed transactions share a challenge")
	}
	assertionB, err := webauthn.Synth(
		e.passkeyPriv, e.credentialID, challengeB,
		fixture.Origin, fixture.RPID, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	directSigA, err := webauthn.SignDigestLowS(e.directPriv, challengeA)
	if err != nil {
		t.Fatal(err)
	}
	spendBB64, err := spendB.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.service.Bind(BindRequest{
		PSBT:              spendBB64,
		CredentialID:      hex.EncodeToString(e.credentialID),
		ClientDataJSON:    hex.EncodeToString(assertionB.ClientDataJSON),
		AuthenticatorData: hex.EncodeToString(assertionB.AuthenticatorData),
		Signature:         hex.EncodeToString(assertionB.DERSignature),
		DirectSig:         hex.EncodeToString(directSigA),
	}); err == nil {
		t.Fatal("Bind accepted transaction A's direct signature for transaction B")
	}
}
