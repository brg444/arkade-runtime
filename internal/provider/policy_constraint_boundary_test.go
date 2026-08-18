package provider

import (
	"bytes"
	"context"
	"testing"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/wire"
)

// TestLocalSignerRejectsCapturedAssertionOnADifferentTransaction is a release
// acceptance test for the raw Arkade signing boundary. Provider-side semantic
// validation is not enough: the script executed by LocalSigner (and therefore
// SubmitOnchainTx) must reject authorization material captured from spend A
// when it is attached to changed spend B.
func TestLocalSignerRejectsCapturedAssertionOnADifferentTransaction(t *testing.T) {
	e := newBoundaryEnv(t)
	spendA := e.canonicalDraft(t, 90_000, 20_000, 500)
	spendB := e.canonicalDraft(t, 90_000, 21_000, 500)
	chA, err := vault.Challenge(spendA, e.service.Operational)
	if err != nil {
		t.Fatal(err)
	}
	chB, err := vault.Challenge(spendB, e.service.Operational)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(chA, chB) {
		t.Fatal("test setup failed: spends share an Arkade challenge")
	}

	assertion, err := webauthn.Synth(
		e.passkeyPriv, e.credentialID, chA, fixture.Origin, fixture.RPID, true, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := e.service.Ledger.GetCredential()
	if err != nil || cred == nil {
		t.Fatalf("enrolled credential: %v", err)
	}
	if _, err := webauthn.Validate(assertion, webauthn.Expected{
		CredentialID: e.credentialID,
		WebAuthnP256: cred.WebAuthnP256,
		Challenge:    chB,
		Origin:       fixture.Origin,
		RPID:         fixture.RPID,
	}); err == nil {
		t.Fatal("provider semantic validation accepted assertion replay on spend B")
	}

	directSigA, err := webauthn.SignDigestLowS(e.directPriv, chA)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.SetPacketWitness(spendB.UnsignedTx, wire.TxWitness{directSigA}); err != nil {
		t.Fatal(err)
	}
	hotSig, err := vault.SignLeaf(
		spendB.UnsignedTx, spendB.Inputs[0].WitnessUtxo,
		e.service.Operational.Leaves.Routine.Script, e.hotPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	vault.AddPartialSig(spendB, e.hotPriv.PubKey(), e.service.Operational.Leaves.Routine.Hash, hotSig)

	if signed, err := (LocalSigner{Priv: e.providerPriv}).Sign(context.Background(), spendB); err == nil {
		t.Fatalf("LocalSigner released a provider signature for authorization material captured from another transaction: provider_signatures=%d", len(signed.Inputs[0].TaprootScriptSpendSig))
	}
}
