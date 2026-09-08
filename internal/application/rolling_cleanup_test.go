package application

import (
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/txscript"
)

func rollingRenewalApplicationFixture(t *testing.T) (*env, *RollingOperations, *fileBackedVaultKeys, *rollingResolverFixture, string) {
	t.Helper()
	e, manager, keys, resolver, payment := rollingApplicationFixture(t)
	now := e.ledger.NowUTC().Unix()
	built, err := rolling.BuildRenewal(manager.contract, payment.Sources, payment.Proof, 100, now, now+600)
	if err != nil {
		t.Fatal(err)
	}
	p := rolling.Proposal{Kind: rolling.RenewalOperation, Message: built.Message, Transaction: built.Proof.UnsignedTx, Sources: payment.Sources, Proof: payment.Proof, CheckpointExit: manager.contract.Parameters.CheckpointExit}
	saved, err := manager.Reserve(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	return e, manager, keys, resolver, saved.Operation.OperationID
}

func authorizeRollingFixture(t *testing.T, e *env, manager *RollingOperations, id string) RollingAuthorization {
	t.Helper()
	digest, err := rolling.AuthorizationDigest(manager.contract, fixture.VaultID, id)
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
	req := rollingAuthorizationRequest{VaultID: fixture.VaultID, OperationID: id, DirectSig: hex.EncodeToString(direct), WebAuthnAssertionRequest: WebAuthnAssertionRequest{CredentialID: hex.EncodeToString(e.credID), ClientDataJSON: hex.EncodeToString(assertion.ClientDataJSON), AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData), Signature: hex.EncodeToString(assertion.DERSignature)}}
	auth, err := e.svc.authorizeRollingOperation(t.Context(), manager, req)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

type rollingCleanupClock struct {
	*policy.Ledger
	now time.Time
}

func (s rollingCleanupClock) NowUTC() time.Time { return s.now }

func TestRollingCleanupRequiresDurableFenceAndRetainsExactProof(t *testing.T) {
	e, manager, keys, resolver, id := rollingRenewalApplicationFixture(t)
	if _, err := keys.authorizeRollingCleanup(t.Context(), fixture.VaultID, id); err == nil {
		t.Fatal("cleanup signed before fence")
	}
	registered := authorizeRollingFixture(t, e, manager, id)
	record, err := manager.operation(t.Context(), id)
	if err != nil || registered.Message != record.Operation.Proposal.Message {
		t.Fatal("renewal registration message missing", err)
	}
	packet, err := parsePSBT(registered.TransactionPSBT)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range packet.Inputs {
		if input.SighashType != txscript.SigHashAll || len(input.TaprootScriptSpendSig) != 1 {
			t.Fatal("registration must commit the complete proof")
		}
	}
	first, err := e.svc.prepareRollingCleanup(t.Context(), manager, id)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := e.svc.prepareRollingCleanup(t.Context(), manager, id)
	if err != nil || !reflect.DeepEqual(first, retry) {
		t.Fatal("cleanup retry changed authority", err)
	}
	record, err = manager.operation(t.Context(), id)
	if err != nil || record.Events["cleanup_authorized"].Evidence == "" {
		t.Fatal("proof released without durable evidence", err)
	}
	if _, err = keys.authorizeRollingOperation(t.Context(), fixture.VaultID, id); err == nil {
		t.Fatal("cleanup reauthorized old registration")
	}
	if _, err = keys.authorizeRollingCleanup(t.Context(), "another-vault", id); err == nil {
		t.Fatal("cleanup crossed vault scope")
	}
	created, err := time.Parse(time.RFC3339, record.Events["cleanup_pending"].CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{created.Add(-time.Second), time.Unix(first.ExpiresAt, 0), created.Add(48 * time.Hour)} {
		keys.bindRollingJournal(rollingCleanupClock{e.ledger, now}, resolver)
		if _, err = keys.authorizeRollingCleanup(t.Context(), fixture.VaultID, id); err == nil {
			t.Fatal("clock rewind or expiry renewed cleanup authority")
		}
	}
	history, err := e.ledger.RollingHistory(t.Context(), fixture.VaultID)
	if err != nil || history.Pending == nil || history.Pending.OperationID != id {
		t.Fatal("uncertain cleanup released controller", err)
	}
}

func TestRollingCleanupResponseRejectsSubstitutionAndInvalidSignature(t *testing.T) {
	e, manager, _, _, id := rollingRenewalApplicationFixture(t)
	authorizeRollingFixture(t, e, manager, id)
	auth, err := e.svc.prepareRollingCleanup(t.Context(), manager, id)
	if err != nil {
		t.Fatal(err)
	}
	record, err := manager.operation(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"operation", "message", "expiry", "output", "signature", "missing-signature", "sighash"} {
		t.Run(mutation, func(t *testing.T) {
			bad := auth
			p, err := parsePSBT(auth.Proof)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "operation":
				bad.OperationID = "another-operation"
			case "message":
				bad.Message = record.Operation.Proposal.Message
			case "expiry":
				bad.ExpiresAt++
			case "output":
				p.UnsignedTx.TxOut[0].Value = 1
			case "signature":
				p.Inputs[1].TaprootScriptSpendSig[0].Signature[0] ^= 1
			case "missing-signature":
				p.Inputs[1].TaprootScriptSpendSig = nil
			case "sighash":
				p.Inputs[1].TaprootScriptSpendSig[0].SigHash = txscript.SigHashSingle
			}
			bad.Proof, err = p.B64Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err = verifyRollingCleanupAuthorization(manager.contract, record, record.Events["cleanup_pending"], bad); err == nil {
				t.Fatal("invalid cleanup response accepted")
			}
		})
	}
}
