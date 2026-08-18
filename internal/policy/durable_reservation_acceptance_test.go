package policy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// TestReservationIsDurableBeforeExternalSignerCanReleaseSignature is a
// release acceptance test for the budget/signature crash boundary.
//
// A usable provider signature can escape the process as soon as the external
// signer callback runs. Before that callback is entered, the reservation must
// therefore be committed and visible to an independent SQLite connection.
// Holding an uncommitted INSERT while signing is not sufficient: a process,
// container or power failure would roll it back while the signature survives.
func TestReservationIsDurableBeforeExternalSignerCanReleaseSignature(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "durability.sqlite")
	clock := func() time.Time {
		return time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	}
	issuer, err := OpenLedger(dbPath, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = issuer.Close() })

	var visibleBeforeSignature int64 = -1
	signed, replay, err := issuer.Issue(
		context.Background(), "vault-a", digest(0x9a), 75, 2, 100,
		func(context.Context) (string, error) {
			observer, err := OpenLedger(dbPath, clock)
			if err != nil {
				return "", err
			}
			if err := observer.SetIntegrityKey(testIntegrityKey()); err != nil {
				return "", err
			}
			defer observer.Close()
			visibleBeforeSignature, err = observer.SpentInPeriod(
				context.Background(), "vault-a", observer.PeriodStart(),
			)
			if err != nil {
				return "", err
			}
			return "externally-usable-signed-psbt", nil
		},
	)
	if err != nil || replay || signed == "" {
		t.Fatalf("issue fixture: signed=%q replay=%v err=%v", signed, replay, err)
	}
	if visibleBeforeSignature != 77 {
		t.Fatalf("second SQLite handle saw %d sats when signer callback began, want durable 77-sat recipient-plus-fee reservation before any signature can escape", visibleBeforeSignature)
	}
}

// TestAmbiguousSignerTimeoutRetainsDurableReservation models a signer that
// produced or retained a usable signature but whose response was lost. Once
// dispatch has happened, a timeout is not proof that signing failed. The
// reserved allowance must remain consumed until a separate reconciliation or
// expiry protocol proves that no signature can be used.
func TestAmbiguousSignerTimeoutRetainsDurableReservation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ambiguous-timeout.sqlite")
	clock := func() time.Time {
		return time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	}
	issuer, err := OpenLedger(dbPath, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = issuer.Close() })

	d := digest(0x9b)
	externalSignerRetainedUsableSignature := false
	_, replay, err := issuer.Issue(
		context.Background(), "vault-a", d, 75, 2, 100,
		func(context.Context) (string, error) {
			externalSignerRetainedUsableSignature = true
			return "", context.DeadlineExceeded
		},
	)
	if !errors.Is(err, context.DeadlineExceeded) || replay {
		t.Fatalf("ambiguous signer result: replay=%v err=%v", replay, err)
	}
	if !externalSignerRetainedUsableSignature {
		t.Fatal("test did not reach the modeled external-signature escape point")
	}

	spent, err := issuer.SpentInPeriod(
		context.Background(), "vault-a", issuer.PeriodStart(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if spent != 77 {
		t.Fatalf("ambiguous signer timeout left %d sats reserved, want 77 recipient-plus-fee sats because a usable signature may exist", spent)
	}

	var retrySignerCalled bool
	if _, _, retryErr := issuer.Issue(
		context.Background(), "vault-a", d, 75, 2, 100,
		func(context.Context) (string, error) {
			retrySignerCalled = true
			return "second-signature", nil
		},
	); retryErr == nil {
		t.Fatal("same digest was reissued after an ambiguous timeout")
	}
	if retrySignerCalled {
		t.Fatal("ambiguous reserved digest reached the signer again")
	}
}
