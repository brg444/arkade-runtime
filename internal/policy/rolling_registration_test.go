package policy

import (
	"testing"
	"time"
)

func TestRollingRegistrationClaimSurvivesSQLiteRestart(t *testing.T) {
	l, now, op := rollingGrantFixture(t)
	if claimed, err := l.ClaimRollingRegistration(t.Context(), op.OperationID); err == nil || claimed {
		t.Fatal("registration claimed without authority")
	}
	if _, err := l.CommitRollingRenewalAuthorization(t.Context(), RollingEvent{OperationID: op.OperationID, Phase: "authorized", Evidence: `{}`}); err != nil {
		t.Fatal(err)
	}
	if claimed, err := l.ClaimRollingRegistration(t.Context(), op.OperationID); err == nil || claimed {
		t.Fatal("registration claimed without emulator approval")
	}
	if _, err := l.AppendRollingEvent(t.Context(), RollingEvent{OperationID: op.OperationID, Phase: "emulator_authorized", Evidence: `{}`}); err != nil {
		t.Fatal(err)
	}
	if claimed, err := l.ClaimRollingRegistration(t.Context(), op.OperationID); err != nil || !claimed {
		t.Fatal("first dispatch was not claimed", err)
	}
	var index int
	var name, path string
	if err := l.db.QueryRow(`PRAGMA database_list`).Scan(&index, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := OpenLedger(path, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if err = current.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(48 * time.Hour)
	if claimed, err := current.ClaimRollingRegistration(t.Context(), op.OperationID); err != nil || claimed {
		t.Fatal("restarted worker acquired prior dispatch", err)
	}
	if used, err := current.SpentInPeriod(t.Context(), op.VaultID, ""); err != nil || used != 100 {
		t.Fatal("uncertain restart released or duplicated renewal fee", used, err)
	}
}
