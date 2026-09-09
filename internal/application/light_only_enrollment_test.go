package application

import (
	"context"
	"strings"
	"testing"
)

func TestLightOnlyEnrollmentRejectsStandardEndpointsBeforeEffects(t *testing.T) {
	s := &Service{LightOnlyEnrollment: true}
	_, start := s.StartEnrollment("", EnrollStartRequest{})
	_, propose := s.ProposeEnrollment("", EnrollFinishRequest{})
	_, finish := s.FinishEnrollment(context.Background(), "", EnrollFinishRequest{})
	for name, err := range map[string]error{"start": start, "propose": propose, "finish": finish} {
		if err == nil || !strings.Contains(err.Error(), "Please choose Light") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestLightOnlyEnrollmentKeepsLightFinishAndExistingStatus(t *testing.T) {
	svc, token, start, req, _ := lightEnrollmentFixture(t, true)
	svc.LightOnlyEnrollment = true
	status, err := svc.PublicStatus()
	if err != nil {
		t.Fatal(err)
	}
	if len(status.SupportedSetups) != 1 || status.SupportedSetups[0] != "light" || status.ConnectorCapability != nil || status.LedgerSavingsCapability != nil {
		t.Fatal("non-Light enrollment advertised")
	}
	if _, err := svc.FinishLightEnrollment(context.Background(), token, req); err != nil {
		t.Fatal(err)
	}
	if err := svc.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StatusFor(context.Background(), start.VaultID); err != nil {
		t.Fatal(err)
	}
}
