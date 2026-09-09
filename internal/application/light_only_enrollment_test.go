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
