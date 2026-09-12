package application

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRetiredSavingsSetupRoutesAreUnavailable(t *testing.T) {
	e := newUnenrolledEnvForNetwork(t, "mutinynet")
	handler := testAuthorizer(e.svc)
	for _, phase := range []string{"info", "prepare", "register", "final", "status", "release"} {
		method := http.MethodPost
		if phase == "info" {
			method = http.MethodGet
		}
		for _, verb := range []string{method, http.MethodOptions} {
			t.Run(verb+"/"+phase, func(t *testing.T) {
				request := httptest.NewRequest(verb, "/v1/vtxo/savings-setup/"+phase, bytes.NewBufferString(`{}`))
				request.Header.Set("Origin", e.svc.ClientOrigin())
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusNotFound {
					t.Fatalf("retired route returned %d: %s", response.Code, response.Body.String())
				}
			})
		}
	}
}

func TestBitcoinPlanRejectsRetiredReserveAuthority(t *testing.T) {
	_, c, prepared, _ := bitcoinFundingFixture(t, "mainnet", "standard", 1)
	for name, mutate := range map[string]func(*bitcoinPaymentPlan){
		"missing outputs": func(p *bitcoinPaymentPlan) { p.Outputs = nil },
		"empty outputs":   func(p *bitcoinPaymentPlan) { p.Outputs = []bitcoinPaymentOutput{} },
		"reserve script":  func(p *bitcoinPaymentPlan) { p.ReserveScript = p.Outputs[0].Script },
		"reserve amount":  func(p *bitcoinPaymentPlan) { p.ReserveSats = 500 },
		"reserve count":   func(p *bitcoinPaymentPlan) { p.ReserveCount = 1 },
		"enrollment":      func(p *bitcoinPaymentPlan) { p.EnrollmentDigest = strings.Repeat("aa", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			plan := prepared.Plan
			mutate(&plan)
			if _, err := plan.digest(c); err == nil {
				t.Fatal("retired payment authority accepted")
			}
		})
	}
}
