package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorizerRejectsUnknownPaths(t *testing.T) {
	h := Authorizer(nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/onchain-tx", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}
