// Package httpapi is the Mutinynet HTTP surface. It parses and maps errors.
// It does not own keys or the ledger.
package httpapi

import (
	"net/http"

	"github.com/brg444/arkade-vault-server/internal/application"
)

// Authorizer is the protected software-box surface. No static files, demo
// routes, or raw signing path.
func Authorizer(svc *application.Service) http.Handler {
	return application.AuthorizerHandler(svc)
}

// NewServer applies the listen timeouts around the authorizer handler.
func NewServer(addr string, h http.Handler) *http.Server {
	return application.NewServer(addr, h)
}
