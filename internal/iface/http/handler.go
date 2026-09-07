// Package httpapi forwards HTTP composition to the application package.
package httpapi

import (
	"net/http"

	"github.com/brg444/arkade-runtime/internal/application"
)

// Authorizer is the protected software-box surface. No static files or raw
// signing path is registered here.
func Authorizer(svc *application.Service) http.Handler {
	return application.AuthorizerHandler(svc)
}

// NewServer applies the listen timeouts around the authorizer handler.
func NewServer(addr string, h http.Handler) *http.Server {
	return application.NewServer(addr, h)
}
