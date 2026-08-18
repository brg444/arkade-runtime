package application

import "net/http"

// attachRegisterRoute is the regtest-only first-enrollment surface.
// AuthorizerHandler must not call this; Mutinynet enrollment is /v1/enroll/*.
func attachRegisterRoute(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("POST /v1/register", func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		err := svc.RegisterWithBootstrap(req, r.Header.Get(EnrollmentTokenHeader))
		writeJSON(w, map[string]any{"ok": err == nil}, err)
	})
}
