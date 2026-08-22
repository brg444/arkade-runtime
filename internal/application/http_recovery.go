package application

import "net/http"

func attachRecoveryRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("POST /v1/initiate", func(w http.ResponseWriter, r *http.Request) {
		var request TransitionRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		request.Purpose = "initiate"
		response, err := svc.SignTransition(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/clawback", func(w http.ResponseWriter, r *http.Request) {
		var request TransitionRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		request.Purpose = "clawback"
		response, err := svc.SignTransition(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/passkey/challenge", func(w http.ResponseWriter, r *http.Request) {
		var request PasskeyChallengeRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.IssuePasskeyChallengeFor(r.Context(), request.VaultID, request.Purpose)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/passkey/binding", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			VaultID string `json:"vaultId"`
			RecoveryBindingRequest
		}
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.BuildRecoveryBindingFor(request.VaultID, request.RecoveryBindingRequest)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/passkey/install", func(w http.ResponseWriter, r *http.Request) {
		var request InstallCredentialEnvelopeRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		err := svc.InstallCredentialEnvelope(r.Context(), request)
		writeJSON(w, map[string]any{"ok": err == nil}, err)
	})
	mux.HandleFunc("POST /v1/passkey/recover", func(w http.ResponseWriter, r *http.Request) {
		var request RecoverCredentialEnvelopeRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.RecoverCredentialEnvelope(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("GET /v1/map", func(w http.ResponseWriter, r *http.Request) {
		response, err := svc.GetMap(r.URL.Query().Get("vault"))
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/map", func(w http.ResponseWriter, r *http.Request) {
		var request MapWriteRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		err := svc.PutMap(r.Context(), request)
		writeJSON(w, map[string]any{"ok": err == nil}, err)
	})
}
