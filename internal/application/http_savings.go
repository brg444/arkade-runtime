package application

import (
	"context"
	"net/http"
)

func attachSavingsRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("POST /v1/preflight", func(w http.ResponseWriter, r *http.Request) {
		var request PreflightRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.PreflightRequestContext(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/draft", func(w http.ResponseWriter, r *http.Request) {
		var request DraftRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		encoded, err := svc.DraftContext(r.Context(), request)
		writeJSON(w, map[string]any{"psbt": encoded}, err)
	})
	mux.HandleFunc("POST /v1/bind", func(w http.ResponseWriter, r *http.Request) {
		var request BindRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		encoded, err := svc.BindContext(r.Context(), request)
		writeJSON(w, map[string]any{"psbt": encoded}, err)
	})
	mux.HandleFunc("POST /v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		var request AuthorizeRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		signed, requestPSBT, replay, err := svc.AuthorizeWithBoundRequest(r.Context(), request)
		writeJSON(w, map[string]any{"requestPsbt": requestPSBT, "signedPsbt": signed, "replay": replay}, err)
	})
	mux.HandleFunc("POST /v1/publish", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			VaultID   string `json:"vaultId"`
			Challenge string `json:"challenge"`
		}
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		operationContext, cancel := context.WithTimeout(r.Context(), publishOperationTimeout)
		defer cancel()
		response, err := svc.PublishVault(operationContext, request.VaultID, request.Challenge)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("GET /v1/tx", func(w http.ResponseWriter, r *http.Request) {
		operationContext, cancel := context.WithTimeout(r.Context(), publishOperationTimeout)
		defer cancel()
		response, err := svc.PublicationStatusVault(
			operationContext,
			r.URL.Query().Get("vaultId"),
			r.URL.Query().Get("challenge"),
		)
		writeJSON(w, response, err)
	})
}
