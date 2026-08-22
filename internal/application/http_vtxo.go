package application

import "net/http"

func attachVtxoRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("POST /v1/vtxo/reserve", func(w http.ResponseWriter, r *http.Request) {
		var request VtxoReserveRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.ReserveVtxo(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/vtxo/authorize", func(w http.ResponseWriter, r *http.Request) {
		var request VtxoAuthorizeRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.AuthorizeVtxoSpend(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/vtxo/checkpoints/authorize", func(w http.ResponseWriter, r *http.Request) {
		var request VtxoCheckpointAuthorizeRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.AuthorizeVtxoCheckpoints(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/vtxo/finalize", func(w http.ResponseWriter, r *http.Request) {
		var request VtxoFinalizeRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.FinalizeVtxo(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("GET /v1/vtxo/operation", func(w http.ResponseWriter, r *http.Request) {
		response, err := svc.GetVtxoOperationView(
			r.Context(),
			r.URL.Query().Get("vaultId"),
			r.URL.Query().Get("operationId"),
		)
		writeJSON(w, response, err)
	})
}
