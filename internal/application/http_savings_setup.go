package application

import (
	"fmt"
	"net/http"
)

func attachSavingsSetupRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("GET /v1/vtxo/savings-setup/info", func(w http.ResponseWriter, r *http.Request) {
		if isNilInterface(svc.keys.savingsSetup) {
			writeJSON(w, nil, fmt.Errorf("Savings setup capability unavailable"))
			return
		}
		c, err := svc.savingsSetupContext(r.URL.Query().Get("vaultId"))
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		writeJSON(w, struct {
			Version        int    `json:"version"`
			MaxInputs      int    `json:"maxInputs"`
			DescriptorHash string `json:"descriptorHash"`
		}{1, 1, c.spending.DescriptorHash}, nil)
	})
	mux.HandleFunc("POST /v1/vtxo/savings-setup/prepare", func(w http.ResponseWriter, r *http.Request) {
		var request savingsSetupPrepareRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.prepareSavingsSetup(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/vtxo/savings-setup/register", func(w http.ResponseWriter, r *http.Request) {
		var request lightRenewalRegisterRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.registerSavingsSetup(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/vtxo/savings-setup/final", func(w http.ResponseWriter, r *http.Request) {
		var request lightRenewalFinalRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.finalizeSavingsSetup(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/vtxo/savings-setup/status", func(w http.ResponseWriter, r *http.Request) {
		var request lightRenewalOperationRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.reconcileSavingsSetup(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/vtxo/savings-setup/release", func(w http.ResponseWriter, r *http.Request) {
		var request savingsSetupReleaseRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.releaseSavingsSetup(r.Context(), request)
		writeJSON(w, response, err)
	})
}
