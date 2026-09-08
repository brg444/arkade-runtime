package application

import (
	"fmt"
	"net/http"
)

func attachSpendingBitcoinRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("GET /v1/vtxo/bitcoin/info", func(w http.ResponseWriter, r *http.Request) {
		if isNilInterface(svc.keys.bitcoinPayment) {
			writeJSON(w, nil, fmt.Errorf("Bitcoin payment capability unavailable"))
			return
		}
		c, err := svc.bitcoinPaymentContext(r.URL.Query().Get("vaultId"), true)
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
	mux.HandleFunc("POST /v1/vtxo/bitcoin/prepare", func(w http.ResponseWriter, r *http.Request) {
		var request spendingBitcoinPrepareRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.prepareSpendingBitcoin(r.Context(), request)
		writeJSON(w, response, err)
	})
	attachBitcoinPaymentLifecycle(mux, svc, origin, "/v1/vtxo/bitcoin")
}

func attachBitcoinPaymentLifecycle(mux *http.ServeMux, svc *Service, origin, prefix string) {
	mux.HandleFunc("POST "+prefix+"/register", func(w http.ResponseWriter, r *http.Request) {
		var request lightRenewalRegisterRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.registerBitcoinPayment(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST "+prefix+"/final", func(w http.ResponseWriter, r *http.Request) {
		var request lightRenewalFinalRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.finalizeBitcoinPayment(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST "+prefix+"/status", func(w http.ResponseWriter, r *http.Request) {
		var request lightRenewalOperationRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.reconcileBitcoinPayment(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST "+prefix+"/release", func(w http.ResponseWriter, r *http.Request) {
		var request bitcoinPaymentReleaseRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.releaseBitcoinPayment(r.Context(), request)
		writeJSON(w, response, err)
	})
}
