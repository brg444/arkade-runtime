package application

import (
	"fmt"
	"net/http"
)

func attachSavingsSetupRoutes(mux *http.ServeMux, svc *Service, origin string) {
	attachSpendingBitcoinRoutes(mux, svc, origin)
	mux.HandleFunc("GET /v1/vtxo/savings-setup/info", func(w http.ResponseWriter, r *http.Request) {
		if isNilInterface(svc.keys.bitcoinPayment) {
			writeJSON(w, nil, fmt.Errorf("Savings setup capability unavailable"))
			return
		}
		c, err := svc.bitcoinPaymentContext(r.URL.Query().Get("vaultId"))
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
	attachBitcoinPaymentLifecycle(mux, svc, origin, "/v1/vtxo/savings-setup")
}
