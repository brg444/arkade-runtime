package application

import (
	"fmt"
	"net/http"
	"strings"
)

func attachConnectorRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("POST /v1/connector/withdraw/authorize", func(w http.ResponseWriter, r *http.Request) {
		var request ConnectorWithdrawRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.AuthorizeConnectorWithdrawal(r.Context(), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("GET /v1/connector/operation", func(w http.ResponseWriter, r *http.Request) {
		vaultID := strings.TrimSpace(r.URL.Query().Get("vaultId"))
		if vaultID == "" {
			vaultID = strings.TrimSpace(r.URL.Query().Get("vault"))
		}
		operationID := strings.TrimSpace(r.URL.Query().Get("operationId"))
		if vaultID == "" || operationID == "" {
			writeJSON(w, nil, fmt.Errorf("vault id and operation id required"))
			return
		}
		response, err := svc.GetConnectorOperationView(r.Context(), vaultID, operationID)
		writeJSON(w, response, err)
	})
}
