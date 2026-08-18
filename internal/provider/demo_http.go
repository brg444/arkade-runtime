package provider

import (
	"net/http"
)

type demoFundRequest struct {
	Amount int64 `json:"amount"`
}

type demoMineRequest struct {
	Blocks int `json:"blocks"`
}

func (d *Demo) attach(mux *http.ServeMux, origin string) {
	mux.HandleFunc("GET /v1/demo/info", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, d.info(), nil)
	})
	mux.HandleFunc("POST /v1/demo/fund", func(w http.ResponseWriter, r *http.Request) {
		var req demoFundRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		out, err := d.fund(r.Context(), req.Amount)
		writeJSON(w, out, err)
	})
	mux.HandleFunc("POST /v1/demo/mine", func(w http.ResponseWriter, r *http.Request) {
		var req demoMineRequest
		if err := decodeMutation(r, &req, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true}, d.mine(r.Context(), req.Blocks))
	})
	// Collaborative publication is /v1/publish (challenge only), not a client PSBT.
	// Owner-path HTTP is not offered. The second-signer key is not held here.
}
