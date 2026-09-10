package application

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
)

func attachEnrollmentRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		vaultID := strings.TrimSpace(r.URL.Query().Get("vault"))
		if vaultID == "" {
			status, err := svc.PublicStatus()
			writeJSON(w, struct {
				PublicStatus
				VtxoBoardingProgram string `json:"vtxoBoardingProgram"`
			}{PublicStatus: status, VtxoBoardingProgram: program.VaultBoardV1}, err)
			return
		}
		status, err := svc.StatusFor(r.Context(), vaultID)
		if err != nil {
			writeJSON(w, status, err)
			return
		}
		if status.LightDescriptor != nil {
			writeJSON(w, status, nil)
			return
		}
		snap := svc.snapshot(vaultID)
		cred, loadErr := svc.loadVerifiedCredentialFor(vaultID)
		if loadErr != nil || cred == nil || snap.Board == nil {
			if loadErr == nil {
				loadErr = fmt.Errorf("vault-board-v1 enrollment descriptor unavailable")
			}
			writeJSON(w, nil, loadErr)
			return
		}
		if cred.TemplateVersion == program.SpendingOnlyTemplate {
			desc, hash, descErr := svc.storedSpendingEnrollmentDescriptor(cred, snap)
			writeJSON(w, struct {
				Status
				SpendingDescriptor         spendingEnrollmentDescriptor `json:"spendingDescriptor"`
				VtxoBoardingDescriptor     vaultBoardPublicDescriptor   `json:"vtxoBoardingDescriptor"`
				VtxoBoardingDescriptorHash string                       `json:"vtxoBoardingDescriptorHash"`
			}{status, desc, desc.Boarding, hash}, descErr)
			return
		}
		if cred.TemplateVersion == savings.LedgerNativeTemplate {
			enrolled, _, verifiedErr := svc.verifiedLedgerSavings(cred)
			if verifiedErr != nil {
				writeJSON(w, nil, verifiedErr)
				return
			}
			board, _, boardErr := svc.buildVaultBoardEnrollment(vaultID, parsedRegisterRequest{phone: snap.PhoneBIP340, boardPub: snap.Board.BoardingPub, boardingProgram: program.VaultBoardV1})
			writeJSON(w, struct {
				Status
				VtxoBoardingDescriptor     vaultBoardPublicDescriptor `json:"vtxoBoardingDescriptor"`
				VtxoBoardingDescriptorHash string                     `json:"vtxoBoardingDescriptorHash"`
			}{status, board, enrolled.DescriptorHash}, boardErr)
			return
		}
		desc, hash, descErr := svc.statusVaultBoardDescriptor(cred, snap)
		writeJSON(w, struct {
			Status
			VtxoBoardingDescriptor     vaultBoardPublicDescriptor `json:"vtxoBoardingDescriptor"`
			VtxoBoardingDescriptorHash string                     `json:"vtxoBoardingDescriptorHash"`
		}{Status: status, VtxoBoardingDescriptor: desc.Boarding, VtxoBoardingDescriptorHash: hash}, descErr)
	})
	mux.HandleFunc("POST /v1/enroll/session", func(w http.ResponseWriter, r *http.Request) {
		var request struct{}
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.IssueEnrollmentSession()
		writeJSON(w, response, err)
	})
	mux.HandleFunc("GET /v1/invite", func(w http.ResponseWriter, r *http.Request) {
		view, err := svc.InviteStatus(r.Header.Get(EnrollmentTokenHeader))
		writeJSON(w, view, err)
	})
	mux.HandleFunc("POST /v1/enroll/start", func(w http.ResponseWriter, r *http.Request) {
		var request EnrollStartRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.StartEnrollment(r.Header.Get(EnrollmentTokenHeader), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/enroll/propose", func(w http.ResponseWriter, r *http.Request) {
		var request EnrollFinishRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.ProposeEnrollment(r.Header.Get(EnrollmentTokenHeader), request)
		writeJSON(w, response, err)
	})
	mux.HandleFunc("POST /v1/enroll/finish", func(w http.ResponseWriter, r *http.Request) {
		var request EnrollFinishRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		response, err := svc.FinishEnrollment(r.Context(), r.Header.Get(EnrollmentTokenHeader), request)
		writeJSON(w, response, err)
	})
}
