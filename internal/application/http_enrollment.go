package application

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/brg444/arkade-vault-server/internal/program"
)

func attachEnrollmentRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		vaultID := strings.TrimSpace(r.URL.Query().Get("vault"))
		if vaultID == "" {
			status, err := svc.PublicStatus()
			if err != nil || svc == nil || svc.VaultBoardV2Store == nil {
				writeJSON(w, status, err)
				return
			}
			writeJSON(w, struct {
				PublicStatus
				VtxoBoardingProgram string `json:"vtxoBoardingProgram"`
			}{PublicStatus: status, VtxoBoardingProgram: program.VaultBoardV2}, nil)
			return
		}
		status, err := svc.StatusFor(r.Context(), vaultID)
		if err != nil || svc == nil || svc.VaultBoardV2Store == nil {
			writeJSON(w, status, err)
			return
		}
		snap := svc.snapshot(vaultID)
		cred, loadErr := svc.loadVerifiedCredentialFor(vaultID)
		if loadErr != nil || cred == nil || snap.BoardV2 == nil {
			if loadErr == nil {
				loadErr = fmt.Errorf("vault-board-v2 enrollment descriptor unavailable")
			}
			writeJSON(w, nil, loadErr)
			return
		}
		desc, hash, descErr := svc.statusVaultBoardV2Descriptor(cred, snap)
		writeJSON(w, struct {
			Status
			VtxoBoardingDescriptor     vaultBoardV2PublicDescriptor `json:"vtxoBoardingDescriptor"`
			VtxoBoardingDescriptorHash string                       `json:"vtxoBoardingDescriptorHash"`
		}{Status: status, VtxoBoardingDescriptor: desc.Boarding, VtxoBoardingDescriptorHash: hash}, descErr)
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
		response, err := svc.StartEnrollment(r.Header.Get(EnrollmentTokenHeader))
		writeJSON(w, response, err)
	})
	if svc == nil || svc.VaultBoardV2Store == nil {
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
	} else {
		mux.HandleFunc("POST /v1/vtxo/board/enroll/propose", func(w http.ResponseWriter, r *http.Request) {
			var request EnrollFinishVaultBoardV2Request
			if err := decodeMutation(r, &request, origin); err != nil {
				writeMutationError(w, err)
				return
			}
			response, err := svc.ProposeVaultBoardV2Enrollment(r.Header.Get(EnrollmentTokenHeader), request)
			writeJSON(w, response, err)
		})
		mux.HandleFunc("POST /v1/vtxo/board/enroll/finish", func(w http.ResponseWriter, r *http.Request) {
			var request EnrollFinishVaultBoardV2Request
			if err := decodeMutation(r, &request, origin); err != nil {
				writeMutationError(w, err)
				return
			}
			response, err := svc.FinishVaultBoardV2Enrollment(r.Context(), r.Header.Get(EnrollmentTokenHeader), request)
			writeJSON(w, response, err)
		})
	}
}
