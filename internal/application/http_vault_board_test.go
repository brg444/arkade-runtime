package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brg444/vaulted-guardian/fixture"
	"github.com/brg444/vaulted-guardian/internal/program"
	"github.com/btcsuite/btcd/wire"
)

func TestVaultBoardHTTPUsesNamedEnrollmentAndExactPhaseWire(t *testing.T) {
	fixtureState := newVaultBoardServiceFixture(t)
	handler := testAuthorizer(fixtureState.svc)

	for _, path := range []string{"/v1/enroll/propose", "/v1/enroll/finish"} {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", fixture.Origin)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("mandatory enrollment route %s = %d", path, res.Code)
		}
	}

	var public struct {
		VtxoBoardingProgram string `json:"vtxoBoardingProgram"`
	}
	decodeHTTPJSON(t, httpJSON(t, handler, http.MethodGet, "/v1/status", nil), &public)
	if public.VtxoBoardingProgram != program.VaultBoardV1 {
		t.Fatalf("public named program = %q", public.VtxoBoardingProgram)
	}
	var tenant struct {
		VtxoBoardingDescriptor     vaultBoardPublicDescriptor `json:"vtxoBoardingDescriptor"`
		VtxoBoardingDescriptorHash string                     `json:"vtxoBoardingDescriptorHash"`
	}
	decodeHTTPJSON(t, httpJSON(t, handler, http.MethodGet, "/v1/status?vault="+fixtureState.vaultID, nil), &tenant)
	if tenant.VtxoBoardingDescriptor.Program != program.VaultBoardV1 || tenant.VtxoBoardingDescriptorHash == "" ||
		tenant.VtxoBoardingDescriptor.Address != fixtureState.proof.tree.OnchainAddress {
		t.Fatalf("tenant descriptor = %+v", tenant)
	}

	var prepared vaultBoardPrepareHTTPResponse
	decodeHTTPJSON(t, httpJSON(t, handler, http.MethodPost, "/v1/vtxo/board/prepare", vaultBoardPrepareRequest{
		VaultID:    fixtureState.vaultID,
		Inputs:     []vaultBoardPrepareInput{{Txid: hex.EncodeToString(fixtureState.proof.operation.Txid), Vout: fixtureState.proof.operation.Vout}},
		Recipients: []vaultBoardPrepareRecipient{{Address: fixtureState.receiver, AmountSats: uint64(fixtureState.proof.receiver.Value)}},
	}), &prepared)
	if prepared.Status != string(vaultBoardReady) || prepared.Handle == "" || prepared.RegisterExpireAt == 0 {
		t.Fatalf("prepare response = %+v", prepared)
	}
	fixtureState.proof.expireAt = prepared.RegisterExpireAt
	message := fixtureState.proof.registerMessage(t)
	var messageDTO vaultBoardRegisterMessageDTO
	if err := json.Unmarshal([]byte(message), &messageDTO); err != nil {
		t.Fatal(err)
	}
	var registered vaultBoardRegisterHTTPResponse
	decodeHTTPJSON(t, httpJSON(t, handler, http.MethodPost, "/v1/vtxo/board/register", vaultBoardPhaseDTO[vaultBoardRegisterMessageDTO]{
		Handle: prepared.Handle, PSBT: fixtureState.proof.proof(t, message, []*wire.TxOut{fixtureState.proof.receiver}),
		InputIndexes: []int{0, 1}, Message: messageDTO,
	}), &registered)
	if registered.Status != string(vaultBoardRegistered) || registered.IntentID == "" {
		t.Fatalf("register response = %+v", registered)
	}
}

func decodeHTTPJSON(t *testing.T, raw []byte, dest any) {
	t.Helper()
	if err := json.Unmarshal(raw, dest); err != nil {
		t.Fatal(err)
	}
}
