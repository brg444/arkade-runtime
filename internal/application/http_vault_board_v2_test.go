package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/wire"
)

func TestVaultBoardV2HTTPUsesNamedEnrollmentAndExactPhaseWire(t *testing.T) {
	fixtureState := newVaultBoardV2ServiceFixture(t)
	handler := testAuthorizer(fixtureState.svc)

	for _, path := range []string{"/v1/enroll/propose", "/v1/enroll/finish"} {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", fixture.Origin)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusNotFound {
			t.Fatalf("v2 downgrade route %s = %d", path, res.Code)
		}
	}

	var public struct {
		VtxoBoardingProgram string `json:"vtxoBoardingProgram"`
	}
	decodeHTTPJSON(t, httpJSON(t, handler, http.MethodGet, "/v1/status", nil), &public)
	if public.VtxoBoardingProgram != program.VaultBoardV2 {
		t.Fatalf("public named program = %q", public.VtxoBoardingProgram)
	}
	var tenant struct {
		VtxoBoardingDescriptor     vaultBoardV2PublicDescriptor `json:"vtxoBoardingDescriptor"`
		VtxoBoardingDescriptorHash string                       `json:"vtxoBoardingDescriptorHash"`
	}
	decodeHTTPJSON(t, httpJSON(t, handler, http.MethodGet, "/v1/status?vault="+fixtureState.vaultID, nil), &tenant)
	if tenant.VtxoBoardingDescriptor.Program != program.VaultBoardV2 || tenant.VtxoBoardingDescriptorHash == "" ||
		tenant.VtxoBoardingDescriptor.Address != fixtureState.proof.tree.OnchainAddress {
		t.Fatalf("tenant descriptor = %+v", tenant)
	}

	var prepared vaultBoardV2PrepareHTTPResponse
	decodeHTTPJSON(t, httpJSON(t, handler, http.MethodPost, "/v1/vtxo/board/prepare", vaultBoardV2PrepareRequest{
		VaultID:    fixtureState.vaultID,
		Inputs:     []vaultBoardV2PrepareInput{{Txid: hex.EncodeToString(fixtureState.proof.operation.Txid), Vout: fixtureState.proof.operation.Vout}},
		Recipients: []vaultBoardV2PrepareRecipient{{Address: fixtureState.receiver, AmountSats: uint64(fixtureState.proof.receiver.Value)}},
	}), &prepared)
	if prepared.Status != string(vaultBoardV2Ready) || prepared.Handle == "" || prepared.RegisterExpireAt == 0 {
		t.Fatalf("prepare response = %+v", prepared)
	}
	fixtureState.proof.expireAt = prepared.RegisterExpireAt
	message := fixtureState.proof.registerMessage(t)
	var messageDTO vaultBoardV2RegisterMessageDTO
	if err := json.Unmarshal([]byte(message), &messageDTO); err != nil {
		t.Fatal(err)
	}
	var registered vaultBoardV2RegisterHTTPResponse
	decodeHTTPJSON(t, httpJSON(t, handler, http.MethodPost, "/v1/vtxo/board/register", vaultBoardV2PhaseDTO[vaultBoardV2RegisterMessageDTO]{
		Handle: prepared.Handle, PSBT: fixtureState.proof.proof(t, message, []*wire.TxOut{fixtureState.proof.receiver}),
		InputIndexes: []int{0, 1}, Message: messageDTO,
	}), &registered)
	if registered.Status != string(vaultBoardV2Registered) || registered.IntentID == "" {
		t.Fatalf("register response = %+v", registered)
	}
}

func decodeHTTPJSON(t *testing.T, raw []byte, dest any) {
	t.Helper()
	if err := json.Unmarshal(raw, dest); err != nil {
		t.Fatal(err)
	}
}
