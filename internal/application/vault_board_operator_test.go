package application

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/brg444/vaulted-guardian/internal/deployment"
)

const vaultBoardTestOperatorDigest = "2e14a884689aba877ecdf423a61862f01b9627927e65cccf119c2aee48fdf4d9"

func vaultBoardOperatorInfoJSON(digest string) string {
	return fmt.Sprintf(
		`{"network":%q,"checkpointTapscript":%q,"signerPubkey":%q,"forfeitPubkey":%q,"unilateralExitDelay":"2048","boardingExitDelay":"604672","dust":"330","digest":%q,"fees":{"intentFee":{"offchainInput":"","offchainOutput":"","onchainInput":"","onchainOutput":""}}}`,
		deployment.NetworkMutinynet, deployment.MutinynetCheckpointTapscriptHex,
		deployment.MutinynetOperatorSignerPubHex, deployment.MutinynetCheckpointForfeitPubHex, digest,
	)
}

func TestVaultBoardOperatorUsesOnlyPinnedStockPublicRoutes(t *testing.T) {
	step := 0
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		step++
		if req.URL.Scheme != "https" || req.URL.Host != "mutinynet.arkade.sh" {
			t.Fatalf("unexpected Operator origin: %s", req.URL)
		}
		if step == 1 {
			if req.Method != http.MethodGet || req.URL.Path != "/v1/info" {
				t.Fatalf("unexpected dial request: %s %s", req.Method, req.URL.Path)
			}
			return jsonResponse(http.StatusOK, vaultBoardOperatorInfoJSON(vaultBoardTestOperatorDigest)), nil
		}
		if req.Method != http.MethodPost || req.Header.Get("X-Digest") != vaultBoardTestOperatorDigest ||
			req.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected Operator request: %s %#v", req.Method, req.Header)
		}
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		switch step {
		case 2:
			if req.URL.Path != "/v1/batch/registerIntent" || len(body) != 1 || body["intent"] == nil {
				t.Fatalf("register request: %s %s", req.URL.Path, raw)
			}
			return jsonResponse(http.StatusOK, `{"intentId":"intent-123"}`), nil
		case 3:
			if req.URL.Path != "/v1/batch/deleteIntent" || len(body) != 1 || body["intent"] == nil {
				t.Fatalf("delete request: %s %s", req.URL.Path, raw)
			}
			return jsonResponse(http.StatusOK, `{}`), nil
		case 4:
			if req.URL.Path != "/v1/batch/submitForfeitTxs" || string(body["signedForfeitTxs"]) != "[]" || string(body["signedCommitmentTx"]) != `"commitment"` {
				t.Fatalf("final request: %s %s", req.URL.Path, raw)
			}
			return jsonResponse(http.StatusOK, `{}`), nil
		default:
			t.Fatalf("unexpected request %d", step)
			return nil, nil
		}
	})
	operator, err := dialVaultBoardOperatorWithClient(context.Background(), deployment.MutinynetArkIndexerOrigin, deployment.NetworkMutinynet, doer)
	if err != nil {
		t.Fatal(err)
	}
	intentID, err := operator.registerIntent(context.Background(), "proof", "message")
	if err != nil || intentID != "intent-123" {
		t.Fatalf("register = %q, %v", intentID, err)
	}
	if err := operator.deleteIntent(context.Background(), "delete-proof", "delete-message"); err != nil {
		t.Fatal(err)
	}
	if err := operator.submitCommitment(context.Background(), "commitment"); err != nil {
		t.Fatal(err)
	}
	if step != 4 {
		t.Fatalf("request count = %d", step)
	}
}

func TestVaultBoardOperatorFailsClosedOnIdentityAndAmbiguousResponse(t *testing.T) {
	infoDoer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, vaultBoardOperatorInfoJSON("not-a-digest")), nil
	})
	if _, err := dialVaultBoardOperatorWithClient(context.Background(), deployment.MutinynetArkIndexerOrigin, deployment.NetworkMutinynet, infoDoer); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("invalid digest accepted: %v", err)
	}
	if _, err := dialVaultBoardOperatorWithClient(context.Background(), "https://attacker.example", deployment.NetworkMutinynet, infoDoer); err == nil || !strings.Contains(err.Error(), "release pin") {
		t.Fatalf("attacker origin accepted: %v", err)
	}

	step := 0
	ambiguousDoer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
		step++
		if step == 1 {
			return jsonResponse(http.StatusOK, vaultBoardOperatorInfoJSON(vaultBoardTestOperatorDigest)), nil
		}
		return nil, fmt.Errorf("connection reset")
	})
	operator, err := dialVaultBoardOperatorWithClient(context.Background(), deployment.MutinynetArkIndexerOrigin, deployment.NetworkMutinynet, ambiguousDoer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operator.registerIntent(context.Background(), "proof", "message"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("response loss was not ambiguous: %v", err)
	}
}

func TestVaultBoardOperatorRejectsResponseShapeDrift(t *testing.T) {
	step := 0
	doer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
		step++
		if step == 1 {
			return jsonResponse(http.StatusOK, vaultBoardOperatorInfoJSON(vaultBoardTestOperatorDigest)), nil
		}
		return jsonResponse(http.StatusOK, `{"intentId":"intent","unexpected":true}`), nil
	})
	operator, err := dialVaultBoardOperatorWithClient(context.Background(), deployment.MutinynetArkIndexerOrigin, deployment.NetworkMutinynet, doer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operator.registerIntent(context.Background(), "proof", "message"); err == nil || !strings.Contains(err.Error(), "response shape") {
		t.Fatalf("response drift accepted: %v", err)
	}
}

func TestVaultBoardOperatorClassifiesOnlyStockPreAcceptanceRejections(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		definite bool
	}{
		{name: "invalid argument", status: http.StatusBadRequest, definite: true},
		{name: "stale digest", status: http.StatusPreconditionFailed, definite: true},
		{name: "conflict may follow acceptance", status: http.StatusConflict, definite: false},
		{name: "server error", status: http.StatusInternalServerError, definite: false},
		{name: "proxy timeout", status: http.StatusRequestTimeout, definite: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			step := 0
			doer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
				step++
				if step == 1 {
					return jsonResponse(http.StatusOK, vaultBoardOperatorInfoJSON(vaultBoardTestOperatorDigest)), nil
				}
				return jsonResponse(test.status, `{}`), nil
			})
			operator, err := dialVaultBoardOperatorWithClient(context.Background(), deployment.MutinynetArkIndexerOrigin, deployment.NetworkMutinynet, doer)
			if err != nil {
				t.Fatal(err)
			}
			_, err = operator.registerIntent(context.Background(), "proof", "message")
			if err == nil || isDefiniteVaultBoardRegisterRejection(err) != test.definite {
				t.Fatalf("error = %v, definite=%v", err, isDefiniteVaultBoardRegisterRejection(err))
			}
		})
	}
}
