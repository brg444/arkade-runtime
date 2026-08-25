package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/brg444/arkade-vault-server/internal/deployment"
)

const (
	vaultBoardV2OperatorResponseLimit = 16 * 1024
	vaultBoardV2OperatorErrorLimit    = 4 * 1024
)

type vaultBoardV2Operator interface {
	registerIntent(context.Context, string, string) (string, error)
	deleteIntent(context.Context, string, string) error
	submitCommitment(context.Context, string) error
}

type stockVaultBoardV2Operator struct {
	origin string
	digest string
	hc     httpDoer
}

// vaultBoardV2OperatorRejection is limited to HTTP statuses that stock arkd
// returns before RegisterIntent reaches its cache Push boundary. It is useful
// only for register: delete no-match and final rejection remain fail-closed.
type vaultBoardV2OperatorRejection struct {
	status int
}

func (e vaultBoardV2OperatorRejection) Error() string {
	return fmt.Sprintf("vault-board-v2 Operator rejected request with HTTP %d", e.status)
}

func isDefiniteVaultBoardV2RegisterRejection(err error) bool {
	_, ok := err.(vaultBoardV2OperatorRejection)
	return ok
}

func dialVaultBoardV2OperatorWithClient(ctx context.Context, rawOrigin string, hc httpDoer) (vaultBoardV2Operator, error) {
	origin, err := canonicalHTTPSOrigin(rawOrigin)
	if err != nil || origin != deployment.MutinynetArkIndexerOrigin {
		return nil, fmt.Errorf("vault-board-v2 Operator origin must be the release pin")
	}
	if hc == nil {
		return nil, fmt.Errorf("vault-board-v2 Operator HTTP client required")
	}
	resolver := &arkResolver{origin: origin, hc: hc, network: deployment.NetworkMutinynet}
	info, err := resolver.getInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("vault-board-v2 Operator info: %w", err)
	}
	if _, _, _, err := validateArkResolverReleaseInfo(deployment.NetworkMutinynet, info); err != nil {
		return nil, err
	}
	if err := requireTxid(info.Digest); err != nil {
		return nil, fmt.Errorf("vault-board-v2 Operator digest required")
	}
	return &stockVaultBoardV2Operator{origin: origin, digest: info.Digest, hc: hc}, nil
}

func (o *stockVaultBoardV2Operator) registerIntent(ctx context.Context, proof, message string) (string, error) {
	request := struct {
		Intent struct {
			Proof   string `json:"proof"`
			Message string `json:"message"`
		} `json:"intent"`
	}{}
	request.Intent.Proof = proof
	request.Intent.Message = message
	var response struct {
		IntentID string `json:"intentId"`
	}
	if err := o.post(ctx, "/v1/batch/registerIntent", request, &response); err != nil {
		return "", err
	}
	if response.IntentID == "" || len(response.IntentID) > 256 {
		return "", fmt.Errorf("vault-board-v2 Operator returned invalid intent id")
	}
	return response.IntentID, nil
}

func (o *stockVaultBoardV2Operator) deleteIntent(ctx context.Context, proof, message string) error {
	request := struct {
		Intent struct {
			Proof   string `json:"proof"`
			Message string `json:"message"`
		} `json:"intent"`
	}{}
	request.Intent.Proof = proof
	request.Intent.Message = message
	return o.post(ctx, "/v1/batch/deleteIntent", request, nil)
}

func (o *stockVaultBoardV2Operator) submitCommitment(ctx context.Context, signedCommitment string) error {
	request := struct {
		SignedForfeitTxs   []string `json:"signedForfeitTxs"`
		SignedCommitmentTx string   `json:"signedCommitmentTx"`
	}{SignedForfeitTxs: []string{}, SignedCommitmentTx: signedCommitment}
	return o.post(ctx, "/v1/batch/submitForfeitTxs", request, nil)
}

func (o *stockVaultBoardV2Operator) post(ctx context.Context, path string, payload, response any) error {
	if o == nil || o.hc == nil || o.origin != deployment.MutinynetArkIndexerOrigin || requireTxid(o.digest) != nil {
		return fmt.Errorf("vault-board-v2 Operator is not release-pinned")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	defer zeroServiceBytes(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.origin+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Digest", o.digest)
	res, err := o.hc.Do(req)
	if err != nil {
		return fmt.Errorf("vault-board-v2 Operator outcome ambiguous: %w", err)
	}
	if res == nil || res.Body == nil {
		return fmt.Errorf("vault-board-v2 Operator outcome ambiguous: empty response")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_, _ = readBoundedResponse(res.Body, vaultBoardV2OperatorErrorLimit)
		if isStockOperatorPreAcceptanceRejection(res.StatusCode) {
			return vaultBoardV2OperatorRejection{status: res.StatusCode}
		}
		return fmt.Errorf("vault-board-v2 Operator HTTP %d", res.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("vault-board-v2 Operator outcome ambiguous: response content type")
	}
	raw, err := readBoundedResponse(res.Body, vaultBoardV2OperatorResponseLimit)
	if err != nil {
		return fmt.Errorf("vault-board-v2 Operator outcome ambiguous: %w", err)
	}
	defer zeroServiceBytes(raw)
	if response == nil {
		var empty map[string]json.RawMessage
		if err := decodeVaultBoardV2OperatorJSON(raw, &empty); err != nil || len(empty) != 0 {
			return fmt.Errorf("vault-board-v2 Operator outcome ambiguous: response shape")
		}
		return nil
	}
	if err := decodeVaultBoardV2OperatorJSON(raw, response); err != nil {
		return fmt.Errorf("vault-board-v2 Operator outcome ambiguous: response shape")
	}
	return nil
}

func isStockOperatorPreAcceptanceRejection(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusPreconditionFailed,
		http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

func decodeVaultBoardV2OperatorJSON(raw []byte, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing response data")
	}
	return nil
}

var _ vaultBoardV2Operator = (*stockVaultBoardV2Operator)(nil)
