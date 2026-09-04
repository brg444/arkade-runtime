package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/brg444/vaulted-guardian/internal/deployment"
)

const (
	vaultBoardOperatorResponseLimit = 16 * 1024
	vaultBoardOperatorErrorLimit    = 4 * 1024
)

type vaultBoardOperator interface {
	registerIntent(context.Context, string, string) (string, error)
	deleteIntent(context.Context, string, string) error
	submitCommitment(context.Context, string) error
}

type stockVaultBoardOperator struct {
	origin string
	digest string
	hc     httpDoer
}

// vaultBoardOperatorRejection is limited to HTTP statuses that stock arkd
// returns before RegisterIntent reaches its cache Push boundary. It is useful
// only for register: delete no-match and final rejection remain fail-closed.
type vaultBoardOperatorRejection struct {
	status int
}

func (e vaultBoardOperatorRejection) Error() string {
	return fmt.Sprintf("vault-board-v1 Operator rejected request with HTTP %d", e.status)
}

func isDefiniteVaultBoardRegisterRejection(err error) bool {
	_, ok := err.(vaultBoardOperatorRejection)
	return ok
}

func dialVaultBoardOperator(ctx context.Context, network string) (vaultBoardOperator, error) {
	id, err := deployment.IdentityFor(network)
	if err != nil {
		return nil, err
	}
	return dialVaultBoardOperatorWithClient(ctx, id.OperatorOrigin, network, newArkResolverHTTPClient())
}

func dialVaultBoardOperatorWithClient(ctx context.Context, rawOrigin, network string, hc httpDoer) (vaultBoardOperator, error) {
	id, err := deployment.IdentityFor(network)
	if err != nil {
		return nil, err
	}
	origin, err := canonicalHTTPSOrigin(rawOrigin)
	if err != nil || origin != id.OperatorOrigin {
		return nil, fmt.Errorf("vault-board-v1 Operator origin must be the release pin")
	}
	if hc == nil {
		return nil, fmt.Errorf("vault-board-v1 Operator HTTP client required")
	}
	resolver := &arkResolver{origin: origin, hc: hc, network: network}
	info, err := resolver.getInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("vault-board-v1 Operator info: %w", err)
	}
	if _, _, _, err := validateArkResolverReleaseInfo(network, info); err != nil {
		return nil, err
	}
	if err := requireTxid(info.Digest); err != nil {
		return nil, fmt.Errorf("vault-board-v1 Operator digest required")
	}
	return &stockVaultBoardOperator{origin: origin, digest: info.Digest, hc: hc}, nil
}

func (o *stockVaultBoardOperator) registerIntent(ctx context.Context, proof, message string) (string, error) {
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
		return "", fmt.Errorf("vault-board-v1 Operator returned invalid intent id")
	}
	return response.IntentID, nil
}

func (o *stockVaultBoardOperator) deleteIntent(ctx context.Context, proof, message string) error {
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

func (o *stockVaultBoardOperator) submitCommitment(ctx context.Context, signedCommitment string) error {
	request := struct {
		SignedForfeitTxs   []string `json:"signedForfeitTxs"`
		SignedCommitmentTx string   `json:"signedCommitmentTx"`
	}{SignedForfeitTxs: []string{}, SignedCommitmentTx: signedCommitment}
	return o.post(ctx, "/v1/batch/submitForfeitTxs", request, nil)
}

func (o *stockVaultBoardOperator) post(ctx context.Context, path string, payload, response any) error {
	if o == nil || o.hc == nil || o.origin != deployment.MutinynetArkIndexerOrigin || requireTxid(o.digest) != nil {
		return fmt.Errorf("vault-board-v1 Operator is not release-pinned")
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
		return fmt.Errorf("vault-board-v1 Operator outcome ambiguous: %w", err)
	}
	if res == nil || res.Body == nil {
		return fmt.Errorf("vault-board-v1 Operator outcome ambiguous: empty response")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_, _ = readBoundedResponse(res.Body, vaultBoardOperatorErrorLimit)
		if isStockOperatorPreAcceptanceRejection(res.StatusCode) {
			return vaultBoardOperatorRejection{status: res.StatusCode}
		}
		return fmt.Errorf("vault-board-v1 Operator HTTP %d", res.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("vault-board-v1 Operator outcome ambiguous: response content type")
	}
	raw, err := readBoundedResponse(res.Body, vaultBoardOperatorResponseLimit)
	if err != nil {
		return fmt.Errorf("vault-board-v1 Operator outcome ambiguous: %w", err)
	}
	defer zeroServiceBytes(raw)
	if response == nil {
		var empty map[string]json.RawMessage
		if err := decodeVaultBoardOperatorJSON(raw, &empty); err != nil || len(empty) != 0 {
			return fmt.Errorf("vault-board-v1 Operator outcome ambiguous: response shape")
		}
		return nil
	}
	if err := decodeVaultBoardOperatorJSON(raw, response); err != nil {
		return fmt.Errorf("vault-board-v1 Operator outcome ambiguous: response shape")
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

func decodeVaultBoardOperatorJSON(raw []byte, dest any) error {
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

var _ vaultBoardOperator = (*stockVaultBoardOperator)(nil)
