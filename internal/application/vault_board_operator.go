package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"github.com/brg444/arkade-runtime/internal/deployment"
)

const (
	vaultBoardOperatorResponseLimit = 16 * 1024
	vaultBoardOperatorErrorLimit    = 4 * 1024
)

type vaultBoardOperator interface {
	registerIntent(context.Context, string, string) (string, error)
	deleteIntent(context.Context, string, string) error
	submitCommitment(context.Context, string) error
	requireUnendedCommitment(context.Context, string) error
}

type stockVaultBoardOperator struct {
	origin  string
	network string
	digest  string
	hc      httpDoer
}

// vaultBoardOperatorRejection is limited to HTTP statuses that stock arkd
// returns before RegisterIntent reaches its cache Push boundary. It is useful
// only for register: delete no-match and final rejection remain fail-closed.
type vaultBoardOperatorRejection struct {
	status int
	reason string
}

func (e vaultBoardOperatorRejection) Error() string {
	if e.reason != "" {
		return e.reason
	}
	return fmt.Sprintf("Operator rejected request with HTTP %d", e.status)
}

func isDefiniteVaultBoardRegisterRejection(err error) bool {
	switch err.(type) {
	case vaultBoardOperatorRejection, vaultBoardOperatorNotSent:
		return true
	default:
		return false
	}
}

// vaultBoardOperatorNotSent is created only before invoking the HTTP client.
// Transport failures after Do remain ambiguous, even if no response arrives.
type vaultBoardOperatorNotSent struct{ err error }

func (e vaultBoardOperatorNotSent) Error() string { return e.err.Error() }
func (e vaultBoardOperatorNotSent) Unwrap() error { return e.err }

// An absent queued intent does not establish a batch outcome. Only callers
// that independently fence final signing may use this response for release.
type stockOperatorIntentAbsent struct{}

func (stockOperatorIntentAbsent) Error() string { return "Operator has no matching queued intent" }

const stockOperatorIntentAbsentMessage = "INVALID_INTENT_PROOF (23): no matching intents found for intent proof"

func isStockOperatorIntentAbsent(raw []byte) bool {
	var response struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Details []struct {
			Type     string            `json:"@type"`
			Code     int               `json:"code"`
			Name     string            `json:"name"`
			Message  string            `json:"message"`
			Metadata map[string]string `json:"metadata"`
		} `json:"details"`
	}
	if decodeVaultBoardOperatorJSON(raw, &response) != nil || response.Code != 3 || response.Message != stockOperatorIntentAbsentMessage || len(response.Details) != 1 {
		return false
	}
	detail := response.Details[0]
	// Stock arkd serializes the zero-value proof metadata as two empty fields.
	for key, value := range detail.Metadata {
		if (key != "proof" && key != "message") || value != "" {
			return false
		}
	}
	return detail.Type == "type.googleapis.com/ark.v1.ErrorDetails" && detail.Code == 23 &&
		detail.Name == "INVALID_INTENT_PROOF" && detail.Message == stockOperatorIntentAbsentMessage
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
	origin, err := CanonicalHTTPSOrigin(rawOrigin)
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
	return &stockVaultBoardOperator{origin: origin, network: network, digest: info.Digest, hc: hc}, nil
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

// A failed batch is still indexed. Its signed recovery tree is not evidence
// that the Operator can accept a late boarding signature for that batch.
// Absence from the index is not proof of liveness; this check only rejects
// known-ended batches and leaves all transaction verification in place.
func (o *stockVaultBoardOperator) requireUnendedCommitment(ctx context.Context, txid string) error {
	if o == nil || o.hc == nil || requireTxid(txid) != nil {
		return fmt.Errorf("vault-board-v1 commitment status unavailable")
	}
	id, err := deployment.IdentityFor(o.network)
	if err != nil || o.origin != id.OperatorOrigin || requireTxid(o.digest) != nil {
		return fmt.Errorf("vault-board-v1 Operator is not release-pinned")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.origin+"/v1/indexer/commitmentTx/"+txid, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := o.hc.Do(req)
	if err != nil {
		return fmt.Errorf("vault-board-v1 commitment status unavailable")
	}
	if res == nil || res.Body == nil {
		return fmt.Errorf("vault-board-v1 commitment status unavailable")
	}
	defer res.Body.Close()
	raw, err := readBoundedResponse(res.Body, vaultBoardOperatorResponseLimit)
	if err != nil {
		return fmt.Errorf("vault-board-v1 commitment status unavailable")
	}
	defer zeroServiceBytes(raw)
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("vault-board-v1 commitment status unavailable")
	}
	if res.StatusCode == http.StatusNotFound {
		var missing struct {
			Code int `json:"code"`
		}
		if json.Unmarshal(raw, &missing) == nil && missing.Code == 5 {
			return nil
		}
	}
	var status struct {
		EndedAt *int64 `json:"endedAt,string"`
	}
	if res.StatusCode != http.StatusOK || json.Unmarshal(raw, &status) != nil || status.EndedAt == nil || *status.EndedAt < 0 {
		return fmt.Errorf("vault-board-v1 commitment status unavailable")
	}
	if *status.EndedAt != 0 {
		return fmt.Errorf("vault-board-v1 batch already ended; wait for a new boarding attempt")
	}
	return nil
}

func (o *stockVaultBoardOperator) post(ctx context.Context, path string, payload, response any) error {
	if o == nil || o.hc == nil {
		return vaultBoardOperatorNotSent{fmt.Errorf("vault-board-v1 Operator is not release-pinned")}
	}
	id, err := deployment.IdentityFor(o.network)
	if err != nil || o.origin != id.OperatorOrigin || requireTxid(o.digest) != nil {
		return vaultBoardOperatorNotSent{fmt.Errorf("vault-board-v1 Operator is not release-pinned")}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return vaultBoardOperatorNotSent{err}
	}
	defer zeroServiceBytes(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.origin+path, bytes.NewReader(body))
	if err != nil {
		return vaultBoardOperatorNotSent{err}
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
		raw, readErr := readBoundedResponse(res.Body, vaultBoardOperatorErrorLimit)
		defer zeroServiceBytes(raw)
		mediaType, _, mediaErr := mime.ParseMediaType(res.Header.Get("Content-Type"))
		if path == "/v1/batch/deleteIntent" && res.StatusCode == http.StatusBadRequest &&
			readErr == nil && mediaErr == nil && mediaType == "application/json" && isStockOperatorIntentAbsent(raw) {
			return stockOperatorIntentAbsent{}
		}
		if isStockOperatorPreAcceptanceRejection(res.StatusCode) {
			return vaultBoardOperatorRejection{status: res.StatusCode, reason: operatorRejectionReason(raw)}
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

// Preserve only bounded human-readable diagnostics. Error metadata can contain
// signed PSBTs and must never enter responses or application logs.
var operatorOpaqueToken = regexp.MustCompile(`[A-Za-z0-9_+/=:-]{48,}`)

func operatorRejectionReason(raw []byte) string {
	var body struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	message := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, body.Message)
	message = strings.Join(strings.Fields(message), " ")
	message = operatorOpaqueToken.ReplaceAllString(message, "[redacted]")
	if runes := []rune(message); len(runes) > 320 {
		message = string(runes[:320])
	}
	return message
}
