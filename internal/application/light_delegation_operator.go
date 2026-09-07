package application

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

type delegationBatchStarted struct {
	ID             string      `json:"id"`
	IntentIDHashes []string    `json:"intentIdHashes"`
	BatchExpiry    json.Number `json:"batchExpiry"`
}
type delegationTreeTx struct {
	ID         string            `json:"id"`
	BatchIndex uint32            `json:"batchIndex"`
	Txid       string            `json:"txid"`
	Tx         string            `json:"tx"`
	Children   map[uint32]string `json:"children"`
}

// Stock Operator TreeTx events can omit txid. Derive identity from the
// transaction before journaling, and reject any contradictory supplied ID.
func (e *delegationTreeTx) UnmarshalJSON(raw []byte) error {
	type wireEvent delegationTreeTx
	var decoded wireEvent
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	packet, err := parseCanonicalVaultBoardPSBT(decoded.Tx, maxVaultBoardProofBytes)
	if err != nil {
		return fmt.Errorf("Light delegation tree event transaction: %w", err)
	}
	txid := packet.UnsignedTx.TxHash().String()
	if decoded.Txid != "" && decoded.Txid != txid {
		return fmt.Errorf("Light delegation tree event transaction identity mismatch")
	}
	decoded.Txid = txid
	*e = delegationTreeTx(decoded)
	return nil
}

type delegationSigningStarted struct {
	ID         string   `json:"id"`
	Cosigners  []string `json:"cosignersPubkeys"`
	Commitment string   `json:"unsignedCommitmentTx"`
}
type delegationTreeNonces struct {
	ID     string            `json:"id"`
	Txid   string            `json:"txid"`
	Nonces map[string]string `json:"nonces"`
}
type delegationTreeSignature struct {
	ID         string `json:"id"`
	Txid       string `json:"txid"`
	Signature  string `json:"signature"`
	BatchIndex uint32 `json:"batchIndex"`
}
type delegationFinalization struct {
	ID         string `json:"id"`
	Commitment string `json:"commitmentTx"`
}
type delegationBatchFinalized struct {
	ID             string `json:"id"`
	CommitmentTxid string `json:"commitmentTxid"`
}
type delegationBatchFailed struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}
type lightDelegationEvent struct {
	StreamStarted      json.RawMessage           `json:"streamStarted"`
	BatchStarted       *delegationBatchStarted   `json:"batchStarted"`
	TreeTx             *delegationTreeTx         `json:"treeTx"`
	TreeSigningStarted *delegationSigningStarted `json:"treeSigningStarted"`
	TreeNonces         *delegationTreeNonces     `json:"treeNonces"`
	TreeSignature      *delegationTreeSignature  `json:"treeSignature"`
	BatchFinalization  *delegationFinalization   `json:"batchFinalization"`
	BatchFinalized     *delegationBatchFinalized `json:"batchFinalized"`
	BatchFailed        *delegationBatchFailed    `json:"batchFailed"`
}
type lightDelegationOperator interface {
	lightRenewalOperator
	deleteIntent(context.Context, string, string) error
	events(context.Context, []string) (<-chan lightDelegationEvent, <-chan error, error)
	ack(context.Context, string) error
	nonces(context.Context, string, string, map[string]string) error
	signatures(context.Context, string, string, map[string]string) error
}

func (o *stockVaultBoardOperator) ack(ctx context.Context, id string) error {
	return o.post(ctx, "/v1/batch/ack", map[string]string{"intentId": id}, nil)
}
func (o *stockVaultBoardOperator) nonces(ctx context.Context, batch, key string, nonces map[string]string) error {
	return o.post(ctx, "/v1/batch/tree/submitNonces", map[string]any{"batchId": batch, "pubkey": key, "treeNonces": nonces}, nil)
}
func (o *stockVaultBoardOperator) signatures(ctx context.Context, batch, key string, sigs map[string]string) error {
	return o.post(ctx, "/v1/batch/tree/submitSignatures", map[string]any{"batchId": batch, "pubkey": key, "treeSignatures": sigs}, nil)
}
func (o *stockVaultBoardOperator) events(ctx context.Context, topics []string) (<-chan lightDelegationEvent, <-chan error, error) {
	query := url.Values{}
	for _, topic := range topics {
		query.Add("topics", topic)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.origin+"/v1/batch/events?"+query.Encode(), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	client := o.hc
	if httpClient, ok := client.(*http.Client); ok {
		copy := *httpClient
		copy.Timeout = 0
		client = &copy
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if res == nil || res.Body == nil {
		return nil, nil, fmt.Errorf("Light delegation event stream unavailable")
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return nil, nil, fmt.Errorf("Light delegation event stream HTTP %d", res.StatusCode)
	}
	if !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		res.Body.Close()
		return nil, nil, fmt.Errorf("Light delegation event stream content type")
	}
	events := make(chan lightDelegationEvent, 8)
	failures := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(failures)
		defer res.Body.Close()
		scanner := bufio.NewScanner(res.Body)
		scanner.Buffer(make([]byte, 4096), 2_000_000)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			var event lightDelegationEvent
			if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &event); err != nil {
				failures <- err
				return
			}
			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil {
			failures <- err
		}
	}()
	return events, failures, nil
}
func delegationFlat(nodes map[string]arktree.TxTreeNode) arktree.FlatTxTree {
	out := make(arktree.FlatTxTree, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, node)
	}
	return out
}
