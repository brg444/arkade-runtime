package application

import (
	"context"
	"encoding/json"
	"fmt"
	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLightDelegationStockEventStreamAndCancellation(t *testing.T) {
	closed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/batch/events" || len(r.URL.Query()["topics"]) != 2 {
			t.Errorf("unexpected stream subscription %s", r.URL)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ":heartbeat\n\ndata:{\"streamStarted\":{}}\n\ndata:{\"batchStarted\":{\"id\":\"batch\",\"intentIdHashes\":[\"hash\"],\"batchExpiry\":\"604800\"}}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(closed)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = time.Millisecond // stream must use context, not finite request timeout
	op := &stockVaultBoardOperator{origin: server.URL, hc: client}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	events, errs, err := op.events(ctx, []string{"key", "txid:0"})
	if err != nil {
		t.Fatal(err)
	}
	first := <-events
	second := <-events
	if string(first.StreamStarted) != "{}" || second.BatchStarted == nil || string(second.BatchStarted.BatchExpiry) != "604800" {
		t.Fatal(first, second)
	}
	cancel()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("stream not cancelled")
	}
	for range events {
	}
	for range errs {
	}
}
func TestLightDelegationStockRejectsMalformedAndOversizedStream(t *testing.T) {
	for _, body := range []string{"data:{broken}\n", "data:" + strings.Repeat("a", 2_000_001) + "\n"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, body)
		}))
		op := &stockVaultBoardOperator{origin: server.URL, hc: server.Client()}
		events, errs, err := op.events(t.Context(), []string{"key"})
		if err != nil {
			t.Fatal(err)
		}
		for range events {
		}
		if err := <-errs; err == nil {
			t.Fatal("bad stream accepted")
		}
		server.Close()
	}
}
func TestLightDelegationStockBatchPostsUsePublicWire(t *testing.T) {
	routes := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("bad POST")
		}
		routes = append(routes, r.URL.Path)
		if r.URL.Path == "/v1/batch/ack" {
			if string(body["intentId"]) != `"intent"` {
				t.Error(body)
			}
		} else {
			if string(body["batchId"]) != `"batch"` || string(body["pubkey"]) != `"pub"` {
				t.Error(body)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()
	pins, _ := deployment.IdentityFor(deployment.NetworkMutinynet)
	local, _ := url.Parse(server.URL)
	op := &stockVaultBoardOperator{origin: pins.OperatorOrigin, network: deployment.NetworkMutinynet, digest: strings.Repeat("aa", 32), hc: delegationTestDoer(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		clone.URL.Scheme = local.Scheme
		clone.URL.Host = local.Host
		return server.Client().Do(clone)
	})}
	if err := op.ack(t.Context(), "intent"); err != nil {
		t.Fatal(err)
	}
	if err := op.nonces(t.Context(), "batch", "pub", map[string]string{"txid": "nonce"}); err != nil {
		t.Fatal(err)
	}
	if err := op.signatures(t.Context(), "batch", "pub", map[string]string{"txid": "sig"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(routes, ",") != "/v1/batch/ack,/v1/batch/tree/submitNonces,/v1/batch/tree/submitSignatures" {
		t.Fatal(routes)
	}
}

type delegationTestDoer func(*http.Request) (*http.Response, error)

func (d delegationTestDoer) Do(r *http.Request) (*http.Response, error) { return d(r) }

func TestLightDelegationStockTreeEventDerivesTransactionID(t *testing.T) {
	f := newDelegatedFixture(t)
	for index, flat := range []arktree.FlatTxTree{f.tree.VtxoTree, f.final.Connectors} {
		node := flat[0]
		for _, supplied := range []string{"", node.Txid, strings.Repeat("ab", 32)} {
			raw, err := json.Marshal(map[string]any{"treeTx": map[string]any{"id": f.tree.BatchID, "batchIndex": index, "txid": supplied, "tx": node.Tx, "children": node.Children}})
			if err != nil {
				t.Fatal(err)
			}
			var event lightDelegationEvent
			err = json.Unmarshal(raw, &event)
			if supplied != "" && supplied != node.Txid {
				if err == nil {
					t.Fatal("contradictory supplied txid accepted")
				}
				continue
			}
			if err != nil || event.TreeTx.Txid != node.Txid {
				t.Fatal("stock transaction identity unavailable", err)
			}
			phase, err := delegationStreamPhase(event, f.tree.BatchID)
			if err != nil || phase != fmt.Sprintf("stream_tree_%d_%s", index, node.Txid) {
				t.Fatal("event cannot be journaled", err)
			}
		}
	}
	var event lightDelegationEvent
	if json.Unmarshal([]byte(`{"treeTx":{"id":"batch","tx":"invalid"}}`), &event) == nil {
		t.Fatal("malformed transaction accepted")
	}
}
