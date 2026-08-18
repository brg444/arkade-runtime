package provider

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/btcsuite/btcd/wire"
)

func TestDialEsploraPinsMutinynetCheckpoint(t *testing.T) {
	checkpoint := func(hash string) httpDoer {
		return rpcDoerFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet || r.URL.Path != "/api/block-height/1" {
				t.Fatalf("unexpected checkpoint request %s %s", r.Method, r.URL.Path)
			}
			return textResponse(http.StatusOK, hash), nil
		})
	}
	if _, err := dialEsplora(context.Background(), "https://mempool.mutinynet.arkade.sh/api", deployment.NetworkMutinynet, checkpoint(strings.Repeat("0", 64))); err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("wrong signet checkpoint accepted: %v", err)
	}
	if _, err := dialEsplora(context.Background(), "https://mempool.mutinynet.arkade.sh/api", deployment.NetworkMutinynet, checkpoint(deployment.MutinynetCheckpoint1)); err != nil {
		t.Fatal(err)
	}
	if _, err := dialEsplora(context.Background(), "http://mempool.mutinynet.arkade.sh/api", deployment.NetworkMutinynet, checkpoint(deployment.MutinynetCheckpoint1)); err == nil {
		t.Fatal("insecure public Esplora URL accepted")
	}
}

func TestEsploraBroadcastAndConfirmationLookup(t *testing.T) {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
	var raw bytes.Buffer
	if err := tx.Serialize(&raw); err != nil {
		t.Fatal(err)
	}
	txid := tx.TxHash().String()

	doer := rpcDoerFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/tx":
			body, _ := io.ReadAll(r.Body)
			if len(body) == 0 || r.Header.Get("Content-Type") != "text/plain" {
				t.Fatal("broadcast did not send hex text")
			}
			return textResponse(http.StatusOK, txid), nil
		case r.Method == http.MethodGet && r.URL.Path == "/api/tx/"+txid+"/status":
			return textResponse(http.StatusOK, `{"confirmed":true,"block_height":10}`), nil
		case r.Method == http.MethodGet && r.URL.Path == "/api/blocks/tip/height":
			return textResponse(http.StatusOK, "12"), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})
	b := &EsploraBroadcaster{base: "https://mempool.mutinynet.arkade.sh/api", hc: doer}
	got, err := b.Broadcast(context.Background(), raw.Bytes())
	if err != nil || got != txid {
		t.Fatalf("Broadcast() = %q, %v", got, err)
	}
	conf, found, err := b.Lookup(context.Background(), txid)
	if err != nil || !found || conf != 3 {
		t.Fatalf("Lookup() = %d, %v, %v", conf, found, err)
	}
}

func TestEsploraLookupDistinguishesMissingAndMempool(t *testing.T) {
	txid := strings.Repeat("ab", 32)
	for _, test := range []struct {
		name  string
		code  int
		body  string
		found bool
	}{
		{name: "missing", code: http.StatusNotFound},
		{name: "mempool", code: http.StatusOK, body: `{"confirmed":false}`, found: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := &EsploraBroadcaster{base: "https://example.invalid/api", hc: rpcDoerFunc(func(*http.Request) (*http.Response, error) {
				return textResponse(test.code, test.body), nil
			})}
			conf, found, err := b.Lookup(context.Background(), txid)
			if err != nil || found != test.found || conf != 0 {
				t.Fatalf("Lookup() = %d, %v, %v", conf, found, err)
			}
		})
	}
}

func TestEsploraRejectsRedirectsAndMalformedConfirmedStatus(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://other.example.invalid/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := newEsploraHTTPClient().CheckRedirect(req, nil); err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("redirect accepted: %v", err)
	}

	b := &EsploraBroadcaster{base: "https://example.invalid/api", hc: rpcDoerFunc(func(*http.Request) (*http.Response, error) {
		return textResponse(http.StatusOK, `{"confirmed":true}`), nil
	})}
	if _, _, err := b.Lookup(context.Background(), strings.Repeat("ab", 32)); err == nil || !strings.Contains(err.Error(), "block height") {
		t.Fatalf("confirmed status without height accepted: %v", err)
	}
}

func textResponse(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
