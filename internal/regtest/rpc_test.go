package regtest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func rpcHTTP(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func clientWith(t *testing.T, rawURL string, fn doerFunc) *Client {
	t.Helper()
	c, err := DialWith(rawURL, fn)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDialRejectsEmptyAndBadURL(t *testing.T) {
	if _, err := Dial(""); err == nil {
		t.Fatal("empty url accepted")
	}
	if _, err := Dial("not-a-url"); err == nil {
		t.Fatal("opaque url accepted")
	}
	if _, err := DialWith("http://127.0.0.1:18443", nil); err == nil {
		t.Fatal("nil doer accepted")
	}
}

func TestClientFailClosedWithoutTransport(t *testing.T) {
	c := &Client{}
	if _, err := c.GetBlockCount(context.Background()); err == nil {
		t.Fatal("nil transport accepted")
	}
}

func TestClientJSONRPCRoundTrip(t *testing.T) {
	c := clientWith(t, "http://127.0.0.1:18443", func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		var req rpcRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("request: %v", err)
		}
		switch req.Method {
		case "getblockcount":
			return rpcHTTP(200, `{"result":12,"error":null}`), nil
		case "getnewaddress":
			return rpcHTTP(200, `{"result":"bcrt1qtest","error":null}`), nil
		default:
			return rpcHTTP(200, `{"result":null,"error":{"code":-32601,"message":"method"}}`), nil
		}
	})
	n, err := c.GetBlockCount(context.Background())
	if err != nil || n != 12 {
		t.Fatalf("blockcount: %d %v", n, err)
	}
	addr, err := c.GetNewAddress(context.Background())
	if err != nil || addr != "bcrt1qtest" {
		t.Fatalf("address: %q %v", addr, err)
	}
	if _, err := c.SendToAddress(context.Background(), "", 1); err == nil {
		t.Fatal("empty fund accepted")
	}
}

func TestLookupTxCodeMinus5InHTTP500IsNotFound(t *testing.T) {
	c := clientWith(t, "http://127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
		return rpcHTTP(500, `{"result":null,"error":{"code":-5,"message":"No such mempool or blockchain transaction"},"id":"vault-demo"}`), nil
	})
	conf, found, err := c.LookupTx(context.Background(), strings.Repeat("ab", 32))
	if err != nil || found || conf != 0 {
		t.Fatalf("code -5: conf=%d found=%v err=%v", conf, found, err)
	}
}

func TestLookupTxOtherRPCErrorsPropagate(t *testing.T) {
	txid := strings.Repeat("ab", 32)
	tests := []struct {
		name string
		body string
		code int
	}{
		{name: "warmup", body: `{"result":null,"error":{"code":-28,"message":"Loading block index..."}}`, code: -28},
		{name: "other", body: `{"result":null,"error":{"code":-8,"message":"Invalid parameter"}}`, code: -8},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := clientWith(t, "http://127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
				return rpcHTTP(500, tc.body), nil
			})
			_, found, err := c.LookupTx(context.Background(), txid)
			if found || err == nil {
				t.Fatal("non-(-5) treated as not found")
			}
			var rpcErr *Error
			if !errors.As(err, &rpcErr) || rpcErr.Code != tc.code {
				t.Fatalf("got %v", err)
			}
		})
	}

	c := clientWith(t, "http://127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
		return rpcHTTP(500, `{"result":null,"error":{"code":-5,"message":"Invalid address or key"}}`), nil
	})
	_, err := c.GetBlockCount(context.Background())
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != -5 {
		t.Fatalf("getblockcount -5 must surface: %v", err)
	}
}

func TestCallHTTP401Propagates(t *testing.T) {
	c := clientWith(t, "http://127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
		return rpcHTTP(http.StatusUnauthorized, "Unauthorized"), nil
	})
	_, found, err := c.LookupTx(context.Background(), strings.Repeat("ab", 32))
	if err == nil || found {
		t.Fatal("401 treated as not found")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("401: %v", err)
	}
}

func TestCallTransportErrorPropagates(t *testing.T) {
	want := errors.New("connection refused")
	c := clientWith(t, "http://127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
		return nil, want
	})
	_, found, err := c.LookupTx(context.Background(), strings.Repeat("ab", 32))
	if found || !errors.Is(err, want) {
		t.Fatalf("transport: found=%v err=%v", found, err)
	}
}

func TestCallDecodeAndTimeoutPropagate(t *testing.T) {
	c := clientWith(t, "http://127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
		return rpcHTTP(200, "not-json"), nil
	})
	_, found, err := c.LookupTx(context.Background(), strings.Repeat("ab", 32))
	if found || err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("decode: found=%v err=%v", found, err)
	}

	c = clientWith(t, "http://127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})
	_, found, err = c.LookupTx(context.Background(), strings.Repeat("ab", 32))
	if found || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: found=%v err=%v", found, err)
	}
}

func TestLookupTxMempoolIsFoundWithZeroConfirmations(t *testing.T) {
	c := clientWith(t, "http://127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
		return rpcHTTP(200, `{"result":{"txid":"ab","confirmations":0},"error":null}`), nil
	})
	conf, found, err := c.LookupTx(context.Background(), strings.Repeat("ab", 32))
	if err != nil || !found || conf != 0 {
		t.Fatalf("mempool: conf=%d found=%v err=%v", conf, found, err)
	}
}

func TestRequireRegtestRejectsMainnet(t *testing.T) {
	c := clientWith(t, "http://alice:s3cret@127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
		return rpcHTTP(200, `{"result":{"chain":"main"},"error":null}`), nil
	})
	if err := c.RequireRegtest(context.Background()); err == nil || !strings.Contains(err.Error(), "regtest") {
		t.Fatalf("mainnet: %v", err)
	}
}

func TestRequireRegtestAcceptsRegtest(t *testing.T) {
	c := clientWith(t, "http://alice:s3cret@127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
		return rpcHTTP(200, `{"result":{"chain":"regtest"},"error":null}`), nil
	})
	if err := c.RequireRegtest(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestClientSendsBasicAuthFromURL(t *testing.T) {
	var got string
	c := clientWith(t, "http://alice:s3cret@127.0.0.1:18443", func(r *http.Request) (*http.Response, error) {
		got = r.Header.Get("Authorization")
		return rpcHTTP(200, `{"result":{"chain":"regtest"},"error":null}`), nil
	})
	if err := c.RequireRegtest(context.Background()); err != nil {
		t.Fatal(err)
	}
	const prefix = "Basic "
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("authorization: %q", got)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, prefix))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "alice:s3cret" {
		t.Fatalf("basic auth: %q", raw)
	}
}

func TestRequireRegtestPropagatesAuthFailure(t *testing.T) {
	c := clientWith(t, "http://alice:bad@127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
		return rpcHTTP(http.StatusUnauthorized, "Unauthorized"), nil
	})
	err := c.RequireRegtest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("auth failure: %v", err)
	}
}

func TestDialDoesNotContactNode(t *testing.T) {
	c, err := Dial("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("nil client")
	}
}

func TestLookupTxRequiresTxid(t *testing.T) {
	c := clientWith(t, "http://127.0.0.1:18443", func(*http.Request) (*http.Response, error) {
		t.Fatal("empty txid contacted node")
		return nil, fmt.Errorf("unused")
	})
	if _, _, err := c.LookupTx(context.Background(), ""); err == nil {
		t.Fatal("empty txid accepted")
	}
}
