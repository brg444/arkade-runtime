package application

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type rpcDoerFunc func(*http.Request) (*http.Response, error)

func (f rpcDoerFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDialBitcoinRPCRejectsMainnet(t *testing.T) {
	doer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"result":{"chain":"main"},"error":null}`)),
			Header:     make(http.Header),
		}, nil
	})
	_, err := dialBitcoin(context.Background(), "http://alice:s3cret@127.0.0.1:18443", doer)
	if err == nil || !strings.Contains(err.Error(), "regtest") {
		t.Fatalf("mainnet: %v", err)
	}
}

func TestDialBitcoinRPCRequiresRegtestAndAuth(t *testing.T) {
	var gotAuth string
	doer := rpcDoerFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		if r.Header.Get("Authorization") == "" {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(strings.NewReader("Unauthorized")),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"result":{"chain":"regtest"},"error":null}`)),
			Header:     make(http.Header),
		}, nil
	})
	got, err := dialBitcoin(context.Background(), "http://alice:s3cret@127.0.0.1:18443", doer)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("nil chain")
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("authorization: %q", gotAuth)
	}

	unauth := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(strings.NewReader("Unauthorized")),
			Header:     make(http.Header),
		}, nil
	})
	if _, err := dialBitcoin(context.Background(), "http://alice:bad@127.0.0.1:18443", unauth); err == nil {
		t.Fatal("unauthorized accepted")
	}
}

func TestDialBitcoinRPCURLStillValidated(t *testing.T) {
	if _, err := DialBitcoinRPC(context.Background(), ""); err == nil {
		t.Fatal("empty url accepted")
	}
}

type lookupChain struct {
	fakeChain
	lookup func(string) (int64, bool, error)
}

func (c *lookupChain) LookupTx(_ context.Context, txid string) (int64, bool, error) {
	return c.lookup(txid)
}

func TestNodeBroadcasterLookupPropagates(t *testing.T) {
	outage := errors.New("rpc warmup")
	n := &NodeBroadcaster{Chain: &lookupChain{lookup: func(string) (int64, bool, error) {
		return 0, false, outage
	}}}
	_, found, err := n.Lookup(context.Background(), strings.Repeat("ab", 32))
	if found || !errors.Is(err, outage) {
		t.Fatalf("outage: found=%v err=%v", found, err)
	}

	n = &NodeBroadcaster{Chain: &lookupChain{lookup: func(string) (int64, bool, error) {
		return 0, false, nil
	}}}
	conf, found, err := n.Lookup(context.Background(), strings.Repeat("ab", 32))
	if err != nil || found || conf != 0 {
		t.Fatalf("missing: conf=%d found=%v err=%v", conf, found, err)
	}
}
