package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
)

func TestConnectorChainRequiresExplicitCanonicalEvidence(t *testing.T) {
	txid, block := strings.Repeat("a", 64), strings.Repeat("b", 64)
	id, _ := deployment.IdentityFor("mainnet")
	for _, tc := range []struct {
		name, body      string
		status          int
		unconfirmed, ok bool
	}{
		{"confirmed", fmt.Sprintf(`{"txid":%q,"status":{"confirmed":true,"block_height":900000,"block_hash":%q}}`, txid, block), 200, false, true},
		{"explicit unconfirmed", fmt.Sprintf(`{"txid":%q,"status":{"confirmed":false}}`, txid), 200, true, false},
		{"missing status", fmt.Sprintf(`{"txid":%q}`, txid), 200, false, false},
		{"missing confirmed", fmt.Sprintf(`{"txid":%q,"status":{}}`, txid), 200, false, false},
		{"null confirmed", fmt.Sprintf(`{"txid":%q,"status":{"confirmed":null}}`, txid), 200, false, false},
		{"missing transaction", `{}`, 404, false, false},
		{"wrong txid", `{"txid":"wrong","status":{"confirmed":false}}`, 200, false, false},
		{"trailing JSON", fmt.Sprintf(`{"txid":%q,"status":{"confirmed":false}} {}`, txid), 200, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			chain, err := dialConnectorChainWithClient(id.EsploraOrigin, rpcDoerFunc(func(r *http.Request) (*http.Response, error) {
				body, content, code := tc.body, "application/json", tc.status
				if strings.Contains(r.URL.Path, "/block-height/") {
					body, content, code = block, "text/plain", 200
				} else {
					reads++
				}
				return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{content}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = chain.confirmedTransaction(context.Background(), txid)
			if (err == nil) != tc.ok || errors.Is(err, errConnectorTransactionUnconfirmed) != tc.unconfirmed {
				t.Fatalf("unexpected evidence: %v", err)
			}
			if (tc.ok || tc.unconfirmed) && reads != 2 {
				t.Fatalf("not double-read: %d", reads)
			}
		})
	}
}

func TestConnectorChainRejectsChangingOrIncompleteOutspends(t *testing.T) {
	txid, block := strings.Repeat("a", 64), strings.Repeat("b", 64)
	id, _ := deployment.IdentityFor("mainnet")
	for _, tc := range []struct {
		name, first, second string
		ok                  bool
	}{
		{"unspent", `[{"spent":false}]`, `[{"spent":false}]`, true},
		{"missing boolean", `[{}]`, `[{}]`, false},
		{"null boolean", `[{"spent":null}]`, `[{"spent":null}]`, false},
		{"changed", `[{"spent":false}]`, fmt.Sprintf(`[{"spent":true,"txid":%q,"vin":0}]`, strings.Repeat("c", 64)), false},
		{"contradiction", fmt.Sprintf(`[{"spent":false,"txid":%q}]`, txid), `[]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			chain, err := dialConnectorChainWithClient(id.EsploraOrigin, rpcDoerFunc(func(r *http.Request) (*http.Response, error) {
				body, content := fmt.Sprintf(`{"txid":%q,"status":{"confirmed":true,"block_height":900000,"block_hash":%q},"vout":[{"value":1000,"scriptpubkey":"0014%s"}]}`, txid, block, strings.Repeat("d", 40)), "application/json"
				if strings.Contains(r.URL.Path, "/block-height/") {
					body, content = block, "text/plain"
				}
				if strings.HasSuffix(r.URL.Path, "/outspends") {
					reads++
					body = tc.first
					if reads > 1 {
						body = tc.second
					}
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{content}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = chain.confirmedOutpoint(context.Background(), txid, 0)
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected evidence: %v", err)
			}
			if tc.ok && reads != 2 {
				t.Fatalf("not double-read: %d", reads)
			}
		})
	}
}
