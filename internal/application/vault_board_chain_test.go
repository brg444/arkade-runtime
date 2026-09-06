package application

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
)

func vaultBoardTextResponse(status int, body string) *http.Response {
	response := jsonResponse(status, body)
	response.Header.Set("Content-Type", "text/plain")
	return response
}

func vaultBoardHTMLResponse(status int, body string) *http.Response {
	response := jsonResponse(status, body)
	response.Header.Set("Content-Type", "text/html; charset=utf-8")
	return response
}

func TestVaultBoardChainAcceptsPinnedBlockHeightHTMLOnly(t *testing.T) {
	hash := strings.Repeat("11", 32)
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		return vaultBoardHTMLResponse(http.StatusOK, hash), nil
	})
	chain := &esploraVaultBoardChain{origin: deployment.MutinynetEsploraOrigin, hc: doer}
	if got, err := chain.getText(context.Background(), "/block-height/1", vaultBoardChainTextLimit); err != nil || got != hash {
		t.Fatalf("pinned block-height representation rejected: got=%q err=%v", got, err)
	}
	if _, err := chain.getText(context.Background(), "/blocks/tip/hash", vaultBoardChainTextLimit); err == nil {
		t.Fatal("HTML accepted outside the pinned block-height endpoint")
	}
}

func TestVaultBoardChainCrossChecksConfirmedOutpointAndMTP(t *testing.T) {
	txid := strings.Repeat("11", 32)
	fundingHash := strings.Repeat("22", 32)
	predecessorHash := strings.Repeat("33", 32)
	tipHash := strings.Repeat("44", 32)
	script := "5120" + strings.Repeat("55", 32)
	txJSON := fmt.Sprintf(`{"txid":%q,"vout":[{"value":50000,"scriptpubkey":%q}],"status":{"confirmed":true,"block_height":100,"block_hash":%q}}`, txid, script, fundingHash)
	requests := make(map[string]int)
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		requests[req.URL.Path]++
		if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "mempool.mutinynet.arkade.sh" || !strings.HasPrefix(req.URL.Path, "/api/") {
			t.Fatalf("unexpected Esplora request: %s %s", req.Method, req.URL)
		}
		switch req.URL.Path {
		case "/api/tx/" + txid:
			return jsonResponse(http.StatusOK, txJSON), nil
		case "/api/block/" + fundingHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":100,"mediantime":100000}`, fundingHash)), nil
		case "/api/block-height/100":
			return vaultBoardTextResponse(http.StatusOK, fundingHash), nil
		case "/api/block-height/99":
			return vaultBoardTextResponse(http.StatusOK, predecessorHash), nil
		case "/api/block/" + predecessorHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":99,"mediantime":99000}`, predecessorHash)), nil
		case "/api/blocks/tip/hash":
			return vaultBoardTextResponse(http.StatusOK, tipHash), nil
		case "/api/block/" + tipHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":105,"mediantime":105000}`, tipHash)), nil
		case "/api/tx/" + txid + "/outspends":
			return jsonResponse(http.StatusOK, `[{"spent":false,"txid":"","vin":0}]`), nil
		default:
			t.Fatalf("unexpected Esplora path: %s", req.URL.Path)
			return nil, nil
		}
	})
	chain, err := dialVaultBoardChainWithClient(deployment.MutinynetEsploraOrigin, doer)
	if err != nil {
		t.Fatal(err)
	}
	state, err := chain.confirmedOutpoint(context.Background(), txid, 0)
	if err != nil {
		t.Fatal(err)
	}
	if state.ValueSats != 50_000 || state.Vout != 0 || state.Spent || state.SpendingTxid != "" ||
		state.SequenceAnchorMTP != 99_000 || state.TipMTP != 105_000 || len(state.Txid) != 32 ||
		len(state.PkScript) != 34 {
		t.Fatalf("confirmed outpoint = %+v", state)
	}
	if requests["/api/tx/"+txid] != 2 || requests["/api/tx/"+txid+"/outspends"] != 2 {
		t.Fatalf("missing reorg cross-checks: %#v", requests)
	}
	if _, err := chain.revalidateOutpoint(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if requests["/api/tx/"+txid] != 2 || requests["/api/tx/"+txid+"/outspends"] != 3 ||
		requests["/api/block-height/100"] != 2 || requests["/api/blocks/tip/hash"] != 2 || requests["/api/block/"+tipHash] != 2 {
		t.Fatalf("narrow revalidation performed unexpected requests: %#v", requests)
	}
}

func TestVaultBoardChainFailsClosedOnStatusOrOutspendRace(t *testing.T) {
	txid := strings.Repeat("11", 32)
	fundingHash := strings.Repeat("22", 32)
	predecessorHash := strings.Repeat("33", 32)
	tipHash := strings.Repeat("44", 32)
	script := "5120" + strings.Repeat("55", 32)
	txCalls := 0
	outspendCalls := 0
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/api/tx/" + txid:
			txCalls++
			blockHeight := 100
			if txCalls == 2 {
				blockHeight = 101
			}
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"txid":%q,"vout":[{"value":50000,"scriptpubkey":%q}],"status":{"confirmed":true,"block_height":%d,"block_hash":%q}}`, txid, script, blockHeight, fundingHash)), nil
		case "/api/block/" + fundingHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":100,"mediantime":100000}`, fundingHash)), nil
		case "/api/block-height/100":
			return vaultBoardTextResponse(http.StatusOK, fundingHash), nil
		case "/api/block-height/99":
			return vaultBoardTextResponse(http.StatusOK, predecessorHash), nil
		case "/api/block/" + predecessorHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":99,"mediantime":99000}`, predecessorHash)), nil
		case "/api/blocks/tip/hash":
			return vaultBoardTextResponse(http.StatusOK, tipHash), nil
		case "/api/block/" + tipHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":105,"mediantime":105000}`, tipHash)), nil
		case "/api/tx/" + txid + "/outspends":
			outspendCalls++
			return jsonResponse(http.StatusOK, `[{"spent":false,"txid":"","vin":0}]`), nil
		default:
			return nil, fmt.Errorf("unexpected path %s", req.URL.Path)
		}
	})
	chain, err := dialVaultBoardChainWithClient(deployment.MutinynetEsploraOrigin, doer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.confirmedOutpoint(context.Background(), txid, 0); err == nil || !strings.Contains(err.Error(), "confirmation changed") {
		t.Fatalf("funding status race accepted: %v", err)
	}
	if outspendCalls != 1 {
		t.Fatalf("unexpected outspend calls = %d", outspendCalls)
	}
}

func TestVaultBoardChainFailsClosedOnOutspendRace(t *testing.T) {
	txid := strings.Repeat("11", 32)
	fundingHash := strings.Repeat("22", 32)
	predecessorHash := strings.Repeat("33", 32)
	tipHash := strings.Repeat("44", 32)
	spendingTxid := strings.Repeat("66", 32)
	script := "5120" + strings.Repeat("55", 32)
	outspendCalls := 0
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/api/tx/" + txid:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"txid":%q,"vout":[{"value":50000,"scriptpubkey":%q}],"status":{"confirmed":true,"block_height":100,"block_hash":%q}}`, txid, script, fundingHash)), nil
		case "/api/block/" + fundingHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":100,"mediantime":100000}`, fundingHash)), nil
		case "/api/block-height/100":
			return vaultBoardTextResponse(http.StatusOK, fundingHash), nil
		case "/api/block-height/99":
			return vaultBoardTextResponse(http.StatusOK, predecessorHash+"\n"), nil
		case "/api/block/" + predecessorHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":99,"mediantime":99000}`, predecessorHash)), nil
		case "/api/blocks/tip/hash":
			return vaultBoardTextResponse(http.StatusOK, tipHash+"\n"), nil
		case "/api/block/" + tipHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":105,"mediantime":105000}`, tipHash)), nil
		case "/api/tx/" + txid + "/outspends":
			outspendCalls++
			if outspendCalls == 1 {
				return jsonResponse(http.StatusOK, `[{"spent":false,"txid":"","vin":0}]`), nil
			}
			return jsonResponse(http.StatusOK, fmt.Sprintf(`[{"spent":true,"txid":%q,"vin":0}]`, spendingTxid)), nil
		default:
			return nil, fmt.Errorf("unexpected path %s", req.URL.Path)
		}
	})
	chain, err := dialVaultBoardChainWithClient(deployment.MutinynetEsploraOrigin, doer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.confirmedOutpoint(context.Background(), txid, 0); err == nil || !strings.Contains(err.Error(), "outspend changed") {
		t.Fatalf("outspend race accepted: %v", err)
	}
}

func TestVaultBoardChainRejectsNonCanonicalFundingBlock(t *testing.T) {
	txid := strings.Repeat("11", 32)
	fundingHash := strings.Repeat("22", 32)
	predecessorHash := strings.Repeat("33", 32)
	tipHash := strings.Repeat("44", 32)
	canonicalHash := strings.Repeat("66", 32)
	script := "5120" + strings.Repeat("55", 32)
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/api/tx/" + txid:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"txid":%q,"vout":[{"value":50000,"scriptpubkey":%q}],"status":{"confirmed":true,"block_height":100,"block_hash":%q}}`, txid, script, fundingHash)), nil
		case "/api/block/" + fundingHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":100,"mediantime":100000}`, fundingHash)), nil
		case "/api/block-height/100":
			return vaultBoardTextResponse(http.StatusOK, canonicalHash), nil
		case "/api/block-height/99":
			return vaultBoardTextResponse(http.StatusOK, predecessorHash), nil
		case "/api/block/" + predecessorHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":99,"mediantime":99000}`, predecessorHash)), nil
		case "/api/blocks/tip/hash":
			return vaultBoardTextResponse(http.StatusOK, tipHash), nil
		case "/api/block/" + tipHash:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"id":%q,"height":105,"mediantime":105000}`, tipHash)), nil
		case "/api/tx/" + txid + "/outspends":
			return jsonResponse(http.StatusOK, `[{"spent":false,"txid":"","vin":0}]`), nil
		default:
			return nil, fmt.Errorf("unexpected path %s", req.URL.Path)
		}
	})
	chain, err := dialVaultBoardChainWithClient(deployment.MutinynetEsploraOrigin, doer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.confirmedOutpoint(context.Background(), txid, 0); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("non-canonical funding block accepted: %v", err)
	}
}

func TestVaultBoardChainRejectsOriginAndUnconfirmedFunding(t *testing.T) {
	doer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{}`), nil
	})
	if _, err := dialVaultBoardChainWithClient("https://attacker.example/api", doer); err == nil || !strings.Contains(err.Error(), "release pin") {
		t.Fatalf("attacker Esplora accepted: %v", err)
	}
	chain, err := dialVaultBoardChainWithClient(deployment.MutinynetEsploraOrigin, doer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.confirmedOutpoint(context.Background(), strings.Repeat("11", 32), 0); err == nil || !strings.Contains(err.Error(), "confirmed funding") {
		t.Fatalf("unconfirmed funding accepted: %v", err)
	}
}

func TestVaultBoardChainVerifiesLiveNetworkCheckpoint(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		t.Run(network, func(t *testing.T) {
			id, err := deployment.IdentityFor(network)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name, body, contentType string
				status                  int
				transportErr            bool
				ok                      bool
			}{
				{"matching", id.CheckpointHash, "text/plain", 200, false, true},
				{"gateway newline", id.CheckpointHash + "\n", "text/html; charset=utf-8", 200, false, true},
				{"wrong chain", strings.Repeat("f", 64), "text/plain", 200, false, false},
				{"uppercase", strings.ToUpper(id.CheckpointHash), "text/plain", 200, false, false},
				{"empty", "", "text/plain", 200, false, false},
				{"oversized", id.CheckpointHash + strings.Repeat(" ", vaultBoardChainTextLimit), "text/plain", 200, false, false},
				{"JSON hash", fmt.Sprintf("%q", id.CheckpointHash), "application/json", 200, false, false},
				{"unavailable", id.CheckpointHash, "text/plain", 503, false, false},
				{"transport failure", "", "text/plain", 200, true, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					calls := 0
					chain, err := dialVaultBoardChainWithClient(id.EsploraOrigin, rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						if req.Method != http.MethodGet || req.URL.String() != fmt.Sprintf("%s/block-height/%d", id.EsploraOrigin, id.CheckpointHeight) {
							t.Fatalf("unexpected checkpoint request: %s %s", req.Method, req.URL)
						}
						if tc.transportErr {
							return nil, fmt.Errorf("unreachable")
						}
						response := vaultBoardTextResponse(tc.status, tc.body)
						response.Header.Set("Content-Type", tc.contentType)
						return response, nil
					}))
					if err != nil {
						t.Fatal(err)
					}
					if err = chain.verifyCheckpoint(context.Background(), network); (err == nil) != tc.ok || calls != 1 {
						t.Fatalf("checkpoint result err=%v calls=%d", err, calls)
					}
					other := deployment.NetworkMainnet
					if network == other {
						other = deployment.NetworkMutinynet
					}
					if chain.verifyCheckpoint(context.Background(), other) == nil || calls != 1 {
						t.Fatal("cross-network chain accepted or queried")
					}
				})
			}
		})
	}
}
