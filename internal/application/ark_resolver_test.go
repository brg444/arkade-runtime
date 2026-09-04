package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/brg444/vaulted-guardian/internal/deployment"
	"github.com/brg444/vaulted-guardian/internal/policy"
	"github.com/brg444/vaulted-guardian/internal/ports"
	"github.com/btcsuite/btcd/btcec/v2"
)

const testCheckpointTapscript = deployment.MutinynetCheckpointTapscriptHex

func TestMutinynetArkIndexerOriginPin(t *testing.T) {
	if deployment.MutinynetArkIndexerOrigin != "https://mutinynet.arkade.sh" {
		t.Fatalf("MutinynetArkIndexerOrigin = %q", deployment.MutinynetArkIndexerOrigin)
	}
}

func TestDialArkResolverPinsMutinynet(t *testing.T) {
	height, hash, err := (deployment.Config{Network: deployment.NetworkMutinynet}).BitcoinCheckpoint()
	if err != nil || height != 1 || hash != deployment.MutinynetCheckpoint1 {
		t.Fatalf("mutinynet checkpoint = %d:%s err=%v", height, hash, err)
	}

	origin := deployment.MutinynetArkIndexerOrigin
	info := fmt.Sprintf(
		`{"network":%q,"checkpointTapscript":%q,"signerPubkey":%q,"forfeitPubkey":%q,"unilateralExitDelay":"2048","boardingExitDelay":"604672","dust":"330","fees":{"intentFee":{"offchainInput":"","offchainOutput":"","onchainInput":"","onchainOutput":""}}}`,
		deployment.NetworkMutinynet, testCheckpointTapscript,
		deployment.MutinynetOperatorSignerPubHex, deployment.MutinynetCheckpointForfeitPubHex,
	)
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "mutinynet.arkade.sh" {
			t.Fatalf("contacted unexpected host %s", req.URL.Host)
		}
		if req.Method != http.MethodGet || req.URL.String() != origin+"/v1/info" {
			t.Fatalf("unexpected info request: %s %s", req.Method, req.URL)
		}
		if req.Header.Get("Accept") != "application/json" {
			t.Fatalf("missing Accept header: %#v", req.Header)
		}
		return jsonResponse(http.StatusOK, info), nil
	})
	resolver, err := dialArkResolver(context.Background(), origin, deployment.NetworkMutinynet, doer)
	if err != nil {
		t.Fatal(err)
	}
	if resolver.Network() != deployment.NetworkMutinynet {
		t.Fatalf("Network() = %q", resolver.Network())
	}
	got := hex.EncodeToString(resolver.CheckpointTapscript())
	if got != testCheckpointTapscript {
		t.Fatalf("CheckpointTapscript() = %q", got)
	}
}

func TestIntentFeePolicyRequiresAllStringProgramsAndAcceptsEmpty(t *testing.T) {
	empty := ""
	info := arkIndexerInfo{}
	info.Fees = &struct {
		IntentFee *struct {
			OffchainInput  *string `json:"offchainInput"`
			OffchainOutput *string `json:"offchainOutput"`
			OnchainInput   *string `json:"onchainInput"`
			OnchainOutput  *string `json:"onchainOutput"`
		} `json:"intentFee"`
	}{
		IntentFee: &struct {
			OffchainInput  *string `json:"offchainInput"`
			OffchainOutput *string `json:"offchainOutput"`
			OnchainInput   *string `json:"onchainInput"`
			OnchainOutput  *string `json:"onchainOutput"`
		}{OffchainInput: &empty, OffchainOutput: &empty, OnchainInput: &empty, OnchainOutput: &empty},
	}
	got, err := validatedIntentFeePolicy(info)
	if err != nil {
		t.Fatal(err)
	}
	estimator, digest, err := newVtxoFeeEstimator(got)
	if err != nil {
		t.Fatal(err)
	}
	fee, err := estimator.Eval(nil, nil, nil, nil)
	if err != nil || fee != 0 {
		t.Fatalf("empty programs fee = %v err=%v", fee, err)
	}
	if !bytes.Equal(digest, policy.ComputeIntentFeePolicyDigest("", "", "", "")) {
		t.Fatal("empty programs were normalized before hashing")
	}
	info.Fees.IntentFee.OnchainOutput = nil
	if _, err := validatedIntentFeePolicy(info); err == nil || !strings.Contains(err.Error(), "four string programs") {
		t.Fatalf("missing program = %v", err)
	}
}

func TestDialArkResolverRejectsCheckpointPolicySubstitution(t *testing.T) {
	_, attacker := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x71}, 32))
	wantForfeit, err := hex.DecodeString(deployment.MutinynetCheckpointForfeitPubHex)
	if err != nil {
		t.Fatal(err)
	}
	forfeit, err := btcec.ParsePubKey(wantForfeit)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		closure *arkscript.CSVMultisigClosure
	}{
		{
			name: "attacker-only key",
			closure: &arkscript.CSVMultisigClosure{
				MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{attacker}, Type: arkscript.MultisigTypeChecksig},
				Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: deployment.MutinynetCheckpointDelaySeconds},
			},
		},
		{
			name: "weaker delay",
			closure: &arkscript.CSVMultisigClosure{
				MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeit}, Type: arkscript.MultisigTypeChecksig},
				Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 2048},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			script, err := test.closure.Script()
			if err != nil {
				t.Fatal(err)
			}
			info := fmt.Sprintf(
				`{"network":%q,"checkpointTapscript":%q,"signerPubkey":%q}`,
				deployment.NetworkMutinynet, hex.EncodeToString(script), deployment.MutinynetOperatorSignerPubHex,
			)
			doer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, info), nil
			})
			if err := mustDialErr(t, doer); err == nil || !strings.Contains(err.Error(), "release policy") {
				t.Fatalf("substituted checkpoint policy was accepted: %v", err)
			}
		})
	}
}

func TestArkResolverRejectsOperatorReleaseProfileDrift(t *testing.T) {
	happy := happyIndexerInfo()
	for name, body := range map[string]string{
		"forfeit key":           strings.Replace(happy, deployment.MutinynetCheckpointForfeitPubHex, strings.Repeat("02", 33), 1),
		"unilateral exit delay": strings.Replace(happy, `"2048"`, `"2049"`, 1),
		"boarding exit delay":   strings.Replace(happy, `"604672"`, `"604160"`, 1),
		"dust":                  strings.Replace(happy, `"330"`, `"331"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			doer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, body), nil
			})
			if err := mustDialErr(t, doer); err == nil || !strings.Contains(err.Error(), "release policy") {
				t.Fatalf("Operator profile drift was accepted: %v", err)
			}
		})
	}
}

func TestArkResolverRechecksOperatorReleaseProfile(t *testing.T) {
	body := happyIndexerInfo()
	doer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, body), nil
	})
	resolver, err := dialArkResolver(context.Background(), deployment.MutinynetArkIndexerOrigin, deployment.NetworkMutinynet, doer)
	if err != nil {
		t.Fatal(err)
	}
	body = strings.Replace(body, `"330"`, `"331"`, 1)
	if _, err := resolver.IntentFeePolicy(context.Background()); err == nil || !strings.Contains(err.Error(), "release policy") {
		t.Fatalf("runtime Operator profile drift was accepted: %v", err)
	}
}

func TestArkResolverSpendableVtxosParsesPinnedAmounts(t *testing.T) {
	pkScript := []byte{0x51}
	txid := strings.Repeat("ab", 32)
	const amount = uint64(1234)
	origin := deployment.MutinynetArkIndexerOrigin
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "mutinynet.arkade.sh" {
			t.Fatalf("contacted unexpected host %s", req.URL.Host)
		}
		switch req.URL.Path {
		case "/v1/info":
			return jsonResponse(http.StatusOK, happyIndexerInfo()), nil
		case "/v1/indexer/vtxos":
			if req.Method != http.MethodGet {
				t.Fatalf("unexpected method %s", req.Method)
			}
			if req.URL.Query().Get("scripts") != hex.EncodeToString(pkScript) || req.URL.Query().Get("spendableOnly") != "true" ||
				req.URL.Query().Get("page.size") != "100" || req.URL.Query().Get("page.index") != "1" {
				t.Fatalf("unexpected vtxos query: %s", req.URL)
			}
			body := fmt.Sprintf(
				`{"vtxos":[{"outpoint":{"txid":%q,"vout":1},"amount":"%d","script":%q,"createdAt":"100","expiresAt":null,"isSpent":false,"isSwept":true,"commitmentTxids":[],"isUnrolled":false,"isPreconfirmed":true}],"page":{"current":1,"next":1,"total":1}}`,
				txid, amount, hex.EncodeToString(pkScript),
			)
			return jsonResponse(http.StatusOK, body), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL)
			return nil, nil
		}
	})
	resolver, err := dialArkResolver(context.Background(), origin, deployment.NetworkMutinynet, doer)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolver.SpendableVtxos(context.Background(), pkScript)
	if err != nil || len(got) != 1 {
		t.Fatalf("SpendableVtxos() = %#v err=%v", got, err)
	}
	if got[0].Txid != txid || got[0].Vout != 1 || got[0].ValueSats != amount {
		t.Fatalf("resolved vtxo = %+v", got[0])
	}
	if hex.EncodeToString(got[0].Script) != hex.EncodeToString(pkScript) {
		t.Fatalf("script = %x", got[0].Script)
	}
}

func TestArkResolverSpendableVtxosPaginatesPast100(t *testing.T) {
	pkScript := []byte{0x51}
	var requestedPages []string
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/v1/info":
			return jsonResponse(http.StatusOK, happyIndexerInfo()), nil
		case "/v1/indexer/vtxos":
			query := req.URL.Query()
			if query.Get("scripts") != hex.EncodeToString(pkScript) || query.Get("spendableOnly") != "true" || query.Get("page.size") != "100" {
				t.Fatalf("unexpected vtxos query: %s", req.URL)
			}
			page := query.Get("page.index")
			requestedPages = append(requestedPages, page)
			switch page {
			case "1":
				return jsonResponse(http.StatusOK, indexerVtxoPageJSON(pkScript, 1, 100, 1, 2, 2)), nil
			case "2":
				return jsonResponse(http.StatusOK, indexerVtxoPageJSON(pkScript, 101, 1, 2, 2, 2)), nil
			default:
				t.Fatalf("unexpected page %q", page)
				return nil, nil
			}
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL)
			return nil, nil
		}
	})
	resolver, err := dialArkResolver(context.Background(), deployment.MutinynetArkIndexerOrigin, deployment.NetworkMutinynet, doer)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolver.SpendableVtxos(context.Background(), pkScript)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 101 {
		t.Fatalf("paginated vtxos = %d, want 101", len(got))
	}
	if got[100].Txid != fmt.Sprintf("%064x", 101) {
		t.Fatalf("last paginated vtxo = %+v", got[100])
	}
	if !reflect.DeepEqual(requestedPages, []string{"1", "2"}) {
		t.Fatalf("requested pages = %#v", requestedPages)
	}
}

func TestArkResolverSpendableVtxosRejectsChangingPageTotal(t *testing.T) {
	pkScript := []byte{0x51}
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/v1/info" {
			return jsonResponse(http.StatusOK, happyIndexerInfo()), nil
		}
		if req.URL.Query().Get("page.index") == "1" {
			return jsonResponse(http.StatusOK, indexerVtxoPageJSON(pkScript, 1, 100, 1, 2, 2)), nil
		}
		return jsonResponse(http.StatusOK, indexerVtxoPageJSON(pkScript, 101, 1, 2, 3, 3)), nil
	})
	resolver, err := dialArkResolver(context.Background(), deployment.MutinynetArkIndexerOrigin, deployment.NetworkMutinynet, doer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.SpendableVtxos(context.Background(), pkScript); err == nil || !strings.Contains(err.Error(), "page total changed") {
		t.Fatalf("changing page total = %v", err)
	}
}

func TestArkResolverSpendableVtxosFailsClosedAtPageCap(t *testing.T) {
	pkScript := []byte{0x51}
	vtxoQueries := 0
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/v1/info" {
			return jsonResponse(http.StatusOK, happyIndexerInfo()), nil
		}
		vtxoQueries++
		return jsonResponse(http.StatusOK, indexerVtxoPageJSON(pkScript, 1, 100, 1, 2, arkResolverVtxoMaxPages+1)), nil
	})
	resolver, err := dialArkResolver(context.Background(), deployment.MutinynetArkIndexerOrigin, deployment.NetworkMutinynet, doer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.SpendableVtxos(context.Background(), pkScript); err == nil || !strings.Contains(err.Error(), "page limit exceeded") {
		t.Fatalf("page cap = %v", err)
	}
	if vtxoQueries != 1 {
		t.Fatalf("page cap made %d vtxo queries, want 1", vtxoQueries)
	}
}

func indexerVtxoPageJSON(pkScript []byte, first, count int, current, next, total int32) string {
	vtxos := make([]string, 0, count)
	for i := 0; i < count; i++ {
		vtxos = append(vtxos, fmt.Sprintf(
			`{"outpoint":{"txid":%q,"vout":0},"amount":"1","script":%q,"createdAt":"100","expiresAt":null,"isSpent":false,"isSwept":false,"commitmentTxids":[]}`,
			fmt.Sprintf("%064x", first+i), hex.EncodeToString(pkScript),
		))
	}
	return fmt.Sprintf(
		`{"vtxos":[%s],"page":{"current":%d,"next":%d,"total":%d}}`,
		strings.Join(vtxos, ","), current, next, total,
	)
}

func TestArkResolverMatchesArkTxidInsteadOfCheckpointSpentBy(t *testing.T) {
	pkScript := []byte{0x51}
	inputTxid := strings.Repeat("ab", 32)
	arkTxid := strings.Repeat("cd", 32)
	checkpointTxid := strings.Repeat("ef", 32)
	origin := deployment.MutinynetArkIndexerOrigin
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/v1/info":
			return jsonResponse(http.StatusOK, happyIndexerInfo()), nil
		case "/v1/indexer/vtxos":
			wantOutpoint := inputTxid + ":1"
			if !reflect.DeepEqual(req.URL.Query()["outpoints"], []string{wantOutpoint}) || req.URL.Query().Has("scripts") || req.URL.Query().Has("spendableOnly") ||
				req.URL.Query().Get("page.size") != "100" || req.URL.Query().Get("page.index") != "1" {
				t.Fatalf("unexpected vtxos query: %s", req.URL)
			}
			body := fmt.Sprintf(
				`{"vtxos":[{"outpoint":{"txid":%q,"vout":1},"amount":"1234","script":%q,"isSpent":true,"spentBy":%q,"arkTxid":%q}],"page":{"current":1,"next":1,"total":1}}`,
				inputTxid, hex.EncodeToString(pkScript), checkpointTxid, arkTxid,
			)
			return jsonResponse(http.StatusOK, body), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL)
			return nil, nil
		}
	})
	resolver, err := dialArkResolver(context.Background(), origin, deployment.NetworkMutinynet, doer)
	if err != nil {
		t.Fatal(err)
	}
	reserved := []ports.ResolvedVtxo{{Txid: inputTxid, Vout: 1, ValueSats: 1234, Script: pkScript}}
	state, err := resolver.SubmittedVtxoState(context.Background(), pkScript, reserved, arkTxid, nil, 0)
	if err != nil || state != ports.SubmittedVtxoFinalized {
		t.Fatalf("valid Arkade transaction = %v err=%v", state, err)
	}
	state, err = resolver.SubmittedVtxoState(context.Background(), pkScript, reserved, strings.Repeat("01", 32), nil, 0)
	if err != nil || state != ports.SubmittedVtxoConflict {
		t.Fatalf("unrelated Arkade transaction = %v err=%v", state, err)
	}
}

func TestArkResolverRequiresChangeVtxoAfterFinalize(t *testing.T) {
	pkScript := []byte{0x51, 0x20}
	inputTxid := strings.Repeat("ab", 32)
	arkTxid := strings.Repeat("cd", 32)
	origin := deployment.MutinynetArkIndexerOrigin
	vtxoQueries := 0
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/v1/info":
			return jsonResponse(http.StatusOK, happyIndexerInfo()), nil
		case "/v1/indexer/vtxos":
			vtxoQueries++
			wantOutpoints := []string{inputTxid + ":0", arkTxid + ":1"}
			if !reflect.DeepEqual(req.URL.Query()["outpoints"], wantOutpoints) || req.URL.Query().Has("scripts") || req.URL.Query().Has("spendableOnly") ||
				req.URL.Query().Get("page.size") != "100" || req.URL.Query().Get("page.index") != "1" {
				t.Fatalf("reconciliation must use exact outpoints: %s", req.URL)
			}
			body := fmt.Sprintf(
				`{"vtxos":[{"outpoint":{"txid":%q,"vout":0},"amount":"10000","script":%q,"isSpent":true,"arkTxid":%q},{"outpoint":{"txid":%q,"vout":1},"amount":"8766","script":%q,"createdAt":"100","expiresAt":null,"isSwept":false,"commitmentTxids":["%s"],"isSpent":true}],"page":{"current":1,"next":1,"total":1}}`,
				inputTxid, hex.EncodeToString(pkScript), arkTxid, arkTxid, hex.EncodeToString(pkScript), strings.Repeat("ef", 32),
			)
			return jsonResponse(http.StatusOK, body), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL)
			return nil, nil
		}
	})
	resolver, err := dialArkResolver(context.Background(), origin, deployment.NetworkMutinynet, doer)
	if err != nil {
		t.Fatal(err)
	}
	reserved := []ports.ResolvedVtxo{{Txid: inputTxid, Vout: 0, ValueSats: 10000, Script: pkScript}}
	changeVout := uint32(1)
	state, err := resolver.SubmittedVtxoState(context.Background(), pkScript, reserved, arkTxid, &changeVout, 8766)
	if err != nil || state != ports.SubmittedVtxoFinalized {
		t.Fatalf("finalized change = %v err=%v", state, err)
	}
	if vtxoQueries != 1 {
		t.Fatalf("submitted reconciliation made %d indexer queries, want 1", vtxoQueries)
	}
	if _, err := resolver.SubmittedVtxoState(context.Background(), pkScript, reserved, arkTxid, &changeVout, 1); err == nil {
		t.Fatal("wrong change amount accepted")
	}
}

func TestDialArkResolverRejectsOriginsWithoutNetwork(t *testing.T) {
	fatalDoer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid origin reached the network")
		return nil, nil
	})
	for _, raw := range []string{
		"http://mutinynet.arkade.sh",
		"https://Mutinynet.arkade.sh",
		"https://mutinynet.arkade.sh/",
		"https://mutinynet.arkade.sh:443",
		"https://user@mutinynet.arkade.sh",
		"https://mutinynet.arkade.sh.",
		"",
		"https://emulator.mutinynet.arkade.sh",
		"https://mutinynet.arkade.sh/api",
	} {
		if _, err := dialArkResolver(context.Background(), raw, deployment.NetworkMutinynet, fatalDoer); err == nil {
			t.Fatalf("non-canonical origin accepted: %q", raw)
		}
	}
}

func TestDialArkResolverRejectsNetworkMismatch(t *testing.T) {
	if _, err := DialArkResolver(context.Background(), "regtest"); err == nil || !strings.Contains(err.Error(), "network") {
		t.Fatalf("regtest dial accepted: %v", err)
	}

	for _, body := range []string{
		`{"network":"","checkpointTapscript":"aabb"}`,
		`{"network":"signet","checkpointTapscript":"aabb"}`,
		`{"network":"bitcoin","checkpointTapscript":"aabb"}`,
		`{"network":"regtest","checkpointTapscript":"aabb"}`,
		`{"network":"mainnet","checkpointTapscript":"aabb"}`,
		`{"network":"testnet","checkpointTapscript":"aabb"}`,
	} {
		t.Run(body, func(t *testing.T) {
			doer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, body), nil
			})
			err := mustDialErr(t, doer)
			if !strings.Contains(err.Error(), "network") && !strings.Contains(err.Error(), "checkpoint") {
				t.Fatalf("error %q must mention network or checkpoint", err)
			}
		})
	}
}

func TestDialArkResolverIgnoresEnvOverride(t *testing.T) {
	t.Setenv("ARK_INDEXER_ORIGIN", "https://attacker.example")
	t.Setenv("EMULATOR_ARKD_URL", "https://attacker.example")
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "mutinynet.arkade.sh" {
			t.Fatalf("contacted unexpected host %s", req.URL.Host)
		}
		if req.URL.Path != "/v1/info" {
			t.Fatalf("unexpected path %s", req.URL.Path)
		}
		return jsonResponse(http.StatusOK, happyIndexerInfo()), nil
	})
	if _, err := dialArkResolver(context.Background(), deployment.MutinynetArkIndexerOrigin, deployment.NetworkMutinynet, doer); err != nil {
		t.Fatal(err)
	}
	if _, err := DialArkResolver(context.Background(), "regtest"); err == nil {
		t.Fatal("public Dial accepted regtest")
	}
}

func TestArkResolverRejectsRedirects(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://attacker.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := newArkResolverHTTPClient().CheckRedirect(req, nil); err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("redirect accepted: %v", err)
	}
}

func TestDialArkResolverRejectsIncompleteAndNonOK(t *testing.T) {
	for name, res := range map[string]*http.Response{
		"empty object": jsonResponse(http.StatusOK, `{}`),
		"missing tap":  jsonResponse(http.StatusOK, `{"network":"mutinynet"}`),
		"missing net":  jsonResponse(http.StatusOK, `{"checkpointTapscript":"aabb"}`),
		"empty tap":    jsonResponse(http.StatusOK, `{"network":"mutinynet","checkpointTapscript":""}`),
		"http 500":     jsonResponse(http.StatusInternalServerError, `{"message":"no"}`),
	} {
		t.Run(name, func(t *testing.T) {
			doer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
				return res, nil
			})
			if err := mustDialErr(t, doer); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSpendableVtxosRejectsEmptyScriptAndSpent(t *testing.T) {
	pkScript := []byte{0x51}
	txid := strings.Repeat("cd", 32)
	origin := deployment.MutinynetArkIndexerOrigin
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/v1/info" {
			return jsonResponse(http.StatusOK, happyIndexerInfo()), nil
		}
		body := fmt.Sprintf(
			`{"vtxos":[{"outpoint":{"txid":%q,"vout":0},"amount":"99","script":%q,"isSpent":true}],"page":{"current":1,"next":1,"total":1}}`,
			txid, hex.EncodeToString(pkScript),
		)
		return jsonResponse(http.StatusOK, body), nil
	})
	resolver, err := dialArkResolver(context.Background(), origin, deployment.NetworkMutinynet, doer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.SpendableVtxos(context.Background(), nil); err == nil {
		t.Fatal("empty pkScript accepted")
	}
	got, err := resolver.SpendableVtxos(context.Background(), pkScript)
	if err != nil || len(got) != 0 {
		t.Fatalf("spent vtxo accepted: %#v err=%v", got, err)
	}
}

func happyIndexerInfo() string {
	return fmt.Sprintf(
		`{"network":%q,"checkpointTapscript":%q,"signerPubkey":%q,"forfeitPubkey":%q,"unilateralExitDelay":"2048","boardingExitDelay":"604672","dust":"330","fees":{"intentFee":{"offchainInput":"","offchainOutput":"","onchainInput":"","onchainOutput":""}}}`,
		deployment.NetworkMutinynet, testCheckpointTapscript, deployment.MutinynetOperatorSignerPubHex,
		deployment.MutinynetCheckpointForfeitPubHex,
	)
}

func mustDialErr(t *testing.T, doer httpDoer) error {
	t.Helper()
	_, err := dialArkResolver(context.Background(), deployment.MutinynetArkIndexerOrigin, deployment.NetworkMutinynet, doer)
	if err == nil {
		t.Fatal("dial succeeded")
	}
	return err
}
